//! The networking runtime: one command loop owning at most one session (server
//! or client), adapted from duopipe's peer runtime with the SOCKS payload
//! replaced by a single long-lived clipboard stream.
//!
//! Per connection (client = dialer): the client opens a single bidirectional
//! stream and authenticates on it (application key or PIN); on success that same stream
//! stays open and both sides pump [`ClipMsg`] frames in both directions until
//! the connection dies or the session is cancelled.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{EndpointAddr, EndpointId};
use rand::RngCore as _;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::auth::{Identity, IdentityCard, unix_now, verify_auth_signature};
use crate::net::endpoint::{
    EndpointReadiness, connect_to_server, connection_paths, create_client_endpoint,
    create_server_endpoint, watch_connection_paths,
};
use crate::net::{
    ConnStatus, DialSpec, EventSender, KeyIdentity, NetEvent, ServerMode, SignalChannel, UiCommand,
};
use crate::protocol::{
    AuthRequest, AuthResponse, ClipBody, ClipMsg, KeyChallenge, KeyProof,
    MAX_CLIP_MESSAGE_SIZE, MAX_CONTROL_MESSAGE_SIZE, decode_auth_request,
    decode_auth_response, decode_clip_msg, decode_key_challenge, decode_key_proof,
    encode_auth_request, encode_auth_response, encode_clip_msg, encode_key_challenge,
    encode_key_proof, read_length_prefixed,
};

/// Retain only the PIN keys from the sender's current and previous rotation buckets for
/// in-band authentication. The joiner may still probe an additional bucket for clock skew.
const RECENT_PIN_CACHE: usize = 2;

/// Timeout for the authentication handshake.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Connection close code for authentication failure (invalid application key/PIN).
const AUTH_FAILED_CODE: u32 = 1;

/// Connection close code for authentication timeout (no auth within deadline).
const AUTH_TIMEOUT_CODE: u32 = 2;

/// Connection close code for a clean local shutdown/disconnect. "No error" by
/// convention; the peer just sees the connection go away.
const SHUTDOWN_CODE: u32 = 0;

/// Connection close code the listener uses to refuse a dialer that isn't its
/// paired peer: this endpoint already pairs with one device at a time. The
/// dialer recognizes it (see [`auth_close_reason`]) and gives up rather than
/// retrying against a server that will never take it.
const SERVER_BUSY_CODE: u32 = 3;

/// Connection close code the listener uses when the dialer's key is trusted but
/// the card carrying that trust has expired. Distinct from [`AUTH_FAILED_CODE`]
/// because the remedy is specific and the user cannot guess it: cards are never
/// refreshed over the wire, so the dialer's owner has to hand over a new one.
const CARD_EXPIRED_CODE: u32 = 4;

/// Fixed delay between reconnect attempts on the dialing peer.
const RECONNECT_DELAY: Duration = Duration::from_secs(3);

/// Maximum number of *consecutive* failed connect attempts before the client
/// gives up. The counter resets on every successful connection, so this bounds
/// only an unbroken run of failures (an unreachable peer) — not a flaky link
/// that keeps recovering. Applied uniformly whether or not a connection has
/// succeeded before, so a dropped session never retries without end. Giving up
/// ends the session task but not the pairing: the endpoint identity and pinned
/// dial target live on in [`SessionMemory`], so pressing Join again with the
/// same PIN/peer reconnects as the same node id instead of being refused by
/// the server's claim.
const MAX_CONNECT_ATTEMPTS: u32 = 10;

/// Marker error for fatal authentication failures (wrong application key/PIN, explicit
/// rejection, auth timeout). The client session ends on these instead of
/// retrying — the credential won't get better on its own.
#[derive(Debug)]
pub struct AuthFailure(pub String);

impl std::fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for AuthFailure {}

fn auth_failure(msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(AuthFailure(msg.into()))
}

/// Marker error for a refusal caused by an expired identity card, so the
/// listener can pick [`CARD_EXPIRED_CODE`] out of the shared failure path.
#[derive(Debug)]
struct ExpiredCard;

impl std::fmt::Display for ExpiredCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the identity card for this device has expired")
    }
}

impl std::error::Error for ExpiredCard {}

/// The wording both roles use when their stored card for the other side has
/// lapsed. Cards are local trust records — the clipboard handshake carries raw
/// public keys, never a card — so each side judges its own copy, and both
/// should say the same thing about it whether it surfaces as a listener refusal
/// or a dialer's own pre-check. (A card does cross the wire during card setup,
/// but that is the hand-over itself, not this handshake.)
fn expired_card_message(card: &IdentityCard) -> String {
    format!(
        "The identity card for {} expired — ask that device for a fresh card and import it again",
        card.name()
    )
}

fn expired_card_error(card: &IdentityCard) -> anyhow::Error {
    anyhow::Error::new(ExpiredCard).context(expired_card_message(card))
}

/// Milliseconds since the Unix epoch (sender timestamp on clipboard items).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Current and previous PIN auth keypairs (newest first), one per rotation bucket the card-setup
/// host has published. Written by the PIN publisher, read by the listener auth path to verify a
/// dialer's proof. Cheap to clone (shared handle).
#[derive(Clone, Default)]
struct RecentPins(Arc<parking_lot::RwLock<VecDeque<nostr_sdk::Keys>>>);

impl RecentPins {
    fn push(&self, keys: nostr_sdk::Keys) {
        let mut g = self.0.write();
        g.push_front(keys);
        while g.len() > RECENT_PIN_CACHE {
            g.pop_back();
        }
    }

    fn snapshot(&self) -> Vec<nostr_sdk::Keys> {
        self.0.read().iter().cloned().collect()
    }

    /// Drop every retained key: no previously shown PIN can authenticate a
    /// dialer anymore (an immediate refresh revokes, unlike natural rotation,
    /// which keeps a look-back window).
    fn clear(&self) {
        self.0.write().clear();
    }
}

/// The single peer a serve endpoint is paired with, for the lifetime of one logical session.
/// duocb links one pair of devices at a time by design: once a client authenticates, its
/// (QUIC/TLS-authenticated) node id claims the endpoint and any other node id is refused until
/// the server is stopped. The claim is intentionally *not* released when the paired peer
/// disconnects, so that peer — and only that peer — can reconnect without re-pairing (in PIN
/// mode, without re-typing a PIN that may since have rotated). The claim lives in
/// [`SessionMemory`], owned by the command loop, so it survives session-task restarts;
/// explicitly stopping the server discards it, and a restarted server then holds a new
/// endpoint id and an empty claim.
#[derive(Clone, Default)]
struct PairClaim {
    peer: Arc<parking_lot::Mutex<Option<ClaimedPeer>>>,
    /// Fires the first time a peer commits the claim. The PIN publisher watches this so it can
    /// stop rotating/publishing (and clear the displayed code) once paired.
    paired: CancellationToken,
}

/// The peer that holds a [`PairClaim`], plus the material needed to let it reconnect.
#[derive(Clone)]
struct ClaimedPeer {
    /// Configure mode claims the stable application identity. Card setup has no
    /// such identity and claims the session-scoped iroh id instead.
    application_key: Option<nostr_sdk::PublicKey>,
    node_id: Option<EndpointId>,
}

impl PairClaim {
    /// Snapshot the current claim (cheap clone) for the pre-auth gate.
    fn peek(&self) -> Option<ClaimedPeer> {
        self.peer.lock().clone()
    }

    /// A token that is cancelled the first time a peer commits the claim, so watchers (the PIN
    /// publisher) can react to pairing without polling.
    fn paired_signal(&self) -> CancellationToken {
        self.paired.clone()
    }

    /// Commit a freshly authenticated peer as the pair. Returns `true` if `node_id` now holds
    /// the claim — either because it was unclaimed and we just took it, or because this same
    /// peer already held it (a reconnect/retry). Returns `false` if another node id won the
    /// claim first (a race between two first-time dialers), in which case the caller must
    /// reject this peer.
    fn commit_key(&self, public_key: nostr_sdk::PublicKey, node_id: EndpointId) -> bool {
        let mut g = self.peer.lock();
        match g.as_ref() {
            Some(c) if c.application_key != Some(public_key) => false,
            Some(_) => {
                if let Some(claimed) = g.as_mut() {
                    claimed.node_id = Some(node_id);
                }
                true
            }
            None => {
                *g = Some(ClaimedPeer {
                    application_key: Some(public_key),
                    node_id: Some(node_id),
                });
                self.paired.cancel();
                true
            }
        }
    }

    /// Commit a card-setup joiner as the pair. Unlike the configure-mode claim
    /// this is never re-presented: a card-setup session ends the moment the cards
    /// cross, so the claim only has to turn away a second dialer arriving
    /// mid-exchange.
    fn commit_pin(&self, node_id: EndpointId) -> bool {
        let mut g = self.peer.lock();
        match g.as_ref() {
            Some(c) if c.node_id != Some(node_id) => false,
            Some(_) => true,
            None => {
                *g = Some(ClaimedPeer {
                    application_key: None,
                    node_id: Some(node_id),
                });
                self.paired.cancel();
                true
            }
        }
    }
}

// ============================================================================
// Command loop
// ============================================================================

enum SessionKind {
    Server(ServerMode),
    Client(DialSpec),
}

/// What a session's identity is bound to. Reusing [`SessionMemory`] is only
/// correct while the session is "the same" from the user's point of view —
/// same role and same credential/target; anything else mints fresh state.
#[derive(Clone, PartialEq, Eq)]
enum SessionKey {
    /// The channel is part of the key: it decides which transport stack the
    /// endpoint is built with, so a session started on a different channel must
    /// not inherit an endpoint bound for the old one.
    ServerCardSetup {
        channel: SignalChannel,
    },
    ServerKey {
        public_key: nostr_sdk::PublicKey,
        channel: SignalChannel,
    },
    ClientCardSetup {
        canonical_pin: String,
        channel: SignalChannel,
    },
    ClientKey {
        public_key: nostr_sdk::PublicKey,
        peer_public_key: nostr_sdk::PublicKey,
        channel: SignalChannel,
    },
}

fn session_key(kind: &SessionKind) -> SessionKey {
    match kind {
        SessionKind::Server(ServerMode::CardSetup { channel, .. }) => SessionKey::ServerCardSetup {
            channel: *channel,
        },
        SessionKind::Server(ServerMode::Key { identity, channel }) => SessionKey::ServerKey {
            public_key: identity.identity.public_key(),
            channel: *channel,
        },
        SessionKind::Client(DialSpec::CardSetup {
            canonical_pin,
            channel,
            ..
        }) => SessionKey::ClientCardSetup {
            canonical_pin: canonical_pin.clone(),
            channel: *channel,
        },
        SessionKind::Client(DialSpec::Key {
            identity,
            peer_public_key,
            channel,
        }) => SessionKey::ClientKey {
            public_key: identity.identity.public_key(),
            peer_public_key: *peer_public_key,
            channel: *channel,
        },
    }
}

/// Identity and pairing state for one logical session, owned by the command
/// loop and lent to every session task started under the same [`SessionKey`].
/// A session task can end while the pairing is still good — the client gives
/// up after [`MAX_CONNECT_ATTEMPTS`], an auth exchange dies mid-handshake, a
/// host restarts the session — and the endpoint identity is what the peer's
/// pair claim is bound to. Keeping the secret key (and with it the node id) and
/// the server's claim here lets the next task reconnect as the same peer
/// instead of being refused as a stranger.
/// Cleared on [`UiCommand::StopServer`]/[`UiCommand::Disconnect`] — the user
/// ending the session is the one legitimate way to unpair — and replaced when
/// a session starts under a different key. Never persisted; a fresh process
/// starts clean.
struct SessionMemory {
    key: SessionKey,
    secret: iroh::SecretKey,
    /// Server: the one-pair-per-session claim (holds the paired peer's node id).
    claim: PairClaim,
    /// Card-setup host: the recent rotation buckets' auth keys.
    recent_pins: RecentPins,
}

impl SessionMemory {
    fn new(key: SessionKey) -> Self {
        Self {
            key,
            secret: iroh::SecretKey::generate(),
            claim: PairClaim::default(),
            recent_pins: RecentPins::default(),
        }
    }
}

/// Reuse the held memory when the new session's key matches (the same logical
/// session continuing under a new task); mint fresh identity and pairing state
/// otherwise.
fn remember(memory: &mut Option<SessionMemory>, key: SessionKey) -> &SessionMemory {
    if memory.as_ref().is_none_or(|m| m.key != key) {
        *memory = Some(SessionMemory::new(key));
    }
    memory.as_ref().expect("memory was just ensured")
}

/// Shared slot holding a clone of the currently-paired connection (or `None`
/// when unpaired), so the command loop can snapshot its paths on demand without
/// interrupting the session task's pump. iroh's `Connection` is a cheap handle.
type ConnSlot = Arc<parking_lot::Mutex<Option<iroh::endpoint::Connection>>>;

/// The single bidirectional session stream: auth runs on it first, then it
/// carries clipboard frames both ways for the life of the connection.
type Bi = (iroh::endpoint::SendStream, iroh::endpoint::RecvStream);

/// The latest item this session sent (text + original send time), kept for the
/// session's lifetime — across reconnects — so a resuming peer can pull it.
/// Never persisted; a fresh session starts empty.
type LastSent = Arc<parking_lot::Mutex<Option<(String, u64)>>>;

/// A running server or client session: its cancel token, task handle, the
/// channel that feeds outbound clipboard items into the active connection, and
/// the shared connection slot for on-demand path queries.
struct Session {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
    clip_tx: mpsc::UnboundedSender<String>,
    conn: ConnSlot,
    /// Kicks the PIN publisher into an immediate rotate-and-revoke (see
    /// [`UiCommand::RefreshPin`]). `Some` only for a card-setup host session.
    pin_refresh: Option<Arc<tokio::sync::Notify>>,
}

fn start_session(
    kind: SessionKind,
    events: EventSender,
    memory: &SessionMemory,
) -> Session {
    let cancel = CancellationToken::new();
    let (clip_tx, clip_rx) = mpsc::unbounded_channel();
    let task_cancel = cancel.clone();
    let conn: ConnSlot = Arc::new(parking_lot::Mutex::new(None));
    let task_conn = conn.clone();
    let pin_refresh = matches!(&kind, SessionKind::Server(ServerMode::CardSetup { .. }))
        .then(|| Arc::new(tokio::sync::Notify::new()));
    let task_pin_refresh = pin_refresh.clone();
    let secret = memory.secret.clone();
    let claim = memory.claim.clone();
    let recent_pins = memory.recent_pins.clone();
    let handle = tokio::spawn(async move {
        let last_sent = LastSent::default();
        // Card setup takes neither `clip_rx` nor the connection slot: it never
        // carries clipboard traffic, and dropping the receiver here means a
        // stray `SendClipboard` fails loudly at the command loop instead of
        // being silently swallowed by a session that would never transmit it.
        match kind {
            SessionKind::Server(ServerMode::CardSetup {
                self_card,
                channel,
                relays,
            }) => {
                run_card_setup_host(
                    *self_card,
                    channel,
                    relays,
                    events,
                    task_cancel,
                    task_pin_refresh.unwrap_or_default(),
                    secret,
                    claim,
                    recent_pins,
                )
                .await
            }
            SessionKind::Server(mode) => {
                run_server_session(
                    mode,
                    events,
                    task_cancel,
                    clip_rx,
                    task_conn,
                    last_sent,
                    secret,
                    claim,
                )
                .await
            }
            SessionKind::Client(DialSpec::CardSetup {
                canonical_pin,
                self_card,
                target_ip,
                channel,
                relays,
            }) => {
                run_card_setup_joiner(
                    canonical_pin,
                    *self_card,
                    target_ip,
                    channel,
                    relays,
                    events,
                    task_cancel,
                    secret,
                )
                .await
            }
            SessionKind::Client(spec) => {
                run_client_session(
                    spec,
                    events,
                    task_cancel,
                    clip_rx,
                    task_conn,
                    last_sent,
                    secret,
                )
                .await
            }
        }
    });
    Session {
        cancel,
        handle,
        clip_tx,
        conn,
        pin_refresh,
    }
}

async fn stop_session(session: &mut Option<Session>) {
    if let Some(s) = session.take() {
        s.cancel.cancel();
        // A graceful teardown (closing the endpoint, notifying the peer)
        // normally finishes in well under a second. Bound the wait so a
        // stalled close can never wedge this command loop — every queued UI
        // command sits behind this await.
        let mut handle = s.handle;
        if tokio::time::timeout(Duration::from_secs(3), &mut handle)
            .await
            .is_err()
        {
            handle.abort();
        }
    }
}

/// The runtime's main loop. It never mutates caller-owned local trust.
pub async fn net_main(mut cmd_rx: mpsc::UnboundedReceiver<UiCommand>, events: EventSender) {
    let mut session: Option<Session> = None;
    let mut memory: Option<SessionMemory> = None;

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            UiCommand::StartServer { mode } => {
                stop_session(&mut session).await;
                let kind = SessionKind::Server(mode);
                let mem = remember(&mut memory, session_key(&kind));
                session = Some(start_session(kind, events.clone(), mem));
            }
            UiCommand::Connect { spec } => {
                stop_session(&mut session).await;
                let kind = SessionKind::Client(spec);
                let mem = remember(&mut memory, session_key(&kind));
                session = Some(start_session(kind, events.clone(), mem));
            }
            UiCommand::StopServer | UiCommand::Disconnect => {
                stop_session(&mut session).await;
                memory = None;
                events.status(ConnStatus::Idle);
            }
            UiCommand::RefreshPin => {
                match session.as_ref().and_then(|s| s.pin_refresh.as_ref()) {
                    Some(refresh) => refresh.notify_one(),
                    None => events.error("No PIN is being published"),
                }
            }
            UiCommand::SendClipboard { text } => {
                let sent = session
                    .as_ref()
                    .is_some_and(|s| s.clip_tx.send(text).is_ok());
                if !sent {
                    events.error("Not connected — start or join a session first");
                }
            }
            UiCommand::QueryConnPath => {
                // Point-in-time snapshot from the live connection, if any.
                let paths = session
                    .as_ref()
                    .and_then(|s| s.conn.lock().clone())
                    .map(|conn| connection_paths(&conn))
                    .unwrap_or_default();
                events.send(NetEvent::ConnPath(paths));
            }
            UiCommand::Shutdown => break,
        }
    }

    stop_session(&mut session).await;
}

// ============================================================================
// Server session
// ============================================================================

/// Background guard that aborts a publisher task on drop.
struct PublisherGuard(JoinHandle<()>);

impl Drop for PublisherGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_server_session(
    mode: ServerMode,
    events: EventSender,
    cancel: CancellationToken,
    mut clip_rx: mpsc::UnboundedReceiver<String>,
    conn_slot: ConnSlot,
    last_sent: LastSent,
    secret: iroh::SecretKey,
    claim: PairClaim,
) {
    let ServerMode::Key { identity, channel } = mode else {
        unreachable!("card-setup hosts run in run_card_setup_host");
    };
    events.status(ConnStatus::Starting);

    let endpoint = match create_server_endpoint(channel_readiness(channel), secret).await {
        Ok(ep) => ep,
        Err(e) => {
            events.error(format!("Failed to start: {e:#}"));
            events.status(ConnStatus::Idle);
            return;
        }
    };
    let node_id = endpoint.id();

    // One pairing per logical session. The claim (owned by the command loop,
    // like the endpoint identity) is empty until the first client authenticates
    // and lives until the server is stopped — surviving a restarted session
    // task, whose paired peer reconnects seamlessly.
    let key_identity = (*identity).clone();
    events.send(NetEvent::ServerReady {
        node_id: node_id.to_string(),
        identity_public_key: Some(identity.identity.to_npub()),
    });
    events.status(ConnStatus::Listening);

    // Pairwise hosting-record publisher, aborted on session teardown.
    let _publisher = PublisherGuard(tokio::spawn(run_hosting_publisher(
        endpoint.clone(),
        *identity,
        channel,
        events.clone(),
        cancel.clone(),
    )));

    // Accept loop: duocb pairs exactly two devices, so at most one clipboard
    // session is served at a time. Crucially the accept keeps running *during*
    // a live session (see the select below): any dialer that isn't the claimed
    // peer is refused immediately with a BUSY close inside `accept_serveable` —
    // the claim's node id is QUIC/TLS-authenticated, so no in-band auth is
    // needed to turn it away — and it gives up instead of hanging until its
    // connect times out. A fresh connection from the *paired* peer preempts the
    // current one, so a resumed link doesn't wait on the dead connection's idle
    // timeout to be reaped.
    //
    // `pending` carries a preempting reconnect from one loop turn to the next.
    let mut pending: Option<iroh::endpoint::Connection> = None;
    loop {
        let conn = match pending.take() {
            Some(conn) => conn,
            None => match accept_serveable(&endpoint, &claim, &cancel, true).await {
                Some(conn) => conn,
                None => break,
            },
        };
        let remote_id = conn.remote_id();
        log::info!("Peer connected: {remote_id} (awaiting auth)");
        events.status(ConnStatus::Authenticating);

        // Auth runs on the single session stream; on success the same stream
        // stays open for clipboard frames (no separate data stream / handshake).
        let (send, recv, peer_public_key) =
            match auth_as_listener(&conn, Some(&key_identity), None, &claim, node_id).await {
                Ok(streams) => streams,
                Err(e) => {
                    log::warn!("Auth failed for {remote_id}: {e:#}");
                    events.status(ConnStatus::Listening);
                    continue;
                }
            };
        events.send(NetEvent::PeerPaired {
            peer_node_id: remote_id.to_string(),
            peer_public_key: peer_public_key.map(|key| key.to_hex()),
        });

        // Debug-only path logging; on-demand status reads `conn_slot` directly.
        let _paths = watch_connection_paths(&conn);
        *conn_slot.lock() = Some(conn.clone());

        events.status(ConnStatus::Connected);
        // Pump this connection while still accepting. `accept_serveable` refuses
        // every other dialer BUSY; it only ever *returns* here for a fresh
        // connection from the paired peer, which preempts (seamless reconnect).
        let pump = pump_clipboard(send, recv, &events, &mut clip_rx, &cancel, &last_sent);
        tokio::pin!(pump);
        let preempt = tokio::select! {
            r = &mut pump => {
                match r {
                    Ok(()) => log::info!("Clipboard session with {remote_id} ended"),
                    Err(e) => log::warn!("Clipboard session with {remote_id} ended: {e:#}"),
                }
                None
            }
            next = accept_serveable(&endpoint, &claim, &cancel, false) => next,
        };
        *conn_slot.lock() = None;

        if cancel.is_cancelled() {
            conn.close(SHUTDOWN_CODE.into(), b"shutdown");
            break;
        }

        match preempt {
            // The paired peer reconnected: drop the old connection and serve the
            // new one on the next turn, without flapping the UI to "waiting".
            Some(next) => {
                conn.close(SHUTDOWN_CODE.into(), b"superseded");
                pending = Some(next);
            }
            // The session ended on its own: back to waiting for the paired peer.
            None => {
                events.send(NetEvent::PeerDisconnected);
                events.status(ConnStatus::Listening);
            }
        }
    }

    endpoint.close().await;
    log::info!("Server session stopped");
}

/// Accept connections, refusing any that isn't the currently-claimed peer with
/// a BUSY close, until a serveable one is obtained: a first-time dialer while
/// the claim is still empty, or the claimed peer (re)connecting. Returns `None`
/// when the session is cancelled or the endpoint closes.
///
/// This runs both between sessions and *concurrently with* a live pump (see the
/// accept loop's select). During a live session the claim is held, so the only
/// connection it returns is a fresh one from the paired peer — every other
/// dialer is turned away here before it ever reaches auth.
async fn accept_serveable(
    endpoint: &iroh::Endpoint,
    claim: &PairClaim,
    cancel: &CancellationToken,
    allow_new_transport_for_key_claim: bool,
) -> Option<iroh::endpoint::Connection> {
    loop {
        let incoming = tokio::select! {
            _ = cancel.cancelled() => return None,
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => {
                    log::info!("Endpoint closed");
                    return None;
                }
            },
        };
        let conn = match incoming.await {
            Ok(conn) => conn,
            Err(e) => {
                log::warn!("Failed to accept connection: {e}");
                continue;
            }
        };
        // The remote id is authenticated by the QUIC/TLS handshake, so a dialer
        // that isn't the paired peer is turned away here — before any in-band
        // auth — with a BUSY close it recognizes and gives up on.
        if let Some(claimed) = claim.peek()
            && claimed.node_id != Some(conn.remote_id())
            && (claimed.application_key.is_none() || !allow_new_transport_for_key_claim)
        {
            log::warn!(
                "Refusing {}: already paired with another device",
                conn.remote_id()
            );
            conn.close(SERVER_BUSY_CODE.into(), b"busy");
            continue;
        }
        return Some(conn);
    }
}

// ============================================================================
// Client session
// ============================================================================

#[allow(clippy::too_many_arguments)]
async fn run_client_session(
    spec: DialSpec,
    events: EventSender,
    cancel: CancellationToken,
    mut clip_rx: mpsc::UnboundedReceiver<String>,
    conn_slot: ConnSlot,
    last_sent: LastSent,
    secret: iroh::SecretKey,
) {
    events.status(ConnStatus::Starting);

    let DialSpec::Key {
        identity,
        peer_public_key,
        channel,
    } = &spec
    else {
        unreachable!("card-setup joiners run in run_card_setup_joiner");
    };
    let channel = *channel;

    // Refuse before spending an endpoint and a relay round trip on a peer whose
    // card has lapsed. The listener enforces the same rule against its own copy;
    // this side checks its own so the failure is immediate and self-explanatory
    // rather than surfacing as a remote rejection.
    if let Some(card) = identity.peer(*peer_public_key)
        && !card.is_valid_at(unix_now())
    {
        events.error(expired_card_message(card));
        events.status(ConnStatus::Idle);
        return;
    }

    let endpoint = match create_client_endpoint(channel_readiness(channel), secret).await {
        Ok(ep) => ep,
        Err(e) => {
            events.error(format!("Failed to start: {e:#}"));
            events.status(ConnStatus::Idle);
            return;
        }
    };
    let own_id = endpoint.id();
    events.send(NetEvent::ClientReady {
        node_id: own_id.to_string(),
        identity_public_key: Some(identity.identity.to_npub()),
    });

    // Consecutive failed attempts, reset to zero on every successful connection
    // (below). Fixed-interval retry, bounded by `MAX_CONNECT_ATTEMPTS`.
    let mut attempts: u32 = 0;

    loop {
        // Resolve the target each attempt: the dial target lives in the peer's
        // hosting record, not a directory, so a restarted host's fresh node id
        // is found, and absent (no readable record) means the peer is not
        // currently hosting.
        events.status(ConnStatus::Resolving);
        let resolved: Result<EndpointAddr> = tokio::select! {
            _ = cancel.cancelled() => return,
            r = resolve_hosting(identity, *peer_public_key, channel) => r,
        };

        // Self-dial guard: end the session — the target won't change.
        if let Ok(addr) = &resolved
            && addr.id == own_id
        {
            events.error("That is this device's own node id — enter the other device's id");
            events.status(ConnStatus::Idle);
            endpoint.close().await;
            return;
        }
        let connect = match resolved {
            Ok(addr) => {
                events.status(ConnStatus::Connecting);
                tokio::select! {
                    _ = cancel.cancelled() => { endpoint.close().await; return; }
                    c = connect_to_server(&endpoint, addr) => c,
                }
            }
            Err(e) => Err(e),
        };

        match connect {
            Ok(conn) => {
                events.status(ConnStatus::Authenticating);
                // Auth runs on the single session stream; on success the same
                // stream stays open for clipboard frames.
                let auth_result =
                    auth_as_dialer_key(&conn, &identity.identity, *peer_public_key, own_id).await;
                match auth_result {
                    Ok((send, recv)) => {
                        let remote_id = conn.remote_id();
                        events.send(NetEvent::PeerPaired {
                            peer_node_id: remote_id.to_string(),
                            peer_public_key: Some(peer_public_key.to_hex()),
                        });
                        events.status(ConnStatus::Connected);
                        // Debug-only path logging; on-demand status reads
                        // `conn_slot` directly.
                        let _paths = watch_connection_paths(&conn);
                        *conn_slot.lock() = Some(conn.clone());
                        attempts = 0;

                        match pump_clipboard(send, recv, &events, &mut clip_rx, &cancel, &last_sent)
                            .await
                        {
                            Ok(()) => log::info!("Clipboard session ended"),
                            Err(e) => log::warn!("Clipboard session ended: {e:#}"),
                        }
                        *conn_slot.lock() = None;
                        if cancel.is_cancelled() {
                            conn.close(SHUTDOWN_CODE.into(), b"shutdown");
                            endpoint.close().await;
                            return;
                        }
                        events.send(NetEvent::PeerDisconnected);
                    }
                    Err(e) => {
                        // Auth failures are fatal for this target (the credential
                        // is wrong for it) — end the session and surface it.
                        if e.downcast_ref::<AuthFailure>().is_some() {
                            events.error(format!("{e:#}"));
                            events.status(ConnStatus::Idle);
                            endpoint.close().await;
                            return;
                        }
                        log::warn!("Connection ended during auth: {e:#}");
                    }
                }
            }
            Err(e) => log::warn!("Failed to connect to peer: {e:#}"),
        }

        // This attempt failed or the session dropped: fixed-interval retry,
        // bounded by a run of consecutive failures. The count resets to zero on
        // any successful connection above, so an unreachable (or already-paired)
        // peer gives up after `MAX_CONNECT_ATTEMPTS`, while a flaky link that
        // keeps recovering never does.
        attempts += 1;
        if attempts >= MAX_CONNECT_ATTEMPTS {
            events.error(format!(
                "Could not reach the peer after {MAX_CONNECT_ATTEMPTS} attempts — press Join to try again"
            ));
            events.status(ConnStatus::Idle);
            endpoint.close().await;
            return;
        }
        events.status(ConnStatus::Reconnecting {
            attempt: attempts,
            max: MAX_CONNECT_ATTEMPTS,
        });
        tokio::select! {
            _ = cancel.cancelled() => { endpoint.close().await; return; }
            _ = tokio::time::sleep(RECONNECT_DELAY) => {}
        }
    }
}

// ============================================================================
// Card-setup sessions
// ============================================================================

/// How long the card exchange may take once the PIN handshake has accepted.
/// Two small frames on an established connection — generous, but bounded so a
/// peer that authenticates and then goes silent cannot hang the session.
const CARD_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Host a card-setup session: show a rotating PIN, accept the one joiner that
/// proves it, swap identity cards, and stop.
///
/// Deliberately **one-shot**. The configure-mode host keeps accepting so a
/// dropped peer can resume a clipboard session; here there is nothing to
/// resume — once the cards have crossed the session's whole purpose is served,
/// and staying up would only keep an authenticated channel open for no reason.
/// It also takes no clipboard channel at all, so there is no path by which this
/// session could carry content.
#[allow(clippy::too_many_arguments)]
async fn run_card_setup_host(
    self_card: IdentityCard,
    channel: SignalChannel,
    relays: Vec<String>,
    events: EventSender,
    cancel: CancellationToken,
    pin_refresh: Arc<tokio::sync::Notify>,
    secret: iroh::SecretKey,
    claim: PairClaim,
    recent_pins: RecentPins,
) {
    events.status(ConnStatus::Starting);
    let endpoint = match create_server_endpoint(channel_readiness(channel), secret).await {
        Ok(ep) => ep,
        Err(e) => {
            events.error(format!("Failed to start: {e:#}"));
            events.status(ConnStatus::Idle);
            return;
        }
    };
    let node_id = endpoint.id();
    events.send(NetEvent::ServerReady {
        node_id: node_id.to_string(),
        identity_public_key: None,
    });
    events.status(ConnStatus::Listening);

    let _publisher = PublisherGuard(tokio::spawn(run_card_setup_publisher(
        endpoint.clone(),
        recent_pins.clone(),
        channel,
        relays,
        events.clone(),
        cancel.clone(),
        claim.paired_signal(),
        pin_refresh,
    )));

    // Serve dialers one at a time until one gets all the way through. A failed
    // handshake must not end the session — a mistyped PIN would otherwise kick
    // the user back a screen — so a pre-auth failure loops round and keeps
    // listening. A completed exchange ends the session, and so does a failure
    // after the PIN was accepted (see the error arm: the claim and the PIN are
    // already spent by then).
    //
    // Strictly sequential, unlike the configure-mode host, which keeps accepting
    // during a live session so a dropped peer can resume. There is nothing to
    // resume here, and racing an accept against the handshake risks dropping a
    // half-accepted connection on the floor. A second device answering the same
    // PIN therefore waits until this handshake finishes, and is then either
    // refused by the claim or finds the endpoint closed — never served.
    loop {
        let Some(conn) = accept_serveable(&endpoint, &claim, &cancel, false).await else {
            break;
        };
        let remote_id = conn.remote_id();
        events.status(ConnStatus::Authenticating);

        let exchange = async {
            let (mut send, mut recv, _) =
                auth_as_listener(&conn, None, Some(&recent_pins), &claim, node_id).await?;
            events.send(NetEvent::PeerPaired {
                peer_node_id: remote_id.to_string(),
                peer_public_key: None,
            });
            events.status(ConnStatus::Connected);
            tokio::time::timeout(
                CARD_EXCHANGE_TIMEOUT,
                crate::card_exchange::exchange_cards(&mut send, &mut recv, &self_card),
            )
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "The other device stopped responding before its identity card arrived"
                )
            })?
        }
        .await;

        match exchange {
            Ok(peer_card) => {
                log::info!("Exchanged identity cards with {}", peer_card.name());
                events.send(NetEvent::PeerCardReceived(Box::new(peer_card)));
                conn.close(SHUTDOWN_CODE.into(), b"card-setup-complete");
                refuse_latecomers(&endpoint).await;
                break;
            }
            Err(e) => {
                conn.close(AUTH_FAILED_CODE.into(), b"card-setup-failed");
                // How far the attempt got decides whether listening on is
                // useful. Before the PIN is proven nothing is spent: the usual
                // cause is a typo on the other device, and the user just
                // retypes it. Once the claim is committed the PIN has already
                // been withdrawn and cleared from the screen, and the claim
                // turns away every other dialer — so looping would leave the
                // host "waiting" on a code nobody can read and no one else
                // could use anyway. End the session and say what happened.
                if claim.peek().is_some_and(|c| c.node_id == Some(remote_id)) {
                    log::warn!("Card setup with {remote_id} failed after the PIN was accepted: {e:#}");
                    events.error(format!("{e:#}"));
                    break;
                }
                log::warn!("Card setup attempt from {remote_id} failed: {e:#}");
                events.status(ConnStatus::Listening);
            }
        }
    }

    endpoint.close().await;
    events.status(ConnStatus::Idle);
    log::info!("Card setup host stopped");
}

/// How long the host keeps answering dialers after its exchange is done, purely
/// to turn them away properly. Short: it only has to cover devices that were
/// already dialing when the exchange finished.
const LATECOMER_GRACE: Duration = Duration::from_secs(3);

/// Turn away anyone still dialing after the exchange is finished.
///
/// A second device that answered the same PIN — someone reading it over your
/// shoulder, or just the wrong device — has an in-flight connect that nothing
/// will ever accept. Closing the endpoint under it leaves it waiting with
/// nothing to show the user, so complete each handshake far enough to send a
/// BUSY close, which the dialer turns into "already paired with another
/// device". Purely about the message: the pair claim already guarantees such a
/// device could never have been served.
async fn refuse_latecomers(endpoint: &iroh::Endpoint) {
    let deadline = tokio::time::Instant::now() + LATECOMER_GRACE;
    while let Ok(Some(incoming)) = tokio::time::timeout_at(deadline, endpoint.accept()).await {
        // The handshake is bounded by the same deadline: a dialer that connects
        // and then stalls must not hold the endpoint open past the grace.
        let Ok(handshake) = tokio::time::timeout_at(deadline, incoming).await else {
            log::debug!("A latecomer's handshake outlasted the grace period");
            break;
        };
        match handshake {
            Ok(conn) => {
                log::info!("Refusing {}: this card setup is already done", conn.remote_id());
                conn.close(SERVER_BUSY_CODE.into(), b"busy");
            }
            Err(e) => log::debug!("A latecomer's handshake failed before it could be refused: {e}"),
        }
    }
}

/// Join a card-setup session: resolve the host from the typed PIN, prove the
/// PIN, swap identity cards, and stop.
///
/// One-shot, like the host. A failure here is reported and ends the session
/// rather than retrying: the typed PIN rotates out of the rendezvous every 60
/// seconds, so a retry loop would mostly re-fail on a stale code — the user is
/// better served by an error that names the fix and a Join button to press
/// again.
#[allow(clippy::too_many_arguments)]
async fn run_card_setup_joiner(
    canonical_pin: String,
    self_card: IdentityCard,
    target_ip: Option<std::net::IpAddr>,
    channel: SignalChannel,
    relays: Vec<String>,
    events: EventSender,
    cancel: CancellationToken,
    secret: iroh::SecretKey,
) {
    events.status(ConnStatus::Starting);
    let endpoint = match create_client_endpoint(channel_readiness(channel), secret).await {
        Ok(ep) => ep,
        Err(e) => {
            events.error(format!("Failed to start: {e:#}"));
            events.status(ConnStatus::Idle);
            return;
        }
    };
    let own_id = endpoint.id();
    events.send(NetEvent::ClientReady {
        node_id: own_id.to_string(),
        identity_public_key: None,
    });

    // Everything below reports through `finish`, so every exit path closes the
    // endpoint and lands the UI back on Idle exactly once.
    let outcome = async {
        events.status(ConnStatus::Resolving);
        let addr = tokio::select! {
            _ = cancel.cancelled() => return Ok(None),
            r = resolve_card_setup(&canonical_pin, target_ip, channel, &relays) => r?,
        };
        if addr.id == own_id {
            anyhow::bail!("That PIN belongs to this device — show it on one device and type it on the other");
        }

        events.status(ConnStatus::Connecting);
        let conn = tokio::select! {
            _ = cancel.cancelled() => return Ok(None),
            c = connect_to_server(&endpoint, addr) => c?,
        };

        events.status(ConnStatus::Authenticating);
        let (mut send, mut recv) = auth_as_dialer_pin(&conn, &canonical_pin, own_id).await?;
        events.send(NetEvent::PeerPaired {
            peer_node_id: conn.remote_id().to_string(),
            peer_public_key: None,
        });
        events.status(ConnStatus::Connected);

        let peer_card = tokio::time::timeout(
            CARD_EXCHANGE_TIMEOUT,
            crate::card_exchange::exchange_cards(&mut send, &mut recv, &self_card),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!("The other device stopped responding before its identity card arrived")
        })??;
        conn.close(SHUTDOWN_CODE.into(), b"card-setup-complete");
        Ok(Some(peer_card))
    }
    .await;

    match outcome {
        Ok(Some(peer_card)) => {
            log::info!("Exchanged identity cards with {}", peer_card.name());
            events.send(NetEvent::PeerCardReceived(Box::new(peer_card)));
        }
        Ok(None) => {}
        Err(e) => events.error(format!("{e:#}")),
    }
    endpoint.close().await;
    events.status(ConnStatus::Idle);
    log::info!("Card setup joiner stopped");
}

// ============================================================================
// Clipboard pump (both roles)
// ============================================================================

/// Pump the established clipboard stream in both directions until the
/// connection dies, the session is cancelled, or the clip channel closes.
///
/// On every (re-)opened stream the writer first sends [`ClipBody::PullLatest`],
/// so a connection resumed after an interruption re-fetches the latest item the
/// peer sent this session (delivered as [`ClipBody::Latest`] and surfaced with
/// `pulled: true` for receiver-side deduplication). On a session's first
/// pairing the peer has sent nothing yet, so the pull is a no-op.
async fn pump_clipboard(
    mut qsend: iroh::endpoint::SendStream,
    mut qrecv: iroh::endpoint::RecvStream,
    events: &EventSender,
    clip_rx: &mut mpsc::UnboundedReceiver<String>,
    cancel: &CancellationToken,
    last_sent: &LastSent,
) -> Result<()> {
    // Reader -> writer nudge: a received PullLatest is answered by the writer
    // (which owns the send stream) from the shared last-sent slot.
    let (pull_tx, mut pull_rx) = mpsc::unbounded_channel::<()>();

    let writer = async {
        let frame = encode_clip_msg(&ClipMsg::pull_latest()).expect("PullLatest always encodes");
        qsend
            .write_all(&frame)
            .await
            .context("writing resume pull")?;
        loop {
            tokio::select! {
                item = clip_rx.recv() => {
                    let Some(text) = item else {
                        // Session dropped its sender: nothing more to send, ever.
                        return Ok::<(), anyhow::Error>(());
                    };
                    let sent_at_ms = now_ms();
                    match encode_clip_msg(&ClipMsg::item(text.clone(), sent_at_ms)) {
                        Err(e) => {
                            // Oversize (or unserializable) content: report and keep the
                            // session alive — nothing was written to the stream.
                            events.error(format!(
                                "Not sent — {e:#} (limit {} KiB)",
                                MAX_CLIP_MESSAGE_SIZE / 1024
                            ));
                        }
                        Ok(frame) => {
                            qsend
                                .write_all(&frame)
                                .await
                                .context("writing clipboard item")?;
                            events.send(NetEvent::ItemSent);
                            *last_sent.lock() = Some((text, sent_at_ms));
                        }
                    }
                }
                nudge = pull_rx.recv() => {
                    if nudge.is_none() {
                        // Sender dropped (reader ended): stop rather than spin
                        // on a closed channel; the pump is ending anyway.
                        return Ok(());
                    }
                    let latest = last_sent.lock().clone();
                    // Nothing sent this session: the pull needs no answer.
                    let Some((text, sent_at_ms)) = latest else { continue };
                    match encode_clip_msg(&ClipMsg::latest(text, sent_at_ms)) {
                        // The "latest" tag is a few bytes longer than "item", so
                        // content that squeaked under the cap on send can miss it
                        // on re-delivery — not worth failing the session over.
                        Err(e) => log::warn!("Skipping resume re-delivery: {e:#}"),
                        Ok(frame) => {
                            qsend
                                .write_all(&frame)
                                .await
                                .context("writing resume re-delivery")?;
                        }
                    }
                }
            }
        }
    };

    let reader = async {
        loop {
            let frame = read_length_prefixed(&mut qrecv, MAX_CLIP_MESSAGE_SIZE)
                .await
                .context("clipboard stream closed")?;
            match decode_clip_msg(&frame)?.body {
                ClipBody::Item { text, .. } => {
                    events.send(NetEvent::ItemReceived {
                        text,
                        pulled: false,
                    });
                }
                ClipBody::PullLatest => {
                    let _ = pull_tx.send(());
                }
                ClipBody::Latest { text, .. } => {
                    events.send(NetEvent::ItemReceived { text, pulled: true });
                }
            }
        }
    };

    tokio::select! {
        _ = cancel.cancelled() => Ok(()),
        r = writer => r,
        r = reader => r,
    }
}

// ============================================================================
// Signaling publishers
// ============================================================================

/// The endpoint-readiness gate (and, with it, the transport stack) for a
/// channel selection: LAN-only must not wait on — or even build — a relay,
/// nostr-only hard-requires one, and the default prefers one but must still
/// come up promptly and pair offline over the LAN half.
fn channel_readiness(channel: SignalChannel) -> EndpointReadiness {
    match channel {
        SignalChannel::LanOnly => EndpointReadiness::LanDirect,
        SignalChannel::NostrOnly => EndpointReadiness::RelayOnline,
        SignalChannel::LanThenNostr => EndpointReadiness::DirectAddr,
    }
}

/// Resolve a trusted peer's live clipboard session: look for the pairwise
/// hosting record it publishes for *this* device on the enabled channel(s).
///
/// Same asymmetry and same ordering as [`resolve_card_setup`], for the same
/// reasons: the host publishes everywhere it can and only the dialer falls
/// back, LAN first because it answers in well under a second when the peer is
/// on this network, so the common case never touches a relay. A LAN error is
/// logged and falls through like a miss, and a channel that looked and cleanly
/// found nothing clears a held error — "not hosting" is the answer the user can
/// act on.
///
/// A LAN hit carries the host's direct addresses (DNS-SD SRV/A/AAAA), so the
/// dial needs no further address lookup; the relay record carries a bare node
/// id, resolved by the endpoint's own discovery.
async fn resolve_hosting(
    identity: &KeyIdentity,
    peer: nostr_sdk::PublicKey,
    channel: SignalChannel,
) -> Result<EndpointAddr> {
    let mut first_error: Option<anyhow::Error> = None;

    if channel.lan() {
        match crate::lan::dnssd_lookup_hosting(&identity.identity, peer).await {
            Ok(Some(found)) => return Ok(found.endpoint_addr()),
            Ok(None) => log::info!("The selected peer is not hosting on the local network"),
            Err(e) => {
                let e = e.context("LAN hosting lookup failed");
                log::warn!("{e:#}");
                first_error = Some(e);
            }
        }
    }

    if channel.nostr() {
        if channel.lan() {
            log::info!("Falling back to the nostr hosting record for the selected peer");
        }
        match crate::nostr::lookup_hosting(&identity.identity, peer, &identity.relays).await {
            Ok(Some(id)) => return Ok(EndpointAddr::new(id)),
            Ok(None) => {
                log::info!("The selected peer has no hosting record on the relays");
                first_error = None;
            }
            Err(e) => {
                let e = e.context("nostr hosting lookup failed");
                log::warn!("{e:#}");
                first_error.get_or_insert(e);
            }
        }
    }

    if let Some(error) = first_error {
        return Err(error);
    }
    Err(match channel {
        SignalChannel::LanOnly => anyhow::anyhow!(
            "The selected peer is not hosting on this network — press Start on that device, and check both devices are on the same network"
        ),
        SignalChannel::NostrOnly | SignalChannel::LanThenNostr => anyhow::anyhow!(
            "The selected peer is not hosting a connection — press Start on that device"
        ),
    })
}

/// How often [`run_hosting_publisher`] wakes to republish. Well inside the
/// relay copy's five-minute expiry, and quoted in the log line so the interval
/// the reader is told about cannot drift from the one actually slept.
const HOSTING_REFRESH: Duration = Duration::from_secs(120);

/// Configure-mode hosting publisher: keep this host's ephemeral node id
/// resolvable by each trusted peer, on every enabled channel, for as long as
/// the session listens.
///
/// The peer list is re-filtered every round, so a peer whose card lapses
/// mid-session stops being signalled to without a restart. The LAN
/// advertisements are rebuilt only when that live set or this endpoint's direct
/// addresses actually change — an mDNS record stays up until it is withdrawn,
/// so re-registering on a timer would only churn goodbye/announce traffic,
/// unlike the relay copy, which has a five-minute TTL and must be refreshed.
async fn run_hosting_publisher(
    endpoint: iroh::Endpoint,
    identity: KeyIdentity,
    channel: SignalChannel,
    events: EventSender,
    cancel: CancellationToken,
) {
    let node_id = endpoint.id();
    let mut adverts: Vec<crate::lan::LanAdvert> = Vec::new();
    // What `adverts` currently says, so an unchanged round is a no-op. `None`
    // also means "retry next round" after a failure to advertise.
    let mut advertised: Option<(Vec<nostr_sdk::PublicKey>, Vec<std::net::SocketAddr>)> = None;
    // Only report a total failure to signal on the transition into it, so a
    // sustained outage does not repaint the banner every round.
    let mut reported = false;

    loop {
        let now = unix_now();
        let live: Vec<IdentityCard> = identity
            .peers
            .iter()
            .filter(|card| card.is_valid_at(now))
            .cloned()
            .collect();
        // Every trusted card lapsed while the session was up: withdraw the LAN
        // advertisements rather than leave records standing for peers that can
        // no longer pair. Only the local channel needs saying — the relay copy
        // just stops being refreshed and ages out of its TTL.
        if live.is_empty() && advertised.is_some() {
            log::info!(
                "Withdrawing the local-network advertisement — no trusted peer's card is still valid"
            );
            adverts.clear();
            advertised = None;
        }
        // Nothing to publish and nobody who could dial: not a failure to report.
        if !live.is_empty() {
            let mut published = false;

            if channel.lan() {
                let mut addrs: Vec<std::net::SocketAddr> =
                    endpoint.addr().ip_addrs().copied().collect();
                addrs.sort_unstable();
                let mut keys: Vec<nostr_sdk::PublicKey> =
                    live.iter().map(IdentityCard::public_key).collect();
                keys.sort_unstable();
                let want = (keys, addrs);
                if advertised.as_ref() != Some(&want) {
                    // Withdraw the stale set first: an advert for a peer that
                    // just expired must not outlive this round.
                    adverts.clear();
                    for peer in &want.0 {
                        match crate::lan::dnssd_advertise_hosting(
                            &identity.identity,
                            *peer,
                            &node_id,
                            &want.1,
                        )
                        .await
                        {
                            Ok(advert) => adverts.push(advert),
                            Err(e) => log::warn!(
                                "Failed to advertise this device on the local network: {e:#}"
                            ),
                        }
                    }
                    if adverts.is_empty() {
                        advertised = None;
                    } else {
                        log::info!(
                            "Advertising this device on the local network for {} trusted peer(s)",
                            adverts.len()
                        );
                        advertised = Some(want);
                    }
                }
                published |= !adverts.is_empty();
            }

            if channel.nostr() {
                match crate::nostr::publish_hosting(
                    &identity.identity,
                    &live,
                    &node_id,
                    &identity.relays,
                )
                .await
                {
                    Ok(()) => {
                        published = true;
                        // Said every round, like the PIN publisher's: on a
                        // relay-only host this is the only evidence the device
                        // ever announced itself, and a stale last line would
                        // otherwise be indistinguishable from a live one.
                        log::info!(
                            "Published pairwise hosting records to nostr for {} trusted peer(s) (refreshes in {}s)",
                            live.len(),
                            HOSTING_REFRESH.as_secs()
                        );
                    }
                    Err(e) => log::warn!("Failed to publish pairwise hosting records: {e:#}"),
                }
            }

            // Listening on a node id nothing can resolve looks identical to
            // waiting for a peer that just hasn't joined yet. Say which it is.
            if !published && !reported {
                events.error(
                    "Could not announce this device on any channel — the other device will not \
                     find it. Check this device's network connection.",
                );
            }
            reported = !published;
        }

        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(HOSTING_REFRESH) => {}
        }
    }
}

/// Resolve the card-setup rendezvous: derive the candidate record keys once
/// (see `pin_record::candidate_keys`), then look the host up on the enabled
/// channel(s).
///
/// On [`SignalChannel::LanThenNostr`] the local lookup runs first and the relays
/// are queried only if it found nothing — sequential, not raced. The LAN browse
/// is bounded by its own short window, and it is the channel that answers in
/// well under a second when the other device is right there, so the ordering
/// costs the common case nothing and keeps the record off the relays' critical
/// path. A LAN *error* (no multicast route, a blocked port) is logged and falls
/// through to the relays exactly like a miss; it only surfaces if the relays
/// then also fail to look.
///
/// The LAN result is a full dial target — both the DNS-SD and unicast records
/// carry the host's direct addresses, so they ride along and the dial needs no
/// further address lookup. The nostr record carries only a node id, which the
/// endpoint's own discovery resolves (which is why that channel is not built
/// relay-less; see [`channel_readiness`]).
///
/// `Some(target_ip)` fetches the record from the host's unicast side channel at
/// that IP — the manual-IP path that works where multicast is blocked — instead
/// of browsing mDNS. It is part of the LAN half, so it is skipped entirely when
/// the LAN channel is off.
async fn resolve_card_setup(
    canonical_pin: &str,
    target_ip: Option<std::net::IpAddr>,
    channel: SignalChannel,
    relays: &[String],
) -> Result<EndpointAddr> {
    let candidates = crate::pin_record::candidate_keys(canonical_pin).await?;

    // Errors are held, not raised: with both channels enabled either one can
    // fail while the other still finds the host. An error is reported only when
    // no enabled channel managed to look at all — a channel that looked and
    // cleanly found nothing answers the question, so it clears a held error and
    // the generic miss (which names what the user can fix) surfaces instead.
    let mut first_error: Option<anyhow::Error> = None;

    if channel.lan() {
        // A typed IP selects the unicast side channel (works where multicast is
        // blocked); no IP browses mDNS.
        let found = match target_ip {
            Some(ip) => crate::lan::unicast_lookup_pin_record(ip, &candidates).await,
            None => crate::lan::dnssd_lookup_pin_record(&candidates).await,
        };
        match found {
            Ok(Some(found)) => return Ok(found.endpoint_addr()),
            Ok(None) => log::info!("No card-setup record for that PIN on the local network"),
            Err(e) => {
                let e = e.context("LAN PIN lookup failed");
                log::warn!("{e:#}");
                first_error = Some(e);
            }
        }
    }

    if channel.nostr() {
        if channel.lan() {
            log::info!("Falling back to the nostr rendezvous for the card-setup PIN");
        }
        match crate::nostr::lookup_pin_record(&candidates, relays).await {
            Ok(Some(id)) => return Ok(EndpointAddr::new(id)),
            Ok(None) => {
                log::info!("No card-setup record for that PIN on the relays");
                // The relays looked and found nothing: that is the answer, and
                // it is the one the user can act on. A LAN failure held from the
                // first half is a detail of how the search went (already logged
                // as a warning) and must not displace the channel's miss.
                first_error = None;
            }
            Err(e) => {
                let e = e.context("nostr PIN lookup failed");
                log::warn!("{e:#}");
                first_error.get_or_insert(e);
            }
        }
    }

    if let Some(error) = first_error {
        return Err(error);
    }
    // Nothing was found anywhere and every enabled channel answered cleanly —
    // phrase the miss for what the user can actually fix on this channel.
    Err(match channel {
        SignalChannel::LanOnly if target_ip.is_some() => anyhow::anyhow!(
            "no device answered for that PIN at that IP — check the address shown on the other device and that the code (it refreshes every 60s) matches"
        ),
        SignalChannel::LanOnly => anyhow::anyhow!(
            "no device found for that PIN on this network — both devices must be on the same network, and the code refreshes every 60s"
        ),
        SignalChannel::NostrOnly => anyhow::anyhow!(
            "no device found for that PIN on the relays — check the current code on the other device (it refreshes every 60s)"
        ),
        SignalChannel::LanThenNostr => anyhow::anyhow!(
            "no device found for that PIN, on this network or through the relays — check the current code on the other device (it refreshes every 60s)"
        ),
    })
}

/// Card-setup PIN publisher: mint a fresh PIN each rotation period (measured
/// from when the PIN is shown, not from wall-clock bucket boundaries), publish
/// the node-id record under it on **every** enabled channel, and surface the PIN
/// and countdown to the UI. Each bucket's PIN auth key is recorded in `recent`
/// so the listener auth path can verify a dialer's proof. Stops (and clears
/// the displayed PIN) once a peer pairs — no more peers are accepted this
/// session.
///
/// The host publishes everywhere it can rather than falling back like the
/// joiner does: it has no way to know which channel the joiner will reach it
/// on, and a record only helps if it is already there when the joiner looks.
///
/// On the LAN channel the record is advertised over DNS-SD plus the unicast
/// side channel (`crate::lan`); the previous bucket's advertisement is kept
/// alive one extra period (`adverts` holds two guards) so a joiner typing a
/// just-rotated code still resolves — the same look-back the nostr record's TTL
/// provides. All advertisements are withdrawn on exit.
///
/// `refresh` (the user's "new PIN now" CTA) cuts the current period short:
/// the next loop turn mints a fresh PIN immediately, and — unlike natural
/// rotation, which keeps a look-back window — every previously shown PIN is
/// revoked first.
#[allow(clippy::too_many_arguments)]
async fn run_card_setup_publisher(
    endpoint: iroh::Endpoint,
    recent: RecentPins,
    channel: SignalChannel,
    relays: Vec<String>,
    events: EventSender,
    cancel: CancellationToken,
    paired: CancellationToken,
    refresh: Arc<tokio::sync::Notify>,
) {
    let node_id = endpoint.id();
    let mut adverts: VecDeque<crate::lan::LanAdvert> = VecDeque::new();
    // Unicast side-channel listeners, kept with the same one-period look-back
    // as `adverts`: the port is PIN-derived, so it rotates with the PIN, and a
    // joiner who typed the just-rotated code still reaches the previous
    // listener.
    let mut unicast: VecDeque<crate::lan::UnicastListener> = VecDeque::new();
    loop {
        // A peer may already have paired (e.g. a reconnect landed before this
        // loop turn). Publishing a fresh PIN would be pointless and misleading.
        if paired.is_cancelled() {
            events.send(NetEvent::PinCleared);
            break;
        }

        let pin = crate::pin::generate_pin();
        let bucket = crate::pin::current_bucket();
        // Surface the host's LAN IPv4 so the UI can offer it for the joiner's
        // manual-IP side channel. Constant across rotations, but sent with every
        // PIN so a late-arriving UI still gets it. Withheld when the LAN channel
        // is off: there would be no side-channel listener to type it at.
        let host_lan_ip = channel
            .lan()
            .then(|| {
                let addrs: Vec<_> = endpoint.addr().ip_addrs().copied().collect();
                crate::lan::preferred_lan_ipv4(&addrs)
            })
            .flatten()
            .map(|ip| ip.to_string());
        // Show the new code right away (before the network publish) and give it a
        // full rotation period from *now*, not from the wall-clock bucket boundary:
        // a PIN minted late in a bucket would otherwise flash for only a few
        // seconds. The dialer's adjacent-bucket look-back (and the record TTL /
        // kept-alive advertisement) keeps the code resolvable for the whole
        // displayed window even when it straddles a boundary.
        let shown_at = tokio::time::Instant::now();
        events.send(NetEvent::PinRotated {
            pin_display: crate::pin::format_pin(&pin),
            seconds_left: crate::pin::BUCKET_SECS,
            host_lan_ip,
        });

        // This bucket's PIN auth key (so an inbound dialer holding this PIN can
        // be authenticated in-band, even after the code rotates) plus the
        // record keypair — two Argon2id runs, off the async executor.
        let derived = tokio::task::spawn_blocking({
            let pin = pin.clone();
            move || {
                (
                    crate::pin_auth::derive_auth_keys(&pin),
                    crate::pin_record::pin_keys(&pin, bucket),
                )
            }
        })
        .await;
        let record_keys = match derived {
            Ok((auth_keys, record_keys)) => {
                match auth_keys {
                    Ok(keys) => recent.push(keys),
                    Err(e) => log::warn!("Failed to derive PIN auth key: {e:#}"),
                }
                match record_keys {
                    Ok(keys) => Some(keys),
                    Err(e) => {
                        log::warn!("Failed to derive PIN record key: {e:#}");
                        None
                    }
                }
            }
            Err(e) => {
                log::warn!("PIN key-derivation task failed: {e}");
                None
            }
        };

        if let Some(keys) = record_keys {
            // A shown PIN nobody can resolve would hang the joiner with nothing
            // to fix, so track what actually got published and report below.
            let (mut discoverable, mut typed_ip_only) = (false, false);
            if channel.lan() {
                let addr = endpoint.addr();
                let addrs: Vec<_> = addr.ip_addrs().copied().collect();
                // Spec-compliant DNS-SD (Bonjour-visible, addresses load-bearing).
                match crate::lan::dnssd_advertise_pin_record(&keys, &node_id, &addrs).await {
                    Ok(advert) => {
                        discoverable = true;
                        adverts.push_back(advert);
                        while adverts.len() > 2 {
                            adverts.pop_front();
                        }
                        log::info!(
                            "Advertising rotating PIN on the local network (refreshes in {}s)",
                            crate::pin::BUCKET_SECS
                        );
                    }
                    Err(e) => log::warn!("Failed to advertise the PIN on the local network: {e:#}"),
                }
                // Also serve the record over the unicast side channel (the
                // manual-IP path). It rides alongside DNS-SD, so a bind failure
                // (e.g. a rare derived-port collision) only warns — multicast
                // still carries the rendezvous for joiners on this network.
                match crate::lan::unicast_advertise_pin_record(&keys, &node_id, &addrs).await {
                    Ok(listener) => {
                        typed_ip_only = true;
                        unicast.push_back(listener);
                        while unicast.len() > 2 {
                            unicast.pop_front();
                        }
                    }
                    Err(e) => log::warn!("Failed to start the manual-IP side channel: {e:#}"),
                }
            }
            if channel.nostr() {
                match crate::nostr::publish_pin_record(&keys, &node_id, &relays).await {
                    Ok(()) => {
                        discoverable = true;
                        log::info!(
                            "Published the rotating PIN to nostr (refreshes in {}s)",
                            crate::pin::BUCKET_SECS
                        );
                    }
                    Err(e) => log::warn!("Failed to publish the PIN to nostr: {e:#}"),
                }
            }
            // Nothing that a joiner can *find* went out. Say so rather than let
            // the code sit on screen looking live.
            if !discoverable && typed_ip_only {
                events.error(
                    "Could not publish the PIN for automatic discovery — the other device will \
                     have to enter the IP shown below",
                );
            } else if !discoverable {
                events.error(
                    "Could not publish the PIN on any channel — check this device's network \
                     connection and press New PIN",
                );
            }
        }

        // Rotate one full period after the PIN was shown (key derivation and the
        // publish above ate into that window), matching the countdown the UI runs.
        let rotate_at = shown_at + Duration::from_secs(crate::pin::BUCKET_SECS);
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = paired.cancelled() => {
                // Paired mid-cycle: drop the now-stale PIN and stop publishing.
                events.send(NetEvent::PinCleared);
                break;
            }
            _ = tokio::time::sleep_until(rotate_at) => {}
            _ = refresh.notified() => {
                // Rotate now, and revoke everything shown so far: no retained
                // auth key means a stale code can no longer authenticate, and
                // dropping the advert guards withdraws the mDNS records and
                // closes the side-channel listeners. A relay copy cannot be
                // withdrawn, but it ages out of its TTL and, with its auth key
                // gone, resolving it only leads to a rejection.
                recent.clear();
                adverts.clear();
                unicast.clear();
                log::info!("Refreshing the PIN on request; previous PINs revoked");
            }
        }
    }
}

// ============================================================================
// Authentication
// ============================================================================

/// If the peer closed the connection with one of the auth close codes, return
/// the corresponding fatal-auth description. The listener closes right after
/// writing its rejection frame, so the dialer's read may fail at the transport
/// level before the frame arrives — the close code still tells the story.
fn auth_close_reason(conn: &iroh::endpoint::Connection) -> Option<String> {
    use iroh::endpoint::ConnectionError;
    match conn.close_reason()? {
        ConnectionError::ApplicationClosed(app) => {
            let code = u64::from(app.error_code);
            if code == u64::from(AUTH_FAILED_CODE) {
                Some(
                    "Authentication rejected by the peer — untrusted application key/wrong PIN, or it is still \
                     paired with a previous session (Stop and Start the server to re-pair)"
                        .to_string(),
                )
            } else if code == u64::from(CARD_EXPIRED_CODE) {
                Some(
                    "The other device's copy of this device's identity card has expired — copy \
                     this device's card again and import it there"
                        .to_string(),
                )
            } else if code == u64::from(AUTH_TIMEOUT_CODE) {
                Some("Authentication timed out on the peer".to_string())
            } else if code == u64::from(SERVER_BUSY_CODE) {
                Some(
                    "The other device is already paired with another device — it links only \
                     one device at a time (Stop and Start it to pair with this one instead)"
                        .to_string(),
                )
            } else {
                None
            }
        }
        _ => None,
    }
}

fn random_nonce() -> String {
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    URL_SAFE_NO_PAD.encode(nonce)
}

#[allow(clippy::too_many_arguments)]
fn key_auth_transcript(
    role: &str,
    client_key: nostr_sdk::PublicKey,
    server_key: nostr_sdk::PublicKey,
    client_nonce: &str,
    server_nonce: &str,
    client_node: EndpointId,
    server_node: EndpointId,
) -> Vec<u8> {
    fn field(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(&(value.len() as u32).to_be_bytes());
        output.extend_from_slice(value);
    }

    let mut transcript = Vec::with_capacity(256);
    transcript.extend_from_slice(&crate::protocol::DUOCB_PROTO_VERSION.to_be_bytes());
    field(&mut transcript, role.as_bytes());
    field(&mut transcript, client_key.as_bytes());
    field(&mut transcript, server_key.as_bytes());
    field(&mut transcript, client_nonce.as_bytes());
    field(&mut transcript, server_nonce.as_bytes());
    field(&mut transcript, client_node.to_string().as_bytes());
    field(&mut transcript, server_node.to_string().as_bytes());
    transcript
}

/// Mutual configure-mode authentication using the persistent application key.
async fn auth_as_dialer_key(
    conn: &iroh::endpoint::Connection,
    identity: &Identity,
    expected_peer: nostr_sdk::PublicKey,
    own_node: EndpointId,
) -> Result<Bi> {
    let handshake = async {
        let (mut send, mut recv) = conn.open_bi().await.context("opening session stream")?;
        let client_nonce = random_nonce();
        let request = AuthRequest::key(identity.public_key().to_hex(), &client_nonce);
        send.write_all(&encode_auth_request(&request)?).await?;

        let challenge_bytes =
            read_length_prefixed(&mut recv, MAX_CONTROL_MESSAGE_SIZE).await?;
        let challenge =
            decode_key_challenge(&challenge_bytes).context("invalid key-auth challenge")?;
        let server_key = nostr_sdk::PublicKey::parse(&challenge.public_key)
            .context("listener supplied an invalid application key")?;
        if server_key != expected_peer {
            anyhow::bail!("listener application key does not match the selected peer");
        }
        let listener_transcript = key_auth_transcript(
            "listener",
            identity.public_key(),
            server_key,
            &client_nonce,
            &challenge.nonce,
            own_node,
            conn.remote_id(),
        );
        verify_auth_signature(server_key, &listener_transcript, &challenge.proof)?;

        let dialer_transcript = key_auth_transcript(
            "dialer",
            identity.public_key(),
            server_key,
            &client_nonce,
            &challenge.nonce,
            own_node,
            conn.remote_id(),
        );
        let proof = KeyProof::new(identity.sign_auth(&dialer_transcript));
        send.write_all(&encode_key_proof(&proof)?).await?;

        let response_bytes =
            read_length_prefixed(&mut recv, MAX_CONTROL_MESSAGE_SIZE).await?;
        let response =
            decode_auth_response(&response_bytes).context("invalid key-auth response")?;
        if !response.accepted {
            anyhow::bail!(
                "authentication rejected: {}",
                response.reason.unwrap_or_else(|| "unknown reason".into())
            );
        }
        Ok::<Bi, anyhow::Error>((send, recv))
    };
    match tokio::time::timeout(AUTH_TIMEOUT, handshake).await {
        Err(_) => Err(auth_failure("Application-key authentication timed out")),
        Ok(Err(error)) => {
            if let Some(reason) = auth_close_reason(conn) {
                return Err(auth_failure(reason));
            }
            Err(auth_failure(format!("{error:#}")))
        }
        Ok(Ok(streams)) => Ok(streams),
    }
}

/// Authenticate as the dialer using the card-setup PIN (in-band
/// challenge-response). The whole exchange is bounded by [`AUTH_TIMEOUT`] and
/// any failure is an [`AuthFailure`] — fatal for this target. On success the opened
/// stream is returned (not finished) for the clipboard.
async fn auth_as_dialer_pin(
    conn: &iroh::endpoint::Connection,
    pin: &str,
    own_id: iroh::EndpointId,
) -> Result<Bi> {
    // One deadline over the whole exchange, including opening the stream — a
    // stalled open_bi must not delay the point where the timeout starts.
    let handshake = async {
        let (mut send, mut recv) = conn.open_bi().await.context("opening session stream")?;
        // Bind the PIN proof to both QUIC-authenticated node ids: our own, and
        // the listener we dialed (`remote_id`, authenticated by QUIC/TLS).
        crate::pin_auth::dialer_handshake(
            &mut send,
            &mut recv,
            pin,
            &own_id.to_string(),
            &conn.remote_id().to_string(),
        )
        .await?;
        Ok::<Bi, anyhow::Error>((send, recv))
    };
    match tokio::time::timeout(AUTH_TIMEOUT, handshake).await {
        Err(_) => Err(auth_failure("PIN auth timed out")),
        Ok(Err(e)) => {
            if let Some(reason) = auth_close_reason(conn) {
                return Err(auth_failure(reason));
            }
            Err(anyhow::Error::new(AuthFailure(format!("{e:#}"))))
        }
        Ok(Ok(streams)) => {
            log::info!("Authenticated with peer via PIN");
            Ok(streams)
        }
    }
}

async fn auth_as_listener(
    conn: &iroh::endpoint::Connection,
    key_identity: Option<&KeyIdentity>,
    pin_cache: Option<&RecentPins>,
    claim: &PairClaim,
    own_id: iroh::EndpointId,
) -> Result<(iroh::endpoint::SendStream, iroh::endpoint::RecvStream, Option<nostr_sdk::PublicKey>)> {
    let remote_id = conn.remote_id();
    let existing = claim.peek();
    let pin_claimed_by_other = existing.as_ref().is_some_and(|claimed| {
        claimed.application_key.is_some() || claimed.node_id != Some(remote_id)
    });
    let auth_result = tokio::time::timeout(AUTH_TIMEOUT, async {
        let (mut send, mut recv) = conn
            .accept_bi()
            .await
            .context("Failed to accept session stream")?;

        let request_bytes = read_length_prefixed(&mut recv, MAX_CONTROL_MESSAGE_SIZE)
            .await
            .context("Failed to read auth request")?;
        match decode_auth_request(&request_bytes).context("Invalid auth request")? {
            AuthRequest::Key {
                public_key,
                nonce: client_nonce,
                ..
            } => {
                let identity = key_identity
                    .ok_or_else(|| anyhow::anyhow!("listener is not in key-auth mode"))?;
                let client_key = nostr_sdk::PublicKey::parse(&public_key)
                    .context("dialer application key is invalid")?;
                // Both trust checks run before this side signs anything: an
                // untrusted or lapsed dialer never gets a proof of our identity.
                let Some(card) = identity.peer(client_key) else {
                    anyhow::bail!("dialer application key is not locally trusted");
                };
                if !card.is_valid_at(unix_now()) {
                    return Err(expired_card_error(card));
                }
                if existing.as_ref().is_some_and(|claimed| {
                    claimed.application_key != Some(client_key)
                }) {
                    anyhow::bail!("already paired with another application identity");
                }
                let server_nonce = random_nonce();
                let listener_transcript = key_auth_transcript(
                    "listener",
                    client_key,
                    identity.identity.public_key(),
                    &client_nonce,
                    &server_nonce,
                    remote_id,
                    own_id,
                );
                let challenge = KeyChallenge::new(
                    identity.identity.public_key().to_hex(),
                    &server_nonce,
                    identity.identity.sign_auth(&listener_transcript),
                );
                send.write_all(&encode_key_challenge(&challenge)?).await?;
                let proof_bytes =
                    read_length_prefixed(&mut recv, MAX_CONTROL_MESSAGE_SIZE).await?;
                let proof =
                    decode_key_proof(&proof_bytes).context("invalid dialer key proof")?;
                let dialer_transcript = key_auth_transcript(
                    "dialer",
                    client_key,
                    identity.identity.public_key(),
                    &client_nonce,
                    &server_nonce,
                    remote_id,
                    own_id,
                );
                verify_auth_signature(client_key, &dialer_transcript, &proof.proof)?;
                if !claim.commit_key(client_key, remote_id) {
                    anyhow::bail!("another application identity paired first");
                }
                let response = AuthResponse::accepted();
                send.write_all(&encode_auth_response(&response)?).await?;
                Ok::<_, anyhow::Error>((send, recv, Some(client_key)))
            }
            AuthRequest::Pin { nonce, .. } => {
                // Verify the dialer's PIN proof against the recent-bucket keys. An empty
                // candidate set — a configure-mode listener, or a peer refused by the gate —
                // yields a clean rejection.
                let candidates = if pin_claimed_by_other {
                    Vec::new()
                } else {
                    pin_cache.map(|c| c.snapshot()).unwrap_or_default()
                };
                // The claim is committed inside the handshake, right after the proof verifies
                // and *before* the acceptance frame is sent — so a race loser is rejected
                // in-band, not accepted-then-dropped.
                // Bind the verified proof to both QUIC-authenticated node ids: the dialer's
                // (`remote_id`, from QUIC/TLS) and our own. A proof only verifies if the dialer
                // folded in the same ids — so this validates the client's node id in-band.
                crate::pin_auth::listener_handshake(
                    &mut send,
                    &mut recv,
                    &candidates,
                    &nonce,
                    &remote_id.to_string(),
                    &own_id.to_string(),
                    || claim.commit_pin(remote_id),
                )
                .await?;
                log::info!("Peer {remote_id} authenticated via PIN");
                Ok((send, recv, None))
            }
        }
    })
    .await;

    match auth_result {
        Ok(Ok(streams)) => Ok(streams),
        Ok(Err(e)) => {
            if e.downcast_ref::<ExpiredCard>().is_some() {
                conn.close(CARD_EXPIRED_CODE.into(), b"card_expired");
            } else {
                conn.close(AUTH_FAILED_CODE.into(), b"auth_failed");
            }
            Err(e.context("auth failed"))
        }
        Err(_) => {
            log::warn!("Authentication timeout for {remote_id}");
            conn.close(AUTH_TIMEOUT_CODE.into(), b"auth_timeout");
            anyhow::bail!("auth timeout")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::NetEvent;
    use std::time::Instant;

    /// Each channel enables exactly the backends it names, and gets the
    /// endpoint gate that matches: LAN-only must never wait on (or build) a
    /// relay, nostr-only must have one before it can publish anything, and the
    /// default must come up on a local address alone so an offline pairing over
    /// the LAN half is not blocked by a relay it may never need.
    #[test]
    fn each_channel_enables_its_backends_and_endpoint_gate() {
        assert!(SignalChannel::LanThenNostr.lan() && SignalChannel::LanThenNostr.nostr());
        assert!(SignalChannel::LanOnly.lan() && !SignalChannel::LanOnly.nostr());
        assert!(!SignalChannel::NostrOnly.lan() && SignalChannel::NostrOnly.nostr());

        assert_eq!(
            channel_readiness(SignalChannel::LanOnly),
            EndpointReadiness::LanDirect
        );
        assert_eq!(
            channel_readiness(SignalChannel::NostrOnly),
            EndpointReadiness::RelayOnline
        );
        assert_eq!(
            channel_readiness(SignalChannel::LanThenNostr),
            EndpointReadiness::DirectAddr
        );
        // The default is the one a plain launch gets.
        assert_eq!(SignalChannel::default(), SignalChannel::LanThenNostr);
    }

    /// With every enabled channel reachable but empty, the joiner reports a miss
    /// naming what the user can check — and the wording follows the channel, so
    /// a nostr-only run is never told to put both devices on one network. Both
    /// rendezvous kinds answer the same way, since one launch flag governs both.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_lan_only_miss_reports_the_local_network() {
        // Nothing is advertising this PIN or hosting for this identity, and
        // LAN-only touches no relay, so these exercise the real miss paths
        // rather than stubbed ones.
        let pin = crate::pin::generate_pin();
        let error = resolve_card_setup(&pin, None, SignalChannel::LanOnly, &[])
            .await
            .expect_err("nothing is advertising that PIN");
        let error = format!("{error:#}");
        assert!(
            error.contains("this network"),
            "a LAN-only card-setup miss should point at the network: {error}"
        );

        let identity = Identity::generate();
        let peer = Identity::generate();
        let key_identity = KeyIdentity {
            self_card: identity.card("me", "a7B2c3D4").unwrap(),
            identity,
            peers: Vec::new(),
            // Empty: a LAN-only resolve must not reach for a relay at all, so
            // touching one would fail here rather than silently succeed.
            relays: Vec::new(),
        };
        let error = resolve_hosting(&key_identity, peer.public_key(), SignalChannel::LanOnly)
            .await
            .expect_err("nobody is hosting for this identity");
        let error = format!("{error:#}");
        assert!(
            error.contains("this network") && error.contains("Start"),
            "a LAN-only hosting miss should name the network and the fix: {error}"
        );
    }

    #[test]
    fn recent_pin_cache_keeps_only_current_and_previous() {
        let recent = RecentPins::default();
        let expired = nostr_sdk::Keys::generate();
        let previous = nostr_sdk::Keys::generate();
        let current = nostr_sdk::Keys::generate();
        let previous_pubkey = previous.public_key();
        let current_pubkey = current.public_key();

        recent.push(expired);
        recent.push(previous);
        recent.push(current);

        let retained: Vec<_> = recent
            .snapshot()
            .into_iter()
            .map(|keys| keys.public_key())
            .collect();
        assert_eq!(retained, vec![current_pubkey, previous_pubkey]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn application_keys_mutually_authenticate_over_independent_iroh_keys() {
        let server_identity = Identity::generate();
        let client_identity = Identity::generate();
        let server_key_identity = KeyIdentity {
            identity: server_identity.clone(),
            self_card: server_identity.card("server", "a7B2c3D4").unwrap(),
            peers: vec![client_identity.card("client", "x9Y8z7W6").unwrap()],
            relays: Vec::new(),
        };

        let server = create_server_endpoint(
            EndpointReadiness::LanDirect,
            iroh::SecretKey::generate(),
        )
        .await
        .unwrap();
        let client = create_client_endpoint(
            EndpointReadiness::LanDirect,
            iroh::SecretKey::generate(),
        )
        .await
        .unwrap();
        assert_ne!(
            server.id().to_string(),
            server_identity.public_key().to_hex(),
            "iroh and application identities must be distinct"
        );

        let server_id = server.id();
        let server_addr = server.addr();
        let claim = PairClaim::default();
        let listener = {
            let server = server.clone();
            let claim = claim.clone();
            tokio::spawn(async move {
                let conn = server.accept().await.unwrap().await.unwrap();
                auth_as_listener(
                    &conn,
                    Some(&server_key_identity),
                    None,
                    &claim,
                    server_id,
                )
                .await
            })
        };

        let conn = connect_to_server(&client, server_addr).await.unwrap();
        let dialer = auth_as_dialer_key(
            &conn,
            &client_identity,
            server_identity.public_key(),
            client.id(),
        )
        .await;
        assert!(dialer.is_ok(), "dialer key auth failed: {dialer:?}");
        let listener = listener.await.unwrap();
        assert!(listener.is_ok(), "listener key auth failed: {listener:?}");
        assert_eq!(
            claim.peek().and_then(|peer| peer.application_key),
            Some(client_identity.public_key())
        );

        client.close().await;
        server.close().await;
    }

    /// The listener refuses a dialer whose key it trusts but whose stored card
    /// has lapsed, and refuses it before signing anything — so an expired peer
    /// cannot even harvest a proof of this device's identity. The dialer learns
    /// why from the dedicated close code.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_expired_peer_card_is_refused_by_the_listener() {
        let server_identity = Identity::generate();
        let client_identity = Identity::generate();
        let stale = client_identity
            .card_issued_at(
                "client",
                "x9Y8z7W6",
                unix_now() - crate::auth::CARD_TTL_SECS - 1,
            )
            .unwrap();
        assert!(stale.is_expired());
        let server_key_identity = KeyIdentity {
            identity: server_identity.clone(),
            self_card: server_identity.card("server", "a7B2c3D4").unwrap(),
            peers: vec![stale],
            relays: Vec::new(),
        };

        let server =
            create_server_endpoint(EndpointReadiness::LanDirect, iroh::SecretKey::generate())
                .await
                .unwrap();
        let client =
            create_client_endpoint(EndpointReadiness::LanDirect, iroh::SecretKey::generate())
                .await
                .unwrap();

        let server_id = server.id();
        let server_addr = server.addr();
        let claim = PairClaim::default();
        let listener = {
            let server = server.clone();
            let claim = claim.clone();
            tokio::spawn(async move {
                let conn = server.accept().await.unwrap().await.unwrap();
                auth_as_listener(&conn, Some(&server_key_identity), None, &claim, server_id).await
            })
        };

        let conn = connect_to_server(&client, server_addr).await.unwrap();
        let dialer = auth_as_dialer_key(
            &conn,
            &client_identity,
            server_identity.public_key(),
            client.id(),
        )
        .await;

        let error = dialer.expect_err("an expired card must not authenticate");
        assert!(
            format!("{error:#}").contains("expired"),
            "dialer should be told the card expired, got: {error:#}"
        );
        let listener = listener.await.unwrap();
        assert!(listener.is_err(), "listener must refuse the expired card");
        assert!(
            claim.peek().is_none(),
            "a refused dialer must not claim the pairing"
        );

        client.close().await;
        server.close().await;
    }

    /// Start a session backed by its own fresh [`SessionMemory`], for tests
    /// that don't exercise session-task restarts.
    fn start_test_session(kind: SessionKind, events: EventSender) -> Session {
        let memory = SessionMemory::new(session_key(&kind));
        start_session(kind, events, &memory)
    }

    /// Drain events from a std receiver until `pred` matches or the deadline
    /// passes, panicking with the seen events on timeout.
    fn wait_for_event<T>(
        rx: &std::sync::mpsc::Receiver<NetEvent>,
        deadline: Duration,
        mut pred: impl FnMut(&NetEvent) -> Option<T>,
    ) -> T {
        let start = Instant::now();
        let mut seen = Vec::new();
        while start.elapsed() < deadline {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(ev) => {
                    if let Some(out) = pred(&ev) {
                        return out;
                    }
                    seen.push(format!("{ev:?}"));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("event channel closed; seen: {seen:?}")
                }
            }
        }
        panic!("timed out waiting for event; seen: {seen:?}");
    }

    /// Block until the card-setup host shows a PIN, and return it in the
    /// canonical form the joiner's `DialSpec` wants — the displayed code is all
    /// the joining user ever gets to type.
    fn wait_for_displayed_pin(rx: &std::sync::mpsc::Receiver<NetEvent>) -> String {
        let displayed = wait_for_event(rx, Duration::from_secs(30), |ev| {
            if let NetEvent::PinRotated { pin_display, .. } = ev {
                Some(pin_display.clone())
            } else {
                None
            }
        });
        crate::pin::normalize_pin(&displayed).expect("a displayed PIN is always valid")
    }

    /// `wait_for_event` predicate pulling the card out of a `PeerCardReceived`.
    fn received_card(ev: &NetEvent) -> Option<IdentityCard> {
        match ev {
            NetEvent::PeerCardReceived(card) => Some((**card).clone()),
            _ => None,
        }
    }

    /// The dialer refuses its own lapsed card for the selected peer before it
    /// touches the network — no endpoint, no relay lookup, and an error that
    /// names the fix rather than a remote rejection.
    #[tokio::test(flavor = "multi_thread")]
    async fn joining_a_peer_with_an_expired_card_fails_before_dialing() {
        let identity = Identity::generate();
        let peer_identity = Identity::generate();
        let stale = peer_identity
            .card_issued_at(
                "server",
                "a7B2c3D4",
                unix_now() - crate::auth::CARD_TTL_SECS - 1,
            )
            .unwrap();
        let key_identity = KeyIdentity {
            identity: identity.clone(),
            self_card: identity.card("client", "x9Y8z7W6").unwrap(),
            peers: vec![stale],
            // Empty relay list: reaching the lookup at all would fail this test
            // for the wrong reason, so the refusal must come first.
            relays: Vec::new(),
        };

        let (tx, rx) = std::sync::mpsc::channel();
        let events = EventSender::new(tx, None);
        let session = start_test_session(
            SessionKind::Client(DialSpec::Key {
                identity: Box::new(key_identity),
                peer_public_key: peer_identity.public_key(),
                channel: SignalChannel::LanOnly,
            }),
            events,
        );

        let message = wait_for_event(&rx, Duration::from_secs(5), |event| match event {
            NetEvent::Error(message) => Some(message.clone()),
            _ => None,
        });
        assert!(
            message.contains("expired") && message.contains("server_a7B2c3D4"),
            "the error should name the expired peer: {message}"
        );
        wait_for_event(&rx, Duration::from_secs(5), |event| {
            matches!(event, NetEvent::Status(ConnStatus::Idle)).then_some(())
        });
        assert!(
            !rx.try_iter().any(|event| matches!(event, NetEvent::ClientReady { .. })),
            "no endpoint should be created for an expired peer"
        );

        stop_session(&mut Some(session)).await;
    }

    /// A refresh request rotates the PIN immediately instead of waiting out
    /// the current period, and the replacement is a different code.
    #[tokio::test(flavor = "multi_thread")]
    async fn refresh_pin_rotates_immediately() {
        let _ = env_logger::builder().is_test(true).try_init();

        let (tx, rx) = std::sync::mpsc::channel();
        let events = EventSender::new(tx, None);
        let session = start_test_session(
            SessionKind::Server(ServerMode::CardSetup {
                self_card: Box::new(Identity::generate().card("host", "a7B2c3D4").unwrap()),
                channel: SignalChannel::LanOnly,
                relays: Vec::new(),
            }),
            events,
        );

        let pin_rotated = |ev: &NetEvent| {
            if let NetEvent::PinRotated { pin_display, .. } = ev {
                Some(pin_display.clone())
            } else {
                None
            }
        };
        let first = wait_for_event(&rx, Duration::from_secs(30), pin_rotated);

        session
            .pin_refresh
            .as_ref()
            .expect("card-setup host sessions expose a refresh handle")
            .notify_one();

        // Far sooner than the rotation period (BUCKET_SECS), so only the
        // refresh can explain a new PIN arriving now.
        let second = wait_for_event(&rx, Duration::from_secs(20), pin_rotated);
        assert_ne!(first, second, "refresh must mint a different PIN");

        session.cancel.cancel();
        let _ = session.handle.await;
    }

    /// Two card-setup peers in one process, driven exactly as the user drives
    /// them: pinned to the LAN-only channel (a test can stand up mDNS, not a
    /// relay), the host advertises the rotating PIN's rendezvous record over
    /// DNS-SD, the joiner resolves it from the displayed PIN alone — including
    /// the direct addresses it dials explicitly — proves the PIN in-band, and
    /// both sides come away holding the other's signed card.
    #[tokio::test(flavor = "multi_thread")]
    async fn card_setup_exchanges_identity_cards() {
        let _ = env_logger::builder().is_test(true).try_init();

        let host_identity = Identity::generate();
        let join_identity = Identity::generate();
        let host_card = host_identity.card("host", "a7B2c3D4").unwrap();
        let join_card = join_identity.card("joiner", "x9Y8z7W6").unwrap();

        let (srv_tx, srv_rx) = std::sync::mpsc::channel();
        let srv_session = start_test_session(
            SessionKind::Server(ServerMode::CardSetup {
                self_card: Box::new(host_card.clone()),
                channel: SignalChannel::LanOnly,
                relays: Vec::new(),
            }),
            EventSender::new(srv_tx, None),
        );

        let canonical_pin = wait_for_displayed_pin(&srv_rx);

        let (cli_tx, cli_rx) = std::sync::mpsc::channel();
        let cli_session = start_test_session(
            SessionKind::Client(DialSpec::CardSetup {
                canonical_pin,
                self_card: Box::new(join_card.clone()),
                target_ip: None,
                channel: SignalChannel::LanOnly,
                relays: Vec::new(),
            }),
            EventSender::new(cli_tx, None),
        );

        // Each side ends up with the *other's* card — the whole point.
        let got_by_joiner = wait_for_event(&cli_rx, Duration::from_secs(120), received_card);
        assert_eq!(got_by_joiner.public_key(), host_identity.public_key());
        assert_eq!(got_by_joiner.name(), "host_a7B2c3D4");

        // Pairing spends the PIN, so `PinCleared` lands before the card does;
        // catch it on the way past rather than looking for it afterwards.
        let mut pin_cleared = false;
        let got_by_host = wait_for_event(&srv_rx, Duration::from_secs(30), |ev| {
            pin_cleared |= matches!(ev, NetEvent::PinCleared);
            received_card(ev)
        });
        assert_eq!(got_by_host.public_key(), join_identity.public_key());
        assert_eq!(got_by_host.name(), "joiner_x9Y8z7W6");
        assert!(pin_cleared, "pairing must stop the host showing a PIN");

        // The fingerprints each side displays are the ones the *other* device
        // shows for itself. This is exactly the comparison the user makes.
        assert_eq!(got_by_joiner.fingerprint(), host_card.fingerprint());
        assert_eq!(got_by_host.fingerprint(), join_card.fingerprint());

        // The session ends on its own once the cards have crossed — nobody has
        // to stop it.
        wait_for_event(&srv_rx, Duration::from_secs(30), |ev| {
            matches!(ev, NetEvent::Status(ConnStatus::Idle)).then_some(())
        });
        wait_for_event(&cli_rx, Duration::from_secs(30), |ev| {
            matches!(ev, NetEvent::Status(ConnStatus::Idle)).then_some(())
        });

        let mut cli = Some(cli_session);
        let mut srv = Some(srv_session);
        stop_session(&mut cli).await;
        stop_session(&mut srv).await;
    }

    /// The clipboard session's own rendezvous, end to end and relay-less: a host
    /// with one trusted peer advertises its ephemeral node id on the local
    /// network, that peer resolves the pairwise record — direct addresses
    /// included — dials it, both authenticate with their application keys, and a
    /// clipboard item crosses.
    ///
    /// Nothing here can reach a relay: the relay lists are empty and `LanOnly`
    /// builds a relay-less endpoint, so a pass is proof the local-network half of
    /// the clipboard signaling stands on its own.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_clipboard_session_signals_over_the_local_network() {
        let _ = env_logger::builder().is_test(true).try_init();

        let host_identity = Identity::generate();
        let join_identity = Identity::generate();
        let host_card = host_identity.card("host", "a7B2c3D4").unwrap();
        let join_card = join_identity.card("joiner", "x9Y8z7W6").unwrap();

        let (srv_tx, srv_rx) = std::sync::mpsc::channel();
        let srv_session = start_test_session(
            SessionKind::Server(ServerMode::Key {
                identity: Box::new(KeyIdentity {
                    identity: host_identity.clone(),
                    self_card: host_card.clone(),
                    peers: vec![join_card.clone()],
                    relays: Vec::new(),
                }),
                channel: SignalChannel::LanOnly,
            }),
            EventSender::new(srv_tx, None),
        );
        // The joiner's first browse may still beat the advertisement; its retry
        // loop covers that, and waiting for Listening keeps the common case to
        // one attempt.
        wait_for_event(&srv_rx, Duration::from_secs(30), |ev| {
            matches!(ev, NetEvent::Status(ConnStatus::Listening)).then_some(())
        });

        let (cli_tx, cli_rx) = std::sync::mpsc::channel();
        let cli_session = start_test_session(
            SessionKind::Client(DialSpec::Key {
                identity: Box::new(KeyIdentity {
                    identity: join_identity.clone(),
                    self_card: join_card,
                    peers: vec![host_card],
                    relays: Vec::new(),
                }),
                peer_public_key: host_identity.public_key(),
                channel: SignalChannel::LanOnly,
            }),
            EventSender::new(cli_tx, None),
        );

        // Both sides pair, and each names the other's *application* key — the
        // record only pointed at a node id, so this is the handshake talking.
        let paired = |ev: &NetEvent| match ev {
            NetEvent::PeerPaired {
                peer_public_key, ..
            } => peer_public_key.clone(),
            _ => None,
        };
        assert_eq!(
            wait_for_event(&cli_rx, Duration::from_secs(120), paired),
            host_identity.public_key().to_hex()
        );
        assert_eq!(
            wait_for_event(&srv_rx, Duration::from_secs(30), paired),
            join_identity.public_key().to_hex()
        );

        // The link is real: an item sent from the host arrives at the joiner.
        srv_session.clip_tx.send("over the LAN".to_string()).unwrap();
        let text = wait_for_event(&cli_rx, Duration::from_secs(30), |ev| match ev {
            NetEvent::ItemReceived { text, .. } => Some(text.clone()),
            _ => None,
        });
        assert_eq!(text, "over the LAN");

        let mut cli = Some(cli_session);
        let mut srv = Some(srv_session);
        stop_session(&mut cli).await;
        stop_session(&mut srv).await;
    }

    /// A card-setup session must never move clipboard content. Sending on
    /// either side's clip channel produces nothing on the peer — the session
    /// task drops the receiver outright, so there is no path for content to
    /// take.
    #[tokio::test(flavor = "multi_thread")]
    async fn card_setup_never_carries_clipboard_content() {
        let _ = env_logger::builder().is_test(true).try_init();

        let host_card = Identity::generate().card("host", "a7B2c3D4").unwrap();
        let join_card = Identity::generate().card("joiner", "x9Y8z7W6").unwrap();

        let (srv_tx, srv_rx) = std::sync::mpsc::channel();
        let srv_session = start_test_session(
            SessionKind::Server(ServerMode::CardSetup {
                self_card: Box::new(host_card),
                channel: SignalChannel::LanOnly,
                relays: Vec::new(),
            }),
            EventSender::new(srv_tx, None),
        );
        let canonical_pin = wait_for_displayed_pin(&srv_rx);

        let (cli_tx, cli_rx) = std::sync::mpsc::channel();
        let cli_session = start_test_session(
            SessionKind::Client(DialSpec::CardSetup {
                canonical_pin,
                self_card: Box::new(join_card),
                target_ip: None,
                channel: SignalChannel::LanOnly,
                relays: Vec::new(),
            }),
            EventSender::new(cli_tx, None),
        );

        wait_for_event(&cli_rx, Duration::from_secs(120), received_card);
        wait_for_event(&srv_rx, Duration::from_secs(30), received_card);

        // The channel send may fail outright (the receiver is dropped) — either
        // way nothing must reach the peer.
        let _ = cli_session.clip_tx.send("should never arrive".to_string());
        let _ = srv_session.clip_tx.send("nor should this".to_string());

        tokio::time::sleep(Duration::from_secs(3)).await;
        for (label, rx) in [("host", &srv_rx), ("joiner", &cli_rx)] {
            assert!(
                !rx.try_iter()
                    .any(|ev| matches!(ev, NetEvent::ItemReceived { .. })),
                "{label} received clipboard content over a card-setup session"
            );
        }

        let mut cli = Some(cli_session);
        let mut srv = Some(srv_session);
        stop_session(&mut cli).await;
        stop_session(&mut srv).await;
    }

    /// Card setup over the manual-IP unicast side channel: the joiner supplies a
    /// `target_ip`, so discovery bypasses mDNS entirely and fetches the
    /// PIN-encrypted record over TCP from the host's IP (here loopback). The
    /// record carries the host's direct addresses, which the joiner then dials —
    /// the whole point being pairing where multicast is blocked.
    #[tokio::test(flavor = "multi_thread")]
    async fn card_setup_exchanges_cards_over_the_unicast_side_channel() {
        let _ = env_logger::builder().is_test(true).try_init();

        let host_identity = Identity::generate();
        let host_card = host_identity.card("host", "a7B2c3D4").unwrap();
        let join_card = Identity::generate().card("joiner", "x9Y8z7W6").unwrap();

        let (srv_tx, srv_rx) = std::sync::mpsc::channel();
        let srv_session = start_test_session(
            SessionKind::Server(ServerMode::CardSetup {
                self_card: Box::new(host_card),
                channel: SignalChannel::LanOnly,
                relays: Vec::new(),
            }),
            EventSender::new(srv_tx, None),
        );
        let canonical_pin = wait_for_displayed_pin(&srv_rx);

        let (cli_tx, cli_rx) = std::sync::mpsc::channel();
        let cli_session = start_test_session(
            SessionKind::Client(DialSpec::CardSetup {
                canonical_pin,
                self_card: Box::new(join_card),
                // The host serves the unicast side channel on all interfaces, so
                // loopback reaches it on the same machine.
                target_ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                channel: SignalChannel::LanOnly,
                relays: Vec::new(),
            }),
            EventSender::new(cli_tx, None),
        );

        let got = wait_for_event(&cli_rx, Duration::from_secs(120), received_card);
        assert_eq!(got.public_key(), host_identity.public_key());
        wait_for_event(&srv_rx, Duration::from_secs(30), received_card);

        let mut cli = Some(cli_session);
        let mut srv = Some(srv_session);
        stop_session(&mut cli).await;
        stop_session(&mut srv).await;
    }

    /// After an interrupted connection resumes, each side pulls the other's
    /// latest sent item (surfaced with `pulled: true` for UI deduplication).
    ///
    /// Driven directly against [`pump_clipboard`] over a pair of loopback
    /// endpoints rather than through a full session: configure mode is the only
    /// mode that carries clipboard traffic, and its client resolves through a
    /// nostr relay, which a test cannot stand up. Both sides keep their
    /// [`LastSent`] across the reconnect, exactly as `run_*_session` does.
    #[tokio::test(flavor = "multi_thread")]
    async fn resume_pulls_latest_from_both_sides() {
        let _ = env_logger::builder().is_test(true).try_init();

        let server_identity = Identity::generate();
        let client_identity = Identity::generate();
        let server_key_identity = KeyIdentity {
            identity: server_identity.clone(),
            self_card: server_identity.card("server", "a7B2c3D4").unwrap(),
            peers: vec![client_identity.card("client", "x9Y8z7W6").unwrap()],
            relays: Vec::new(),
        };

        let server = create_server_endpoint(EndpointReadiness::LanDirect, iroh::SecretKey::generate())
            .await
            .unwrap();
        let client = create_client_endpoint(EndpointReadiness::LanDirect, iroh::SecretKey::generate())
            .await
            .unwrap();
        let server_id = server.id();
        let server_addr = server.addr();
        let claim = PairClaim::default();

        // Per-side state that outlives an individual connection — this is what
        // makes a resume a resume.
        let (srv_tx, srv_rx) = std::sync::mpsc::channel();
        let (cli_tx, cli_rx) = std::sync::mpsc::channel();
        let srv_events = EventSender::new(srv_tx, None);
        let cli_events = EventSender::new(cli_tx, None);
        let srv_last = LastSent::default();
        let cli_last = LastSent::default();
        let (srv_clip_tx, mut srv_clip_rx) = mpsc::unbounded_channel();
        let (cli_clip_tx, mut cli_clip_rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();

        // Bring up one authenticated connection and hand back both sides'
        // session streams.
        #[allow(clippy::too_many_arguments)]
        async fn connect_pair(
            server: &iroh::Endpoint,
            client: &iroh::Endpoint,
            server_addr: EndpointAddr,
            server_id: iroh::EndpointId,
            server_key_identity: &KeyIdentity,
            client_identity: &Identity,
            server_public: nostr_sdk::PublicKey,
            claim: &PairClaim,
        ) -> (Bi, Bi, iroh::endpoint::Connection, iroh::endpoint::Connection) {
            let listener = tokio::spawn({
                let server = server.clone();
                let claim = claim.clone();
                let ident = server_key_identity.clone();
                async move {
                    let conn = server.accept().await.unwrap().await.unwrap();
                    let (s, r, _) = auth_as_listener(&conn, Some(&ident), None, &claim, server_id)
                        .await
                        .unwrap();
                    ((s, r), conn)
                }
            });
            let conn = connect_to_server(client, server_addr).await.unwrap();
            let dialer = auth_as_dialer_key(&conn, client_identity, server_public, client.id())
                .await
                .unwrap();
            let (server_side, server_conn) = listener.await.unwrap();
            (server_side, dialer, conn, server_conn)
        }

        // One pump round, owning its receiver for the duration and handing it
        // back so the next round can reuse it — the receiver is session state,
        // not connection state.
        fn spawn_pump(
            bi: Bi,
            events: EventSender,
            mut clip_rx: mpsc::UnboundedReceiver<String>,
            cancel: CancellationToken,
            last: LastSent,
        ) -> JoinHandle<mpsc::UnboundedReceiver<String>> {
            tokio::spawn(async move {
                let (send, recv) = bi;
                let _ = pump_clipboard(send, recv, &events, &mut clip_rx, &cancel, &last).await;
                clip_rx
            })
        }

        let (srv_bi, cli_bi, conn, srv_conn) = connect_pair(
            &server,
            &client,
            server_addr.clone(),
            server_id,
            &server_key_identity,
            &client_identity,
            server_identity.public_key(),
            &claim,
        )
        .await;

        // Round one: one item each way, so both sides hold a last-sent.
        let srv_pump = spawn_pump(
            srv_bi,
            srv_events.clone(),
            srv_clip_rx,
            cancel.clone(),
            srv_last.clone(),
        );
        let cli_pump = spawn_pump(
            cli_bi,
            cli_events.clone(),
            cli_clip_rx,
            cancel.clone(),
            cli_last.clone(),
        );
        srv_clip_tx.send("server latest".to_string()).unwrap();
        cli_clip_tx.send("client latest".to_string()).unwrap();
        wait_for_event(&cli_rx, Duration::from_secs(15), |ev| {
            matches!(ev, NetEvent::ItemReceived { pulled: false, .. }).then_some(())
        });
        wait_for_event(&srv_rx, Duration::from_secs(15), |ev| {
            matches!(ev, NetEvent::ItemReceived { pulled: false, .. }).then_some(())
        });

        // Interrupt: kill the connection out from under both pumps.
        conn.close(0u32.into(), b"test interruption");
        drop(srv_conn);
        srv_clip_rx = srv_pump.await.unwrap();
        cli_clip_rx = cli_pump.await.unwrap();

        // Resume on a fresh connection, carrying each side's LastSent forward.
        let (srv_bi, cli_bi, _conn, _srv_conn) = connect_pair(
            &server,
            &client,
            server_addr,
            server_id,
            &server_key_identity,
            &client_identity,
            server_identity.public_key(),
            &claim,
        )
        .await;
        let srv_pump = spawn_pump(srv_bi, srv_events, srv_clip_rx, cancel.clone(), srv_last);
        let cli_pump = spawn_pump(cli_bi, cli_events, cli_clip_rx, cancel.clone(), cli_last);

        // On resume each side pulls the other's latest, marked for dedup.
        let text = wait_for_event(&cli_rx, Duration::from_secs(30), |ev| {
            if let NetEvent::ItemReceived { text, pulled: true } = ev {
                Some(text.clone())
            } else {
                None
            }
        });
        assert_eq!(text, "server latest");
        let text = wait_for_event(&srv_rx, Duration::from_secs(30), |ev| {
            if let NetEvent::ItemReceived { text, pulled: true } = ev {
                Some(text.clone())
            } else {
                None
            }
        });
        assert_eq!(text, "client latest");

        cancel.cancel();
        let _ = srv_pump.await;
        let _ = cli_pump.await;
        client.close().await;
        server.close().await;
    }

    /// One PIN admits exactly one device. After a device has answered the PIN
    /// and taken its card, a second device answering the *same* code gets
    /// nothing — and is told so rather than left waiting.
    ///
    /// This is what stops a bystander who reads the PIN over your shoulder from
    /// collecting a card of their own. The refusal's wording depends on how far
    /// the latecomer gets before the finished host tears down (a `SERVER_BUSY`
    /// close inside the grace window, a resolve failure after it), so the
    /// assertion is on the outcome — no card, and an error — not the wording.
    #[tokio::test(flavor = "multi_thread")]
    async fn only_one_device_can_answer_a_card_setup_pin() {
        let _ = env_logger::builder().is_test(true).try_init();

        let (srv_tx, srv_rx) = std::sync::mpsc::channel();
        let srv_session = start_test_session(
            SessionKind::Server(ServerMode::CardSetup {
                self_card: Box::new(Identity::generate().card("host", "a7B2c3D4").unwrap()),
                channel: SignalChannel::LanOnly,
                relays: Vec::new(),
            }),
            EventSender::new(srv_tx, None),
        );
        let canonical_pin = wait_for_displayed_pin(&srv_rx);
        let dial = || DialSpec::CardSetup {
            canonical_pin: canonical_pin.clone(),
            self_card: Box::new(Identity::generate().card("joiner", "x9Y8z7W6").unwrap()),
            target_ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            channel: SignalChannel::LanOnly,
            relays: Vec::new(),
        };

        // The device the user meant to pair answers first and takes its card.
        let (a_tx, a_rx) = std::sync::mpsc::channel();
        let mut a_session =
            Some(start_test_session(SessionKind::Client(dial()), EventSender::new(a_tx, None)));
        wait_for_event(&a_rx, Duration::from_secs(120), received_card);
        wait_for_event(&srv_rx, Duration::from_secs(30), received_card);

        // Now the bystander tries the same code.
        let (b_tx, b_rx) = std::sync::mpsc::channel();
        let mut b_session =
            Some(start_test_session(SessionKind::Client(dial()), EventSender::new(b_tx, None)));

        let start = Instant::now();
        let mut refused: Option<String> = None;
        let mut seen: Vec<String> = Vec::new();
        while start.elapsed() < Duration::from_secs(60) && refused.is_none() {
            match b_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(NetEvent::PeerCardReceived(_)) => {
                    panic!("a second device must never come away with a card")
                }
                Ok(NetEvent::Error(e)) => refused = Some(e),
                Ok(other) => seen.push(format!("{other:?}")),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        assert!(
            refused.is_some(),
            "the second device must be told why it got nothing, not left waiting; saw {seen:?}"
        );

        stop_session(&mut a_session).await;
        stop_session(&mut b_session).await;
        stop_session(&mut Some(srv_session)).await;
    }
}
