//! The networking runtime: one command loop owning at most one session (server
//! or client), adapted from duopipe's peer runtime with the SOCKS payload
//! replaced by a single long-lived clipboard stream.
//!
//! Per connection (client = dialer): the client opens a single bidirectional
//! stream and authenticates on it (token or PIN); on success that same stream
//! stays open and both sides pump [`ClipMsg`] frames in both directions until
//! the connection dies or the session is cancelled.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::{EndpointAddr, EndpointId};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::auth::is_token_valid;
use crate::net::endpoint::{
    EndpointReadiness, connect_to_server, connection_paths, create_client_endpoint,
    create_server_endpoint, watch_connection_paths,
};
use crate::net::{
    ConnStatus, DialSpec, EventSender, NetEvent, PinChannel, ServerMode, TokenIdentity, UiCommand,
};
use crate::protocol::{
    AuthRequest, AuthResponse, ClipBody, ClipMsg, MAX_CLIP_MESSAGE_SIZE,
    MAX_CONTROL_MESSAGE_SIZE, decode_auth_request, decode_auth_response, decode_clip_msg,
    encode_auth_request, encode_auth_response, encode_clip_msg, read_length_prefixed,
};

/// Retain only the PIN keys from the sender's current and previous rotation buckets for
/// in-band authentication. The joiner may still probe an additional bucket for clock skew.
const RECENT_PIN_CACHE: usize = 2;

/// Timeout for the authentication handshake.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Connection close code for authentication failure (invalid token/PIN).
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

/// Fixed delay between reconnect attempts on the dialing peer.
const RECONNECT_DELAY: Duration = Duration::from_secs(3);

/// Maximum number of *consecutive* failed connect attempts before the client
/// gives up. The counter resets on every successful connection, so this bounds
/// only an unbroken run of failures (an unreachable peer) — not a flaky link
/// that keeps recovering. Applied uniformly whether or not a connection has
/// succeeded before, so a dropped session never retries without end.
const MAX_CONNECT_ATTEMPTS: u32 = 10;

/// Marker error for fatal authentication failures (wrong token/PIN, explicit
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

/// Milliseconds since the Unix epoch (sender timestamp on clipboard items).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Current and previous PIN auth keypairs (newest first), one per rotation bucket the quick-mode
/// server has published. Written by the PIN publisher, read by the listener auth path to verify a
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

/// The single peer a serve endpoint is paired with, for the lifetime of one server session.
/// duocb links one pair of devices at a time by design: once a client authenticates, its
/// (QUIC/TLS-authenticated) node id claims the endpoint and any other node id is refused until
/// the server is stopped. The claim is intentionally *not* released when the paired peer
/// disconnects, so that peer — and only that peer — can reconnect without re-pairing (in PIN
/// mode, without re-typing a PIN that may since have rotated). A fresh server session mints a
/// new endpoint id and a new (empty) claim.
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
    /// The paired client's node id (its public key; authenticated by the iroh/QUIC handshake).
    node_id: EndpointId,
    /// The PIN auth key that verified this peer at pairing (PIN mode only). Retained so the
    /// paired peer can complete the in-band challenge-response on reconnect even after its PIN
    /// has rotated out of the server's recent-bucket cache. `None` for token pairings.
    pin_key: Option<nostr_sdk::Keys>,
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
    fn commit(&self, node_id: EndpointId, pin_key: Option<nostr_sdk::Keys>) -> bool {
        let mut g = self.peer.lock();
        match g.as_ref() {
            Some(c) if c.node_id != node_id => false,
            Some(_) => true,
            None => {
                *g = Some(ClaimedPeer { node_id, pin_key });
                // First pairing: signal watchers (the PIN publisher stops here).
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

/// Shared channel carrying the hosting state (the server endpoint's node id
/// while a configure-mode session is listening, `None` otherwise) from the
/// session into the standing presence publisher, which republishes on change.
type HostingTx = Arc<tokio::sync::watch::Sender<Option<EndpointId>>>;

/// A running server or client session: its cancel token, task handle, the
/// channel that feeds outbound clipboard items into the active connection, and
/// the shared connection slot for on-demand path queries.
struct Session {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
    clip_tx: mpsc::UnboundedSender<String>,
    conn: ConnSlot,
    /// Kicks the PIN publisher into an immediate rotate-and-revoke (see
    /// [`UiCommand::RefreshPin`]). `Some` only for a PIN-mode server session.
    pin_refresh: Option<Arc<tokio::sync::Notify>>,
}

fn start_session(kind: SessionKind, events: EventSender, hosting: Option<HostingTx>) -> Session {
    let cancel = CancellationToken::new();
    let (clip_tx, clip_rx) = mpsc::unbounded_channel();
    let task_cancel = cancel.clone();
    let conn: ConnSlot = Arc::new(parking_lot::Mutex::new(None));
    let task_conn = conn.clone();
    let pin_refresh = matches!(&kind, SessionKind::Server(ServerMode::Pin { .. }))
        .then(|| Arc::new(tokio::sync::Notify::new()));
    let task_pin_refresh = pin_refresh.clone();
    let handle = tokio::spawn(async move {
        let last_sent = LastSent::default();
        match kind {
            SessionKind::Server(mode) => {
                run_server_session(
                    mode,
                    events,
                    task_cancel,
                    clip_rx,
                    task_conn,
                    last_sent,
                    hosting,
                    task_pin_refresh,
                )
                .await
            }
            SessionKind::Client(spec) => {
                run_client_session(spec, events, task_cancel, clip_rx, task_conn, last_sent).await
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
        // command (and the iOS FFI's stop, which blocks on shutdown) sits
        // behind this await.
        let mut handle = s.handle;
        if tokio::time::timeout(Duration::from_secs(3), &mut handle)
            .await
            .is_err()
        {
            handle.abort();
        }
    }
}

/// The standing presence publisher task and the identity it broadcasts.
struct Presence {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
    identity: TokenIdentity,
}

async fn stop_presence(presence: &mut Option<Presence>) {
    if let Some(p) = presence.take() {
        p.cancel.cancel();
        let _ = p.handle.await;
    }
}

/// Random per-publisher-run id (16 hex chars) carried in presence records so a
/// publisher can recognize a record written by another live process under its
/// own identity.
fn generate_run_id() -> String {
    let bytes: [u8; 8] = rand::Rng::random(&mut rand::rng());
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn spawn_presence(identity: TokenIdentity, hosting: &HostingTx, events: EventSender) -> Presence {
    let cancel = CancellationToken::new();
    let handle = tokio::spawn(run_presence_publisher(
        identity.clone(),
        generate_run_id(),
        hosting.subscribe(),
        events,
        cancel.clone(),
    ));
    Presence {
        cancel,
        handle,
        identity,
    }
}

/// The runtime's main loop: consume UI commands until shutdown. At most one
/// session (server or client) runs at a time; starting a new one replaces the
/// current one. The presence publisher is independent of sessions: it runs from
/// [`UiCommand::SetPresence`] until stopped, with the hosting watch channel
/// carrying the current server node id into its records.
pub async fn net_main(mut cmd_rx: mpsc::UnboundedReceiver<UiCommand>, events: EventSender) {
    let mut session: Option<Session> = None;
    let mut presence: Option<Presence> = None;
    // One in-flight peer-list fetch at a time; a completed handle is replaced.
    let mut peer_fetch: Option<JoinHandle<()>> = None;
    let hosting: HostingTx = Arc::new(tokio::sync::watch::channel(None).0);

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            UiCommand::StartServer { mode } => {
                stop_session(&mut session).await;
                let session_hosting = if let ServerMode::NostrToken { identity } = &mode {
                    // Hosting requires the presence publisher: its record is how
                    // peers find this device's node id. Ensure it runs for this
                    // exact identity (the UI normally has it running already).
                    if presence.as_ref().is_none_or(|p| p.identity != *identity) {
                        stop_presence(&mut presence).await;
                        presence = Some(spawn_presence(identity.clone(), &hosting, events.clone()));
                    }
                    Some(hosting.clone())
                } else {
                    None
                };
                session = Some(start_session(
                    SessionKind::Server(mode),
                    events.clone(),
                    session_hosting,
                ));
            }
            UiCommand::Connect { spec } => {
                stop_session(&mut session).await;
                session = Some(start_session(SessionKind::Client(spec), events.clone(), None));
            }
            UiCommand::StopServer | UiCommand::Disconnect => {
                stop_session(&mut session).await;
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
            UiCommand::SetPresence { identity } => {
                stop_presence(&mut presence).await;
                if let Some(identity) = identity {
                    presence = Some(spawn_presence(identity, &hosting, events.clone()));
                }
            }
            UiCommand::RefreshPeers => {
                if peer_fetch.as_ref().is_some_and(|h| !h.is_finished()) {
                    // A fetch is already running; its answer is on the way.
                } else if let Some(p) = &presence {
                    let identity = p.identity.clone();
                    let events = events.clone();
                    // Spawned so a slow relay lookup never blocks this loop.
                    peer_fetch = Some(tokio::spawn(async move {
                        match crate::nostr::fetch_presence_records(
                            &identity.token,
                            &identity.relays,
                        )
                        .await
                        {
                            Ok(records) => {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0);
                                let peers =
                                    crate::nostr::build_peer_list(records, &identity.suffix, now);
                                events.send(NetEvent::PeerList { peers });
                            }
                            Err(e) => {
                                events.error(format!("Could not refresh the device list: {e:#}"));
                            }
                        }
                    }));
                } else {
                    events.error("Set up the secret and device name first");
                }
            }
            UiCommand::Shutdown => break,
        }
    }

    stop_session(&mut session).await;
    stop_presence(&mut presence).await;
    if let Some(fetch) = peer_fetch.take() {
        fetch.abort();
    }
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

/// Marks this device as hosting for the lifetime of a configure-mode server
/// session: publishes the node id into the hosting watch channel on creation
/// and clears it on drop, so every session exit path (stop, error, replacement)
/// reliably flips the presence record back to non-hosting.
struct HostingGuard(HostingTx);

impl HostingGuard {
    fn new(tx: HostingTx, node_id: EndpointId) -> Self {
        tx.send_replace(Some(node_id));
        Self(tx)
    }
}

impl Drop for HostingGuard {
    fn drop(&mut self) {
        self.0.send_replace(None);
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
    hosting: Option<HostingTx>,
    pin_refresh: Option<Arc<tokio::sync::Notify>>,
) {
    events.status(ConnStatus::Starting);

    // Only the modes that hard-require the internet gate on the relay coming
    // online (`online()` never resolves offline, so they fail fast without
    // it). The PIN quick mode gates on a first local address only — the PIN
    // shows immediately and LAN signaling needs no internet, while the relay
    // connects in the background for a cross-network dial.
    let readiness = match &mode {
        ServerMode::Pin { channel, .. } => pin_channel_readiness(*channel),
        ServerMode::NostrToken { .. } => EndpointReadiness::RelayOnline,
    };
    let endpoint = match create_server_endpoint(readiness).await {
        Ok(ep) => ep,
        Err(e) => {
            events.error(format!("Failed to start: {e:#}"));
            events.status(ConnStatus::Idle);
            return;
        }
    };
    let node_id = endpoint.id();

    // One pairing per server session (all modes). The claim is empty until the
    // first client authenticates and lives until the server is stopped.
    let claim = PairClaim::default();
    let recent_pins = RecentPins::default();

    // Tokens accepted from clients — configure mode only. The PIN quick mode
    // authenticates with the in-band PIN challenge-response instead.
    let (tokens, token_fingerprint): (HashSet<String>, Option<String>) = match &mode {
        ServerMode::NostrToken { identity } => {
            let fingerprint = crate::auth::token_fingerprint(&identity.token);
            (HashSet::from([identity.token.clone()]), Some(fingerprint))
        }
        ServerMode::Pin { .. } => (HashSet::new(), None),
    };
    events.send(NetEvent::ServerReady {
        node_id: node_id.to_string(),
        token_fingerprint,
    });
    events.status(ConnStatus::Listening);

    let pin_cache = matches!(mode, ServerMode::Pin { .. }).then(|| recent_pins.clone());

    // Configure mode: mark this device as hosting for the session's lifetime.
    // The standing presence publisher (owned by the command loop) picks the
    // node id up from the watch channel and republishes; the guard's drop
    // clears it on every exit path.
    let _hosting_guard = hosting.map(|tx| HostingGuard::new(tx, node_id));

    // Mode-specific signaling publisher, aborted on session teardown.
    let _publisher: Option<PublisherGuard> = match &mode {
        ServerMode::NostrToken { .. } => None,
        ServerMode::Pin { relays, channel } => {
            Some(PublisherGuard(tokio::spawn(run_pin_publisher(
                endpoint.clone(),
                recent_pins,
                relays.clone(),
                *channel,
                events.clone(),
                cancel.clone(),
                claim.paired_signal(),
                pin_refresh.unwrap_or_default(),
            ))))
        }
    };

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
            None => match accept_serveable(&endpoint, &claim, &cancel).await {
                Some(conn) => conn,
                None => break,
            },
        };
        let remote_id = conn.remote_id();
        log::info!("Peer connected: {remote_id} (awaiting auth)");
        events.status(ConnStatus::Authenticating);

        // Auth runs on the single session stream; on success the same stream
        // stays open for clipboard frames (no separate data stream / handshake).
        let (send, recv) =
            match auth_as_listener(&conn, &tokens, pin_cache.as_ref(), &claim, node_id).await {
            Ok(streams) => streams,
            Err(e) => {
                log::warn!("Auth failed for {remote_id}: {e:#}");
                events.status(ConnStatus::Listening);
                continue;
            }
        };
        events.send(NetEvent::PeerPaired {
            peer_node_id: remote_id.to_string(),
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
            next = accept_serveable(&endpoint, &claim, &cancel) => next,
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
            && claimed.node_id != conn.remote_id()
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

async fn run_client_session(
    spec: DialSpec,
    events: EventSender,
    cancel: CancellationToken,
    mut clip_rx: mpsc::UnboundedReceiver<String>,
    conn_slot: ConnSlot,
    last_sent: LastSent,
) {
    events.status(ConnStatus::Starting);

    // Same policy as the server side: only the internet-requiring mode gates on
    // the relay; the PIN quick mode starts resolving and dialing right away (the
    // relay connects in the background, and a cross-network dial's own timeout
    // covers it coming up). The LAN-only channel is relay-less either way (mDNS
    // or the typed-IP side channel), so its readiness is `LanDirect`.
    let readiness = match &spec {
        DialSpec::Pin { channel, .. } => pin_channel_readiness(*channel),
        DialSpec::NostrToken { .. } => EndpointReadiness::RelayOnline,
    };
    let endpoint = match create_client_endpoint(readiness).await {
        Ok(ep) => ep,
        Err(e) => {
            events.error(format!("Failed to start: {e:#}"));
            events.status(ConnStatus::Idle);
            return;
        }
    };
    let own_id = endpoint.id();
    let token_fingerprint = match &spec {
        DialSpec::NostrToken { identity, .. } => {
            Some(crate::auth::token_fingerprint(&identity.token))
        }
        DialSpec::Pin { .. } => None,
    };
    events.send(NetEvent::ClientReady {
        node_id: own_id.to_string(),
        token_fingerprint,
    });

    // Consecutive failed attempts, reset to zero on every successful connection
    // (below). Fixed-interval retry, bounded by `MAX_CONNECT_ATTEMPTS`.
    let mut attempts: u32 = 0;
    // For a PIN target: the dial target resolved on the first successful
    // pairing (node id plus any direct addresses the rendezvous carried).
    // Reused on every reconnect thereafter — the typed PIN has since rotated
    // off the relay (so a fresh lookup would fail), but the server retains our
    // pairing key, so we reconnect by node id and re-prove the same PIN in-band
    // without the user re-typing a code.
    let mut pinned_pin_addr: Option<EndpointAddr> = None;

    loop {
        // Resolve the target each attempt: configure mode re-queries the chosen
        // peer's presence record, so a restarted host's fresh node id is found.
        let resolved: Result<EndpointAddr> = match &spec {
            DialSpec::NostrToken {
                identity,
                peer_display,
            } => {
                events.status(ConnStatus::Resolving);
                // The dial target lives in the peer's hosting record, not the
                // directory: re-resolved each attempt so a restarted host's fresh
                // node id is found, and absent (no readable record) means the peer
                // is not currently hosting.
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    r = crate::nostr::lookup_hosting(&identity.token, peer_display, &identity.relays) => match r {
                        Ok(Some(id)) => Ok(EndpointAddr::new(id)),
                        Ok(None) => Err(anyhow::anyhow!(
                            "'{peer_display}' is not hosting a connection — press Start on that device (and confirm it uses the same secret)"
                        )),
                        Err(e) => Err(e.context("nostr hosting lookup failed")),
                    },
                }
            }
            DialSpec::Pin { .. } if pinned_pin_addr.is_some() => {
                Ok(pinned_pin_addr.clone().unwrap())
            }
            DialSpec::Pin {
                canonical_pin,
                relays,
                channel,
                target_ip,
            } => {
                events.status(ConnStatus::Resolving);
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    r = resolve_pin(canonical_pin, relays, *channel, *target_ip) => r,
                }
            }
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
        let attempt_addr = resolved.as_ref().ok().cloned();

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
                let auth_result = match &spec {
                    DialSpec::NostrToken { identity, .. } => {
                        auth_as_dialer(&conn, &identity.token).await
                    }
                    DialSpec::Pin { canonical_pin, .. } => {
                        auth_as_dialer_pin(&conn, canonical_pin, own_id).await
                    }
                };
                match auth_result {
                    Ok((send, recv)) => {
                        // Auth succeeded, so the server has committed us as its pair and
                        // (PIN mode) stopped publishing PINs. Pin the dial target NOW so
                        // reconnects dial this id — a fresh rendezvous lookup could
                        // never succeed again.
                        if matches!(spec, DialSpec::Pin { .. }) && pinned_pin_addr.is_none() {
                            pinned_pin_addr = attempt_addr;
                        }
                        let remote_id = conn.remote_id();
                        events.send(NetEvent::PeerPaired {
                            peer_node_id: remote_id.to_string(),
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

/// Configure mode: broadcast this device's presence record and keep it fresh.
/// Runs from `SetPresence` until stopped, independent of sessions; the hosting
/// watch channel feeds the current server node id into the record, and a change
/// there triggers an immediate republish. After the first publish, finding a
/// record under our own identity written by a different publisher run means
/// another live process is broadcasting as this device — surface the conflict
/// and stop rather than fight over the record.
async fn run_presence_publisher(
    identity: TokenIdentity,
    run_id: String,
    mut hosting_rx: tokio::sync::watch::Receiver<Option<EndpointId>>,
    events: EventSender,
    cancel: CancellationToken,
) {
    let display = identity.display();
    let mut publishes: u32 = 0;
    loop {
        // The nostr round-trips (conflict lookup + publish) run raced against
        // the cancel token: stopping the publisher must not wait out a relay
        // round-trip — the iOS FFI's stop (and with it the app's screen
        // transition away from the hub) blocks on this task ending.
        let cycle = async {
            if publishes > 0 {
                match crate::nostr::lookup_presence(&identity.token, &display, &identity.relays)
                    .await
                {
                    Ok(Some((record, _))) if record.run_id != run_id => {
                        events.send(NetEvent::PresenceConflict {
                            message: format!(
                                "Another process is broadcasting as '{display}' — stopped \
                                 publishing presence. Is a second instance using this device's \
                                 config?"
                            ),
                        });
                        return false;
                    }
                    // Our own record, no record, or a network error: nothing provable.
                    _ => {}
                }
            }

            // Snapshot (and mark seen, so the wait below only fires on the next
            // change) the current hosting state before publishing.
            let hosting: Option<EndpointId> = *hosting_rx.borrow_and_update();
            let record = crate::nostr::PresenceRecord {
                version: crate::nostr::PRESENCE_VERSION,
                name: identity.name.clone(),
                suffix: identity.suffix.clone(),
                run_id: run_id.clone(),
            };
            match crate::nostr::publish_presence(&identity.token, &record, &identity.relays).await
            {
                Ok(()) => log::info!("Published presence to nostr"),
                Err(e) => log::warn!("Failed to publish presence to nostr: {e:#}"),
            }
            // While hosting, refresh the out-of-directory hosting record that
            // carries the dial target; when idle, publish nothing and let the
            // last record expire (NIP-40) so no standing liveness lingers.
            if let Some(node_id) = hosting {
                match crate::nostr::publish_hosting(
                    &identity.token,
                    &display,
                    &node_id,
                    &identity.relays,
                )
                .await
                {
                    Ok(()) => log::info!("Published hosting record to nostr"),
                    Err(e) => log::warn!("Failed to publish hosting record to nostr: {e:#}"),
                }
            }
            true
        };
        tokio::select! {
            _ = cancel.cancelled() => return,
            keep_publishing = cycle => if !keep_publishing { return },
        }
        publishes = publishes.saturating_add(1);

        // Re-publish quickly for the first few cycles, then settle to the slow
        // heartbeat; a hosting change republishes immediately.
        let interval = if publishes <= crate::nostr::PRESENCE_STARTUP_CYCLES {
            crate::nostr::PRESENCE_STARTUP_INTERVAL
        } else {
            crate::nostr::PRESENCE_REPUBLISH_INTERVAL
        };
        tokio::select! {
            _ = cancel.cancelled() => return,
            changed = hosting_rx.changed() => {
                if changed.is_err() {
                    // The hosting sender is owned by the command loop; it going
                    // away means the runtime is tearing down.
                    return;
                }
            }
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

/// The endpoint-readiness gate for a PIN channel selection: LAN-only must not
/// wait on a relay at all, the default nostr+LAN prefers one but tolerates
/// being offline, and nostr-only requires it.
fn pin_channel_readiness(channel: PinChannel) -> EndpointReadiness {
    match channel {
        PinChannel::NostrOnly => EndpointReadiness::RelayOnline,
        PinChannel::NostrAndLan => EndpointReadiness::DirectAddr,
        PinChannel::LanOnly => EndpointReadiness::LanDirect,
    }
}

/// Resolve the PIN rendezvous on the enabled channel(s): derive the candidate
/// record keys once (see `pin_record::candidate_keys`), then query nostr
/// relays and/or the local network — racing them when both are enabled, first
/// hit wins.
///
/// The result is a full dial target: on the LAN-only channel both the DNS-SD
/// and unicast records carry the host's direct addresses and they ride along
/// (the only dialable path against an iOS host, which runs no iroh mDNS
/// responder); the other channels return a bare node id for iroh's discovery to
/// resolve.
///
/// `target_ip` (LAN-only only): `Some(ip)` fetches the record from the host's
/// unicast side channel at that IP — the manual-IP path that works where
/// multicast is blocked — instead of browsing mDNS. `None` browses mDNS.
async fn resolve_pin(
    canonical_pin: &str,
    relays: &[String],
    channel: PinChannel,
    target_ip: Option<std::net::IpAddr>,
) -> Result<EndpointAddr> {
    let candidates = crate::pin_record::candidate_keys(canonical_pin).await?;
    // The no-record outcome, phrased for what the user can actually fix.
    let miss = || match channel {
        PinChannel::NostrOnly => anyhow::anyhow!(
            "no peer found for that PIN (it refreshes every 60s — check the current code on the other device)"
        ),
        PinChannel::LanOnly if target_ip.is_some() => anyhow::anyhow!(
            "no device answered for that PIN at that IP — check the address shown on the other device and that the code (it refreshes every 60s) matches"
        ),
        PinChannel::LanOnly => anyhow::anyhow!(
            "no device found for that PIN on this network — both devices must be on the same network, and the code refreshes every 60s"
        ),
        PinChannel::NostrAndLan => anyhow::anyhow!(
            "no peer found for that PIN (it refreshes every 60s — check the current code; without internet, both devices must be on the same network)"
        ),
    };
    match channel {
        PinChannel::NostrOnly => match crate::nostr::lookup_pin_record(&candidates, relays).await {
            Ok(Some(id)) => Ok(EndpointAddr::new(id)),
            Ok(None) => Err(miss()),
            Err(e) => Err(e.context("nostr PIN lookup failed")),
        },
        PinChannel::LanOnly => {
            // A typed IP selects the unicast side channel (works where multicast
            // is blocked); no IP browses mDNS. Either way the record carries the
            // host's direct addresses, so the node id rides back dialable.
            let found = match target_ip {
                Some(ip) => {
                    crate::lan::unicast_lookup_pin_record(ip, &candidates).await
                }
                None => crate::lan::dnssd_lookup_pin_record(&candidates).await,
            };
            match found {
                Ok(Some(found)) => Ok(found.endpoint_addr()),
                Ok(None) => Err(miss()),
                Err(e) => Err(e.context("LAN PIN lookup failed")),
            }
        }
        PinChannel::NostrAndLan => {
            // Race both lookups; the first hit wins (the LAN answers in well
            // under a second when the peer is local). A channel that misses or
            // errors (e.g. nostr with no internet) leaves the outcome to the
            // other; errors only surface when both channels failed to look.
            let lan = crate::lan::lookup_pin_record(&candidates);
            let nostr = crate::nostr::lookup_pin_record(&candidates, relays);
            tokio::pin!(lan);
            tokio::pin!(nostr);
            let (mut lan_done, mut nostr_done) = (false, false);
            let mut first_err: Option<anyhow::Error> = None;
            let mut errors = 0;
            while !(lan_done && nostr_done) {
                let outcome = tokio::select! {
                    r = &mut lan, if !lan_done => {
                        lan_done = true;
                        r.map_err(|e| e.context("LAN PIN lookup failed"))
                    }
                    r = &mut nostr, if !nostr_done => {
                        nostr_done = true;
                        r.map_err(|e| e.context("nostr PIN lookup failed"))
                    }
                };
                match outcome {
                    Ok(Some(id)) => return Ok(EndpointAddr::new(id)),
                    Ok(None) => {}
                    Err(e) => {
                        log::warn!("{e:#}");
                        errors += 1;
                        first_err.get_or_insert(e);
                    }
                }
            }
            if errors == 2 {
                Err(first_err.expect("two errors were recorded"))
            } else {
                Err(miss())
            }
        }
    }
}

/// PIN quick mode publisher: mint a fresh PIN each rotation period (measured
/// from when the PIN is shown, not from wall-clock bucket boundaries), publish
/// the node-id record under it on the enabled channel(s), and surface the PIN
/// and countdown to the UI. Each bucket's PIN auth key is recorded in `recent`
/// so the listener auth path can verify a dialer's proof. Stops (and clears
/// the displayed PIN) once a peer pairs — no more peers are accepted this
/// session.
///
/// On the LAN channel the record is advertised over mDNS (`crate::lan`); the
/// previous bucket's advertisement is kept alive one extra period (`adverts`
/// holds two guards), mirroring the look-back window the nostr record's TTL
/// provides. All advertisements are withdrawn on exit.
///
/// `refresh` (the user's "new PIN now" CTA) cuts the current period short:
/// the next loop turn mints a fresh PIN immediately, and — unlike natural
/// rotation, which keeps a look-back window — every previously shown PIN is
/// revoked first.
#[allow(clippy::too_many_arguments)]
async fn run_pin_publisher(
    endpoint: iroh::Endpoint,
    recent: RecentPins,
    relays: Vec<String>,
    channel: PinChannel,
    events: EventSender,
    cancel: CancellationToken,
    paired: CancellationToken,
    refresh: Arc<tokio::sync::Notify>,
) {
    let node_id = endpoint.id();
    let mut adverts: VecDeque<crate::lan::PinAdvert> = VecDeque::new();
    // LAN-only unicast side-channel listeners, kept with the same one-period
    // look-back as `adverts`: the port is PIN-derived, so it rotates with the
    // PIN, and a joiner who typed the just-rotated code still reaches the
    // previous listener.
    let mut unicast: VecDeque<crate::lan::UnicastListener> = VecDeque::new();
    loop {
        // A peer may already have paired (e.g. a reconnect landed before this
        // loop turn). Publishing a fresh PIN would be pointless and misleading.
        if paired.is_cancelled() {
            events.send(NetEvent::PinCleared);
            break;
        }

        let pin = crate::pin::generate_pin(matches!(channel, PinChannel::LanOnly));
        let bucket = crate::pin::current_bucket();
        // On the LAN-only channel, surface the host's LAN IPv4 so the UI can
        // offer it for the joiner's manual-IP side channel. Constant across
        // rotations, but sent with every PIN so a late-arriving UI still gets it.
        let host_lan_ip = matches!(channel, PinChannel::LanOnly)
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
            // LAN first: the advertisement is instant, while the nostr publish
            // costs a relay round-trip. The LAN-only channel advertises over
            // spec-compliant DNS-SD (Bonjour-visible, addresses load-bearing);
            // the default channel keeps the swarm responder (see `crate::lan`).
            if channel.lan() {
                let addr = endpoint.addr();
                let addrs: Vec<_> = addr.ip_addrs().copied().collect();
                let advert = if matches!(channel, PinChannel::LanOnly) {
                    crate::lan::dnssd_advertise_pin_record(&keys, &node_id, &addrs).await
                } else {
                    crate::lan::advertise_pin_record(&keys, &node_id, &addrs)
                };
                match advert {
                    Ok(advert) => {
                        adverts.push_back(advert);
                        while adverts.len() > 2 {
                            adverts.pop_front();
                        }
                        log::info!(
                            "Advertising rotating PIN on the local network (refreshes in {}s)",
                            crate::pin::BUCKET_SECS
                        );
                    }
                    // On the LAN-only channel the advertisement IS the
                    // rendezvous — a shown PIN nobody can resolve must fail
                    // loudly (e.g. iOS denying the registration until Local
                    // Network permission is granted). The default channel
                    // still has nostr carrying the record, so a warn will do.
                    Err(e) if matches!(channel, PinChannel::LanOnly) => {
                        events.error(format!(
                            "Could not publish the PIN on the local network: {e:#}"
                        ));
                    }
                    Err(e) => log::warn!("Failed to advertise PIN on the local network: {e:#}"),
                }
                // LAN-only also serves the record over the unicast side channel
                // (manual-IP path). It rides alongside mDNS, so a bind failure
                // (e.g. a rare derived-port collision) only warns — mDNS still
                // carries the rendezvous for joiners on this network.
                if matches!(channel, PinChannel::LanOnly) {
                    match crate::lan::unicast_advertise_pin_record(&keys, &node_id, &addrs).await {
                        Ok(listener) => {
                            unicast.push_back(listener);
                            while unicast.len() > 2 {
                                unicast.pop_front();
                            }
                        }
                        Err(e) => {
                            log::warn!("Failed to start the manual-IP side channel: {e:#}")
                        }
                    }
                }
            }
            if channel.nostr() {
                match crate::nostr::publish_pin_record(&keys, &node_id, &relays).await {
                    Ok(()) => log::info!(
                        "Published rotating PIN to nostr (refreshes in {}s)",
                        crate::pin::BUCKET_SECS
                    ),
                    Err(e) => log::warn!("Failed to publish PIN to nostr: {e:#}"),
                }
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
                // dropping the advert guards withdraws the mDNS records (old
                // nostr records just age out — resolving one only leads to an
                // auth rejection).
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
                    "Authentication rejected by the peer — wrong token/PIN, or it is still \
                     paired with a previous session (Stop and Start the server to re-pair)"
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

/// Authenticate as the dialer with a pre-shared token. On success the opened
/// stream is returned (send side *not* finished): the same stream carries the
/// clipboard afterward.
async fn auth_as_dialer(conn: &iroh::endpoint::Connection, auth_token: &str) -> Result<Bi> {
    // Opening the stream and sending the request can fail if the listener has
    // already closed the connection (e.g. a BUSY refusal, which the listener
    // sends without ever accepting a stream). Surface that as the fatal reason
    // it is, rather than a generic transport error the client would retry on.
    let opened = async {
        let (mut send, recv) = conn.open_bi().await.context("opening session stream")?;
        let request = AuthRequest::new(auth_token);
        send.write_all(&encode_auth_request(&request)?).await?;
        Ok::<Bi, anyhow::Error>((send, recv))
    };
    let (send, mut recv) = match opened.await {
        Ok(streams) => streams,
        Err(e) => {
            if let Some(reason) = auth_close_reason(conn) {
                return Err(auth_failure(reason));
            }
            return Err(e);
        }
    };

    let response_bytes = match tokio::time::timeout(
        AUTH_TIMEOUT,
        read_length_prefixed(&mut recv, MAX_CONTROL_MESSAGE_SIZE),
    )
    .await
    {
        Err(_) => return Err(auth_failure("Auth response timed out")),
        Ok(Err(e)) => {
            // The response never arrived; if the peer closed with an auth code,
            // surface that as the fatal auth failure it is.
            if let Some(reason) = auth_close_reason(conn) {
                return Err(auth_failure(reason));
            }
            return Err(e.context("Failed to read auth response"));
        }
        Ok(Ok(bytes)) => bytes,
    };
    let response = decode_auth_response(&response_bytes).context("Invalid auth response")?;

    if !response.accepted {
        let reason = response.reason.unwrap_or_else(|| "Unknown".to_string());
        return Err(auth_failure(format!("Authentication rejected: {reason}")));
    }

    log::info!("Authenticated with peer successfully");
    Ok((send, recv))
}

/// Authenticate as the dialer using the quick-mode PIN (in-band challenge-response). No token
/// crosses the wire. The whole exchange is bounded by [`AUTH_TIMEOUT`] and any failure is an
/// [`AuthFailure`] — fatal for this target, exactly like a wrong token. On success the opened
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

/// Authenticate as the listener. Accepts either a pre-shared token or (PIN mode) a PIN proof;
/// `pin_cache` holds the recent-bucket PIN keys and is `None` outside PIN mode.
///
/// `claim` enforces the one-pair-at-a-time rule across all modes: if another node id already
/// holds the claim this peer is refused up front; otherwise a successful handshake commits this
/// peer as the pair. The claimed peer may reconnect freely — its own node id always passes the
/// gate, and in PIN mode the key it paired with is added to the candidate set so its proof
/// still verifies after the PIN has rotated out of `pin_cache`.
async fn auth_as_listener(
    conn: &iroh::endpoint::Connection,
    auth_tokens: &HashSet<String>,
    pin_cache: Option<&RecentPins>,
    claim: &PairClaim,
    own_id: iroh::EndpointId,
) -> Result<Bi> {
    let remote_id = conn.remote_id();

    // Pre-auth gate: this endpoint pairs with one peer at a time. `existing` is the current
    // claim; if it belongs to a different node id we still run the handshake (so the dialer
    // gets a proper rejection instead of a bare connection drop) but with no valid credentials,
    // guaranteeing it fails. If it belongs to this peer, `reconnect_key` lets its rotated PIN
    // still verify.
    let existing = claim.peek();
    let claimed_by_other = existing.as_ref().is_some_and(|c| c.node_id != remote_id);
    let reconnect_key = existing
        .as_ref()
        .filter(|c| c.node_id == remote_id)
        .and_then(|c| c.pin_key.clone());
    if claimed_by_other {
        log::warn!("Refusing {remote_id}: already paired with another device");
    }

    // Auth runs on the single session stream; on success that same stream (send
    // side left open) is returned for the clipboard. Rejection paths finish the
    // send side to flush the reason before the connection is closed below.
    let auth_result = tokio::time::timeout(AUTH_TIMEOUT, async {
        let (mut send, mut recv) = conn
            .accept_bi()
            .await
            .context("Failed to accept session stream")?;

        let request_bytes = read_length_prefixed(&mut recv, MAX_CONTROL_MESSAGE_SIZE)
            .await
            .context("Failed to read auth request")?;
        match decode_auth_request(&request_bytes).context("Invalid auth request")? {
            AuthRequest::Token { auth_token, .. } => {
                if claimed_by_other || !is_token_valid(auth_token.as_str(), auth_tokens) {
                    let reason = if claimed_by_other {
                        "Already paired with another device"
                    } else {
                        log::warn!("Invalid auth token from {remote_id}");
                        "Invalid authentication token"
                    };
                    let response = AuthResponse::rejected(reason);
                    send.write_all(&encode_auth_response(&response)?).await?;
                    send.finish()?;
                    anyhow::bail!("{reason}");
                }
                // Win the one-pair claim *before* telling the dialer it is accepted, so a race
                // loser is rejected rather than briefly told "accepted" and then dropped.
                if !claim.commit(remote_id, None) {
                    let response =
                        AuthResponse::rejected("Already paired with another device");
                    send.write_all(&encode_auth_response(&response)?).await?;
                    send.finish()?;
                    anyhow::bail!("another device paired first");
                }
                let response = AuthResponse::accepted();
                send.write_all(&encode_auth_response(&response)?).await?;
                Ok::<Bi, anyhow::Error>((send, recv))
            }
            AuthRequest::Pin { nonce, .. } => {
                // Verify the dialer's PIN proof against the recent-bucket keys, plus (for a
                // reconnecting paired peer) the key it originally paired with. An empty
                // candidate set — a non-PIN listener, or a peer refused by the gate — yields a
                // clean rejection.
                let mut candidates = if claimed_by_other {
                    Vec::new()
                } else {
                    pin_cache.map(|c| c.snapshot()).unwrap_or_default()
                };
                if let Some(key) = &reconnect_key {
                    candidates.push(key.clone());
                }
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
                    |key| claim.commit(remote_id, Some(key.clone())),
                )
                .await?;
                log::info!("Peer {remote_id} authenticated via PIN");
                Ok((send, recv))
            }
        }
    })
    .await;

    match auth_result {
        Ok(Ok(streams)) => Ok(streams),
        Ok(Err(e)) => {
            conn.close(AUTH_FAILED_CODE.into(), b"auth_failed");
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

    /// A refresh request rotates the PIN immediately instead of waiting out
    /// the current period, and the replacement is a different code.
    #[tokio::test(flavor = "multi_thread")]
    async fn refresh_pin_rotates_immediately() {
        let _ = env_logger::builder().is_test(true).try_init();

        let (tx, rx) = std::sync::mpsc::channel();
        let events = EventSender::new(tx, None);
        let session = start_session(
            SessionKind::Server(ServerMode::Pin {
                relays: Vec::new(),
                channel: PinChannel::LanOnly,
            }),
            events,
            None,
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
            .expect("PIN server sessions expose a refresh handle")
            .notify_one();

        // Far sooner than the rotation period (BUCKET_SECS), so only the
        // refresh can explain a new PIN arriving now.
        let second = wait_for_event(&rx, Duration::from_secs(20), pin_rotated);
        assert_ne!(first, second, "refresh must mint a different PIN");

        session.cancel.cancel();
        let _ = session.handle.await;
    }

    /// Stopping the presence publisher returns promptly even while it is in
    /// the middle of a nostr round-trip (here: a publish hanging on an
    /// unroutable relay). The iOS FFI's stop — and with it the app's screen
    /// transition away from the hub — blocks on this task ending, so a relay
    /// round-trip must never be waited out.
    #[tokio::test(flavor = "multi_thread")]
    async fn stopping_presence_mid_publish_is_prompt() {
        let _ = env_logger::builder().is_test(true).try_init();

        let (tx, _rx) = std::sync::mpsc::channel();
        let events = EventSender::new(tx, None);
        let hosting: HostingTx = Arc::new(tokio::sync::watch::channel(None).0);
        let identity = TokenIdentity {
            token: "test-token".to_string(),
            name: "test".to_string(),
            suffix: "a7B2c3D4".to_string(),
            // TEST-NET-1: unroutable, so the first publish hangs in its
            // connect wait (CONNECT_TIMEOUT is 10s) when the stop lands.
            relays: vec!["wss://192.0.2.1".to_string()],
        };
        let mut presence = Some(spawn_presence(identity, &hosting, events));

        // Let the publisher enter the publish's connect wait.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let start = Instant::now();
        stop_presence(&mut presence).await;
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "stop_presence took {:?} — the publish round-trip was waited out",
            start.elapsed()
        );
    }

    /// End-to-end LAN-only PIN mode within one process: the server advertises
    /// the rotating PIN's rendezvous record over DNS-SD (no nostr at all), the
    /// client resolves it from the displayed PIN alone — including the direct
    /// addresses it dials explicitly — pairs via the in-band PIN handshake,
    /// and both sides exchange one clipboard item.
    #[tokio::test(flavor = "multi_thread")]
    async fn lan_pin_mode_pairs_and_exchanges_items() {
        let _ = env_logger::builder().is_test(true).try_init();

        let (srv_tx, srv_rx) = std::sync::mpsc::channel();
        let srv_session = start_session(
            SessionKind::Server(ServerMode::Pin {
                relays: Vec::new(),
                channel: PinChannel::LanOnly,
            }),
            EventSender::new(srv_tx, None),
            None,
        );

        // The displayed PIN is all the joining user gets to type.
        let pin_display = wait_for_event(&srv_rx, Duration::from_secs(30), |ev| {
            if let NetEvent::PinRotated { pin_display, .. } = ev {
                Some(pin_display.clone())
            } else {
                None
            }
        });
        let canonical_pin =
            crate::pin::normalize_pin(&pin_display).expect("displayed PIN is valid");

        let (cli_tx, cli_rx) = std::sync::mpsc::channel();
        let cli_session = start_session(
            SessionKind::Client(DialSpec::Pin {
                canonical_pin,
                relays: Vec::new(),
                channel: PinChannel::LanOnly,
                target_ip: None,
            }),
            EventSender::new(cli_tx, None),
            None,
        );

        // Both sides pair; pairing clears the displayed PIN on the server.
        wait_for_event(&cli_rx, Duration::from_secs(120), |ev| {
            matches!(ev, NetEvent::Status(ConnStatus::Connected)).then_some(())
        });
        wait_for_event(&srv_rx, Duration::from_secs(30), |ev| {
            matches!(ev, NetEvent::PinCleared).then_some(())
        });

        // Client -> server.
        cli_session
            .clip_tx
            .send("from the client".to_string())
            .unwrap();
        let text = wait_for_event(&srv_rx, Duration::from_secs(15), |ev| {
            if let NetEvent::ItemReceived { text, .. } = ev {
                Some(text.clone())
            } else {
                None
            }
        });
        assert_eq!(text, "from the client");

        // Server -> client.
        srv_session
            .clip_tx
            .send("from the server".to_string())
            .unwrap();
        let text = wait_for_event(&cli_rx, Duration::from_secs(15), |ev| {
            if let NetEvent::ItemReceived { text, .. } = ev {
                Some(text.clone())
            } else {
                None
            }
        });
        assert_eq!(text, "from the server");

        let mut cli = Some(cli_session);
        let mut srv = Some(srv_session);
        stop_session(&mut cli).await;
        stop_session(&mut srv).await;
    }

    /// End-to-end LAN-only PIN mode via the manual-IP unicast side channel: the
    /// joiner supplies a `target_ip`, so discovery bypasses mDNS entirely and
    /// fetches the PIN-encrypted record over TCP from the host's IP (here
    /// loopback). The record carries the host's direct addresses, which the
    /// joiner then dials — the whole point being pairing where multicast is
    /// blocked.
    #[tokio::test(flavor = "multi_thread")]
    async fn lan_pin_mode_pairs_over_the_unicast_side_channel() {
        let _ = env_logger::builder().is_test(true).try_init();

        let (srv_tx, srv_rx) = std::sync::mpsc::channel();
        let srv_session = start_session(
            SessionKind::Server(ServerMode::Pin {
                relays: Vec::new(),
                channel: PinChannel::LanOnly,
            }),
            EventSender::new(srv_tx, None),
            None,
        );
        let pin_display = wait_for_event(&srv_rx, Duration::from_secs(30), |ev| {
            if let NetEvent::PinRotated { pin_display, .. } = ev {
                Some(pin_display.clone())
            } else {
                None
            }
        });
        let canonical_pin =
            crate::pin::normalize_pin(&pin_display).expect("displayed PIN is valid");

        let (cli_tx, cli_rx) = std::sync::mpsc::channel();
        let cli_session = start_session(
            SessionKind::Client(DialSpec::Pin {
                canonical_pin,
                relays: Vec::new(),
                channel: PinChannel::LanOnly,
                // The host serves the unicast side channel on all interfaces, so
                // loopback reaches it on the same machine.
                target_ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            }),
            EventSender::new(cli_tx, None),
            None,
        );

        wait_for_event(&cli_rx, Duration::from_secs(120), |ev| {
            matches!(ev, NetEvent::Status(ConnStatus::Connected)).then_some(())
        });
        wait_for_event(&srv_rx, Duration::from_secs(30), |ev| {
            matches!(ev, NetEvent::PinCleared).then_some(())
        });

        cli_session
            .clip_tx
            .send("over the side channel".to_string())
            .unwrap();
        let text = wait_for_event(&srv_rx, Duration::from_secs(15), |ev| {
            if let NetEvent::ItemReceived { text, .. } = ev {
                Some(text.clone())
            } else {
                None
            }
        });
        assert_eq!(text, "over the side channel");

        let mut cli = Some(cli_session);
        let mut srv = Some(srv_session);
        stop_session(&mut cli).await;
        stop_session(&mut srv).await;
    }

    /// After an interrupted connection resumes, each side pulls the other's
    /// latest sent item (surfaced with `pulled: true` for UI deduplication).
    #[tokio::test(flavor = "multi_thread")]
    async fn resume_pulls_latest_from_both_sides() {
        let _ = env_logger::builder().is_test(true).try_init();

        let (srv_tx, srv_rx) = std::sync::mpsc::channel();
        let srv_session = start_session(
            SessionKind::Server(ServerMode::Pin {
                relays: Vec::new(),
                channel: PinChannel::LanOnly,
            }),
            EventSender::new(srv_tx, None),
            None,
        );
        let pin_display = wait_for_event(&srv_rx, Duration::from_secs(30), |ev| {
            if let NetEvent::PinRotated { pin_display, .. } = ev {
                Some(pin_display.clone())
            } else {
                None
            }
        });
        let canonical_pin =
            crate::pin::normalize_pin(&pin_display).expect("displayed PIN is valid");

        let (cli_tx, cli_rx) = std::sync::mpsc::channel();
        let cli_session = start_session(
            SessionKind::Client(DialSpec::Pin {
                canonical_pin,
                relays: Vec::new(),
                channel: PinChannel::LanOnly,
                target_ip: None,
            }),
            EventSender::new(cli_tx, None),
            None,
        );
        wait_for_event(&cli_rx, Duration::from_secs(60), |ev| {
            matches!(ev, NetEvent::Status(ConnStatus::Connected)).then_some(())
        });

        // One item each way, so both sessions hold a last-sent.
        srv_session.clip_tx.send("server latest".to_string()).unwrap();
        cli_session.clip_tx.send("client latest".to_string()).unwrap();
        wait_for_event(&cli_rx, Duration::from_secs(15), |ev| {
            matches!(ev, NetEvent::ItemReceived { pulled: false, .. }).then_some(())
        });
        wait_for_event(&srv_rx, Duration::from_secs(15), |ev| {
            matches!(ev, NetEvent::ItemReceived { pulled: false, .. }).then_some(())
        });

        // Interrupt: kill the live connection out from under both pumps. Both
        // sessions stay up; the client auto-reconnects to the same node id.
        let conn = srv_session.conn.lock().clone().expect("paired connection");
        conn.close(0u32.into(), b"test interruption");

        // On resume each side pulls the other's latest.
        let text = wait_for_event(&cli_rx, Duration::from_secs(60), |ev| {
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

        let mut cli = Some(cli_session);
        let mut srv = Some(srv_session);
        stop_session(&mut cli).await;
        stop_session(&mut srv).await;
    }

    /// A second device dialing a server that is already pairing with someone
    /// else is refused promptly with a fatal "busy" error (a `SERVER_BUSY`
    /// close), not left hanging in the reconnect loop. Both devices reach the
    /// server via the LAN-only unicast side channel (loopback), started
    /// concurrently — discovery is withdrawn once a peer pairs, so both must
    /// fetch the record before either pairing completes. The server pairs
    /// whichever authenticates first and refuses the other; the test is
    /// order-agnostic about which wins.
    #[tokio::test(flavor = "multi_thread")]
    async fn busy_server_refuses_a_third_device() {
        let _ = env_logger::builder().is_test(true).try_init();

        // Server.
        let (srv_tx, srv_rx) = std::sync::mpsc::channel();
        let srv_session = start_session(
            SessionKind::Server(ServerMode::Pin {
                relays: Vec::new(),
                channel: PinChannel::LanOnly,
            }),
            EventSender::new(srv_tx, None),
            None,
        );
        let pin_display = wait_for_event(&srv_rx, Duration::from_secs(30), |ev| {
            if let NetEvent::PinRotated { pin_display, .. } = ev {
                Some(pin_display.clone())
            } else {
                None
            }
        });
        let canonical_pin =
            crate::pin::normalize_pin(&pin_display).expect("displayed PIN is valid");
        let dial = || DialSpec::Pin {
            canonical_pin: canonical_pin.clone(),
            relays: Vec::new(),
            channel: PinChannel::LanOnly,
            target_ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        };

        // Both devices dial concurrently — both fetch the record before either
        // pairing completes (the pairing handshake far outlasts a loopback fetch).
        let (a_tx, a_rx) = std::sync::mpsc::channel();
        let a_session = start_session(SessionKind::Client(dial()), EventSender::new(a_tx, None), None);
        let (b_tx, b_rx) = std::sync::mpsc::channel();
        let b_session = start_session(SessionKind::Client(dial()), EventSender::new(b_tx, None), None);

        // Exactly one pairs; the other is turned away as busy. Watch both.
        let start = Instant::now();
        let (mut connected, mut busy) = (false, false);
        while start.elapsed() < Duration::from_secs(90) && !(connected && busy) {
            for rx in [&a_rx, &b_rx] {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(NetEvent::Status(ConnStatus::Connected)) => connected = true,
                    Ok(NetEvent::Error(e)) if e.contains("another device") => busy = true,
                    Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        }
        assert!(connected, "one device must pair");
        assert!(busy, "the other device must be refused as busy");

        let mut a = Some(a_session);
        let mut b = Some(b_session);
        let mut srv = Some(srv_session);
        stop_session(&mut a).await;
        stop_session(&mut b).await;
        stop_session(&mut srv).await;
    }

    /// A peer-list refresh before any presence identity is configured must
    /// answer with an actionable error instead of silently doing nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn refresh_peers_without_presence_yields_error() {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (ev_tx, ev_rx) = std::sync::mpsc::channel();
        let main = tokio::spawn(net_main(cmd_rx, EventSender::new(ev_tx, None)));

        cmd_tx.send(UiCommand::RefreshPeers).unwrap();
        let err = wait_for_event(&ev_rx, Duration::from_secs(5), |ev| {
            if let NetEvent::Error(e) = ev {
                Some(e.clone())
            } else {
                None
            }
        });
        assert!(
            err.contains("secret"),
            "expected a setup hint, got: {err}"
        );

        cmd_tx.send(UiCommand::Shutdown).unwrap();
        let _ = main.await;
    }
}
