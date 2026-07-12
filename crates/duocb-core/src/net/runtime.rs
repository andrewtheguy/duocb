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
use iroh::EndpointId;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::auth::is_token_valid;
use crate::net::endpoint::{
    connect_to_server, connection_paths, create_client_endpoint, create_server_endpoint,
    watch_connection_paths,
};
use crate::net::{
    ConnStatus, DialSpec, EventSender, NetEvent, ServerMode, TokenIdentity, UiCommand,
};
use crate::protocol::{
    AuthRequest, AuthResponse, ClipBody, ClipMsg, MAX_CLIP_MESSAGE_SIZE,
    MAX_CONTROL_MESSAGE_SIZE, decode_auth_request, decode_auth_response, decode_clip_msg,
    encode_auth_request, encode_auth_response, encode_clip_msg, read_length_prefixed,
};

/// How many recent buckets' PIN keys the server retains for in-band PIN auth. Mirrors the
/// client's adjacent-bucket look-back in `nostr::lookup_pin_record`.
const RECENT_PIN_CACHE: usize = 3;

/// Timeout for the authentication handshake.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Connection close code for authentication failure (invalid token/PIN).
const AUTH_FAILED_CODE: u32 = 1;

/// Connection close code for authentication timeout (no auth within deadline).
const AUTH_TIMEOUT_CODE: u32 = 2;

/// Connection close code for a clean local shutdown/disconnect. "No error" by
/// convention; the peer just sees the connection go away.
const SHUTDOWN_CODE: u32 = 0;

/// Maximum reconnect backoff for the dialing peer.
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(30);

/// Maximum number of attempts to establish the *first* connection before giving
/// up. Once a connection has been established at least once, the client
/// reconnects without limit. This bounds the startup phase so an unreachable
/// peer fails fast instead of looping forever.
const MAX_INITIAL_CONNECT_ATTEMPTS: u32 = 10;

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

/// Recent PIN auth keypairs (newest first), one per rotation bucket the quick-mode server has
/// published. Written by the PIN publisher, read by the listener auth path to verify a dialer's
/// proof. Cheap to clone (shared handle).
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
}

fn start_session(kind: SessionKind, events: EventSender, hosting: Option<HostingTx>) -> Session {
    let cancel = CancellationToken::new();
    let (clip_tx, clip_rx) = mpsc::unbounded_channel();
    let task_cancel = cancel.clone();
    let conn: ConnSlot = Arc::new(parking_lot::Mutex::new(None));
    let task_conn = conn.clone();
    let handle = tokio::spawn(async move {
        let last_sent = LastSent::default();
        match kind {
            SessionKind::Server(mode) => {
                run_server_session(
                    mode, events, task_cancel, clip_rx, task_conn, last_sent, hosting,
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

async fn run_server_session(
    mode: ServerMode,
    events: EventSender,
    cancel: CancellationToken,
    mut clip_rx: mpsc::UnboundedReceiver<String>,
    conn_slot: ConnSlot,
    last_sent: LastSent,
    hosting: Option<HostingTx>,
) {
    events.status(ConnStatus::Starting);

    let endpoint = match create_server_endpoint().await {
        Ok(ep) => ep,
        Err(e) => {
            events.error(format!("Failed to start: {e:#}"));
            events.status(ConnStatus::Idle);
            return;
        }
    };
    let node_id = endpoint.id();

    // Tokens accepted from clients. Manual mode mints a fresh ephemeral token
    // here and surfaces it in the UI for the user to hand to the client; PIN
    // mode accepts no tokens (only PIN proofs).
    let (tokens, manual_token): (HashSet<String>, Option<String>) = match &mode {
        ServerMode::Manual => {
            let token = crate::auth::generate_token();
            (HashSet::from([token.clone()]), Some(token))
        }
        ServerMode::NostrToken { identity } => (HashSet::from([identity.token.clone()]), None),
        ServerMode::NostrPin { .. } => (HashSet::new(), None),
    };
    let token_fingerprint = tokens
        .iter()
        .next()
        .map(|t| crate::auth::token_fingerprint(t));
    events.send(NetEvent::ServerReady {
        node_id: node_id.to_string(),
        manual_token,
        token_fingerprint,
    });
    events.status(ConnStatus::Listening);

    // One pairing per server session (all modes). The claim is empty until the
    // first client authenticates and lives until the server is stopped.
    let claim = PairClaim::default();
    let recent_pins = RecentPins::default();
    let pin_cache = matches!(mode, ServerMode::NostrPin { .. }).then(|| recent_pins.clone());

    // Configure mode: mark this device as hosting for the session's lifetime.
    // The standing presence publisher (owned by the command loop) picks the
    // node id up from the watch channel and republishes; the guard's drop
    // clears it on every exit path.
    let _hosting_guard = hosting.map(|tx| HostingGuard::new(tx, node_id));

    // Mode-specific signaling publisher, aborted on session teardown.
    let _publisher: Option<PublisherGuard> = match &mode {
        ServerMode::NostrToken { .. } => None,
        ServerMode::NostrPin { relays } => Some(PublisherGuard(tokio::spawn(run_pin_publisher(
            node_id,
            recent_pins,
            relays.clone(),
            events.clone(),
            cancel.clone(),
            claim.paired_signal(),
        )))),
        ServerMode::Manual => None,
    };

    // Accept loop: one connection served at a time (duocb pairs two devices).
    // While a clipboard session is live we don't accept further connections; a
    // reconnecting paired peer retries and gets through once the dead
    // connection is torn down. The claim gate refuses any other node id.
    loop {
        let incoming = tokio::select! {
            _ = cancel.cancelled() => break,
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => {
                    log::info!("Endpoint closed");
                    break;
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
        let remote_id = conn.remote_id();
        log::info!("Peer connected: {remote_id} (awaiting auth)");
        events.status(ConnStatus::Authenticating);

        // Auth runs on the single session stream; on success the same stream
        // stays open for clipboard frames (no separate data stream / handshake).
        let (send, recv) = match auth_as_listener(&conn, &tokens, pin_cache.as_ref(), &claim).await
        {
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
        match pump_clipboard(send, recv, &events, &mut clip_rx, &cancel, &last_sent).await {
            Ok(()) => log::info!("Clipboard session with {remote_id} ended"),
            Err(e) => log::warn!("Clipboard session with {remote_id} ended: {e:#}"),
        }
        *conn_slot.lock() = None;

        if cancel.is_cancelled() {
            conn.close(SHUTDOWN_CODE.into(), b"shutdown");
            break;
        }
        events.send(NetEvent::PeerDisconnected);
        events.status(ConnStatus::Listening);
    }

    endpoint.close().await;
    log::info!("Server session stopped");
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

    // A manually typed node id is parsed once up front: if it's malformed it
    // will never work, so fail the session immediately.
    let manual_id: Option<EndpointId> = match &spec {
        DialSpec::Manual { node_id, .. } => match node_id.trim().parse() {
            Ok(id) => Some(id),
            Err(e) => {
                events.error(format!("Invalid node id: {e}"));
                events.status(ConnStatus::Idle);
                return;
            }
        },
        _ => None,
    };

    let endpoint = match create_client_endpoint().await {
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
        DialSpec::Pin { .. } | DialSpec::Manual { .. } => None,
    };
    events.send(NetEvent::ClientReady {
        node_id: own_id.to_string(),
        token_fingerprint,
    });

    let mut backoff = Duration::from_secs(1);
    let mut attempts: u32 = 0;
    let mut connected_once = false;
    // For a PIN target: the node id resolved on the first successful pairing.
    // Reused on every reconnect thereafter — the typed PIN has since rotated
    // off the relay (so a fresh lookup would fail), but the server retains our
    // pairing key, so we reconnect by node id and re-prove the same PIN in-band
    // without the user re-typing a code.
    let mut pinned_pin_id: Option<EndpointId> = None;

    loop {
        // Resolve the target each attempt: configure mode re-queries the chosen
        // peer's presence record, so a restarted host's fresh node id is found.
        let resolved: Result<EndpointId> = match &spec {
            DialSpec::Manual { .. } => Ok(manual_id.expect("validated above")),
            DialSpec::NostrToken {
                identity,
                peer_display,
            } => {
                events.status(ConnStatus::Resolving);
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    r = crate::nostr::lookup_presence(&identity.token, peer_display, &identity.relays) => match r {
                        Ok(Some((record, _))) => match record.node_id {
                            Some(id) => id
                                .trim()
                                .parse::<EndpointId>()
                                .context("the peer's presence record holds an invalid node id"),
                            None => Err(anyhow::anyhow!(
                                "'{peer_display}' is not hosting a connection — press Start on that device"
                            )),
                        },
                        Ok(None) => Err(anyhow::anyhow!(
                            "no presence record found for '{peer_display}' — is it running with the same secret?"
                        )),
                        Err(e) => Err(e.context("nostr presence lookup failed")),
                    },
                }
            }
            DialSpec::Pin { .. } if pinned_pin_id.is_some() => Ok(pinned_pin_id.unwrap()),
            DialSpec::Pin {
                canonical_pin,
                relays,
            } => {
                events.status(ConnStatus::Resolving);
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    r = crate::nostr::lookup_pin_record(canonical_pin, relays) => match r {
                        Ok(Some(id)) => Ok(id),
                        Ok(None) => Err(anyhow::anyhow!(
                            "no peer found for that PIN (it refreshes every 60s — check the current code on the other device)"
                        )),
                        Err(e) => Err(e.context("nostr PIN lookup failed")),
                    },
                }
            }
        };

        // Self-dial guard: end the session — the target won't change.
        if let Ok(id) = &resolved
            && *id == own_id
        {
            events.error("That is this device's own node id — enter the other device's id");
            events.status(ConnStatus::Idle);
            endpoint.close().await;
            return;
        }
        let attempt_id = resolved.as_ref().ok().copied();

        let connect = match resolved {
            Ok(id) => {
                events.status(ConnStatus::Connecting);
                tokio::select! {
                    _ = cancel.cancelled() => { endpoint.close().await; return; }
                    c = connect_to_server(&endpoint, id) => c,
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
                    DialSpec::Manual { token, .. } => auth_as_dialer(&conn, token).await,
                    DialSpec::NostrToken { identity, .. } => {
                        auth_as_dialer(&conn, &identity.token).await
                    }
                    DialSpec::Pin { canonical_pin, .. } => {
                        auth_as_dialer_pin(&conn, canonical_pin).await
                    }
                };
                match auth_result {
                    Ok((send, recv)) => {
                        // Auth succeeded, so the server has committed us as its pair and
                        // (PIN mode) stopped publishing PINs. Pin the node id NOW so
                        // reconnects dial this id — a fresh relay lookup could never
                        // succeed again.
                        if matches!(spec, DialSpec::Pin { .. }) && pinned_pin_id.is_none() {
                            pinned_pin_id = attempt_id;
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
                        connected_once = true;
                        attempts = 0;
                        backoff = Duration::from_secs(1);

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

        // Backoff before the next attempt. Before the first successful
        // connection, a bounded number of attempts; afterwards, unlimited.
        if !connected_once {
            attempts += 1;
            if attempts >= MAX_INITIAL_CONNECT_ATTEMPTS {
                events.error(format!(
                    "Could not reach the peer after {MAX_INITIAL_CONNECT_ATTEMPTS} attempts"
                ));
                events.status(ConnStatus::Idle);
                endpoint.close().await;
                return;
            }
        }
        events.status(ConnStatus::Reconnecting {
            backoff_secs: backoff.as_secs(),
        });
        tokio::select! {
            _ = cancel.cancelled() => { endpoint.close().await; return; }
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(MAX_RECONNECT_BACKOFF);
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
        if publishes > 0 {
            match crate::nostr::lookup_presence(&identity.token, &display, &identity.relays).await
            {
                Ok(Some((record, _))) if record.run_id != run_id => {
                    events.send(NetEvent::PresenceConflict {
                        message: format!(
                            "Another process is broadcasting as '{display}' — stopped publishing \
                             presence. Is a second instance using this device's config?"
                        ),
                    });
                    return;
                }
                // Our own record, no record, or a network error: nothing provable.
                _ => {}
            }
        }

        let record = crate::nostr::PresenceRecord {
            version: crate::nostr::PRESENCE_VERSION,
            name: identity.name.clone(),
            suffix: identity.suffix.clone(),
            run_id: run_id.clone(),
            node_id: hosting_rx.borrow_and_update().map(|id| id.to_string()),
        };
        match crate::nostr::publish_presence(&identity.token, &record, &identity.relays).await {
            Ok(()) => log::info!("Published presence to nostr"),
            Err(e) => log::warn!("Failed to publish presence to nostr: {e:#}"),
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

/// PIN quick mode publisher: mint a fresh PIN each rotation period (measured
/// from when the PIN is shown, not from wall-clock bucket boundaries), publish
/// the node-id record under it, and surface the PIN + countdown to the UI.
/// Each bucket's PIN auth key is recorded in `recent` so the listener auth path
/// can verify a dialer's proof. Stops (and clears the displayed PIN) once a
/// peer pairs — no more peers are accepted this session.
async fn run_pin_publisher(
    node_id: EndpointId,
    recent: RecentPins,
    relays: Vec<String>,
    events: EventSender,
    cancel: CancellationToken,
    paired: CancellationToken,
) {
    loop {
        // A peer may already have paired (e.g. a reconnect landed before this
        // loop turn). Publishing a fresh PIN would be pointless and misleading.
        if paired.is_cancelled() {
            events.send(NetEvent::PinCleared);
            break;
        }

        let pin = crate::pin::generate_pin();
        let bucket = crate::pin::current_bucket();
        // Show the new code right away (before the network publish) and give it a
        // full rotation period from *now*, not from the wall-clock bucket boundary:
        // a PIN minted late in a bucket would otherwise flash for only a few
        // seconds. The dialer's adjacent-bucket look-back (and the record TTL)
        // keeps the code resolvable for the whole displayed window even when it
        // straddles a boundary.
        let shown_at = tokio::time::Instant::now();
        events.send(NetEvent::PinRotated {
            pin_display: crate::pin::format_pin(&pin),
            seconds_left: crate::pin::BUCKET_SECS,
        });

        // Record this bucket's PIN auth key so an inbound dialer holding this
        // PIN can be authenticated in-band, even after the code rotates. The
        // Argon2id derivation runs off the async executor.
        let derived = tokio::task::spawn_blocking({
            let pin = pin.clone();
            move || crate::pin_auth::derive_auth_keys(&pin)
        })
        .await;
        match derived {
            Ok(Ok(keys)) => recent.push(keys),
            Ok(Err(e)) => log::warn!("Failed to derive PIN auth key: {e:#}"),
            Err(e) => log::warn!("PIN key-derivation task failed: {e}"),
        }

        match crate::nostr::publish_pin_record(&pin, bucket, &node_id, &relays).await {
            Ok(()) => log::info!(
                "Published rotating PIN to nostr (refreshes in {}s)",
                crate::pin::BUCKET_SECS
            ),
            Err(e) => log::warn!("Failed to publish PIN to nostr: {e:#}"),
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
    let (mut send, mut recv) = conn.open_bi().await.context("opening session stream")?;

    let request = AuthRequest::new(auth_token);
    send.write_all(&encode_auth_request(&request)?).await?;

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
async fn auth_as_dialer_pin(conn: &iroh::endpoint::Connection, pin: &str) -> Result<Bi> {
    // One deadline over the whole exchange, including opening the stream — a
    // stalled open_bi must not delay the point where the timeout starts.
    let handshake = async {
        let (mut send, mut recv) = conn.open_bi().await.context("opening session stream")?;
        crate::pin_auth::dialer_handshake(&mut send, &mut recv, pin).await?;
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
                crate::pin_auth::listener_handshake(
                    &mut send,
                    &mut recv,
                    &candidates,
                    &nonce,
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

    /// End-to-end manual mode within one process: a server session and a client
    /// session pair over real iroh endpoints (discovery via mDNS/pkarr), then
    /// exchange one clipboard item in each direction.
    #[tokio::test(flavor = "multi_thread")]
    async fn manual_mode_pairs_and_exchanges_items() {
        let _ = env_logger::builder().is_test(true).try_init();

        // Server side.
        let (srv_tx, srv_rx) = std::sync::mpsc::channel();
        let srv_events = EventSender::new(srv_tx, None);
        let srv_session = start_session(SessionKind::Server(ServerMode::Manual), srv_events, None);

        let (node_id, token) = wait_for_event(&srv_rx, Duration::from_secs(30), |ev| {
            if let NetEvent::ServerReady {
                node_id,
                manual_token: Some(token),
                ..
            } = ev
            {
                Some((node_id.clone(), token.clone()))
            } else {
                None
            }
        });

        // Client side.
        let (cli_tx, cli_rx) = std::sync::mpsc::channel();
        let cli_events = EventSender::new(cli_tx, None);
        let cli_session = start_session(
            SessionKind::Client(DialSpec::Manual { node_id, token }),
            cli_events,
            None,
        );

        // Both sides report Connected.
        wait_for_event(&cli_rx, Duration::from_secs(60), |ev| {
            matches!(ev, NetEvent::Status(ConnStatus::Connected)).then_some(())
        });
        wait_for_event(&srv_rx, Duration::from_secs(30), |ev| {
            matches!(ev, NetEvent::Status(ConnStatus::Connected)).then_some(())
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

        // Teardown.
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
            SessionKind::Server(ServerMode::Manual),
            EventSender::new(srv_tx, None),
            None,
        );
        let (node_id, token) = wait_for_event(&srv_rx, Duration::from_secs(30), |ev| {
            if let NetEvent::ServerReady {
                node_id,
                manual_token: Some(token),
                ..
            } = ev
            {
                Some((node_id.clone(), token.clone()))
            } else {
                None
            }
        });

        let (cli_tx, cli_rx) = std::sync::mpsc::channel();
        let cli_session = start_session(
            SessionKind::Client(DialSpec::Manual { node_id, token }),
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

    /// A client presenting the wrong token is rejected with a fatal auth error.
    #[tokio::test(flavor = "multi_thread")]
    async fn manual_mode_rejects_wrong_token() {
        let _ = env_logger::builder().is_test(true).try_init();

        let (srv_tx, srv_rx) = std::sync::mpsc::channel();
        let srv_session = start_session(
            SessionKind::Server(ServerMode::Manual),
            EventSender::new(srv_tx, None),
            None,
        );
        let node_id = wait_for_event(&srv_rx, Duration::from_secs(30), |ev| {
            if let NetEvent::ServerReady { node_id, .. } = ev {
                Some(node_id.clone())
            } else {
                None
            }
        });

        let (cli_tx, cli_rx) = std::sync::mpsc::channel();
        let cli_session = start_session(
            SessionKind::Client(DialSpec::Manual {
                node_id,
                token: crate::auth::generate_token(), // not the server's token
            }),
            EventSender::new(cli_tx, None),
            None,
        );

        let err = wait_for_event(&cli_rx, Duration::from_secs(60), |ev| {
            if let NetEvent::Error(e) = ev {
                Some(e.clone())
            } else {
                None
            }
        });
        assert!(
            err.contains("rejected"),
            "expected an auth rejection, got: {err}"
        );

        let mut cli = Some(cli_session);
        let mut srv = Some(srv_session);
        stop_session(&mut cli).await;
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
