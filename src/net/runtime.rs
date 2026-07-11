//! The networking runtime: one command loop owning at most one session (server
//! or client), adapted from duopipe's peer runtime with the SOCKS payload
//! replaced by a single long-lived clipboard stream.
//!
//! Per connection (client = dialer):
//! 1. The client opens the auth stream and authenticates (token or PIN).
//! 2. The client opens the clipboard stream; both sides exchange a
//!    [`ClipMsg::Hello`], then pump [`ClipMsg::Item`] frames in both directions
//!    until the connection dies or the session is cancelled.

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
use crate::net::{ConnStatus, DialSpec, EventSender, NetEvent, ServerMode, UiCommand};
use crate::protocol::{
    AuthRequest, AuthResponse, ClipMsg, MAX_CLIP_MESSAGE_SIZE, MAX_CONTROL_MESSAGE_SIZE,
    decode_auth_request, decode_auth_response, decode_clip_msg, encode_auth_request,
    encode_auth_response, encode_clip_msg, read_length_prefixed,
};

/// How many recent buckets' PIN keys the server retains for in-band PIN auth. Mirrors the
/// client's adjacent-bucket look-back in `nostr::lookup_pin_record`.
const RECENT_PIN_CACHE: usize = 3;

/// Timeout for the authentication handshake.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for the clipboard stream's opening Hello exchange.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

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

/// Steady-state interval between node-id republishes (token mode). Replaceable
/// nostr events can be dropped by relays at varying times, so we refresh
/// periodically while listening.
const NODE_ID_REPUBLISH_INTERVAL: Duration = Duration::from_secs(300);

/// Interval for the initial republish burst: a second device launched against a
/// live name surfaces quickly instead of waiting a full republish interval.
const STARTUP_RECHECK_INTERVAL: Duration = Duration::from_secs(10);

/// Number of publish cycles that use [`STARTUP_RECHECK_INTERVAL`] before
/// settling into [`NODE_ID_REPUBLISH_INTERVAL`].
const STARTUP_RECHECK_CYCLES: u32 = 6;

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

/// A running server or client session: its cancel token, task handle, the
/// channel that feeds outbound clipboard items into the active connection, and
/// the shared connection slot for on-demand path queries.
struct Session {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
    clip_tx: mpsc::UnboundedSender<String>,
    conn: ConnSlot,
}

fn start_session(kind: SessionKind, events: EventSender) -> Session {
    let cancel = CancellationToken::new();
    let (clip_tx, clip_rx) = mpsc::unbounded_channel();
    let task_cancel = cancel.clone();
    let conn: ConnSlot = Arc::new(parking_lot::Mutex::new(None));
    let task_conn = conn.clone();
    let handle = tokio::spawn(async move {
        match kind {
            SessionKind::Server(mode) => {
                run_server_session(mode, events, task_cancel, clip_rx, task_conn).await
            }
            SessionKind::Client(spec) => {
                run_client_session(spec, events, task_cancel, clip_rx, task_conn).await
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
        let _ = s.handle.await;
    }
}

/// The runtime's main loop: consume UI commands until shutdown. At most one
/// session (server or client) runs at a time; starting a new one replaces the
/// current one.
pub async fn net_main(mut cmd_rx: mpsc::UnboundedReceiver<UiCommand>, events: EventSender) {
    let mut session: Option<Session> = None;

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            UiCommand::StartServer { mode } => {
                stop_session(&mut session).await;
                session = Some(start_session(SessionKind::Server(mode), events.clone()));
            }
            UiCommand::Connect { spec } => {
                stop_session(&mut session).await;
                session = Some(start_session(SessionKind::Client(spec), events.clone()));
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

async fn run_server_session(
    mode: ServerMode,
    events: EventSender,
    cancel: CancellationToken,
    mut clip_rx: mpsc::UnboundedReceiver<String>,
    conn_slot: ConnSlot,
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
        ServerMode::NostrToken { token, .. } => (HashSet::from([token.clone()]), None),
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

    // Mode-specific signaling publisher, aborted on session teardown.
    let _publisher: Option<PublisherGuard> = match &mode {
        ServerMode::NostrToken {
            token,
            name,
            relays,
        } => Some(PublisherGuard(tokio::spawn(run_node_id_publisher(
            token.clone(),
            name.clone(),
            node_id,
            relays.clone(),
            events.clone(),
            cancel.clone(),
        )))),
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

        match auth_as_listener(&conn, &tokens, pin_cache.as_ref(), &claim).await {
            Ok(()) => {}
            Err(e) => {
                log::warn!("Auth failed for {remote_id}: {e:#}");
                events.status(ConnStatus::Listening);
                continue;
            }
        }
        events.send(NetEvent::PeerPaired {
            peer_node_id: remote_id.to_string(),
        });

        // Debug-only path logging; on-demand status reads `conn_slot` directly.
        let _paths = watch_connection_paths(&conn);
        *conn_slot.lock() = Some(conn.clone());

        match serve_clip_connection(&conn, &events, &mut clip_rx, &cancel).await {
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

/// Server side of the clipboard stream: accept the client's post-auth stream,
/// answer its Hello, then pump items both ways.
async fn serve_clip_connection(
    conn: &iroh::endpoint::Connection,
    events: &EventSender,
    clip_rx: &mut mpsc::UnboundedReceiver<String>,
    cancel: &CancellationToken,
) -> Result<()> {
    let accept = async {
        let (mut send, mut recv) = conn
            .accept_bi()
            .await
            .context("accepting clipboard stream")?;
        let frame = read_length_prefixed(&mut recv, MAX_CLIP_MESSAGE_SIZE)
            .await
            .context("reading clipboard hello")?;
        match decode_clip_msg(&frame)? {
            ClipMsg::Hello { .. } => {}
            other => anyhow::bail!("expected Hello, got {other:?}"),
        }
        send.write_all(&encode_clip_msg(&ClipMsg::hello())?)
            .await
            .context("writing clipboard hello")?;
        Ok::<_, anyhow::Error>((send, recv))
    };
    let (send, recv) = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        r = tokio::time::timeout(HELLO_TIMEOUT, accept) => {
            r.context("timed out waiting for the clipboard stream")??
        }
    };

    events.status(ConnStatus::Connected);
    pump_clipboard(send, recv, events, clip_rx, cancel).await
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
        // Resolve the target each attempt: a nostr name re-resolves so a server
        // that restarted with a fresh ephemeral id self-heals on the next try.
        let resolved: Result<EndpointId> = match &spec {
            DialSpec::Manual { .. } => Ok(manual_id.expect("validated above")),
            DialSpec::NostrToken {
                token,
                peer_name,
                relays,
            } => {
                events.status(ConnStatus::Resolving);
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    r = crate::nostr::lookup_node_id(token, peer_name, relays) => r,
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
                let auth_result = match &spec {
                    DialSpec::Manual { token, .. } => auth_as_dialer(&conn, token).await,
                    DialSpec::NostrToken { token, .. } => auth_as_dialer(&conn, token).await,
                    DialSpec::Pin { canonical_pin, .. } => {
                        auth_as_dialer_pin(&conn, canonical_pin).await
                    }
                };
                match auth_result {
                    Ok(()) => {
                        // Auth succeeded, so the server has committed us as its pair and
                        // (PIN mode) stopped publishing PINs. Pin the node id NOW — even
                        // if opening the clipboard stream fails below, a fresh relay
                        // lookup could never succeed again; reconnects must dial this id.
                        if matches!(spec, DialSpec::Pin { .. }) && pinned_pin_id.is_none() {
                            pinned_pin_id = attempt_id;
                        }
                        match open_clip_stream(&conn).await {
                            Ok((send, recv)) => {
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

                                match pump_clipboard(send, recv, &events, &mut clip_rx, &cancel)
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
                            Err(e) => log::warn!("Failed to open clipboard stream: {e:#}"),
                        }
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

/// Client side of the clipboard stream: open it post-auth, send our Hello, and
/// wait for the server's.
async fn open_clip_stream(
    conn: &iroh::endpoint::Connection,
) -> Result<(iroh::endpoint::SendStream, iroh::endpoint::RecvStream)> {
    let open = async {
        let (mut send, mut recv) = conn.open_bi().await.context("opening clipboard stream")?;
        send.write_all(&encode_clip_msg(&ClipMsg::hello())?)
            .await
            .context("writing clipboard hello")?;
        let frame = read_length_prefixed(&mut recv, MAX_CLIP_MESSAGE_SIZE)
            .await
            .context("reading clipboard hello")?;
        match decode_clip_msg(&frame)? {
            ClipMsg::Hello { .. } => {}
            other => anyhow::bail!("expected Hello, got {other:?}"),
        }
        Ok((send, recv))
    };
    tokio::time::timeout(HELLO_TIMEOUT, open)
        .await
        .context("timed out opening the clipboard stream")?
}

// ============================================================================
// Clipboard pump (both roles)
// ============================================================================

/// Pump the established clipboard stream in both directions until the
/// connection dies, the session is cancelled, or the clip channel closes.
async fn pump_clipboard(
    mut qsend: iroh::endpoint::SendStream,
    mut qrecv: iroh::endpoint::RecvStream,
    events: &EventSender,
    clip_rx: &mut mpsc::UnboundedReceiver<String>,
    cancel: &CancellationToken,
) -> Result<()> {
    let writer = async {
        loop {
            let Some(text) = clip_rx.recv().await else {
                // Session dropped its sender: nothing more to send, ever.
                return Ok::<(), anyhow::Error>(());
            };
            match encode_clip_msg(&ClipMsg::item(text, now_ms())) {
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
                }
            }
        }
    };

    let reader = async {
        loop {
            let frame = read_length_prefixed(&mut qrecv, MAX_CLIP_MESSAGE_SIZE)
                .await
                .context("clipboard stream closed")?;
            match decode_clip_msg(&frame)? {
                ClipMsg::Item { text, .. } => events.send(NetEvent::ItemReceived { text }),
                ClipMsg::Hello { .. } => anyhow::bail!("unexpected Hello mid-stream"),
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
// Signaling publishers (server side)
// ============================================================================

/// Token mode: claim/refresh this device's name on nostr. On a conflict
/// (another device took the name over), stop publishing and surface an error —
/// the connection itself is unaffected.
async fn run_node_id_publisher(
    token: String,
    name: String,
    node_id: EndpointId,
    relays: Vec<String>,
    events: EventSender,
    cancel: CancellationToken,
) {
    let mut publishes: u32 = 0;
    loop {
        // After the first publish, check whether a live competitor overwrote our
        // record with a different node id. Startup deliberately does no lookup:
        // our own stale record from a previous run (a different ephemeral node
        // id) must not read as a conflict.
        if publishes > 0 {
            match crate::nostr::lookup_node_id_opt(&token, &name, &relays).await {
                Ok(Some(id)) if id != node_id => {
                    let short: String = id.to_string().chars().take(12).collect();
                    events.error(format!(
                        "Name '{name}' is now used by another device ({short}…); stopped publishing"
                    ));
                    return;
                }
                // Our own record, no record, or a network error: can't prove a
                // conflict, so just (re)publish.
                _ => {}
            }
        }

        match crate::nostr::publish_node_id(&token, &name, &node_id, &relays).await {
            Ok(()) => log::info!("Published node id to nostr for peer discovery"),
            Err(e) => log::warn!("Failed to publish node id to nostr: {e:#}"),
        }
        publishes = publishes.saturating_add(1);

        // Re-check quickly for the first few cycles, then settle to the slow cadence.
        let interval = if publishes <= STARTUP_RECHECK_CYCLES {
            STARTUP_RECHECK_INTERVAL
        } else {
            NODE_ID_REPUBLISH_INTERVAL
        };
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

/// PIN quick mode publisher: mint a fresh PIN each rotation period, publish the
/// node-id record under it, and surface the PIN + rollover countdown to the UI.
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
        let remaining = crate::pin::secs_until_next_bucket();
        // Show the new code right away (before the network publish).
        events.send(NetEvent::PinRotated {
            pin_display: crate::pin::format_pin(&pin),
            seconds_left: remaining,
        });

        // Record this bucket's PIN auth key so an inbound dialer holding this
        // PIN can be authenticated in-band, even after the code rotates.
        match crate::pin_auth::derive_auth_keys(&pin) {
            Ok(keys) => recent.push(keys),
            Err(e) => log::warn!("Failed to derive PIN auth key: {e:#}"),
        }

        match crate::nostr::publish_pin_record(&pin, bucket, &node_id, &relays).await {
            Ok(()) => log::info!("Published rotating PIN to nostr (refreshes in {remaining}s)"),
            Err(e) => log::warn!("Failed to publish PIN to nostr: {e:#}"),
        }

        // Sleep to the next bucket boundary, then rotate. `max(1)` avoids a busy
        // spin if we happen to land exactly on the boundary.
        let sleep_for = Duration::from_secs(crate::pin::secs_until_next_bucket().max(1));
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = paired.cancelled() => {
                // Paired mid-cycle: drop the now-stale PIN and stop publishing.
                events.send(NetEvent::PinCleared);
                break;
            }
            _ = tokio::time::sleep(sleep_for) => {}
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

/// Authenticate as the dialer with a pre-shared token.
async fn auth_as_dialer(conn: &iroh::endpoint::Connection, auth_token: &str) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("opening auth stream")?;

    let request = AuthRequest::new(auth_token);
    send.write_all(&encode_auth_request(&request)?).await?;
    send.finish()?;

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
    Ok(())
}

/// Authenticate as the dialer using the quick-mode PIN (in-band challenge-response). No token
/// crosses the wire. The whole exchange is bounded by [`AUTH_TIMEOUT`] and any failure is an
/// [`AuthFailure`] — fatal for this target, exactly like a wrong token.
async fn auth_as_dialer_pin(conn: &iroh::endpoint::Connection, pin: &str) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("opening auth stream")?;
    match tokio::time::timeout(
        AUTH_TIMEOUT,
        crate::pin_auth::dialer_handshake(&mut send, &mut recv, pin),
    )
    .await
    {
        Err(_) => return Err(auth_failure("PIN auth timed out")),
        Ok(Err(e)) => {
            if let Some(reason) = auth_close_reason(conn) {
                return Err(auth_failure(reason));
            }
            return Err(anyhow::Error::new(AuthFailure(format!("{e:#}"))));
        }
        Ok(Ok(())) => {}
    }
    let _ = send.finish();
    log::info!("Authenticated with peer via PIN");
    Ok(())
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
) -> Result<()> {
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

    let auth_result = tokio::time::timeout(AUTH_TIMEOUT, async {
        let (mut send, mut recv) = conn
            .accept_bi()
            .await
            .context("Failed to accept auth stream")?;

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
                send.finish()?;
                Ok::<(), anyhow::Error>(())
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
                let _ = send.finish();
                log::info!("Peer {remote_id} authenticated via PIN");
                Ok(())
            }
        }
    })
    .await;

    match auth_result {
        Ok(Ok(())) => Ok(()),
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
        let srv_session = start_session(
            SessionKind::Server(ServerMode::Manual),
            srv_events,
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

        // Client side.
        let (cli_tx, cli_rx) = std::sync::mpsc::channel();
        let cli_events = EventSender::new(cli_tx, None);
        let cli_session = start_session(
            SessionKind::Client(DialSpec::Manual { node_id, token }),
            cli_events,
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

    /// A client presenting the wrong token is rejected with a fatal auth error.
    #[tokio::test(flavor = "multi_thread")]
    async fn manual_mode_rejects_wrong_token() {
        let _ = env_logger::builder().is_test(true).try_init();

        let (srv_tx, srv_rx) = std::sync::mpsc::channel();
        let srv_session = start_session(
            SessionKind::Server(ServerMode::Manual),
            EventSender::new(srv_tx, None),
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
}
