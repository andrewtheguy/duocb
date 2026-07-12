//! Bridge between a host UI and the tokio networking runtime.
//!
//! The UI sends [`UiCommand`]s over an unbounded tokio channel (sync send from
//! the UI thread); the runtime sends [`NetEvent`]s back over a std mpsc channel
//! and invokes an optional wake callback so the host UI can wake its render
//! loop even when idle. Channels only — no shared mutable app state between
//! the two sides.

pub mod endpoint;
pub mod runtime;

/// Callback invoked after every event so the host UI can wake its render loop
/// (wakes the Slint event loop's event drain on desktop; unused on iOS, where
/// Swift polls on a timer, and in headless tests).
pub type WakeFn = std::sync::Arc<dyn Fn() + Send + Sync>;

/// The standing configure-mode identity: the shared secret plus this device's
/// collision-resistant display identity (`<name>_<suffix>`, see
/// `crate::identity`). Everything the presence publisher, a hosting session,
/// and a joining session need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenIdentity {
    /// The shared auth token (the standing secret).
    pub token: String,
    /// This device's user-chosen short name.
    pub name: String,
    /// This device's permanent random suffix.
    pub suffix: String,
    pub relays: Vec<String>,
}

impl TokenIdentity {
    /// The full display identity `<name>_<suffix>` broadcast to peers.
    pub fn display(&self) -> String {
        crate::identity::display_identity(&self.name, &self.suffix)
    }
}

/// Which transport(s) carry the rotating-PIN rendezvous record (the same
/// encrypted record either way — see `crate::pin_record`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinChannel {
    /// Publish/look up on nostr relays **and** the local network (mDNS); the
    /// lookup races both. The default: works across the internet, and still
    /// pairs on the same network with no internet.
    NostrAndLan,
    /// Nostr relays only (internet required).
    NostrOnly,
    /// Local network only (mDNS): zero internet, both devices on one network.
    LanOnly,
}

impl PinChannel {
    pub fn nostr(self) -> bool {
        matches!(self, Self::NostrAndLan | Self::NostrOnly)
    }
    pub fn lan(self) -> bool {
        matches!(self, Self::NostrAndLan | Self::LanOnly)
    }
}

/// How the server signals its ephemeral node id to the client.
#[derive(Debug, Clone)]
pub enum ServerMode {
    /// Configure mode: host under the standing secret. The presence publisher
    /// (kept running by the runtime) carries the node id to peers; in-band
    /// token auth gates the connection.
    NostrToken { identity: TokenIdentity },
    /// Rotating-PIN quick mode: publish the rendezvous record under per-bucket
    /// PIN-derived keys on the selected channel(s); in-band PIN
    /// challenge-response auth.
    Pin {
        relays: Vec<String>,
        channel: PinChannel,
    },
    /// Manual/offline mode: no signaling at all. The server displays a single
    /// pairing code — its node id plus a fresh session secret (see
    /// `crate::manual_code`, reported via [`NetEvent::ServerReady`]) — which
    /// the user carries to the other device out of band. Auth is the same
    /// in-band PIN challenge-response as the PIN mode. Discovery falls back to
    /// mDNS on the LAN, so this works with zero internet.
    Manual,
}

/// What the client dials.
#[derive(Debug, Clone)]
pub enum DialSpec {
    /// Dial exactly the chosen peer: resolve `peer_display`'s presence record
    /// under the shared token-derived nostr author (re-resolved on every attempt,
    /// so a restarted host self-heals), then authenticate with the token.
    NostrToken {
        identity: TokenIdentity,
        /// The selected peer's full display identity, e.g. `mac-book_a7B2c3D4`.
        peer_display: String,
    },
    /// Resolve via the rotating-PIN rendezvous on the selected channel(s) —
    /// racing them when both are enabled — then prove PIN possession in-band.
    Pin {
        canonical_pin: String,
        relays: Vec<String>,
        channel: PinChannel,
    },
    /// Dial the node id carried by a pasted pairing code and prove its session
    /// secret in-band (the same PIN challenge-response as the PIN mode).
    Manual { node_id: String, secret: String },
}

/// Commands from the UI thread to the networking runtime.
#[derive(Debug)]
pub enum UiCommand {
    StartServer { mode: ServerMode },
    StopServer,
    Connect { spec: DialSpec },
    Disconnect,
    SendClipboard { text: String },
    /// Request a point-in-time snapshot of the live connection's paths, answered
    /// with [`NetEvent::ConnPath`]. Empty if no connection is up.
    QueryConnPath,
    /// `Some`: start (or replace) the standing presence publisher for this
    /// identity. `None`: stop it (the secret was cleared). Independent of any
    /// session; [`UiCommand::StartServer`] in configure mode ensures it runs.
    SetPresence { identity: Option<TokenIdentity> },
    /// One-shot fetch of the peer device list under the configured presence
    /// identity, answered with [`NetEvent::PeerList`]. Ignored while a previous
    /// fetch is still in flight; an error event if no identity is configured.
    RefreshPeers,
    Shutdown,
}

/// Connection status surfaced to the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnStatus {
    /// No session running.
    Idle,
    /// Session starting (endpoint coming online).
    Starting,
    /// Server: listening, no peer yet.
    Listening,
    /// Client: resolving the target via nostr.
    Resolving,
    /// Client: dialing the resolved node id.
    Connecting,
    /// Authenticating with the peer.
    Authenticating,
    /// Paired and the clipboard channel is up.
    Connected,
    /// Client: waiting to retry after a failed/dropped connection.
    Reconnecting { backoff_secs: u64 },
}

/// Events from the networking runtime to the UI thread.
#[derive(Debug)]
pub enum NetEvent {
    /// Server endpoint is up. `pairing_code` is set in manual mode (the code
    /// the user carries to the other device); `token_fingerprint` is set in
    /// configure mode (the standing secret's).
    ServerReady {
        node_id: String,
        token_fingerprint: Option<String>,
        pairing_code: Option<String>,
    },
    /// Client endpoint is online. Token mode includes the fingerprint so the
    /// connector retains the same identity details as the initiator screen.
    ClientReady {
        node_id: String,
        token_fingerprint: Option<String>,
    },
    /// PIN quick mode: a fresh PIN was minted (display form, `XXXX-XXXX`).
    PinRotated {
        pin_display: String,
        seconds_left: u64,
    },
    /// PIN quick mode: paired (or stopped) — stop showing a PIN.
    PinCleared,
    Status(ConnStatus),
    PeerPaired { peer_node_id: String },
    PeerDisconnected,
    /// Answer to [`UiCommand::QueryConnPath`]: a point-in-time snapshot of the
    /// connection's paths (empty if no connection is currently up).
    ConnPath(Vec<endpoint::ConnPath>),
    /// A clipboard item arrived. `pulled` marks a resume re-delivery — the
    /// peer's latest sent item, fetched when an interrupted connection came
    /// back — which the UI should drop if it already holds that content.
    ItemReceived { text: String, pulled: bool },
    ItemSent,
    /// Answer to [`UiCommand::RefreshPeers`]: the decoded peer device list
    /// (this device's own record already excluded).
    PeerList { peers: Vec<crate::nostr::PeerInfo> },
    /// The presence publisher found a record under this device's own identity
    /// written by another live publisher and stopped. Another process is using
    /// this device's identity (e.g. a second instance on a cloned config).
    PresenceConflict { message: String },
    Error(String),
}

/// Cloneable sender for [`NetEvent`]s that wakes the host UI after each send.
/// The wake callback is optional so the runtime can run in headless tests and
/// under polling hosts (the iOS FFI).
#[derive(Clone)]
pub struct EventSender {
    tx: std::sync::mpsc::Sender<NetEvent>,
    wake: Option<WakeFn>,
}

impl EventSender {
    pub fn new(tx: std::sync::mpsc::Sender<NetEvent>, wake: Option<WakeFn>) -> Self {
        Self { tx, wake }
    }

    pub fn send(&self, event: NetEvent) {
        let _ = self.tx.send(event);
        if let Some(wake) = &self.wake {
            wake();
        }
    }

    pub fn status(&self, status: ConnStatus) {
        self.send(NetEvent::Status(status));
    }

    pub fn error(&self, message: impl Into<String>) {
        self.send(NetEvent::Error(message.into()));
    }
}

/// Handle held by the UI: the command sender, the event receiver, and the
/// runtime thread join handle (joined on exit).
pub struct NetHandle {
    pub cmd_tx: tokio::sync::mpsc::UnboundedSender<UiCommand>,
    pub events: std::sync::mpsc::Receiver<NetEvent>,
    pub thread: Option<std::thread::JoinHandle<()>>,
}

impl NetHandle {
    pub fn send(&self, cmd: UiCommand) {
        let _ = self.cmd_tx.send(cmd);
    }

    /// Request shutdown and join the runtime thread (bounded by the runtime's
    /// own teardown; the thread exits once sessions are cancelled).
    pub fn shutdown(&mut self) {
        let _ = self.cmd_tx.send(UiCommand::Shutdown);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Spawn the networking runtime on a dedicated thread with its own tokio
/// multi-thread runtime. `wake` is invoked after every event so the host UI
/// can wake its render loop.
pub fn spawn_net_runtime(wake: Option<WakeFn>) -> NetHandle {
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, event_rx) = std::sync::mpsc::channel();
    let events = EventSender::new(event_tx, wake);
    let thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");
        rt.block_on(runtime::net_main(cmd_rx, events));
    });
    NetHandle {
        cmd_tx,
        events: event_rx,
        thread: Some(thread),
    }
}
