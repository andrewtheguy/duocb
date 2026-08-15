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
/// (wakes the Slint event loop's event drain; unused in headless tests).
pub type WakeFn = std::sync::Arc<dyn Fn() + Send + Sync>;

/// Persistent configure-mode identity plus its local trust store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyIdentity {
    pub identity: crate::auth::Identity,
    pub self_card: crate::auth::IdentityCard,
    pub peers: Vec<crate::auth::IdentityCard>,
    pub relays: Vec<String>,
}

impl KeyIdentity {
    pub fn peer(&self, public_key: nostr_sdk::PublicKey) -> Option<&crate::auth::IdentityCard> {
        self.peers
            .iter()
            .find(|card| card.public_key() == public_key)
    }
}

/// How the server signals its ephemeral node id to the client.
#[derive(Debug, Clone)]
pub enum ServerMode {
    /// Configure mode: publish pairwise hosting records and authenticate with
    /// the persistent application key.
    NostrKey { identity: Box<KeyIdentity> },
    /// LAN setup: show a rotating PIN, publish the rendezvous record under
    /// per-bucket PIN-derived keys over DNS-SD, and authenticate a joiner with
    /// the in-band PIN challenge-response. A unicast side-channel listener runs
    /// alongside (see `crate::lan::unicast`) serving the same PIN-encrypted
    /// record, so a joiner who types this host's LAN IP can still pair where
    /// multicast is blocked.
    ///
    /// The session exists only to hand `self_card` over and take the joiner's in
    /// return; it never carries clipboard traffic and ends as soon as the cards
    /// have crossed.
    LanSetup {
        self_card: Box<crate::auth::IdentityCard>,
    },
}

/// What the client dials.
#[derive(Debug, Clone)]
pub enum DialSpec {
    /// Resolve and authenticate exactly one locally trusted application key.
    NostrKey {
        identity: Box<KeyIdentity>,
        peer_public_key: nostr_sdk::PublicKey,
    },
    /// Resolve the host through the rotating-PIN rendezvous on the local
    /// network, prove PIN possession in-band, then swap identity cards.
    ///
    /// `Some(target_ip)` fetches the PIN-encrypted node-id record from the
    /// host's unicast side channel at that address (the joiner typed the IP the
    /// host displayed — this is the path that works where multicast is blocked);
    /// `None` browses DNS-SD. The side-channel port is derived from the PIN's
    /// rendezvous key (see `crate::lan`), so no port is ever typed.
    LanSetup {
        canonical_pin: String,
        self_card: Box<crate::auth::IdentityCard>,
        target_ip: Option<std::net::IpAddr>,
    },
}

/// Commands from the UI thread to the networking runtime.
#[derive(Debug, Clone)]
pub enum UiCommand {
    StartServer { mode: ServerMode },
    StopServer,
    Connect { spec: DialSpec },
    Disconnect,
    /// LAN setup: mint and publish a fresh PIN immediately, invalidating every
    /// previously shown PIN — their auth keys are dropped and their LAN
    /// advertisements withdrawn, so a stale code can resolve at most an auth
    /// rejection. The new code arrives as the next [`NetEvent::PinRotated`].
    /// An error event if no LAN-setup server session is running.
    RefreshPin,
    SendClipboard { text: String },
    /// Request a point-in-time snapshot of the live connection's paths, answered
    /// with [`NetEvent::ConnPath`]. Empty if no connection is up.
    QueryConnPath,
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
    /// Client: waiting to retry after a failed/dropped connection, showing the
    /// current attempt against the give-up bound (fixed-interval retry).
    Reconnecting { attempt: u32, max: u32 },
}

/// Events from the networking runtime to the UI thread.
#[derive(Debug)]
pub enum NetEvent {
    ServerReady {
        node_id: String,
        identity_public_key: Option<String>,
    },
    ClientReady {
        node_id: String,
        identity_public_key: Option<String>,
    },
    /// LAN setup: a fresh PIN was minted (display form, `XXXX-XXXX`).
    /// `host_lan_ip` is this host's LAN IPv4, so the UI can offer it for the
    /// joiner's manual-IP side channel; `None` when none was detected.
    PinRotated {
        pin_display: String,
        seconds_left: u64,
        host_lan_ip: Option<String>,
    },
    /// LAN setup: paired (or stopped) — stop showing a PIN.
    PinCleared,
    Status(ConnStatus),
    /// A peer authenticated. `peer_public_key` is the trusted application key in
    /// configure mode, and always `None` in LAN setup: nothing on that
    /// connection authenticates an application identity, so the card that
    /// follows is unverified until a human compares its fingerprint.
    PeerPaired {
        peer_node_id: String,
        peer_public_key: Option<String>,
    },
    /// LAN setup: the peer's signed identity card arrived on the
    /// PIN-authenticated connection. Boxed to keep the enum small.
    ///
    /// The runtime decides nothing about it — the card is verified as
    /// well-formed and correctly signed, nothing more. Whether it is trusted is
    /// the host app's call, and it must not be made without the user comparing
    /// the sender's fingerprint against the value shown on the other device.
    ///
    /// Emitted **before** the closing [`ConnStatus::Idle`] on the same channel,
    /// so a host app is guaranteed to see the card before it processes session
    /// teardown. It carries no ordering against [`NetEvent::PinCleared`], which
    /// a separate publisher task emits as soon as the pair claim is committed —
    /// that is, before the cards have even crossed.
    PeerCardReceived(Box<crate::auth::IdentityCard>),
    PeerDisconnected,
    /// Answer to [`UiCommand::QueryConnPath`]: a point-in-time snapshot of the
    /// connection's paths (empty if no connection is currently up).
    ConnPath(Vec<endpoint::ConnPath>),
    /// A clipboard item arrived. `pulled` marks a resume re-delivery — the
    /// peer's latest sent item, fetched when an interrupted connection came
    /// back — which the UI should drop if it already holds that content.
    ItemReceived { text: String, pulled: bool },
    ItemSent,
    Error(String),
}

/// Cloneable sender for [`NetEvent`]s that wakes the host UI after each send.
/// The wake callback is optional so the runtime can run in headless tests and
/// under polling hosts.
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
