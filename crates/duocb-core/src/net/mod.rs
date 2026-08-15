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

/// Which transport(s) carry duocb's rendezvous records: the card-setup PIN
/// record (`crate::pin_record`) and the pairwise hosting record that points a
/// trusted peer at a live clipboard session (`crate::hosting_record`). Both
/// records are the same on either transport — an encrypted node id under a
/// derived label — so this chooses only where they are put and looked for.
///
/// Launch-fixed for the whole process (`--lan-only` / `--nostr-only`), so both
/// flows always agree on which channels are in play.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignalChannel {
    /// The default: try the local network first (Bonjour/DNS-SD, or the typed
    /// host IP during card setup), and fall back to nostr relays when nothing
    /// local answers. LAN-first because it resolves in well under a second,
    /// needs no third-party server, and is the common case — two devices in one
    /// room. The nostr fallback is what lets two devices on *different*
    /// networks reach each other at all.
    #[default]
    LanThenNostr,
    /// Nostr relays only — the internet is required, and no mDNS query or
    /// side-channel listener is used. Test/diagnostic override.
    NostrOnly,
    /// Local network only: mDNS discovery plus direct device-to-device traffic,
    /// with no third-party server involved. Not a packet-level subnet boundary.
    /// Test/diagnostic override, and the choice for an entirely offline pair of
    /// devices.
    LanOnly,
}

impl SignalChannel {
    /// Whether the local-network backends (DNS-SD and the unicast side channel)
    /// participate.
    pub fn lan(self) -> bool {
        matches!(self, Self::LanThenNostr | Self::LanOnly)
    }

    /// Whether the nostr relay backend participates.
    pub fn nostr(self) -> bool {
        matches!(self, Self::LanThenNostr | Self::NostrOnly)
    }
}

/// How the server signals its ephemeral node id to the client.
#[derive(Debug, Clone)]
pub enum ServerMode {
    /// Configure mode: publish a pairwise hosting record for each trusted peer
    /// on every enabled channel, and authenticate with the persistent
    /// application key.
    ///
    /// Like [`CardSetup`](Self::CardSetup), the host publishes everywhere it can
    /// rather than falling back — it cannot know which channel the joiner will
    /// find it on. Only the joiner falls back (see [`DialSpec::Key`]).
    Key {
        identity: Box<KeyIdentity>,
        channel: SignalChannel,
    },
    /// Card setup: show a rotating PIN, publish the rendezvous record under
    /// per-bucket PIN-derived keys on the enabled channel(s), and authenticate
    /// a joiner with the in-band PIN challenge-response. Whenever the LAN
    /// channel is enabled a unicast side-channel listener runs alongside the
    /// DNS-SD advertisement (see `crate::lan::unicast`) serving the same
    /// PIN-encrypted record, so a joiner who types this host's LAN IP can still
    /// pair where multicast is blocked.
    ///
    /// The host publishes on *every* enabled channel — it cannot know which one
    /// the joiner will find it on; only the joiner falls back (see
    /// [`DialSpec::CardSetup`]).
    ///
    /// The session exists only to hand `self_card` over and take the joiner's in
    /// return; it never carries clipboard traffic and ends as soon as the cards
    /// have crossed.
    CardSetup {
        self_card: Box<crate::auth::IdentityCard>,
        channel: SignalChannel,
        /// Relays for the nostr rendezvous; ignored on [`SignalChannel::LanOnly`].
        relays: Vec<String>,
    },
}

/// What the client dials.
#[derive(Debug, Clone)]
pub enum DialSpec {
    /// Resolve and authenticate exactly one locally trusted application key.
    ///
    /// On [`SignalChannel::LanThenNostr`] the host's pairwise hosting record is
    /// looked for on the local network first and on the relays only if that
    /// missed — sequential, not raced, for the same reasons as
    /// [`CardSetup`](Self::CardSetup). A LAN hit carries the host's direct
    /// addresses, so the dial needs no further address lookup.
    ///
    /// The relays used are the ones on `identity`; they are ignored on
    /// [`SignalChannel::LanOnly`].
    Key {
        identity: Box<KeyIdentity>,
        peer_public_key: nostr_sdk::PublicKey,
        channel: SignalChannel,
    },
    /// Resolve the host through the rotating-PIN rendezvous, prove PIN
    /// possession in-band, then swap identity cards.
    ///
    /// On [`SignalChannel::LanThenNostr`] the lookups run in order, not in
    /// parallel: the local one first, and the relays only if it finds nothing.
    /// The LAN answers in well under a second when the peer is there, so the
    /// common case never touches a relay.
    ///
    /// `Some(target_ip)` fetches the PIN-encrypted node-id record from the
    /// host's unicast side channel at that address (the joiner typed the IP the
    /// host displayed — this is the path that works where multicast is blocked);
    /// `None` browses DNS-SD. The side-channel port is derived from the PIN's
    /// rendezvous key (see `crate::lan`), so no port is ever typed. Either way
    /// it is the LAN half of the lookup, so it is ignored on
    /// [`SignalChannel::NostrOnly`].
    CardSetup {
        canonical_pin: String,
        self_card: Box<crate::auth::IdentityCard>,
        target_ip: Option<std::net::IpAddr>,
        channel: SignalChannel,
        /// Relays for the nostr rendezvous; ignored on [`SignalChannel::LanOnly`].
        relays: Vec<String>,
    },
}

/// Commands from the UI thread to the networking runtime.
#[derive(Debug, Clone)]
pub enum UiCommand {
    StartServer { mode: ServerMode },
    StopServer,
    Connect { spec: DialSpec },
    Disconnect,
    /// Card setup: mint and publish a fresh PIN immediately, invalidating every
    /// previously shown PIN — their auth keys are dropped and their LAN
    /// advertisements withdrawn, so a stale code can resolve at most an auth
    /// rejection. (A relay copy of an older record just ages out of its TTL,
    /// which is the same outcome once its auth key is gone.) The new code
    /// arrives as the next [`NetEvent::PinRotated`]. An error event if no
    /// card-setup server session is running.
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
    /// Client: resolving the target — a peer's hosting record or the card-setup
    /// PIN rendezvous, on whichever channel(s) are enabled.
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
    /// Card setup: a fresh PIN was minted (display form, `XXXX-XXXX`).
    /// `host_lan_ip` is this host's LAN IPv4, so the UI can offer it for the
    /// joiner's manual-IP side channel; `None` when none was detected or the
    /// LAN channel is disabled (there is no side channel to reach then).
    PinRotated {
        pin_display: String,
        seconds_left: u64,
        host_lan_ip: Option<String>,
    },
    /// Card setup: paired (or stopped) — stop showing a PIN.
    PinCleared,
    Status(ConnStatus),
    /// A peer authenticated. `peer_public_key` is the trusted application key in
    /// configure mode, and always `None` in card setup: nothing on that
    /// connection authenticates an application identity, so the card that
    /// follows is unverified until a human compares its fingerprint.
    PeerPaired {
        peer_node_id: String,
        peer_public_key: Option<String>,
    },
    /// Card setup: the peer's signed identity card arrived on the
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
