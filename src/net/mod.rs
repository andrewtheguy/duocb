//! Bridge between the egui UI thread and the tokio networking runtime.
//!
//! The UI sends [`UiCommand`]s over an unbounded tokio channel (sync send from
//! the UI thread); the runtime sends [`NetEvent`]s back over a std mpsc channel
//! and pokes `egui::Context::request_repaint()` so the GUI wakes even when idle.
//! Channels only — no shared mutable app state between the two sides.

pub mod endpoint;
pub mod runtime;

use eframe::egui;

/// How the server signals its ephemeral node id to the client.
#[derive(Debug, Clone)]
pub enum ServerMode {
    /// Nostr token/name mode: publish the node id under keys derived from the
    /// shared auth token, tagged with this device's name. In-band token auth.
    NostrToken {
        token: String,
        name: String,
        relays: Vec<String>,
    },
    /// Nostr rotating-PIN quick mode: publish under per-bucket PIN-derived keys;
    /// in-band PIN challenge-response auth.
    NostrPin { relays: Vec<String> },
    /// Manual/offline mode: no signaling. The server displays its node id and a
    /// freshly generated auth token (reported via [`NetEvent::ServerReady`]);
    /// the client types both. Discovery falls back to mDNS on the LAN, so this
    /// works with zero internet.
    Manual,
}

/// What the client dials.
#[derive(Debug, Clone)]
pub enum DialSpec {
    /// Resolve the peer's node id by name via nostr (token-derived keys), then
    /// authenticate with the same shared token.
    NostrToken {
        token: String,
        peer_name: String,
        relays: Vec<String>,
    },
    /// Resolve via the rotating-PIN rendezvous, then prove PIN possession in-band.
    Pin {
        canonical_pin: String,
        relays: Vec<String>,
    },
    /// Dial a manually typed node id and present the server's token.
    Manual { node_id: String, token: String },
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
    /// Server endpoint is up. `manual_token` is set in manual mode (the token the
    /// client must type); `token_fingerprint` is set whenever a token is in play.
    ServerReady {
        node_id: String,
        manual_token: Option<String>,
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
    ItemReceived { text: String },
    ItemSent,
    Error(String),
}

/// Cloneable sender for [`NetEvent`]s that wakes the egui event loop after each
/// send. The repaint context is optional so the runtime can run in headless
/// tests.
#[derive(Clone)]
pub struct EventSender {
    tx: std::sync::mpsc::Sender<NetEvent>,
    repaint: Option<egui::Context>,
}

impl EventSender {
    pub fn new(tx: std::sync::mpsc::Sender<NetEvent>, repaint: Option<egui::Context>) -> Self {
        Self { tx, repaint }
    }

    pub fn send(&self, event: NetEvent) {
        let _ = self.tx.send(event);
        if let Some(ctx) = &self.repaint {
            ctx.request_repaint();
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
/// multi-thread runtime. `ctx` is used to wake the egui loop on every event.
pub fn spawn_net_runtime(ctx: egui::Context) -> NetHandle {
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, event_rx) = std::sync::mpsc::channel();
    let events = EventSender::new(event_tx, Some(ctx));
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
