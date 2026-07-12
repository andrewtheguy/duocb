//! The eframe application: drains runtime events, routes screens, and holds
//! all UI state (including the in-memory inbox — clipboard content never
//! touches disk).

use std::time::{Duration, Instant};

use eframe::egui;

use crate::clipboard::SystemClipboard;
use duocb_core::net::endpoint::ConnPath;
use duocb_core::net::{
    ConnStatus, NetEvent, NetHandle, TokenIdentity, UiCommand, spawn_net_runtime,
};
use duocb_core::nostr::PeerInfo;
use crate::ui::{ClipItem, ConfigureStep, PairMode, Screen, screens, session};

/// How long the "sent ✓" flash stays visible.
const SENT_FLASH: Duration = Duration::from_secs(2);

/// Retention cap for the in-memory inbox: newest-first, only the last few
/// received items are kept and older ones are dropped.
const MAX_INBOX_ITEMS: usize = 5;

/// How often the configure hub auto-refreshes the peer device list while
/// visible.
const PEER_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

pub struct DuocbApp {
    pub(crate) config_lock: crate::config::ConfigLock,
    pub(crate) net: NetHandle,
    pub(crate) clipboard: SystemClipboard,

    // Navigation.
    pub(crate) screen: Screen,
    pub(crate) mode: PairMode,

    // Shared status.
    pub(crate) status: ConnStatus,
    pub(crate) error: Option<String>,

    // Configure-mode standing state (the primary mode).
    /// The standing secret from the config, always checksum-valid when `Some`.
    pub(crate) secret: Option<String>,
    /// The confirmed short device name from the config.
    pub(crate) saved_name: Option<String>,
    /// This device's permanent random suffix (always present; minted on the
    /// first launch with this config file).
    pub(crate) device_suffix: String,
    pub(crate) configure_step: ConfigureStep,
    /// A freshly generated secret during its one-time reveal, not yet committed.
    pub(crate) wizard_token: Option<String>,
    /// The discovered peer device list and when it was last received/asked for.
    pub(crate) peers: Vec<PeerInfo>,
    pub(crate) peers_refreshed_at: Option<Instant>,
    pub(crate) peers_requested_at: Option<Instant>,
    /// The selected peer, by its stable suffix (survives list refreshes).
    pub(crate) selected_peer: Option<String>,
    /// The joined peer's display identity while a configure-mode dial runs.
    pub(crate) joined_peer: Option<String>,
    /// Warning from the presence publisher (another live process broadcasts
    /// under this device's identity); cleared when presence is reconfigured.
    pub(crate) presence_conflict: Option<String>,
    pub(crate) confirm_clear_secret: bool,

    // Server presentation state.
    pub(crate) server_running: bool,
    pub(crate) node_id: Option<String>,
    pub(crate) manual_token: Option<String>,
    pub(crate) token_fingerprint: Option<String>,
    pub(crate) pin_display: Option<String>,
    pub(crate) pin_deadline: Option<Instant>,
    /// PIN cleared because a peer paired (vs. never shown).
    pub(crate) pin_paired: bool,

    // Client-side session flag (a dial session exists, connected or retrying).
    pub(crate) client_active: bool,

    // Form inputs.
    pub(crate) in_my_name: String,
    pub(crate) in_import_token: String,
    pub(crate) in_pin: String,
    pub(crate) in_node_id: String,
    pub(crate) in_manual_token: String,

    // Live session state.
    pub(crate) peer_node_id: Option<String>,
    /// Connection-path snapshot shown in a modal on demand, or `None` when the
    /// modal is closed. Populated by [`NetEvent::ConnPath`].
    pub(crate) conn_path: Option<Vec<ConnPath>>,
    pub(crate) inbox: Vec<ClipItem>,
    /// The last item successfully sent, shown above the inbox so the receiver
    /// can compare its size/CRC against what arrived.
    pub(crate) outbox: Option<ClipItem>,
    /// Text handed to the runtime, promoted to `outbox` once the send is
    /// confirmed by `NetEvent::ItemSent` (so a rejected/oversize send never
    /// shows up as sent).
    pub(crate) pending_outbox: Option<String>,
    pub(crate) sent_flash: Option<Instant>,
}

impl DuocbApp {
    pub fn new(cc: &eframe::CreationContext<'_>, mut config_lock: crate::config::ConfigLock) -> Self {
        let net = spawn_net_runtime(Some(std::sync::Arc::new({
            let ctx = cc.egui_ctx.clone();
            move || ctx.request_repaint()
        })));
        let mut config = config_lock.load();

        // The permanent device suffix is minted on the first launch with this
        // config file and persisted immediately. A failed save still leaves a
        // usable in-memory suffix for this session; the next successful save
        // persists it.
        let mut startup_error = None;
        let device_suffix = match config.device_suffix.as_deref() {
            Some(s) if duocb_core::identity::is_valid_suffix(s) => s.to_string(),
            _ => {
                let suffix = duocb_core::identity::generate_suffix();
                config.device_suffix = Some(suffix.clone());
                if let Err(e) = config_lock.save(&config) {
                    startup_error = Some(format!("Could not save the device id: {e:#}"));
                }
                suffix
            }
        };

        let secret = config
            .auth_token
            .filter(|t| duocb_core::auth::validate_token(t).is_ok());
        let saved_name = config
            .my_name
            .filter(|n| duocb_core::identity::validate_name(n).is_ok());
        let configure_step = match (&secret, &saved_name) {
            (Some(_), Some(_)) => ConfigureStep::Ready,
            (Some(_), None) => ConfigureStep::SetupName,
            (None, _) => ConfigureStep::SetupChoice,
        };

        let mut app = Self {
            config_lock,
            net,
            clipboard: SystemClipboard::new(),
            screen: Screen::Home,
            mode: PairMode::NostrToken,
            status: ConnStatus::Idle,
            error: startup_error,
            secret,
            saved_name: saved_name.clone(),
            device_suffix,
            configure_step,
            wizard_token: None,
            peers: Vec::new(),
            peers_refreshed_at: None,
            peers_requested_at: None,
            selected_peer: None,
            joined_peer: None,
            presence_conflict: None,
            confirm_clear_secret: false,
            server_running: false,
            node_id: None,
            manual_token: None,
            token_fingerprint: None,
            pin_display: None,
            pin_deadline: None,
            pin_paired: false,
            client_active: false,
            in_my_name: saved_name.unwrap_or_default(),
            in_import_token: String::new(),
            in_pin: String::new(),
            in_node_id: String::new(),
            in_manual_token: String::new(),
            peer_node_id: None,
            conn_path: None,
            inbox: Vec::new(),
            outbox: None,
            pending_outbox: None,
            sent_flash: None,
        };
        // A fully configured device starts broadcasting presence right away and
        // fetches the peer list for the hub.
        if app.configure_step == ConfigureStep::Ready {
            app.sync_presence();
            app.refresh_peers();
        }
        app
    }

    fn apply_event(&mut self, event: NetEvent) {
        match event {
            NetEvent::ServerReady {
                node_id,
                manual_token,
                token_fingerprint,
            } => {
                self.node_id = Some(node_id);
                self.manual_token = manual_token;
                self.token_fingerprint = token_fingerprint;
            }
            NetEvent::ClientReady {
                node_id,
                token_fingerprint,
            } => {
                self.node_id = Some(node_id);
                self.token_fingerprint = token_fingerprint;
            }
            NetEvent::PinRotated {
                pin_display,
                seconds_left,
            } => {
                self.pin_display = Some(pin_display);
                self.pin_deadline = Some(Instant::now() + Duration::from_secs(seconds_left));
                self.pin_paired = false;
            }
            NetEvent::PinCleared => {
                if self.pin_display.take().is_some() {
                    self.pin_paired = true;
                }
                self.pin_deadline = None;
            }
            NetEvent::Status(status) => {
                if status == ConnStatus::Idle {
                    // Session ended (stopped, or failed fatally): reset the
                    // presentation state. The inbox and outbox are kept — items
                    // are only discarded via the explicit Clear button; a
                    // never-confirmed pending send is dropped.
                    self.server_running = false;
                    self.client_active = false;
                    self.node_id = None;
                    self.manual_token = None;
                    self.token_fingerprint = None;
                    self.joined_peer = None;
                    self.pin_display = None;
                    self.pin_deadline = None;
                    self.pin_paired = false;
                    self.peer_node_id = None;
                    self.conn_path = None;
                    self.pending_outbox = None;
                }
                self.status = status;
            }
            NetEvent::PeerPaired { peer_node_id } => {
                self.peer_node_id = Some(peer_node_id);
                // The manual-mode token stays valid for the whole server session
                // — the paired peer can reconnect with it — so keep it copyable on
                // the initiator (it is cleared only when the session ends, in the
                // Idle branch above). Drop the joiner's typed copy now it's paired.
                self.in_manual_token.clear();
            }
            NetEvent::PeerDisconnected => {
                self.peer_node_id = None;
                self.conn_path = None;
                // A send in flight when the link dropped will never be
                // confirmed; drop it so it can't be promoted later and so it
                // doesn't block sends after a reconnect.
                self.pending_outbox = None;
            }
            NetEvent::ConnPath(paths) => {
                self.conn_path = Some(paths);
            }
            NetEvent::ItemReceived { text, pulled } => {
                // A resume re-delivery may duplicate content this inbox already
                // holds (it was received before the connection dropped) — skip it.
                if pulled && self.inbox.iter().any(|item| item.text == text) {
                    return;
                }
                self.inbox.insert(0, ClipItem::new(text, jiff::Zoned::now()));
                // Bounded retention (see MAX_INBOX_ITEMS): drop the oldest.
                self.inbox.truncate(MAX_INBOX_ITEMS);
            }
            NetEvent::ItemSent => {
                // The send is confirmed on the wire: promote the pending text
                // to the outbox so its size/CRC reflect what actually left.
                if let Some(text) = self.pending_outbox.take() {
                    self.outbox = Some(ClipItem::new(text, jiff::Zoned::now()));
                }
                self.sent_flash = Some(Instant::now());
            }
            NetEvent::PeerList { peers } => {
                // Drop a selection whose device vanished from the list.
                if let Some(suffix) = &self.selected_peer
                    && !peers.iter().any(|p| p.suffix == *suffix)
                {
                    self.selected_peer = None;
                }
                self.peers = peers;
                self.peers_refreshed_at = Some(Instant::now());
            }
            NetEvent::PresenceConflict { message } => {
                self.presence_conflict = Some(message);
            }
            NetEvent::Error(message) => {
                // A rejected send (e.g. oversize) reports an error instead of
                // ItemSent, so drop its pending text — it must never be promoted
                // to the outbox as "sent".
                self.pending_outbox = None;
                self.error = Some(message);
            }
        }
    }

    /// Read the system clipboard and push it to the peer.
    pub(crate) fn send_clipboard(&mut self) {
        match self.clipboard.read_text() {
            Ok(text) if text.is_empty() => {
                self.error = Some("The clipboard is empty".to_string());
            }
            Ok(_) if self.pending_outbox.is_some() => {
                // A previous send is still unconfirmed. Ignore this one so the
                // outbox tracks exactly one in-flight item — otherwise the next
                // ItemSent could promote the wrong (possibly rejected) text.
            }
            Ok(text) => {
                // Stash it; it becomes the outbox item once ItemSent confirms.
                self.pending_outbox = Some(text.clone());
                self.net.send(UiCommand::SendClipboard { text });
            }
            Err(e) => self.error = Some(format!("Could not read the clipboard: {e:#}")),
        }
    }

    /// Copy arbitrary text (an inbox item, the node id, the token) to the
    /// system clipboard, surfacing failures in the error banner.
    pub(crate) fn copy_to_clipboard(&mut self, text: &str) {
        if let Err(e) = self.clipboard.write_text(text) {
            self.error = Some(format!("Could not write the clipboard: {e:#}"));
        }
    }

    /// Ask the runtime for a fresh connection-path snapshot; the reply arrives
    /// as [`NetEvent::ConnPath`] and opens the modal.
    pub(crate) fn query_conn_path(&mut self) {
        self.net.send(UiCommand::QueryConnPath);
    }

    // ------------------------------------------------------------------
    // Configure-mode state transitions
    // ------------------------------------------------------------------

    /// The standing identity, available once secret + name are configured.
    pub(crate) fn token_identity(&self) -> Option<TokenIdentity> {
        Some(TokenIdentity {
            token: self.secret.clone()?,
            name: self.saved_name.clone()?,
            suffix: self.device_suffix.clone(),
            relays: crate::ui::screens::default_relays(),
        })
    }

    /// This device's display identity, using the confirmed name when present.
    pub(crate) fn display_identity(&self) -> String {
        let name = self.saved_name.as_deref().unwrap_or("");
        duocb_core::identity::display_identity(name, &self.device_suffix)
    }

    /// Whether a confirmed secret + name pair exists (the hub is reachable).
    pub(crate) fn has_saved_identity(&self) -> bool {
        self.secret.is_some() && self.saved_name.is_some()
    }

    /// Persist the configure-mode state to this process's active config.
    /// Returns false and surfaces the error when the save fails.
    fn save_configure_config(&mut self) -> bool {
        let cfg = crate::config::Config {
            auth_token: self.secret.clone(),
            my_name: self.saved_name.clone(),
            device_suffix: Some(self.device_suffix.clone()),
        };
        match self.config_lock.save(&cfg) {
            Ok(()) => true,
            Err(e) => {
                self.error = Some(format!("Could not save the settings: {e:#}"));
                false
            }
        }
    }

    /// (Re)start or stop the presence broadcast to match the current identity.
    pub(crate) fn sync_presence(&mut self) {
        self.presence_conflict = None;
        self.net.send(UiCommand::SetPresence {
            identity: self.token_identity(),
        });
    }

    /// Ask the runtime for a fresh peer device list.
    pub(crate) fn refresh_peers(&mut self) {
        if self.has_saved_identity() {
            self.peers_requested_at = Some(Instant::now());
            self.net.send(UiCommand::RefreshPeers);
        }
    }

    /// Start the one-time reveal of a freshly generated secret.
    pub(crate) fn begin_generate_secret(&mut self) {
        self.wizard_token = Some(duocb_core::auth::generate_token());
        self.configure_step = ConfigureStep::SetupGenerate;
    }

    /// Commit a generated or imported secret and move on to naming the device.
    pub(crate) fn set_secret(&mut self, token: String) {
        self.secret = Some(token);
        self.save_configure_config();
        self.sync_presence();
        self.reset_name_field();
        self.configure_step = ConfigureStep::SetupName;
    }

    /// Prefill the name field from the confirmed name.
    pub(crate) fn reset_name_field(&mut self) {
        self.in_my_name = self.saved_name.clone().unwrap_or_default();
    }

    /// Confirm the name field: persist it, enter the hub, and start broadcasting.
    pub(crate) fn save_name(&mut self) {
        let name = self.in_my_name.trim().to_string();
        if duocb_core::identity::validate_name(&name).is_err() {
            return;
        }
        self.saved_name = Some(name);
        if self.save_configure_config() {
            self.configure_step = ConfigureStep::Ready;
            self.sync_presence();
            self.refresh_peers();
        }
    }

    /// Clear the standing secret (explicit, confirmed): stop broadcasting and
    /// return to the setup wizard. The permanent suffix is kept; the name stays
    /// as a prefill for the next setup.
    pub(crate) fn clear_secret(&mut self) {
        self.secret = None;
        self.save_configure_config();
        self.net.send(UiCommand::SetPresence { identity: None });
        self.peers.clear();
        self.selected_peer = None;
        self.peers_refreshed_at = None;
        self.peers_requested_at = None;
        self.presence_conflict = None;
        self.wizard_token = None;
        self.in_import_token.clear();
        self.configure_step = ConfigureStep::SetupChoice;
    }

    /// The selected peer's display identity, only if it is currently hosting
    /// (the only state a join can dial).
    pub(crate) fn selected_hosting_peer_display(&self) -> Option<String> {
        let suffix = self.selected_peer.as_deref()?;
        self.peers
            .iter()
            .find(|p| p.suffix == suffix && p.node_id.is_some())
            .map(|p| p.display())
    }

    /// Join the selected hosting peer from the hub.
    pub(crate) fn join_selected_peer(&mut self) {
        if self.client_dial_spec().is_some() {
            self.screen = Screen::Client;
            self.connect_client();
        }
    }

    /// Move the hub's peer selection up/down (keyboard navigation).
    pub(crate) fn move_peer_selection(&mut self, delta: i32) {
        if self.peers.is_empty() {
            return;
        }
        let current = self
            .selected_peer
            .as_deref()
            .and_then(|suffix| self.peers.iter().position(|p| p.suffix == suffix));
        let next = match current {
            None => {
                if delta > 0 {
                    0
                } else {
                    self.peers.len() - 1
                }
            }
            Some(i) => (i as i64 + delta as i64).rem_euclid(self.peers.len() as i64) as usize,
        };
        self.selected_peer = Some(self.peers[next].suffix.clone());
    }

    /// Whether the "sent ✓" flash should currently show.
    pub(crate) fn sent_flash_active(&self) -> bool {
        self.sent_flash.is_some_and(|t| t.elapsed() < SENT_FLASH)
    }

    /// Human-readable status line.
    pub(crate) fn status_text(&self) -> String {
        match &self.status {
            ConnStatus::Idle => "Idle".to_string(),
            ConnStatus::Starting => "Starting…".to_string(),
            ConnStatus::Listening => "Waiting for the other device…".to_string(),
            ConnStatus::Resolving => "Looking up the peer…".to_string(),
            ConnStatus::Connecting => "Connecting…".to_string(),
            ConnStatus::Authenticating => "Authenticating…".to_string(),
            ConnStatus::Connected => "Connected".to_string(),
            ConnStatus::Reconnecting { backoff_secs } => {
                format!("Reconnecting in {backoff_secs}s…")
            }
        }
    }

    /// Stop whatever session is running (used by the back buttons).
    pub(crate) fn stop_session(&mut self) {
        if self.server_running {
            self.net.send(UiCommand::StopServer);
        } else if self.client_active {
            self.net.send(UiCommand::Disconnect);
        }
    }

    /// Navigate back to the home screen, stopping any running session.
    pub(crate) fn go_back(&mut self) {
        self.stop_session();
        self.screen = Screen::Home;
    }

    /// Build the server mode from the current state, if it validates.
    pub(crate) fn server_mode_spec(&self) -> Option<duocb_core::net::ServerMode> {
        use duocb_core::net::ServerMode;
        match self.mode {
            PairMode::NostrToken => self
                .token_identity()
                .map(|identity| ServerMode::NostrToken { identity }),
            PairMode::NostrPin => Some(ServerMode::NostrPin {
                relays: crate::ui::screens::default_relays(),
            }),
            PairMode::Manual => Some(ServerMode::Manual),
        }
    }

    /// Build the dial spec from the current state, if it validates. Configure
    /// mode dials exactly the peer selected in the hub (which must be hosting).
    pub(crate) fn client_dial_spec(&self) -> Option<duocb_core::net::DialSpec> {
        use duocb_core::net::DialSpec;
        match self.mode {
            PairMode::NostrToken => Some(DialSpec::NostrToken {
                identity: self.token_identity()?,
                peer_display: self.selected_hosting_peer_display()?,
            }),
            PairMode::NostrPin => {
                duocb_core::pin::normalize_pin(&self.in_pin).map(|canonical_pin| DialSpec::Pin {
                    canonical_pin,
                    relays: crate::ui::screens::default_relays(),
                })
            }
            PairMode::Manual => {
                let node_id = self.in_node_id.trim();
                let token = self.in_manual_token.trim();
                (!node_id.is_empty() && duocb_core::auth::validate_token(token).is_ok()).then(|| {
                    DialSpec::Manual {
                        node_id: node_id.to_string(),
                        token: token.to_string(),
                    }
                })
            }
        }
    }

    /// Go to the start screen and launch. Every mode starts immediately now:
    /// the configure mode's identity lives on the home hub, and the quick modes
    /// never had a pre-start form.
    pub(crate) fn begin_server(&mut self) {
        if self.server_mode_spec().is_none() {
            return;
        }
        self.screen = Screen::Server;
        self.start_server();
    }

    /// Start the server session if the state validates.
    pub(crate) fn start_server(&mut self) {
        if let Some(mode) = self.server_mode_spec() {
            self.server_running = true;
            self.net.send(UiCommand::StartServer { mode });
        }
    }

    /// Start the client session if the state validates.
    pub(crate) fn connect_client(&mut self) {
        if let Some(spec) = self.client_dial_spec() {
            if let duocb_core::net::DialSpec::NostrToken { peer_display, .. } = &spec {
                self.joined_peer = Some(peer_display.clone());
            }
            self.client_active = true;
            self.net.send(UiCommand::Connect { spec });
        }
    }

    /// Global keyboard shortcuts. Plain letter keys are only bound on the home
    /// screen (which has no text fields); everywhere else shortcuts require
    /// the platform command modifier (Ctrl on Windows/Linux, Command on macOS)
    /// so typing into fields is never hijacked. Escape is ignored while a text
    /// field has focus (egui uses it to release focus).
    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        use egui::{Key, Modifiers};

        let focus_free = ctx.memory(|m| m.focused().is_none());
        if focus_free
            && self.screen != Screen::Home
            && ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape))
        {
            self.go_back();
            return;
        }

        match self.screen {
            Screen::Home => {
                // Plain letters/digits only while no text field has focus — the
                // configure wizard and hub put editable fields on this screen.
                if focus_free {
                    // 1 = configure (primary), 2 = PIN quick pair, 3 = manual.
                    if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Num1)) {
                        self.mode = PairMode::NostrToken;
                    }
                    if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Num2)) {
                        self.mode = PairMode::NostrPin;
                    }
                    if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Num3)) {
                        self.mode = PairMode::Manual;
                    }
                    if self.mode == PairMode::NostrToken {
                        self.handle_configure_shortcuts(ctx);
                    } else {
                        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::S)) {
                            self.begin_server();
                        }
                        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::C)) {
                            self.screen = Screen::Client;
                        }
                    }
                }
            }
            Screen::Server => {
                // Copy displayed initiator credentials without the mouse.
                if let Some(node_id) = self.node_id.clone()
                    && ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::I))
                {
                    self.copy_to_clipboard(&node_id);
                }
                if let Some(token) = self.manual_token.clone()
                    && ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::T))
                {
                    self.copy_to_clipboard(&token);
                }
            }
            Screen::Client => {
                if !self.client_active
                    && ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::Enter))
                {
                    self.connect_client();
                }
            }
        }

        self.handle_session_shortcuts(ctx, focus_free);
    }

    /// Configure-mode home shortcuts, per wizard/hub step. Only called with no
    /// text field focused.
    fn handle_configure_shortcuts(&mut self, ctx: &egui::Context) {
        use egui::{Key, Modifiers};
        match self.configure_step {
            ConfigureStep::SetupChoice => {
                if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::G)) {
                    self.begin_generate_secret();
                }
                if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::I)) {
                    self.configure_step = ConfigureStep::SetupImport;
                }
            }
            ConfigureStep::SetupGenerate | ConfigureStep::SetupImport => {
                if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape)) {
                    self.wizard_token = None;
                    self.in_import_token.clear();
                    self.configure_step = ConfigureStep::SetupChoice;
                }
            }
            ConfigureStep::SetupName => {
                if self.has_saved_identity()
                    && ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape))
                {
                    self.reset_name_field();
                    self.configure_step = ConfigureStep::Ready;
                }
            }
            ConfigureStep::Ready => {
                if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::S)) {
                    self.begin_server();
                }
                if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::C))
                    || ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Enter))
                {
                    self.join_selected_peer();
                }
                if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::R)) {
                    self.refresh_peers();
                }
                if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::ArrowDown)) {
                    self.move_peer_selection(1);
                }
                if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::ArrowUp)) {
                    self.move_peer_selection(-1);
                }
                if let Some(secret) = self.secret.clone()
                    && ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::T))
                {
                    self.copy_to_clipboard(&secret);
                }
            }
        }
    }

    /// Shortcuts for a live paired session (any screen).
    fn handle_session_shortcuts(&mut self, ctx: &egui::Context, focus_free: bool) {
        use egui::{Key, Modifiers};
        // Session shortcuts are also gated on no text field having focus, so
        // TextEdit editing shortcuts (e.g. Ctrl/Command+Y redo) and destructive actions
        // like clearing the inbox can't fire while typing or selecting text.
        if self.status == ConnStatus::Connected && focus_free {
            if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::S)) {
                self.send_clipboard();
            }
            if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::P))
                && let Some(item) = self.inbox.first_mut()
            {
                item.toggle_peek();
            }
            // Ctrl/Command+Y ("yank"): the platform Copy shortcuts are intercepted
            // by egui's winit layer and never reach key handling.
            if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::Y))
                && let Some(text) = self.inbox.first().map(|i| i.text.clone())
            {
                self.copy_to_clipboard(&text);
            }
            if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::L)) {
                self.inbox.clear();
            }
        }
    }

    /// The on-demand connection-path modal: a point-in-time snapshot of how the
    /// session is currently routed (direct vs. relay, with RTT). Dismissed by
    /// the Close button or a click on the backdrop.
    fn conn_path_modal(&mut self, ctx: &egui::Context) {
        let Some(paths) = self.conn_path.clone() else {
            return;
        };
        let mut close = false;
        let response = egui::Modal::new(egui::Id::new("conn_path_modal")).show(ctx, |ui| {
            ui.set_max_width(460.0);
            ui.heading("Connection path");
            ui.add_space(4.0);
            if paths.is_empty() {
                ui.label("No active connection.");
            } else {
                for path in &paths {
                    let color = match path.kind {
                        duocb_core::net::endpoint::ConnPathKind::Direct => {
                            egui::Color32::from_rgb(0x2e, 0xa0, 0x43)
                        }
                        duocb_core::net::endpoint::ConnPathKind::Relay => {
                            egui::Color32::from_rgb(0xd2, 0x92, 0x22)
                        }
                        duocb_core::net::endpoint::ConnPathKind::Other => ui.visuals().weak_text_color(),
                    };
                    ui.horizontal(|ui| {
                        let marker = if path.selected { "●" } else { "○" };
                        ui.colored_label(color, marker);
                        ui.label(egui::RichText::new(&path.display).monospace());
                    });
                }
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new("● selected route · ○ other known path")
                        .weak()
                        .small(),
                );
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Close").clicked() {
                    close = true;
                }
                if ui.button("Refresh").clicked() {
                    self.query_conn_path();
                }
            });
        });
        if close || response.backdrop_response.clicked() {
            self.conn_path = None;
        }
    }

    fn error_banner(&mut self, ui: &mut egui::Ui) {
        let Some(error) = self.error.clone() else {
            return;
        };
        let mut dismissed = false;
        egui::Frame::group(ui.style())
            .fill(ui.visuals().error_fg_color.gamma_multiply(0.15))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(ui.visuals().error_fg_color, &error);
                    if ui.small_button("✕").clicked() {
                        dismissed = true;
                    }
                });
            });
        if dismissed {
            self.error = None;
        }
        ui.add_space(6.0);
    }
}

impl eframe::App for DuocbApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drain runtime events first so the frame renders the latest state.
        let events: Vec<NetEvent> = {
            let rx = &self.net.events;
            std::iter::from_fn(|| rx.try_recv().ok()).collect()
        };
        for event in events {
            self.apply_event(event);
        }

        self.handle_shortcuts(ctx);

        // While the configure hub is visible, keep the peer list fresh (the
        // runtime ignores a refresh while one is already in flight) and its
        // last-seen labels ticking.
        if self.screen == Screen::Home
            && self.mode == PairMode::NostrToken
            && self.configure_step == ConfigureStep::Ready
        {
            let due = self
                .peers_requested_at
                .is_none_or(|at| at.elapsed() >= PEER_REFRESH_INTERVAL);
            if due {
                self.refresh_peers();
            }
            ctx.request_repaint_after(Duration::from_secs(1));
        }

        // Auto-hide peeked items after PEEK_TIMEOUT (see ClipItem::tick_peek).
        let mut any_peeked = false;
        for item in self.inbox.iter_mut().chain(self.outbox.iter_mut()) {
            any_peeked |= item.tick_peek();
        }

        // Keep the PIN countdown, "sent" flash, and peek auto-hide ticking
        // without user input.
        if self.pin_display.is_some() || self.sent_flash_active() || any_peeked {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Frame::central_panel(ui.style()).show(ui, |ui| {
            self.error_banner(ui);
            match self.screen {
                Screen::Home => screens::show_home(self, ui),
                Screen::Server => screens::show_server(self, ui),
                Screen::Client => screens::show_client(self, ui),
            }
        });
        self.conn_path_modal(ui.ctx());
    }

    fn on_exit(&mut self) {
        self.net.shutdown();
    }
}

/// Render the shared "paired" session panel (send button + outbox + inbox),
/// used by both connection roles, when connected.
pub(crate) fn session_panel_if_connected(app: &mut DuocbApp, ui: &mut egui::Ui) {
    if app.status == ConnStatus::Connected {
        session::show_session(app, ui);
    }
}
