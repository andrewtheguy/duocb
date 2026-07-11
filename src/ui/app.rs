//! The eframe application: drains runtime events, routes screens, and holds
//! all UI state (including the in-memory inbox — clipboard content never
//! touches disk).

use std::time::{Duration, Instant};

use eframe::egui;

use crate::clipboard::SystemClipboard;
use crate::net::{ConnStatus, NetEvent, NetHandle, UiCommand, spawn_net_runtime};
use crate::ui::{ClipItem, PairMode, Screen, screens, session};

/// How long the "sent ✓" flash stays visible.
const SENT_FLASH: Duration = Duration::from_secs(2);

/// Retention cap for the in-memory inbox: newest-first, only the last few
/// received items are kept and older ones are dropped.
const MAX_INBOX_ITEMS: usize = 5;

pub struct DuocbApp {
    pub(crate) net: NetHandle,
    pub(crate) clipboard: SystemClipboard,

    // Navigation.
    pub(crate) screen: Screen,
    pub(crate) mode: PairMode,

    // Shared status.
    pub(crate) status: ConnStatus,
    pub(crate) error: Option<String>,

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
    pub(crate) in_token: String,
    pub(crate) in_my_name: String,
    pub(crate) in_peer_name: String,
    pub(crate) in_pin: String,
    pub(crate) in_node_id: String,
    pub(crate) in_manual_token: String,

    // Live session state.
    pub(crate) peer_node_id: Option<String>,
    pub(crate) path_display: Option<String>,
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
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let net = spawn_net_runtime(cc.egui_ctx.clone());
        let config = crate::config::Config::load();
        Self {
            net,
            clipboard: SystemClipboard::new(),
            screen: Screen::Home,
            mode: PairMode::NostrPin,
            status: ConnStatus::Idle,
            error: None,
            server_running: false,
            node_id: None,
            manual_token: None,
            token_fingerprint: None,
            pin_display: None,
            pin_deadline: None,
            pin_paired: false,
            client_active: false,
            in_token: config.auth_token.unwrap_or_default(),
            in_my_name: config.my_name.unwrap_or_default(),
            in_peer_name: config.peer_name.unwrap_or_default(),
            in_pin: String::new(),
            in_node_id: String::new(),
            in_manual_token: String::new(),
            peer_node_id: None,
            path_display: None,
            inbox: Vec::new(),
            outbox: None,
            pending_outbox: None,
            sent_flash: None,
        }
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
                    self.pin_display = None;
                    self.pin_deadline = None;
                    self.pin_paired = false;
                    self.peer_node_id = None;
                    self.path_display = None;
                    self.pending_outbox = None;
                }
                self.status = status;
            }
            NetEvent::PeerPaired { peer_node_id } => {
                self.peer_node_id = Some(peer_node_id);
                // The manual-mode one-time token is consumed by pairing: stop
                // displaying/copying it on the server and drop the client's
                // typed copy. (A new server session mints a fresh one anyway.)
                self.manual_token = None;
                self.in_manual_token.clear();
            }
            NetEvent::PeerDisconnected => {
                self.peer_node_id = None;
                self.path_display = None;
            }
            NetEvent::PathUpdate(path) => {
                self.path_display = Some(path);
            }
            NetEvent::ItemReceived { text, .. } => {
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
            NetEvent::Error(message) => {
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

    /// Persist the token-mode form fields (explicit "Remember" action only).
    pub(crate) fn remember_token_settings(&mut self) {
        let cfg = crate::config::Config {
            auth_token: Some(self.in_token.trim().to_string()).filter(|s| !s.is_empty()),
            my_name: Some(self.in_my_name.trim().to_string()).filter(|s| !s.is_empty()),
            peer_name: Some(self.in_peer_name.trim().to_string()).filter(|s| !s.is_empty()),
        };
        if let Err(e) = cfg.save() {
            self.error = Some(format!("Could not save the settings: {e:#}"));
        }
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

    /// Build the server mode from the current inputs, if they validate.
    pub(crate) fn server_mode_spec(&self) -> Option<crate::net::ServerMode> {
        use crate::net::ServerMode;
        match self.mode {
            PairMode::NostrToken => {
                let token = self.in_token.trim();
                let name = self.in_my_name.trim();
                (crate::auth::validate_token(token).is_ok() && !name.is_empty()).then(|| {
                    ServerMode::NostrToken {
                        token: token.to_string(),
                        name: name.to_string(),
                        relays: crate::ui::screens::default_relays(),
                    }
                })
            }
            PairMode::NostrPin => Some(ServerMode::NostrPin {
                relays: crate::ui::screens::default_relays(),
            }),
            PairMode::Manual => Some(ServerMode::Manual),
        }
    }

    /// Build the dial spec from the current inputs, if they validate.
    pub(crate) fn client_dial_spec(&self) -> Option<crate::net::DialSpec> {
        use crate::net::DialSpec;
        match self.mode {
            PairMode::NostrToken => {
                let token = self.in_token.trim();
                let peer = self.in_peer_name.trim();
                (crate::auth::validate_token(token).is_ok() && !peer.is_empty()).then(|| {
                    DialSpec::NostrToken {
                        token: token.to_string(),
                        peer_name: peer.to_string(),
                        relays: crate::ui::screens::default_relays(),
                    }
                })
            }
            PairMode::NostrPin => {
                crate::pin::normalize_pin(&self.in_pin).map(|canonical_pin| DialSpec::Pin {
                    canonical_pin,
                    relays: crate::ui::screens::default_relays(),
                })
            }
            PairMode::Manual => {
                let node_id = self.in_node_id.trim();
                let token = self.in_manual_token.trim();
                (!node_id.is_empty() && crate::auth::validate_token(token).is_ok()).then(|| {
                    DialSpec::Manual {
                        node_id: node_id.to_string(),
                        token: token.to_string(),
                    }
                })
            }
        }
    }

    /// Start the server session if the inputs validate.
    pub(crate) fn start_server(&mut self) {
        if let Some(mode) = self.server_mode_spec() {
            self.server_running = true;
            self.net.send(UiCommand::StartServer { mode });
        }
    }

    /// Start the client session if the inputs validate.
    pub(crate) fn connect_client(&mut self) {
        if let Some(spec) = self.client_dial_spec() {
            self.client_active = true;
            self.net.send(UiCommand::Connect { spec });
        }
    }

    /// Global keyboard shortcuts. Plain letter keys are only bound on the home
    /// screen (which has no text fields); everywhere else shortcuts require
    /// Ctrl so typing into fields is never hijacked. Escape is ignored while a
    /// text field has focus (egui uses it to release focus).
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
                if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Num1)) {
                    self.mode = PairMode::NostrPin;
                }
                if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Num2)) {
                    self.mode = PairMode::NostrToken;
                }
                if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Num3)) {
                    self.mode = PairMode::Manual;
                }
                if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::S)) {
                    self.screen = Screen::Server;
                }
                if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::C)) {
                    self.screen = Screen::Client;
                }
            }
            Screen::Server => {
                if !self.server_running
                    && ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::Enter))
                {
                    self.start_server();
                }
                // Manual mode: copy the displayed credentials without the mouse.
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

        // Session shortcuts are also gated on no text field having focus, so
        // TextEdit editing shortcuts (e.g. Ctrl+Y redo) and destructive actions
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
            // Ctrl+Y ("yank"): Ctrl+C / Ctrl+Shift+C are intercepted by egui's
            // winit layer as the built-in Copy event and never reach key handling.
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
