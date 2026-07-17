//! The application state and logic: drains runtime events, routes screens,
//! and holds all UI state (including the in-memory inbox — clipboard content
//! never touches disk). Rendering lives in the `ui/*.slint` files; this state
//! is projected into them by [`sync`](App::sync) and mutated by the `Actions`
//! callbacks (`callbacks.rs`) and global shortcuts (`keys.rs`).

pub(crate) mod callbacks;
pub(crate) mod item;
pub(crate) mod keys;
mod sync;

use std::time::{Duration, Instant};

use crate::clipboard::SystemClipboard;
use crate::{ConfigureStep, PairMode, PinChannel, Screen};
use duocb_core::net::endpoint::ConnPath;
use duocb_core::net::{ConnStatus, NetEvent, NetHandle, TokenIdentity, UiCommand};
use duocb_core::nostr::PeerInfo;
use item::ClipItem;

/// How long the "sent ✓" / "✔ Copied" flashes stay visible.
const SENT_FLASH: Duration = Duration::from_secs(2);

/// Retention cap for the in-memory inbox: newest-first, only the last few
/// received items are kept and older ones are dropped.
const MAX_INBOX_ITEMS: usize = 5;

/// How often the device picker auto-refreshes the peer list while visible.
const PEER_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

pub(crate) struct App {
    pub(crate) config_lock: crate::config::ConfigLock,
    pub(crate) net: NetHandle,
    pub(crate) clipboard: SystemClipboard,

    // Navigation.
    pub(crate) screen: Screen,
    pub(crate) mode: PairMode,
    /// Which rendezvous transport(s) the PIN quick mode uses (both sides must
    /// have overlapping channels; the default covers everything).
    pub(crate) pin_channel: PinChannel,
    /// Whether the user has expanded the quick screen's "Advanced options"
    /// section. The section also shows whenever an advanced option is the
    /// active selection (see `quick_advanced_open`), so a live choice is never
    /// hidden regardless of this flag.
    pub(crate) quick_advanced_expanded: bool,

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
    /// Whether the presence publisher is running. Stays `false` at launch —
    /// nostr is dormant until the user picks Start or Join on the hub — so
    /// [`ensure_presence`](App::ensure_presence) can start it exactly once
    /// without needlessly restarting (and risking a false self-conflict).
    pub(crate) presence_active: bool,
    pub(crate) confirm_clear_secret: bool,

    // Server presentation state.
    pub(crate) server_running: bool,
    pub(crate) node_id: Option<String>,
    /// The host's LAN IPv4 on the LAN-only channel, surfaced so the joiner can
    /// type it for the manual-IP side channel (from [`NetEvent::PinRotated`]);
    /// `None` on other channels or before an address is known.
    pub(crate) host_lan_ip: Option<String>,
    pub(crate) token_fingerprint: Option<String>,
    pub(crate) pin_display: Option<String>,
    pub(crate) pin_deadline: Option<Instant>,
    /// PIN cleared because a peer paired (vs. never shown).
    pub(crate) pin_paired: bool,

    // Client-side session flag (a dial session exists, connected or retrying).
    pub(crate) client_active: bool,

    // Form inputs (mirrors of the UI's two-way field properties, updated on
    // every edit; authoritative — sync writes them back, which is how resets
    // reach the fields).
    pub(crate) in_my_name: String,
    pub(crate) in_import_token: String,
    /// The joiner's PIN entry, split into its two `XXXX` groups (one text field
    /// each) so grouping never edits a field's text mid-keystroke.
    pub(crate) in_pin_a: String,
    pub(crate) in_pin_b: String,
    /// The joiner's optional host-IP entry, shown only for a LAN-only PIN. Holds
    /// only the *host part* typed after the locked network prefix (or a full
    /// address pasted whole); [`App::join_ip_ctx`] resolves and range-checks it.
    /// When it resolves to an in-range address it selects the unicast side
    /// channel (see [`App::quick_dial_spec`]); blank resolves via mDNS.
    pub(crate) in_join_ip: String,
    /// The local-subnet constraint the host-IP entry is held to (this device's
    /// own private IPv4 subnet). Detected when the quick screen opens; drives
    /// the locked prefix, the range hint, and out-of-range rejection.
    pub(crate) join_ip_ctx: duocb_core::subnet::JoinIpConstraint,
    /// Draft of the session panel's compose field (send typed text).
    pub(crate) in_compose: String,

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
    /// Which copy button was last used and when, for the per-button "✔ Copied"
    /// feedback. Only a successful copy sets this; a failure raises the error
    /// banner instead (see [`App::copy_with_flash`]).
    pub(crate) copied_flash: Option<(CopyTarget, Instant)>,
}

/// Which copy button a successful copy came from, so only that button shows the
/// "✔ Copied" flash. `Inbox` carries the row index (the newest is 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CopyTarget {
    Secret,
    Pin,
    Outbox,
    Inbox(usize),
}

impl App {
    pub(crate) fn new(config_lock: crate::config::ConfigLock, net: NetHandle) -> Self {
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

        // Nostr stays dormant at launch: the presence broadcast and the peer
        // fetch only start when the user picks Start a connection or Join
        // another device on the hub, so opening the app (or using only quick
        // mode) never touches the relays.
        Self {
            config_lock,
            net,
            clipboard: SystemClipboard::new(),
            screen: Screen::Home,
            mode: PairMode::NostrToken,
            pin_channel: PinChannel::Both,
            quick_advanced_expanded: false,
            status: ConnStatus::Idle,
            error: startup_error,
            secret,
            saved_name: saved_name.clone(),
            device_suffix,
            configure_step,
            peers: Vec::new(),
            peers_refreshed_at: None,
            peers_requested_at: None,
            selected_peer: None,
            joined_peer: None,
            presence_conflict: None,
            presence_active: false,
            confirm_clear_secret: false,
            server_running: false,
            node_id: None,
            host_lan_ip: None,
            token_fingerprint: None,
            pin_display: None,
            pin_deadline: None,
            pin_paired: false,
            client_active: false,
            in_my_name: saved_name.unwrap_or_default(),
            in_import_token: String::new(),
            in_pin_a: String::new(),
            in_pin_b: String::new(),
            in_join_ip: String::new(),
            join_ip_ctx: duocb_core::subnet::JoinIpConstraint::unconstrained(),
            in_compose: String::new(),
            peer_node_id: None,
            conn_path: None,
            inbox: Vec::new(),
            outbox: None,
            pending_outbox: None,
            sent_flash: None,
            copied_flash: None,
        }
    }

    /// Drain every event the runtime has queued. Returns whether any arrived
    /// (i.e. whether the UI projection needs a refresh).
    pub(crate) fn drain_events(&mut self) -> bool {
        let events: Vec<NetEvent> = {
            let rx = &self.net.events;
            std::iter::from_fn(|| rx.try_recv().ok()).collect()
        };
        let any = !events.is_empty();
        for event in events {
            self.apply_event(event);
        }
        any
    }

    pub(crate) fn apply_event(&mut self, event: NetEvent) {
        match event {
            NetEvent::ServerReady {
                node_id,
                token_fingerprint,
            } => {
                self.node_id = Some(node_id);
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
                host_lan_ip,
            } => {
                self.pin_display = Some(pin_display);
                self.pin_deadline = Some(Instant::now() + Duration::from_secs(seconds_left));
                self.pin_paired = false;
                self.host_lan_ip = host_lan_ip;
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
                    self.host_lan_ip = None;
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

    /// Periodic work, driven by the UI's heartbeat timer: peek auto-hide and
    /// the device picker's list refresh. Flash/countdown expiry needs no state
    /// change — `sync` derives those from timestamps.
    pub(crate) fn tick(&mut self) {
        for item in self.inbox.iter_mut().chain(self.outbox.iter_mut()) {
            item.tick_peek();
        }
        // While the device picker is visible, keep the peer list fresh (the
        // runtime ignores a refresh while one is already in flight). The hub
        // itself shows no list, so nothing is polled there.
        if self.screen == Screen::Home
            && self.mode == PairMode::NostrToken
            && self.configure_step == ConfigureStep::Join
        {
            let due = self
                .peers_requested_at
                .is_none_or(|at| at.elapsed() >= PEER_REFRESH_INTERVAL);
            if due {
                self.refresh_peers();
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
            Ok(text) => self.send_text(text),
            Err(e) => self.error = Some(format!("Could not read the clipboard: {e:#}")),
        }
    }

    /// Send arbitrary text (the compose field, or a just-read clipboard) to
    /// the peer. One in-flight send at a time, like the outbox slot.
    pub(crate) fn send_text(&mut self, text: String) {
        if text.is_empty() || self.pending_outbox.is_some() {
            return;
        }
        // Stash it; it becomes the outbox item once ItemSent confirms.
        self.pending_outbox = Some(text.clone());
        self.net.send(UiCommand::SendClipboard { text });
    }

    /// Send the compose field's draft and clear it (one in-flight send; the
    /// draft is kept if a previous send is still unconfirmed).
    pub(crate) fn compose_send(&mut self) {
        if self.in_compose.is_empty() || self.pending_outbox.is_some() {
            return;
        }
        let text = std::mem::take(&mut self.in_compose);
        self.send_text(text);
    }

    /// Copy arbitrary text (an inbox item, the node id, the token) to the
    /// system clipboard, surfacing failures in the error banner. Returns
    /// whether the copy succeeded, so callers can show feedback.
    pub(crate) fn copy_to_clipboard(&mut self, text: &str) -> bool {
        match self.clipboard.write_text(text) {
            Ok(()) => true,
            Err(e) => {
                self.error = Some(format!("Could not write the clipboard: {e:#}"));
                false
            }
        }
    }

    /// Copy `text` and, on success, flash "✔ Copied" on the originating button
    /// (`target`); on failure the error banner shows the reason instead. Every
    /// copy button routes through here so all of them confirm the result.
    pub(crate) fn copy_with_flash(&mut self, text: &str, target: CopyTarget) {
        let text = text.to_string();
        if self.copy_to_clipboard(&text) {
            self.copied_flash = Some((target, Instant::now()));
        }
    }

    /// The copy button that should currently show "✔ Copied", if any (the flash
    /// is fresh). Buttons compare their own [`CopyTarget`] against this.
    pub(crate) fn copied_target(&self) -> Option<CopyTarget> {
        self.copied_flash
            .filter(|(_, t)| t.elapsed() < SENT_FLASH)
            .map(|(target, _)| target)
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
            relays: default_relays(),
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
        let identity = self.token_identity();
        self.presence_active = identity.is_some();
        self.net.send(UiCommand::SetPresence { identity });
    }

    /// Start the presence broadcast if it isn't already running. This is the
    /// single entry point that wakes nostr up, called when the user first acts
    /// on the hub (Start a connection or Join another device); it is idempotent
    /// so re-entering the picker never restarts a healthy publisher.
    pub(crate) fn ensure_presence(&mut self) {
        if !self.presence_active && self.token_identity().is_some() {
            self.sync_presence();
        }
    }

    /// Ask the runtime for a fresh peer device list.
    pub(crate) fn refresh_peers(&mut self) {
        if self.has_saved_identity() {
            self.peers_requested_at = Some(Instant::now());
            self.net.send(UiCommand::RefreshPeers);
        }
    }

    /// Generate a fresh secret and go straight to naming this device. There is
    /// no separate "save the secret" step: it is persisted immediately and can
    /// be copied from the hub at any time (Copy secret), so a confirm-you-saved-
    /// it screen would only add a click without safeguarding anything.
    pub(crate) fn begin_generate_secret(&mut self) {
        self.set_secret(duocb_core::auth::generate_token());
    }

    /// Commit the pasted secret from the import step, if it validates.
    pub(crate) fn use_imported_secret(&mut self) {
        let token = self.in_import_token.trim().to_string();
        if duocb_core::auth::validate_token(&token).is_ok() {
            self.in_import_token.clear();
            self.set_secret(token);
        }
    }

    /// Cancel the import step back to the choice.
    pub(crate) fn cancel_setup(&mut self) {
        self.in_import_token.clear();
        self.configure_step = ConfigureStep::SetupChoice;
    }

    /// Commit a generated or imported secret and move on to naming the device.
    pub(crate) fn set_secret(&mut self, token: String) {
        self.secret = Some(token);
        self.save_configure_config();
        self.reset_name_field();
        self.configure_step = ConfigureStep::SetupName;
    }

    /// Prefill the name field from the confirmed name.
    pub(crate) fn reset_name_field(&mut self) {
        self.in_my_name = self.saved_name.clone().unwrap_or_default();
    }

    /// Confirm the name field: persist it and enter the hub. Presence stays
    /// dormant until the user picks Start or Join there (see `ensure_presence`).
    pub(crate) fn save_name(&mut self) {
        let name = self.in_my_name.trim().to_string();
        if duocb_core::identity::validate_name(&name).is_err() {
            return;
        }
        self.saved_name = Some(name);
        if self.save_configure_config() {
            self.configure_step = ConfigureStep::Ready;
            // A rename while nostr is already awake (the user paired earlier
            // this session) rebroadcasts under the new name; otherwise presence
            // stays dormant until the next Start/Join.
            if self.presence_active {
                self.sync_presence();
            }
        }
    }

    /// Leave the name step without saving (only when an identity exists).
    pub(crate) fn cancel_name(&mut self) {
        if self.has_saved_identity() {
            self.reset_name_field();
            self.configure_step = ConfigureStep::Ready;
        }
    }

    /// Clear the standing secret (explicit, confirmed): stop broadcasting and
    /// return to the setup wizard. The permanent suffix is kept; the name stays
    /// as a prefill for the next setup.
    pub(crate) fn clear_secret(&mut self) {
        self.secret = None;
        self.save_configure_config();
        self.presence_active = false;
        self.net.send(UiCommand::SetPresence { identity: None });
        self.peers.clear();
        self.selected_peer = None;
        self.peers_refreshed_at = None;
        self.peers_requested_at = None;
        self.presence_conflict = None;
        self.in_import_token.clear();
        self.configure_step = ConfigureStep::SetupChoice;
    }

    /// The selected peer's display identity. Any listed device may be joined:
    /// the dial re-resolves the record on every attempt and retries at a fixed
    /// interval (a bounded number of times), so a join placed shortly before the
    /// other device presses Start succeeds once it does.
    pub(crate) fn selected_peer_display(&self) -> Option<String> {
        let suffix = self.selected_peer.as_deref()?;
        self.peers
            .iter()
            .find(|p| p.suffix == suffix)
            .map(|p| p.display())
    }

    /// Open the device picker (the hub's Join action). Wakes nostr up (this is
    /// one of the two entry points that do) and refreshes the list on entry
    /// unless a fetch just went out.
    pub(crate) fn enter_join_picker(&mut self) {
        self.configure_step = ConfigureStep::Join;
        self.ensure_presence();
        let fresh = self
            .peers_requested_at
            .is_some_and(|at| at.elapsed() < Duration::from_secs(5));
        if !fresh {
            self.refresh_peers();
        }
    }

    /// Leave the device picker back to the hub, putting nostr back to sleep.
    pub(crate) fn leave_join_picker(&mut self) {
        self.configure_step = ConfigureStep::Ready;
        self.stop_presence();
    }

    /// Toggle the picker selection for a peer row (by stable suffix).
    pub(crate) fn toggle_peer(&mut self, suffix: &str) {
        self.selected_peer = if self.selected_peer.as_deref() == Some(suffix) {
            None
        } else {
            Some(suffix.to_string())
        };
    }

    /// Join the selected peer from the device picker.
    pub(crate) fn join_selected_peer(&mut self) {
        if self.client_dial_spec().is_some() {
            self.screen = Screen::Client;
            self.connect_client();
        }
    }

    /// Move the picker's peer selection up/down (keyboard navigation).
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
            ConnStatus::Reconnecting { attempt, max } => {
                format!("Reconnecting… (attempt {attempt} of {max})")
            }
        }
    }

    /// Stop whatever session is running (used by the back actions).
    pub(crate) fn stop_session(&mut self) {
        if self.server_running {
            self.net.send(UiCommand::StopServer);
        } else if self.client_active {
            self.net.send(UiCommand::Disconnect);
        }
    }

    /// Put nostr back to sleep: stop the presence broadcast and peer discovery.
    /// Called when the user leaves every nostr flow (Start/Join) back to the
    /// hub, so the plain home screen holds no relay connections. Idempotent.
    pub(crate) fn stop_presence(&mut self) {
        if !self.presence_active {
            return;
        }
        self.presence_active = false;
        self.presence_conflict = None;
        // Force the next Join to re-fetch: the list is no longer kept fresh.
        self.peers_requested_at = None;
        self.net.send(UiCommand::SetPresence { identity: None });
    }

    /// Open the quick-options screen (ad-hoc rotating-PIN pairing).
    pub(crate) fn open_quick(&mut self) {
        self.screen = Screen::Quick;
        // Home implies configure mode; entering the quick screen picks its
        // default so the actions there never run configure mode.
        if self.mode == PairMode::NostrToken {
            self.mode = PairMode::NostrPin;
        }
        // Start with the advanced options collapsed; they still reveal
        // themselves if an advanced option is the active selection.
        self.quick_advanced_expanded = false;
        // Detect this device's LAN subnet so a LAN-only join can lock the host
        // IP's network octets to it and reject an out-of-range address. Read
        // once on entry — a mid-session network change is rare and the field is
        // optional anyway (blank falls back to mDNS).
        self.join_ip_ctx = duocb_core::subnet::JoinIpConstraint::detect();
    }

    /// Select the PIN rendezvous channel (the quick screen's P/L/I rows); it
    /// applies to both the host and join actions there.
    pub(crate) fn set_pin_channel(&mut self, channel: PinChannel) {
        self.mode = PairMode::NostrPin;
        self.pin_channel = channel;
    }

    /// Quick join: dial what the quick screen's join entry holds (the typed PIN,
    /// plus an optional host IP for a LAN-only PIN) and move to the client
    /// screen. A no-op while the entry doesn't validate (the Join action is
    /// disabled then — see `dial-ready`).
    pub(crate) fn join_quick(&mut self) {
        if self.client_dial_spec().is_some() {
            self.connect_client();
            self.screen = Screen::Client;
        }
    }

    /// Whether the current quick-mode selection is one of the "uncommon"
    /// (testing-leaning) options — currently only internet-only PIN discovery.
    /// Used to keep the quick screen's uncommon section open while such an
    /// option is active, so the live choice is never hidden.
    pub(crate) fn quick_uncommon_selected(&self) -> bool {
        self.mode == PairMode::NostrPin && self.pin_channel == PinChannel::NostrOnly
    }

    /// Whether the quick screen's uncommon section should render open.
    pub(crate) fn quick_advanced_open(&self) -> bool {
        self.quick_advanced_expanded || self.quick_uncommon_selected()
    }

    /// Navigate back one screen, stopping any running session. Role screens
    /// return to where they launched from (the quick-options screen for the
    /// quick modes, the home hub for configure mode); leaving the quick
    /// screen restores the home invariant (mode = configure).
    pub(crate) fn go_back(&mut self) {
        self.stop_session();
        self.screen = match (self.screen, self.mode) {
            (Screen::Server | Screen::Client, PairMode::NostrPin) => Screen::Quick,
            _ => {
                self.mode = PairMode::NostrToken;
                Screen::Home
            }
        };
        // Home is the hub, not the device picker a join may have started from.
        if self.configure_step == ConfigureStep::Join {
            self.configure_step = ConfigureStep::Ready;
        }
        // Back on the plain hub, nostr goes dormant again until the next
        // Start/Join. (Leaving a quick-mode role lands on Quick, not Home, and
        // never ran presence anyway.)
        if self.screen == Screen::Home {
            self.stop_presence();
        }
    }

    /// The selected PIN channel as the core's enum.
    fn core_pin_channel(&self) -> duocb_core::net::PinChannel {
        use duocb_core::net::PinChannel as Core;
        match self.pin_channel {
            PinChannel::Both => Core::NostrAndLan,
            PinChannel::NostrOnly => Core::NostrOnly,
            PinChannel::LanOnly => Core::LanOnly,
        }
    }

    /// Build the server mode from the current state, if it validates.
    pub(crate) fn server_mode_spec(&self) -> Option<duocb_core::net::ServerMode> {
        use duocb_core::net::ServerMode;
        match self.mode {
            PairMode::NostrToken => self
                .token_identity()
                .map(|identity| ServerMode::NostrToken { identity }),
            PairMode::NostrPin => Some(ServerMode::Pin {
                relays: default_relays(),
                channel: self.core_pin_channel(),
            }),
        }
    }

    /// Build the dial spec from the current state, if it validates. Configure
    /// mode dials exactly the peer selected in the device picker; the quick
    /// modes join from what was *entered*, independent of the show-side channel
    /// choice (see [`App::quick_dial_spec`]).
    pub(crate) fn client_dial_spec(&self) -> Option<duocb_core::net::DialSpec> {
        use duocb_core::net::DialSpec;
        match self.mode {
            PairMode::NostrToken => Some(DialSpec::NostrToken {
                identity: self.token_identity()?,
                peer_display: self.selected_peer_display()?,
            }),
            PairMode::NostrPin => self.quick_dial_spec(),
        }
    }

    /// The current validation outcome of the host-IP entry against the detected
    /// subnet constraint — the single source for both the displayed error
    /// (`sync`) and the dial's `target_ip` (`quick_dial_spec`).
    pub(crate) fn join_ip_outcome(&self) -> duocb_core::subnet::JoinIpOutcome {
        self.join_ip_ctx.resolve(&self.in_join_ip)
    }

    /// The quick-join dial spec, derived purely from the join entry — never from
    /// the show-side P/L/I choice. The typed PIN's first character selects the
    /// channel (see `duocb_core::pin`); for a LAN-only PIN the optional host-IP
    /// entry, resolved and range-checked against this device's own subnet (see
    /// [`App::join_ip_ctx`]), selects the unicast side channel (blank resolves
    /// via mDNS). `None` when the PIN is incomplete/invalid, or the typed host IP
    /// is malformed or out of range — which is what keeps the Join button
    /// disabled.
    fn quick_dial_spec(&self) -> Option<duocb_core::net::DialSpec> {
        use duocb_core::net::{DialSpec, PinChannel as Core};
        use duocb_core::subnet::JoinIpOutcome;
        let canonical_pin =
            duocb_core::pin::normalize_pin(&format!("{}{}", self.in_pin_a, self.in_pin_b))?;
        let lan_only = duocb_core::pin::pin_is_lan_only(&canonical_pin);
        let channel = if lan_only { Core::LanOnly } else { Core::NostrAndLan };
        // The host-IP field only applies to a LAN-only PIN. Blank means mDNS; an
        // in-range address selects the side channel; anything malformed or out of
        // range yields `None` so Join stays disabled.
        let target_ip = if lan_only {
            match self.join_ip_outcome() {
                JoinIpOutcome::Empty => None,
                JoinIpOutcome::InRange(ip) => Some(std::net::IpAddr::V4(ip)),
                JoinIpOutcome::OutOfRange | JoinIpOutcome::Malformed => return None,
            }
        } else {
            None
        };
        Some(DialSpec::Pin {
            canonical_pin,
            relays: default_relays(),
            channel,
            target_ip,
        })
    }

    /// Go to the start screen and launch. Every mode starts immediately: the
    /// configure mode's identity lives on the home hub, and the quick modes
    /// never had a pre-start form.
    pub(crate) fn begin_server(&mut self) {
        if self.server_mode_spec().is_none() {
            return;
        }
        self.screen = Screen::Server;
        self.start_server();
    }

    /// Start the server session if the state validates. The configure-mode
    /// host is the other nostr wake-up point: its presence record is how the
    /// joiner finds this device's node id, so start the broadcast first.
    pub(crate) fn start_server(&mut self) {
        if let Some(mode) = self.server_mode_spec() {
            if self.mode == PairMode::NostrToken {
                self.ensure_presence();
            }
            self.server_running = true;
            self.net.send(UiCommand::StartServer { mode });
        }
    }

    /// Start the client session if the state validates.
    pub(crate) fn connect_client(&mut self) {
        if let Some(spec) = self.client_dial_spec() {
            if let duocb_core::net::DialSpec::NostrToken { peer_display, .. } = &spec {
                // The dial resolves the peer through the presence relays, so
                // make sure the broadcast is awake (normally already is, from
                // entering the picker). Quick-mode dials never reach here.
                self.ensure_presence();
                self.joined_peer = Some(peer_display.clone());
            }
            self.client_active = true;
            self.net.send(UiCommand::Connect { spec });
        }
    }
}

pub(crate) fn default_relays() -> Vec<String> {
    duocb_core::nostr::DEFAULT_NOSTR_RELAYS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Shorten a node id for display.
pub(crate) fn short_id(id: &str) -> String {
    if id.len() <= 16 {
        id.to_string()
    } else {
        format!("{}…{}", &id[..8], &id[id.len() - 8..])
    }
}

/// Mask a secret for display: asterisks plus its last four characters — never
/// the whole value, but enough of a hint to spot-check that a paste into a
/// place without fingerprint support (a password manager, a note) took the
/// right one.
pub(crate) fn masked_secret_hint(secret: &str) -> String {
    let tail_start = secret
        .char_indices()
        .rev()
        .nth(3)
        .map(|(i, _)| i)
        .unwrap_or(0);
    format!("********{}", &secret[tail_start..])
}

/// Seconds since the Unix epoch (for peer last-seen ages).
pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Humanize an age in seconds: "just now", "3m ago", "2h ago", "5d ago".
pub(crate) fn ago(secs: u64) -> String {
    if secs < 60 {
        "just now".to_string()
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use duocb_core::net::spawn_net_runtime;

    /// A throwaway App on a fresh temp config with a headless runtime.
    pub(crate) fn test_app() -> App {
        let dir = std::env::temp_dir().join(format!(
            "duocb-app-test-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let lock = crate::config::acquire_lock(&dir.join("config.json")).unwrap();
        App::new(lock, spawn_net_runtime(None))
    }

    fn rand_suffix() -> String {
        duocb_core::identity::generate_suffix()
    }

    pub(crate) fn peer(name: &str, suffix: &str) -> PeerInfo {
        PeerInfo {
            name: name.to_string(),
            suffix: suffix.to_string(),
            last_seen_unix: now_unix(),
        }
    }

    #[test]
    fn status_idle_resets_session_state_but_keeps_inbox() {
        let mut app = test_app();
        app.server_running = true;
        app.node_id = Some("n".into());
        app.pending_outbox = Some("draft".into());
        app.inbox.push(ClipItem::new("kept".into(), jiff::Zoned::now()));

        app.apply_event(NetEvent::Status(ConnStatus::Idle));

        assert!(!app.server_running);
        assert!(app.node_id.is_none());
        assert!(app.pending_outbox.is_none());
        assert_eq!(app.inbox.len(), 1);
    }

    #[test]
    fn pulled_item_dedupes_and_inbox_is_capped() {
        let mut app = test_app();
        app.apply_event(NetEvent::ItemReceived {
            text: "dup".into(),
            pulled: false,
        });
        app.apply_event(NetEvent::ItemReceived {
            text: "dup".into(),
            pulled: true,
        });
        assert_eq!(app.inbox.len(), 1);

        for i in 0..10 {
            app.apply_event(NetEvent::ItemReceived {
                text: format!("item {i}"),
                pulled: false,
            });
        }
        assert_eq!(app.inbox.len(), MAX_INBOX_ITEMS);
        assert_eq!(app.inbox[0].text, "item 9");
    }

    #[test]
    fn item_sent_promotes_pending_and_error_drops_it() {
        let mut app = test_app();
        app.pending_outbox = Some("sent text".into());
        app.apply_event(NetEvent::ItemSent);
        assert_eq!(app.outbox.as_ref().unwrap().text, "sent text");
        assert!(app.pending_outbox.is_none());

        app.pending_outbox = Some("rejected".into());
        app.apply_event(NetEvent::Error("too big".into()));
        assert!(app.pending_outbox.is_none());
        assert_eq!(app.outbox.as_ref().unwrap().text, "sent text");
        assert_eq!(app.error.as_deref(), Some("too big"));
    }

    #[test]
    fn peer_list_drops_vanished_selection() {
        let mut app = test_app();
        app.selected_peer = Some("gone".into());
        app.apply_event(NetEvent::PeerList {
            peers: vec![peer("mac", "here")],
        });
        assert!(app.selected_peer.is_none());

        app.selected_peer = Some("here".into());
        app.apply_event(NetEvent::PeerList {
            peers: vec![peer("mac", "here")],
        });
        assert_eq!(app.selected_peer.as_deref(), Some("here"));
    }

    /// Build an App whose command receiver we keep, so no real runtime spawns
    /// and the exact `UiCommand` stream can be read back. Returns a configured
    /// (secret + name) app on the idle hub, plus the command receiver.
    fn app_with_cmd_spy() -> (App, tokio::sync::mpsc::UnboundedReceiver<UiCommand>) {
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        // These tests never poll events, so the sender can drop right away.
        let (_event_tx, event_rx) = std::sync::mpsc::channel();
        let net = NetHandle {
            cmd_tx,
            events: event_rx,
            thread: None,
        };
        let dir = std::env::temp_dir().join(format!(
            "duocb-cmdspy-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let lock = crate::config::acquire_lock(&dir.join("config.json")).unwrap();
        let mut app = App::new(lock, net);
        app.secret = Some(duocb_core::auth::generate_token());
        app.saved_name = Some("mac".into());
        app.configure_step = ConfigureStep::Ready;
        app.mode = PairMode::NostrToken;
        (app, cmd_rx)
    }

    fn drain(rx: &mut tokio::sync::mpsc::UnboundedReceiver<UiCommand>) -> Vec<UiCommand> {
        let mut cmds = Vec::new();
        while let Ok(c) = rx.try_recv() {
            cmds.push(c);
        }
        cmds
    }

    #[test]
    fn nostr_is_dormant_until_start_or_join_and_stops_on_return() {
        let (mut app, mut cmd_rx) = app_with_cmd_spy();

        // Idle hub: nothing is broadcast until the user acts.
        assert!(!app.presence_active);
        assert!(
            drain(&mut cmd_rx).is_empty(),
            "no relay activity before a hub action"
        );

        // Join wakes presence (Some identity) and asks for the peer list.
        app.enter_join_picker();
        assert!(app.presence_active);
        let cmds = drain(&mut cmd_rx);
        assert!(
            matches!(
                cmds.first(),
                Some(UiCommand::SetPresence { identity: Some(_) })
            ),
            "Join must wake presence first: {cmds:?}"
        );
        assert!(cmds.iter().any(|c| matches!(c, UiCommand::RefreshPeers)));

        // Leaving the picker for the hub puts nostr back to sleep.
        app.leave_join_picker();
        assert!(!app.presence_active);
        assert_eq!(app.configure_step, ConfigureStep::Ready);
        assert!(
            drain(&mut cmd_rx)
                .iter()
                .any(|c| matches!(c, UiCommand::SetPresence { identity: None })),
            "leaving Join must stop presence"
        );

        // Start wakes presence, then hosts; going back stops it again.
        app.begin_server();
        assert!(app.presence_active);
        let cmds = drain(&mut cmd_rx);
        assert!(cmds
            .iter()
            .any(|c| matches!(c, UiCommand::SetPresence { identity: Some(_) })));
        assert!(cmds
            .iter()
            .any(|c| matches!(c, UiCommand::StartServer { .. })));

        app.go_back();
        assert_eq!(app.screen, Screen::Home);
        assert!(!app.presence_active);
        assert!(
            drain(&mut cmd_rx)
                .iter()
                .any(|c| matches!(c, UiCommand::SetPresence { identity: None })),
            "returning to the hub must stop presence"
        );
    }

    #[test]
    fn quick_mode_never_wakes_presence() {
        let (mut app, mut cmd_rx) = app_with_cmd_spy();
        app.open_quick(); // mode → NostrPin
        app.begin_server(); // quick host under a PIN
        assert!(!app.presence_active);
        assert!(
            !drain(&mut cmd_rx)
                .iter()
                .any(|c| matches!(c, UiCommand::SetPresence { identity: Some(_) })),
            "quick mode must never broadcast presence"
        );
    }

    #[test]
    fn go_back_routes_by_mode_and_stops_picker() {
        let mut app = test_app();
        app.screen = Screen::Server;
        app.mode = PairMode::NostrPin;
        app.go_back();
        assert_eq!(app.screen, Screen::Quick);
        assert_eq!(app.mode, PairMode::NostrPin);

        app.screen = Screen::Client;
        app.mode = PairMode::NostrToken;
        app.configure_step = ConfigureStep::Join;
        app.go_back();
        assert_eq!(app.screen, Screen::Home);
        assert_eq!(app.configure_step, ConfigureStep::Ready);

        app.screen = Screen::Quick;
        app.mode = PairMode::NostrPin;
        app.go_back();
        assert_eq!(app.screen, Screen::Home);
        assert_eq!(app.mode, PairMode::NostrToken);
    }

    #[test]
    fn copy_flash_targets_only_the_button_that_copied() {
        let mut app = test_app();
        assert_eq!(app.copied_target(), None, "no flash before any copy");

        // Each successful copy flashes exactly its own target, replacing the last.
        app.copy_with_flash("d-secret", CopyTarget::Secret);
        assert_eq!(app.copied_target(), Some(CopyTarget::Secret));
        app.copy_with_flash("ABCD-EFGH", CopyTarget::Pin);
        assert_eq!(app.copied_target(), Some(CopyTarget::Pin));

        // Inbox feedback is keyed by row index — only the copied row flashes.
        app.copy_with_flash("hello", CopyTarget::Inbox(2));
        assert_eq!(app.copied_target(), Some(CopyTarget::Inbox(2)));
        assert_ne!(app.copied_target(), Some(CopyTarget::Inbox(0)));

        // A stale flash (older than the flash window) no longer shows.
        app.copied_flash = Some((CopyTarget::Pin, Instant::now() - SENT_FLASH));
        assert_eq!(app.copied_target(), None, "expired flash clears");
    }

    #[test]
    fn host_spec_uses_the_selected_channel() {
        let mut app = test_app();
        app.mode = PairMode::NostrPin;
        app.pin_channel = PinChannel::LanOnly;
        match app.server_mode_spec() {
            Some(duocb_core::net::ServerMode::Pin { channel, .. }) => {
                assert_eq!(channel, duocb_core::net::PinChannel::LanOnly);
            }
            other => panic!("unexpected server mode: {other:?}"),
        }
    }

    #[test]
    fn join_spec_infers_the_channel_from_the_pin() {
        use duocb_core::net::PinChannel as Core;
        let g = duocb_core::pin::PIN_GROUP_LEN;
        // The typed PIN — not the on-screen channel selection — decides the join
        // channel. A LAN-only PIN dials LAN-only even when a nostr channel is
        // selected, and vice versa.
        for (lan_only, selected, expected) in [
            (true, PinChannel::NostrOnly, Core::LanOnly),
            (false, PinChannel::LanOnly, Core::NostrAndLan),
        ] {
            let mut app = test_app();
            app.mode = PairMode::NostrPin;
            app.pin_channel = selected;
            let canonical = duocb_core::pin::generate_pin(lan_only);
            app.in_pin_a = canonical[..g].to_string();
            app.in_pin_b = canonical[g..].to_string();
            match app.client_dial_spec() {
                Some(duocb_core::net::DialSpec::Pin {
                    channel,
                    canonical_pin,
                    ..
                }) => {
                    assert_eq!(channel, expected);
                    assert_eq!(canonical_pin, canonical);
                }
                other => panic!("unexpected dial spec: {other:?}"),
            }
        }
    }

    #[test]
    fn join_ip_selects_the_side_channel_for_a_lan_only_pin() {
        use duocb_core::net::{DialSpec, PinChannel as Core};
        let g = duocb_core::pin::PIN_GROUP_LEN;
        let mut app = test_app();
        app.mode = PairMode::NostrPin;
        let lan_pin = duocb_core::pin::generate_pin(true);
        app.in_pin_a = lan_pin[..g].to_string();
        app.in_pin_b = lan_pin[g..].to_string();

        // No IP typed: a LAN-only PIN resolves via mDNS (target_ip None).
        match app.client_dial_spec() {
            Some(DialSpec::Pin { channel, target_ip, .. }) => {
                assert_eq!(channel, Core::LanOnly);
                assert!(target_ip.is_none(), "blank IP means mDNS");
            }
            other => panic!("unexpected dial spec: {other:?}"),
        }

        // A well-formed IPv4 selects the unicast side channel.
        app.in_join_ip = "192.168.1.42".to_string();
        match app.client_dial_spec() {
            Some(DialSpec::Pin { target_ip: Some(ip), .. }) => {
                assert_eq!(ip, "192.168.1.42".parse::<std::net::IpAddr>().unwrap());
            }
            other => panic!("unexpected dial spec: {other:?}"),
        }

        // A malformed IP disables Join (no valid spec).
        app.in_join_ip = "not-an-ip".to_string();
        assert!(app.client_dial_spec().is_none());

        // The IP is ignored for a non-LAN-only PIN (the field is hidden then),
        // so a stale value never blocks the dial.
        let net_pin = duocb_core::pin::generate_pin(false);
        app.in_pin_a = net_pin[..g].to_string();
        app.in_pin_b = net_pin[g..].to_string();
        match app.client_dial_spec() {
            Some(DialSpec::Pin { channel, target_ip, .. }) => {
                assert_eq!(channel, Core::NostrAndLan);
                assert!(target_ip.is_none());
            }
            other => panic!("unexpected dial spec: {other:?}"),
        }
    }

    #[test]
    fn move_peer_selection_wraps() {
        let mut app = test_app();
        app.peers = vec![peer("a", "s1"), peer("b", "s2")];

        app.move_peer_selection(1);
        assert_eq!(app.selected_peer.as_deref(), Some("s1"));
        app.move_peer_selection(1);
        assert_eq!(app.selected_peer.as_deref(), Some("s2"));
        app.move_peer_selection(1);
        assert_eq!(app.selected_peer.as_deref(), Some("s1"));
        app.move_peer_selection(-1);
        assert_eq!(app.selected_peer.as_deref(), Some("s2"));
    }

    #[test]
    fn toggle_peer_selects_and_deselects() {
        let mut app = test_app();
        app.toggle_peer("s1");
        assert_eq!(app.selected_peer.as_deref(), Some("s1"));
        app.toggle_peer("s1");
        assert!(app.selected_peer.is_none());
    }

    #[test]
    fn masked_secret_hint_shows_last_four() {
        assert_eq!(masked_secret_hint("abcdefgh"), "********efgh");
        assert_eq!(masked_secret_hint("abc"), "********abc");
    }

    #[test]
    fn ago_humanizes() {
        assert_eq!(ago(5), "just now");
        assert_eq!(ago(180), "3m ago");
        assert_eq!(ago(7200), "2h ago");
        assert_eq!(ago(200_000), "2d ago");
    }
}
