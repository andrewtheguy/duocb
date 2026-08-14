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
use crate::{ConfigureStep, PairMode, Screen};
use duocb_core::net::endpoint::ConnPath;
use duocb_core::auth::{Identity, IdentityCard};
use duocb_core::net::{ConnStatus, KeyIdentity, NetEvent, NetHandle, UiCommand};
use item::ClipItem;

/// How long the "sent ✓" / "✔ Copied" flashes stay visible.
const SENT_FLASH: Duration = Duration::from_secs(2);

/// Retention cap for the in-memory inbox: newest-first, only the last few
/// received items are kept and older ones are dropped.
const MAX_INBOX_ITEMS: usize = 5;

pub(crate) struct App {
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
    pub(crate) identity: Identity,
    pub(crate) saved_name: Option<String>,
    pub(crate) device_suffix: String,
    pub(crate) self_card: Option<IdentityCard>,
    pub(crate) configure_step: ConfigureStep,
    /// Locally trusted peers, added only by importing a signed card.
    pub(crate) peers: Vec<IdentityCard>,
    /// Selected peer by hex application public key.
    pub(crate) selected_peer: Option<String>,
    pub(crate) joined_peer: Option<String>,
    pub(crate) confirm_reset_identity: bool,

    // Server presentation state.
    pub(crate) server_running: bool,
    pub(crate) node_id: Option<String>,
    /// The host's LAN IPv4 on the LAN-only channel, surfaced so the joiner can
    /// type it for the manual-IP side channel (from [`NetEvent::PinRotated`]);
    /// `None` on other channels or before an address is known.
    pub(crate) host_lan_ip: Option<String>,
    pub(crate) identity_public_key: Option<String>,
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
    pub(crate) in_private_key: String,
    pub(crate) in_peer_card: String,
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

#[cfg(test)]
mod recovery_offer_tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn test_app() -> (App, PathBuf) {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "duocb-recovery-offer-{}-{}.json",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let lock = crate::config::acquire_lock(&path).unwrap();
        let config = crate::config::Config::default();
        (
            App::new(lock, config, duocb_core::net::spawn_net_runtime(None)),
            path,
        )
    }

    /// A self-card close to expiry is re-minted at startup, so the copy a user
    /// hands out always has plenty of life left.
    #[test]
    fn a_stale_self_card_is_re_minted_on_load() {
        let (mut app, path) = test_app();
        app.saved_name = Some("desktop".into());
        app.device_suffix = "a7B2c3D4".into();
        app.self_card = Some(
            app.identity
                .card_issued_at(
                    "desktop",
                    "a7B2c3D4",
                    duocb_core::auth::unix_now() - duocb_core::auth::CARD_TTL_SECS - 1,
                )
                .unwrap(),
        );
        assert!(app.self_card.as_ref().unwrap().is_expired());

        app.renew_self_card_if_stale();

        let renewed = app.self_card.as_ref().expect("a self card is held");
        assert!(!renewed.is_expired(), "the renewed card must be current");
        assert_eq!(renewed.name(), "desktop_a7B2c3D4");

        let persisted = IdentityCard::parse(&app.config_lock.load().unwrap().self_card.unwrap())
            .expect("the persisted card parses");
        assert!(
            !persisted.is_expired(),
            "the card written to disk must be the current one"
        );

        app.net.shutdown();
        drop(app);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path.display()));
    }

    #[test]
    fn signed_name_uses_permanent_suffix_and_identity_reset_keeps_it() {
        let (mut app, path) = test_app();
        let suffix = app.device_suffix.clone();
        app.in_my_name = "desktop".into();

        app.save_name();

        assert_eq!(
            app.self_card.as_ref().unwrap().name(),
            duocb_core::identity::display_identity("desktop", &suffix)
        );
        let saved = app.config_lock.load().unwrap();
        assert_eq!(saved.device_suffix, suffix);

        app.reset_identity();
        assert_eq!(app.device_suffix, suffix);
        assert_eq!(app.config_lock.load().unwrap().device_suffix, suffix);

        app.net.shutdown();
        drop(app);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path.display()));
    }
}

/// Which copy button a successful copy came from, so only that button shows the
/// "✔ Copied" flash. `Inbox` carries the row index (the newest is 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CopyTarget {
    Card,
    PrivateKey,
    Pin,
    Outbox,
    Inbox(usize),
}

impl App {
    pub(crate) fn new(
        config_lock: crate::config::ConfigLock,
        config: crate::config::Config,
        net: NetHandle,
    ) -> Self {
        let identity = Identity::parse_nsec(&config.identity_secret)
            .expect("ConfigLock::load validated the identity key");
        let device_suffix = config.device_suffix.clone();
        let saved_name = config
            .my_name
            .filter(|n| duocb_core::identity::validate_name(n).is_ok());
        let expected_card_name = saved_name
            .as_deref()
            .map(|name| duocb_core::identity::display_identity(name, &device_suffix));
        let self_card = config
            .self_card
            .as_deref()
            .and_then(|card| IdentityCard::parse(card).ok())
            .filter(|card| {
                card.public_key() == identity.public_key()
                    && expected_card_name.as_deref() == Some(card.name())
            });
        let peers: Vec<IdentityCard> = config
            .peers
            .iter()
            .filter_map(|card| IdentityCard::parse(card).ok())
            .filter(|card| card.public_key() != identity.public_key())
            .take(duocb_core::auth::MAX_TRUSTED_PEERS)
            .collect();
        let configure_step = match (&saved_name, &self_card) {
            (Some(_), Some(_)) => ConfigureStep::Ready,
            _ => ConfigureStep::SetupChoice,
        };

        let mut app = Self {
            config_lock,
            net,
            clipboard: SystemClipboard::new(),
            screen: Screen::Home,
            mode: PairMode::NostrKey,
            status: ConnStatus::Idle,
            error: None,
            identity,
            saved_name: saved_name.clone(),
            device_suffix,
            self_card,
            configure_step,
            peers,
            selected_peer: None,
            joined_peer: None,
            confirm_reset_identity: false,
            server_running: false,
            node_id: None,
            host_lan_ip: None,
            identity_public_key: None,
            pin_display: None,
            pin_deadline: None,
            pin_paired: false,
            client_active: false,
            in_my_name: saved_name.unwrap_or_default(),
            in_private_key: String::new(),
            in_peer_card: String::new(),
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
        };
        app.renew_self_card_if_stale();
        app
    }

    /// Re-mint this device's own card once it is close to expiry.
    ///
    /// Cards last [`duocb_core::auth::CARD_TTL_SECS`] and are never refreshed
    /// over the wire, so the copy a user hands out must have plenty of life
    /// left. Signing costs nothing — the key is local — so this runs at startup
    /// and again before the card is copied, which is enough to keep a handed-out
    /// card from being nearly dead on arrival. It does not affect peers: their
    /// stored copy only refreshes when its owner re-imports.
    pub(crate) fn renew_self_card_if_stale(&mut self) {
        let Some(fresh) = self.freshly_minted_self_card() else {
            return;
        };
        self.self_card = Some(fresh);
        self.save_configure_config();
    }

    /// A replacement for the current self-card when it is close to expiry, or
    /// `None` when it is still current (or there is nothing to re-mint).
    /// Separate from [`App::renew_self_card_if_stale`] so a caller that is about
    /// to persist anyway can swap the card in without triggering a second save.
    fn freshly_minted_self_card(&self) -> Option<IdentityCard> {
        let card = self.self_card.as_ref()?;
        let name = self.saved_name.as_deref()?;
        if card.remaining_secs_at(duocb_core::auth::unix_now())
            > duocb_core::auth::CARD_RENEW_BEFORE_SECS
        {
            return None;
        }
        self.identity.card(name, &self.device_suffix).ok()
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
                identity_public_key,
            } => {
                self.node_id = Some(node_id);
                self.identity_public_key = identity_public_key;
            }
            NetEvent::ClientReady {
                node_id,
                identity_public_key,
            } => {
                self.node_id = Some(node_id);
                self.identity_public_key = identity_public_key;
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
                    self.identity_public_key = None;
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
            NetEvent::PeerPaired {
                peer_node_id,
                peer_public_key: _,
            } => {
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
            NetEvent::Error(message) => {
                // A rejected send (e.g. oversize) reports an error instead of
                // ItemSent, so drop its pending text — it must never be promoted
                // to the outbox as "sent".
                self.pending_outbox = None;
                self.error = Some(message);
            }
        }
    }

    /// Periodic work, driven by the UI's heartbeat timer: peek auto-hide.
    /// Flash/countdown expiry needs no state change — `sync` derives those from
    /// timestamps.
    pub(crate) fn tick(&mut self) {
        for item in self.inbox.iter_mut().chain(self.outbox.iter_mut()) {
            item.tick_peek();
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

    /// Copy arbitrary text (an inbox item, an identity card, or a node id) to the
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
    pub(crate) fn key_identity(&self) -> Option<KeyIdentity> {
        Some(KeyIdentity {
            identity: self.identity.clone(),
            self_card: self.self_card.clone()?,
            peers: self.peers.clone(),
            relays: default_relays(),
        })
    }

    pub(crate) fn display_identity(&self) -> String {
        self.saved_name
            .as_deref()
            .map(|name| duocb_core::identity::display_identity(name, &self.device_suffix))
            .unwrap_or_default()
    }

    pub(crate) fn has_saved_identity(&self) -> bool {
        self.saved_name.is_some() && self.self_card.is_some()
    }

    fn save_configure_config(&mut self) -> bool {
        let cfg = crate::config::Config {
            version: crate::config::CONFIG_VERSION,
            identity_secret: self.identity.to_nsec(),
            device_suffix: self.device_suffix.clone(),
            my_name: self.saved_name.clone(),
            self_card: self.self_card.as_ref().map(IdentityCard::encode),
            peers: self.peers.iter().map(IdentityCard::encode).collect(),
        };
        match self.config_lock.save(&cfg) {
            Ok(()) => true,
            Err(e) => {
                self.error = Some(format!("Could not save the settings: {e:#}"));
                false
            }
        }
    }

    pub(crate) fn begin_generate_identity(&mut self) {
        self.identity = Identity::generate();
        self.saved_name = None;
        self.self_card = None;
        self.peers.clear();
        self.reset_name_field();
        self.configure_step = ConfigureStep::SetupName;
    }

    pub(crate) fn use_imported_identity(&mut self) {
        if let Ok(identity) = Identity::parse_nsec(&self.in_private_key) {
            self.identity = identity;
            self.saved_name = None;
            self.self_card = None;
            self.peers.clear();
            self.in_private_key.clear();
            self.configure_step = ConfigureStep::SetupName;
            self.save_configure_config();
        }
    }

    /// Cancel the import step back to the choice.
    pub(crate) fn cancel_setup(&mut self) {
        self.in_private_key.clear();
        self.configure_step = ConfigureStep::SetupChoice;
    }

    pub(crate) fn reset_name_field(&mut self) {
        self.in_my_name = self.saved_name.clone().unwrap_or_default();
    }

    pub(crate) fn save_name(&mut self) {
        let name = self.in_my_name.trim().to_string();
        if duocb_core::identity::validate_name(&name).is_err() {
            return;
        }
        let Ok(card) = self.identity.card(&name, &self.device_suffix) else {
            return;
        };
        self.saved_name = Some(name);
        self.self_card = Some(card);
        if self.save_configure_config() {
            self.configure_step = ConfigureStep::Ready;
        }
    }

    /// Leave the name step without saving (only when an identity exists).
    pub(crate) fn cancel_name(&mut self) {
        if self.has_saved_identity() {
            self.reset_name_field();
            self.configure_step = ConfigureStep::Ready;
        }
    }

    pub(crate) fn reset_identity(&mut self) {
        self.identity = Identity::generate();
        self.saved_name = None;
        self.self_card = None;
        self.peers.clear();
        self.selected_peer = None;
        self.in_private_key.clear();
        self.in_peer_card.clear();
        self.save_configure_config();
        self.configure_step = ConfigureStep::SetupChoice;
    }

    pub(crate) fn selected_peer_card(&self) -> Option<&IdentityCard> {
        let key = self.selected_peer.as_deref()?;
        self.peers
            .iter()
            .find(|peer| peer.public_key().to_hex() == key)
    }

    pub(crate) fn enter_join_picker(&mut self) {
        self.configure_step = ConfigureStep::Join;
    }

    pub(crate) fn leave_join_picker(&mut self) {
        self.configure_step = ConfigureStep::Ready;
    }

    pub(crate) fn toggle_peer(&mut self, public_key: &str) {
        self.selected_peer = if self.selected_peer.as_deref() == Some(public_key) {
            None
        } else {
            Some(public_key.to_string())
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
            .and_then(|key| {
                self.peers
                    .iter()
                    .position(|peer| peer.public_key().to_hex() == key)
            });
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
        self.selected_peer = Some(self.peers[next].public_key().to_hex());
    }

    pub(crate) fn import_peer_card(&mut self) {
        let Ok(card) = IdentityCard::parse(&self.in_peer_card) else {
            self.error = Some("The pasted identity card is invalid".into());
            return;
        };
        if card.public_key() == self.identity.public_key() {
            self.error = Some("That is this device's own identity card".into());
            return;
        }
        // Importing a lapsed card would store trust that can never pair, so
        // refuse it here rather than at the first Join.
        if card.is_expired() {
            self.error = Some(format!(
                "That identity card expired on {} — copy a fresh one from the other device",
                card_expiry_date(&card)
            ));
            return;
        }
        if let Some(existing) = self
            .peers
            .iter_mut()
            .find(|peer| peer.public_key() == card.public_key())
        {
            *existing = card;
        } else if self.peers.len() >= duocb_core::auth::MAX_TRUSTED_PEERS {
            self.error = Some("The trusted-peer limit is 128".into());
            return;
        } else {
            self.peers.push(card);
        }
        self.in_peer_card.clear();
        self.save_configure_config();
    }

    pub(crate) fn remove_peer(&mut self, public_key: &str) {
        let before = self.peers.len();
        self.peers
            .retain(|peer| peer.public_key().to_hex() != public_key);
        if self.peers.len() != before {
            if self.selected_peer.as_deref() == Some(public_key) {
                self.selected_peer = None;
            }
            self.save_configure_config();
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

    pub(crate) fn stop_presence(&mut self) {
        // Configure-mode Nostr work is scoped to a running server session's
        // hosting-record publisher; there is no standing presence publisher.
    }

    /// Open the quick-options screen (ad-hoc rotating-PIN pairing).
    pub(crate) fn open_quick(&mut self) {
        self.screen = Screen::Quick;
        // Home implies configure mode; entering the quick screen picks its
        // default so the actions there never run configure mode.
        if self.mode == PairMode::NostrKey {
            self.mode = PairMode::Pin;
        }
        // Detect this device's LAN subnet so a LAN-only join can lock the host
        // IP's network octets to it and reject an out-of-range address. Read
        // once on entry — a mid-session network change is rare and the field is
        // optional anyway (blank falls back to mDNS).
        self.join_ip_ctx = duocb_core::subnet::JoinIpConstraint::detect();
    }

    /// Quick join: dial what the quick screen's join entry holds (the typed PIN,
    /// plus an optional host IP) and move to the client screen. A no-op while
    /// the entry isn't a valid local-only PIN (the Join action is disabled then
    /// — see `dial-ready`).
    pub(crate) fn join_quick(&mut self) {
        if self.client_dial_spec().is_some() {
            self.connect_client();
            self.screen = Screen::Client;
        }
    }

    /// Navigate back one screen, stopping any running session. Role screens
    /// return to where they launched from (the quick-options screen for the
    /// quick mode, the home hub for configure mode); leaving the quick
    /// screen restores the home invariant (mode = configure).
    pub(crate) fn go_back(&mut self) {
        self.stop_session();
        self.screen = match (self.screen, self.mode) {
            (Screen::Server | Screen::Client, PairMode::Pin) => Screen::Quick,
            _ => {
                self.mode = PairMode::NostrKey;
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

    /// Build the server mode from the current state, if it validates.
    pub(crate) fn server_mode_spec(&self) -> Option<duocb_core::net::ServerMode> {
        use duocb_core::net::ServerMode;
        match self.mode {
            PairMode::NostrKey => self
                .key_identity()
                .map(|identity| ServerMode::NostrKey {
                    identity: Box::new(identity),
                }),
            PairMode::Pin => Some(ServerMode::Pin {
                relays: default_relays(),
                channel: duocb_core::net::PinChannel::LanOnly,
            }),
        }
    }

    /// Build the dial spec from the current state, if it validates. Configure
    /// mode dials exactly the peer selected in the device picker; the quick
    /// mode joins from the local-only PIN and optional host IP that were entered
    /// (see [`App::quick_dial_spec`]).
    pub(crate) fn client_dial_spec(&self) -> Option<duocb_core::net::DialSpec> {
        use duocb_core::net::DialSpec;
        match self.mode {
            PairMode::NostrKey => Some(DialSpec::NostrKey {
                identity: Box::new(self.key_identity()?),
                peer_public_key: self.selected_peer_card()?.public_key(),
            }),
            PairMode::Pin => self.quick_dial_spec(),
        }
    }

    /// The current validation outcome of the host-IP entry against the detected
    /// subnet constraint — the single source for both the displayed error
    /// (`sync`) and the dial's `target_ip` (`quick_dial_spec`).
    pub(crate) fn join_ip_outcome(&self) -> duocb_core::subnet::JoinIpOutcome {
        self.join_ip_ctx.resolve(&self.in_join_ip)
    }

    /// The local-only quick-join dial spec, derived from the join entry. The
    /// PIN's first character must mark the LAN-only channel; internet-capable
    /// quick PINs are rejected. The optional host-IP entry, resolved and
    /// range-checked against this device's own subnet (see [`App::join_ip_ctx`]),
    /// selects the unicast side channel (blank resolves via mDNS). `None` when
    /// the PIN is incomplete, invalid, or non-local, or when the typed host IP
    /// is malformed or out of range — which keeps the Join button disabled.
    fn quick_dial_spec(&self) -> Option<duocb_core::net::DialSpec> {
        use duocb_core::net::{DialSpec, PinChannel};
        use duocb_core::subnet::JoinIpOutcome;
        let canonical_pin =
            duocb_core::pin::normalize_pin(&format!("{}{}", self.in_pin_a, self.in_pin_b))?;
        if !duocb_core::pin::pin_is_lan_only(&canonical_pin) {
            return None;
        }
        // Blank means mDNS; an in-range address selects the side channel;
        // anything malformed or out of range yields `None`.
        let target_ip = match self.join_ip_outcome() {
            JoinIpOutcome::Empty => None,
            JoinIpOutcome::InRange(ip) => Some(std::net::IpAddr::V4(ip)),
            JoinIpOutcome::OutOfRange | JoinIpOutcome::Malformed => return None,
        };
        Some(DialSpec::Pin {
            canonical_pin,
            relays: default_relays(),
            channel: PinChannel::LanOnly,
            target_ip,
        })
    }

    /// Go to the start screen and launch. Every mode starts immediately: the
    /// configure mode's identity lives on the home hub, and the quick mode
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
            self.server_running = true;
            self.net.send(UiCommand::StartServer { mode });
        }
    }

    /// Start the client session if the state validates.
    pub(crate) fn connect_client(&mut self) {
        if let Some(spec) = self.client_dial_spec() {
            if let duocb_core::net::DialSpec::NostrKey {
                peer_public_key, ..
            } = &spec {
                let peer = self
                    .peers
                    .iter()
                    .find(|peer| peer.public_key() == *peer_public_key);
                // The runtime refuses an expired peer too; catching it here
                // answers immediately instead of after an endpoint spins up.
                if let Some(peer) = peer.filter(|peer| peer.is_expired()) {
                    self.error = Some(format!(
                        "The identity card for {} expired on {} — import a fresh card from that device",
                        peer.name(),
                        card_expiry_date(peer)
                    ));
                    return;
                }
                self.joined_peer = peer.map(|peer| peer.name().to_string());
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

/// The expiry state for a peer row. The date is always shown — it is signed
/// into the card itself, so a trusted device can be read at a glance without
/// re-parsing anything — and a countdown is appended only once the card is
/// close enough to expiry that the user should go copy a fresh one.
pub(crate) fn card_expiry_note(card: &IdentityCard) -> String {
    const DAY: u64 = 24 * 60 * 60;
    let date = card_expiry_date(card);
    let remaining = card.remaining_secs_at(duocb_core::auth::unix_now());
    // Kept short: this is appended to a list row, and the trust card's own text
    // already explains that the fix is to import a fresh card.
    if remaining == 0 {
        return format!("EXPIRED {date}");
    }
    if remaining > duocb_core::auth::CARD_RENEW_BEFORE_SECS {
        return format!("expires {date}");
    }
    match remaining / DAY {
        0 => format!("expires {date} (today)"),
        1 => format!("expires {date} (1 day)"),
        days => format!("expires {date} ({days} days)"),
    }
}

/// The card's signed expiry as a local-time calendar date.
pub(crate) fn card_expiry_date(card: &IdentityCard) -> String {
    i64::try_from(card.expires_at())
        .ok()
        .and_then(|secs| jiff::Timestamp::from_second(secs).ok())
        .map(|ts| {
            ts.to_zoned(jiff::tz::TimeZone::system())
                .strftime("%Y-%m-%d")
                .to_string()
        })
        .unwrap_or_else(|| "an unreadable date".to_string())
}

#[cfg(test)]
mod expiry_note_tests {
    use super::*;

    const DAY: u64 = 24 * 60 * 60;

    /// Derived independently of `card_expiry_date` so the assertions below
    /// cannot pass by agreeing with a broken formatter.
    fn local_date(secs: u64) -> String {
        jiff::Timestamp::from_second(i64::try_from(secs).unwrap())
            .unwrap()
            .to_zoned(jiff::tz::TimeZone::system())
            .strftime("%Y-%m-%d")
            .to_string()
    }

    #[test]
    fn a_healthy_card_still_shows_its_expiry_date() {
        let card = Identity::generate().card("phone", "x9Y8z7W6").unwrap();
        assert_eq!(
            card_expiry_note(&card),
            format!("expires {}", local_date(card.expires_at()))
        );
    }

    #[test]
    fn a_card_near_expiry_shows_the_date_and_a_countdown() {
        let now = duocb_core::auth::unix_now();
        let card = Identity::generate()
            .card_issued_at(
                "phone",
                "x9Y8z7W6",
                now - duocb_core::auth::CARD_TTL_SECS + 2 * DAY + 60,
            )
            .unwrap();
        assert_eq!(
            card_expiry_note(&card),
            format!("expires {} (2 days)", local_date(card.expires_at()))
        );
    }

    #[test]
    fn an_expired_card_shows_the_date_it_lapsed() {
        let now = duocb_core::auth::unix_now();
        let card = Identity::generate()
            .card_issued_at(
                "phone",
                "x9Y8z7W6",
                now - duocb_core::auth::CARD_TTL_SECS - DAY,
            )
            .unwrap();
        assert!(card.is_expired());
        assert_eq!(
            card_expiry_note(&card),
            format!("EXPIRED {}", local_date(card.expires_at()))
        );
    }
}

/// Shorten a node id for display.
pub(crate) fn short_id(id: &str) -> String {
    if id.len() <= 16 {
        id.to_string()
    } else {
        format!("{}…{}", &id[..8], &id[id.len() - 8..])
    }
}

#[cfg(all(test, any()))]
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
        let config = lock.load().unwrap();
        App::new(lock, config, spawn_net_runtime(None))
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
        let config = lock.load().unwrap();
        let mut app = App::new(lock, config, net);
        app.secret = Some(duocb_core::auth::Secret::generate());
        app.saved_name = Some("mac".into());
        app.configure_step = ConfigureStep::Ready;
        app.mode = PairMode::NostrKey;
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
        app.open_quick(); // mode → Pin
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
        app.mode = PairMode::Pin;
        app.go_back();
        assert_eq!(app.screen, Screen::Quick);
        assert_eq!(app.mode, PairMode::Pin);

        app.screen = Screen::Client;
        app.mode = PairMode::NostrKey;
        app.configure_step = ConfigureStep::Join;
        app.go_back();
        assert_eq!(app.screen, Screen::Home);
        assert_eq!(app.configure_step, ConfigureStep::Ready);

        app.screen = Screen::Quick;
        app.mode = PairMode::Pin;
        app.go_back();
        assert_eq!(app.screen, Screen::Home);
        assert_eq!(app.mode, PairMode::NostrKey);
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
    fn quick_host_is_always_lan_only() {
        let mut app = test_app();
        app.mode = PairMode::Pin;
        match app.server_mode_spec() {
            Some(duocb_core::net::ServerMode::Pin { channel, .. }) => {
                assert_eq!(channel, duocb_core::net::PinChannel::LanOnly);
            }
            other => panic!("unexpected server mode: {other:?}"),
        }
    }

    #[test]
    fn quick_join_accepts_only_lan_only_pins() {
        use duocb_core::net::{DialSpec, PinChannel};
        let g = duocb_core::pin::PIN_GROUP_LEN;
        let mut app = test_app();
        app.mode = PairMode::Pin;

        let local_pin = duocb_core::pin::generate_pin(true);
        app.in_pin_a = local_pin[..g].to_string();
        app.in_pin_b = local_pin[g..].to_string();
        match app.client_dial_spec() {
            Some(DialSpec::Pin {
                channel,
                canonical_pin,
                ..
            }) => {
                assert_eq!(channel, PinChannel::LanOnly);
                assert_eq!(canonical_pin, local_pin);
            }
            other => panic!("unexpected dial spec: {other:?}"),
        }

        let internet_pin = duocb_core::pin::generate_pin(false);
        app.in_pin_a = internet_pin[..g].to_string();
        app.in_pin_b = internet_pin[g..].to_string();
        assert!(
            app.client_dial_spec().is_none(),
            "internet-capable PINs are not accepted by local-only quick pairing"
        );
    }

    #[test]
    fn join_ip_selects_the_side_channel_for_a_lan_only_pin() {
        use duocb_core::net::{DialSpec, PinChannel as Core};
        let g = duocb_core::pin::PIN_GROUP_LEN;
        let mut app = test_app();
        app.mode = PairMode::Pin;
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

        // An internet-capable PIN is rejected even if a valid local-only PIN
        // was entered before it.
        let net_pin = duocb_core::pin::generate_pin(false);
        app.in_pin_a = net_pin[..g].to_string();
        app.in_pin_b = net_pin[g..].to_string();
        assert!(app.client_dial_spec().is_none());
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

        // On a real secret the tail is the checksum section: enough to tell two
        // secrets apart in a password manager, and the fingerprint shown beside
        // it is the actual cross-device check.
        let secret = duocb_core::auth::Secret::generate();
        let encoded = secret.encode();
        let hint = masked_secret_hint(&encoded);
        assert!(hint.starts_with("********"));
        assert!(encoded.ends_with(hint.trim_start_matches('*')));
        assert_eq!(hint.chars().count(), 12);
    }

    #[test]
    fn ago_humanizes() {
        assert_eq!(ago(5), "just now");
        assert_eq!(ago(180), "3m ago");
        assert_eq!(ago(7200), "2h ago");
        assert_eq!(ago(200_000), "2d ago");
    }
}
