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
use crate::{ConfigureStep, Screen};
use duocb_core::net::endpoint::ConnPath;
use duocb_core::auth::{Identity, IdentityCard};
use duocb_core::net::{ConnStatus, KeyIdentity, NetEvent, NetHandle, SignalChannel, UiCommand};
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

    // Shared status.
    pub(crate) status: ConnStatus,
    pub(crate) error: Option<String>,

    /// Which transport(s) card setup uses to trade the PIN rendezvous record.
    /// Defaults to LAN-first-then-nostr; the `--lan-only` / `--nostr-only` CLI
    /// flags pin it to a single channel so a test can exercise one path without
    /// the other quietly covering for it. Fixed for the process — it is a
    /// launch-time choice, not persisted state.
    pub(crate) signal_channel: SignalChannel,

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
    /// This host's LAN IPv4, surfaced so the joiner can type it for the
    /// manual-IP side channel (from [`NetEvent::PinRotated`]); `None` before an
    /// address is known.
    pub(crate) host_lan_ip: Option<String>,
    pub(crate) identity_public_key: Option<String>,
    pub(crate) pin_display: Option<String>,
    pub(crate) pin_deadline: Option<Instant>,

    /// Card setup: the peer's signed card, received over the PIN-authenticated
    /// connection and waiting on the user's fingerprint check.
    ///
    /// Deliberately survives the session teardown that immediately follows it —
    /// the runtime ends a card-setup session as soon as the cards cross, so the
    /// confirmation screen always outlives the session that produced it. Cleared
    /// only by Import or Cancel.
    pub(crate) pending_peer_card: Option<IdentityCard>,

    // Client-side session flag (a dial session exists, connected or retrying).
    pub(crate) client_active: bool,

    // Form inputs (mirrors of the UI's two-way field properties, updated on
    // every edit; authoritative — sync writes them back, which is how resets
    // reach the fields).
    pub(crate) in_my_name: String,
    pub(crate) in_private_key: String,
    pub(crate) in_peer_card: String,
    /// The joining device's PIN entry, split into its two `XXXX` groups (one
    /// text field each) so grouping never edits a field's text mid-keystroke.
    pub(crate) in_pin_a: String,
    pub(crate) in_pin_b: String,
    /// The joiner's optional host-IP entry on the card-setup screen. Holds
    /// only the *host part* typed after the locked network prefix (or a full
    /// address pasted whole); [`App::join_ip_ctx`] resolves and range-checks it.
    /// When it resolves to an in-range address it selects the unicast side
    /// channel (see [`App::card_setup_dial_spec`]); blank resolves via mDNS.
    pub(crate) in_join_ip: String,
    /// The local-subnet constraint the host-IP entry is held to (this device's
    /// own private IPv4 subnet). Detected when the card-setup screen opens;
    /// drives the locked prefix, the range hint, and out-of-range rejection.
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
mod self_card_tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn test_app() -> (App, PathBuf) {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "duocb-self-card-{}-{}.json",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let lock = crate::config::acquire_lock(&path).unwrap();
        let config = crate::config::Config::default();
        (
            App::new(
                lock,
                config,
                duocb_core::net::spawn_net_runtime(None),
                SignalChannel::default(),
            ),
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
        signal_channel: SignalChannel,
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
            status: ConnStatus::Idle,
            error: None,
            signal_channel,
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
            pending_peer_card: None,
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
                self.host_lan_ip = host_lan_ip;
            }
            NetEvent::PinCleared => {
                self.pin_display = None;
                self.pin_deadline = None;
            }
            NetEvent::PeerCardReceived(card) => {
                // The exchange succeeded. Nothing is trusted yet: hold the card
                // and put the user in front of the fingerprint comparison.
                self.pending_peer_card = Some(*card);
                self.screen = Screen::CardConfirm;
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
                    self.peer_node_id = None;
                    // `pending_peer_card` and `screen` are deliberately NOT
                    // reset here: a card-setup session goes idle the instant the
                    // cards cross, so clearing them would wipe the confirmation
                    // screen out from under the user the moment it appeared.
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
        if self.store_peer_card(card) {
            self.in_peer_card.clear();
        }
    }

    /// Add a verified card to the trusted list, replacing any existing entry for
    /// the same key, and persist. Returns whether it was stored; on refusal the
    /// error banner says why.
    ///
    /// The single place trust is granted, so a card arriving over card setup is
    /// held to exactly the same rules as one pasted in by hand.
    fn store_peer_card(&mut self, card: IdentityCard) -> bool {
        if card.public_key() == self.identity.public_key() {
            self.error = Some("That is this device's own identity card".into());
            return false;
        }
        // Storing a lapsed card would record trust that can never pair, so
        // refuse it here rather than at the first Join.
        if card.is_expired() {
            self.error = Some(format!(
                "That identity card expired on {} — get a fresh one from the other device",
                card_expiry_date(&card)
            ));
            return false;
        }
        if let Some(existing) = self
            .peers
            .iter_mut()
            .find(|peer| peer.public_key() == card.public_key())
        {
            *existing = card;
        } else if self.peers.len() >= duocb_core::auth::MAX_TRUSTED_PEERS {
            self.error = Some("The trusted-peer limit is 128".into());
            return false;
        } else {
            self.peers.push(card);
        }
        self.save_configure_config();
        true
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

    /// Open the card-setup screen.
    ///
    /// Unlike the quick pairing this replaced, card setup hands over this
    /// device's signed card, so it needs an identity to exist: a no-op before
    /// setup is finished, and the entry point is hidden until then.
    pub(crate) fn open_card_setup(&mut self) {
        if self.self_card.is_none() {
            return;
        }
        // The card we are about to hand over should have most of its life left,
        // for the same reason `copy_card` re-mints before copying.
        self.renew_self_card_if_stale();
        self.screen = Screen::CardSetup;
        // Detect this device's LAN subnet so the join can lock the host IP's
        // network octets to it and reject an out-of-range address. Read once on
        // entry — a mid-session network change is rare and the field is optional
        // anyway (blank falls back to mDNS).
        self.join_ip_ctx = duocb_core::subnet::JoinIpConstraint::detect();
    }

    /// Show a PIN on this device so the other one can type it.
    pub(crate) fn host_card_setup(&mut self) {
        if self.server_mode_spec().is_none() {
            return;
        }
        self.screen = Screen::CardPairing;
        self.start_server();
    }

    /// Join a card setup: dial what the entry holds (the typed PIN, plus an
    /// optional host IP).
    ///
    /// Invalid input never dials, and says so. The Join *button* is disabled
    /// until the entry validates (see `dial-ready`), but the keyboard shortcut
    /// bypasses that, and a shortcut that silently does nothing reads as a
    /// broken key rather than a bad PIN.
    pub(crate) fn join_card_setup(&mut self) {
        let Some(spec) = self.card_setup_dial_spec() else {
            self.error = Some(self.card_setup_dial_problem());
            return;
        };
        self.client_active = true;
        self.net.send(UiCommand::Connect { spec });
        self.screen = Screen::CardPairing;
    }

    /// Why [`App::card_setup_dial_spec`] refused, phrased for the error banner.
    /// Checked in the same order the spec builds, so the message names the first
    /// thing the user has to fix.
    fn card_setup_dial_problem(&self) -> String {
        use duocb_core::subnet::JoinIpOutcome;
        if duocb_core::pin::normalize_pin(&format!("{}{}", self.in_pin_a, self.in_pin_b)).is_none() {
            return "Enter the full eight-character PIN shown on the other device".into();
        }
        // Same wording as the field's inline error (see `sync`), so the banner
        // and the field never describe one problem two ways.
        match self.join_ip_outcome() {
            JoinIpOutcome::OutOfRange => {
                format!("IP out of range for {}", self.join_ip_ctx.label())
            }
            JoinIpOutcome::Malformed => "Not a valid IPv4 address".into(),
            _ => "This device has no identity card to offer yet".into(),
        }
    }

    /// The heading and body shown for how this device and the other one find
    /// each other. It is launch-fixed (`--lan-only` / `--nostr-only`) and covers
    /// **both** flows — trading cards and every clipboard session after it —
    /// because one launch choice governs both. The difference is exactly the
    /// thing a user has to know before trusting the screen (whether a
    /// third-party server is involved, and whether the other device has to be on
    /// this network), so each channel says its own piece rather than one hedged
    /// paragraph covering all three.
    pub(crate) fn signal_channel_text(&self) -> (&'static str, &'static str) {
        match self.signal_channel {
            SignalChannel::LanThenNostr => (
                "How the devices find each other",
                "The other device is looked for on the local network first (Bonjour/DNS-SD, with traffic direct between the devices and no relay involved). If nothing answers there, the search falls back to public Nostr relays, which works when the two devices are on different networks. Only an encrypted record holding a temporary connection id is ever published, and this applies to trading cards and to clipboard sessions alike.",
            ),
            SignalChannel::LanOnly => (
                "Local network only",
                "No third-party server participates, for trading cards or for clipboard sessions: discovery uses Bonjour (DNS-SD) and traffic stays direct between the devices. If multicast is blocked, trading cards still works by typing the IP shown while hosting, but a clipboard session has no fallback and the two devices will not find each other. This is a discovery policy, not a packet-level subnet boundary; reflected mDNS, a VPN/overlay, or globally routed addresses can extend the direct path beyond a conventional LAN.",
            ),
            SignalChannel::NostrOnly => (
                "Relays only",
                "The local network is not searched at all, for trading cards or for clipboard sessions: the encrypted record is published to public Nostr relays, so the other device can be anywhere with internet access. The record holds only a temporary connection id, and the connection still goes direct between the devices when they can reach each other.",
            ),
        }
    }

    /// A one-line banner for the hub, shown only when the launch flags moved the
    /// app off its default channel. Empty for the default: the hub would
    /// otherwise carry a second copy of the card-setup screen's explanation, and
    /// the copy nobody edits is the one that goes stale. An override is worth
    /// naming, because it silently changes whether Start and Join can reach a
    /// device that is not on this network.
    pub(crate) fn signal_channel_badge(&self) -> &'static str {
        match self.signal_channel {
            SignalChannel::LanThenNostr => "",
            SignalChannel::LanOnly => {
                "Started with --lan-only: devices find each other on this network only."
            }
            SignalChannel::NostrOnly => {
                "Started with --nostr-only: devices find each other through relays only."
            }
        }
    }

    /// The identity line for one trusted-device row: name plus the fingerprint
    /// the user compared when importing it. The single source for that row, so
    /// what a test asserts is what the user sees.
    pub(crate) fn peer_row_line(&self, index: usize) -> Option<String> {
        let card = self.peers.get(index)?;
        Some(format!("{}  · {}", card.name(), card.fingerprint()))
    }

    /// What the confirmation screen shows for the incoming card: `(name,
    /// fingerprint, expiry)`, all empty when no card is pending. The single
    /// source for that panel, so what a test asserts is what the user sees.
    pub(crate) fn incoming_card_display(&self) -> (String, String, String) {
        match &self.pending_peer_card {
            Some(card) => (
                card.name().to_string(),
                card.fingerprint(),
                card_expiry_note(card),
            ),
            None => (String::new(), String::new(), String::new()),
        }
    }

    /// Trust the card that arrived, after the user has compared fingerprints.
    /// Returns to the hub on success; on refusal (own card, expired, list full)
    /// the error banner explains why.
    pub(crate) fn import_received_card(&mut self) {
        let Some(card) = self.pending_peer_card.take() else {
            return;
        };
        if self.store_peer_card(card) {
            self.screen = Screen::Home;
            self.configure_step = ConfigureStep::Ready;
        } else {
            self.screen = Screen::CardSetup;
        }
    }

    /// Discard the card that arrived without trusting it — the fingerprint did
    /// not match, or the user changed their mind.
    pub(crate) fn cancel_received_card(&mut self) {
        self.pending_peer_card = None;
        self.screen = Screen::CardSetup;
    }

    /// Navigate back one screen, stopping any running session. The card-setup
    /// screens step back through their own flow; everything else returns to the
    /// home hub.
    pub(crate) fn go_back(&mut self) {
        self.stop_session();
        self.screen = match self.screen {
            Screen::CardPairing => Screen::CardSetup,
            // Leaving the confirmation without importing discards the card.
            Screen::CardConfirm => {
                self.pending_peer_card = None;
                Screen::CardSetup
            }
            _ => Screen::Home,
        };
        // Home is the hub, not the device picker a join may have started from.
        if self.configure_step == ConfigureStep::Join {
            self.configure_step = ConfigureStep::Ready;
        }
    }

    /// Build the server mode from the current state, if it validates. Which
    /// mode is decided by the screen the user started from: the card-setup
    /// screens host a card exchange, everything else hosts a clipboard session.
    pub(crate) fn server_mode_spec(&self) -> Option<duocb_core::net::ServerMode> {
        use duocb_core::net::ServerMode;
        match self.screen {
            Screen::CardSetup | Screen::CardPairing => Some(ServerMode::CardSetup {
                self_card: Box::new(self.self_card.clone()?),
                channel: self.signal_channel,
                relays: default_relays(),
            }),
            _ => self.key_identity().map(|identity| ServerMode::Key {
                identity: Box::new(identity),
                channel: self.signal_channel,
            }),
        }
    }

    /// Build the configure-mode dial spec: exactly the peer selected in the
    /// device picker. Card setup dials through [`App::card_setup_dial_spec`]
    /// instead.
    pub(crate) fn client_dial_spec(&self) -> Option<duocb_core::net::DialSpec> {
        use duocb_core::net::DialSpec;
        Some(DialSpec::Key {
            identity: Box::new(self.key_identity()?),
            peer_public_key: self.selected_peer_card()?.public_key(),
            channel: self.signal_channel,
        })
    }

    /// The current validation outcome of the host-IP entry against the detected
    /// subnet constraint — the single source for both the displayed error
    /// (`sync`) and the dial's `target_ip` (`card_setup_dial_spec`).
    pub(crate) fn join_ip_outcome(&self) -> duocb_core::subnet::JoinIpOutcome {
        self.join_ip_ctx.resolve(&self.in_join_ip)
    }

    /// The card-setup dial spec, derived from the PIN entry. The optional
    /// host-IP entry, resolved and range-checked against this device's own
    /// subnet (see [`App::join_ip_ctx`]), selects the unicast side channel
    /// (blank resolves via mDNS, then the relays unless the channel says
    /// otherwise). `None` when the PIN is incomplete or fails its checksum,
    /// when this device has no card to offer, or when the typed host IP is
    /// malformed or out of range — which keeps the Join button disabled.
    pub(crate) fn card_setup_dial_spec(&self) -> Option<duocb_core::net::DialSpec> {
        use duocb_core::net::DialSpec;
        use duocb_core::subnet::JoinIpOutcome;
        let canonical_pin =
            duocb_core::pin::normalize_pin(&format!("{}{}", self.in_pin_a, self.in_pin_b))?;
        // Blank means mDNS; an in-range address selects the side channel;
        // anything malformed or out of range yields `None`.
        let target_ip = match self.join_ip_outcome() {
            JoinIpOutcome::Empty => None,
            JoinIpOutcome::InRange(ip) => Some(std::net::IpAddr::V4(ip)),
            JoinIpOutcome::OutOfRange | JoinIpOutcome::Malformed => return None,
        };
        Some(DialSpec::CardSetup {
            canonical_pin,
            self_card: Box::new(self.self_card.clone()?),
            target_ip,
            channel: self.signal_channel,
            relays: default_relays(),
        })
    }

    /// Go to the start screen and launch a configure-mode host.
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
            if let duocb_core::net::DialSpec::Key {
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

/// Card setup: the screen flow and, more importantly, the trust decisions made
/// at the end of it. These are the checks standing between "a card arrived over
/// the network" and "this device is trusted".
#[cfg(test)]
pub(crate) mod card_setup_tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A configured app (identity, name, self-card) on a throwaway config, plus
    /// its path so the test can clean up.
    pub(crate) fn configured_app() -> (App, PathBuf) {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "duocb-card-setup-{}-{}.json",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let lock = crate::config::acquire_lock(&path).unwrap();
        let mut app = App::new(
            lock,
            crate::config::Config::default(),
            duocb_core::net::spawn_net_runtime(None),
            SignalChannel::default(),
        );
        app.in_my_name = "desktop".into();
        app.save_name();
        assert!(app.self_card.is_some(), "the fixture must be configured");
        (app, path)
    }

    pub(crate) fn cleanup(mut app: App, path: PathBuf) {
        app.net.shutdown();
        drop(app);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path.display()));
    }

    /// Some other device's card, issued `age_secs` ago.
    pub(crate) fn peer_card(name: &str, age_secs: u64) -> IdentityCard {
        Identity::generate()
            .card_issued_at(name, "x9Y8z7W6", duocb_core::auth::unix_now() - age_secs)
            .unwrap()
    }

    /// Card setup hands over this device's signed card, so there has to be one:
    /// before setup is finished the screen must not open at all.
    #[test]
    fn card_setup_requires_a_configured_identity() {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "duocb-card-unconfigured-{}-{}.json",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let lock = crate::config::acquire_lock(&path).unwrap();
        let mut app = App::new(
            lock,
            crate::config::Config::default(),
            duocb_core::net::spawn_net_runtime(None),
            SignalChannel::default(),
        );
        assert!(app.self_card.is_none());

        app.open_card_setup();
        assert_eq!(app.screen, Screen::Home, "no card to offer, so no card setup");
        assert!(app.server_mode_spec().is_none());
        assert!(app.card_setup_dial_spec().is_none());

        cleanup(app, path);
    }

    /// The host offers *this* device's card, not something else.
    #[test]
    fn hosting_offers_this_devices_card() {
        let (mut app, path) = configured_app();
        app.open_card_setup();
        assert_eq!(app.screen, Screen::CardSetup);

        match app.server_mode_spec() {
            Some(duocb_core::net::ServerMode::CardSetup { self_card, .. }) => {
                assert_eq!(self_card.public_key(), app.identity.public_key());
            }
            other => panic!("expected a card-setup host, got {other:?}"),
        }
        cleanup(app, path);
    }

    /// The launch-time channel override reaches *both* roles. A flag that
    /// only took effect on the side that happened to be hosting would let a
    /// "nostr-only" test still pair over mDNS and prove nothing.
    #[test]
    fn the_channel_override_reaches_both_roles() {
        use duocb_core::net::{DialSpec, ServerMode};

        for channel in [
            SignalChannel::LanThenNostr,
            SignalChannel::LanOnly,
            SignalChannel::NostrOnly,
        ] {
            let (mut app, path) = configured_app();
            app.signal_channel = channel;
            app.open_card_setup();
            let pin = duocb_core::pin::generate_pin();
            app.in_pin_a = pin[..4].to_string();
            app.in_pin_b = pin[4..].to_string();

            match app.server_mode_spec() {
                Some(ServerMode::CardSetup {
                    channel: hosted,
                    relays,
                    ..
                }) => {
                    assert_eq!(hosted, channel, "host channel");
                    // The relays travel with the spec even on LAN-only (where
                    // they go unused): the runtime, not the UI, decides.
                    assert!(!relays.is_empty(), "a host needs relays to publish to");
                }
                other => panic!("expected a card-setup host, got {other:?}"),
            }
            match app.card_setup_dial_spec() {
                Some(DialSpec::CardSetup {
                    channel: dialed,
                    relays,
                    ..
                }) => {
                    assert_eq!(dialed, channel, "joiner channel");
                    assert!(!relays.is_empty(), "a joiner needs relays to query");
                }
                other => panic!("expected a card-setup dial, got {other:?}"),
            }

            // The same flag governs clipboard sessions, whose signaling is the
            // pairwise hosting record. Both roles again: a host that ignored the
            // override would keep announcing itself on a channel the test meant
            // to rule out.
            app.go_back();
            let peer = peer_card("peer", 0);
            assert!(app.store_peer_card(peer.clone()));
            app.toggle_peer(&peer.public_key().to_hex());
            match app.server_mode_spec() {
                Some(ServerMode::Key {
                    channel: hosted,
                    identity,
                }) => {
                    assert_eq!(hosted, channel, "clipboard host channel");
                    assert!(
                        !identity.relays.is_empty(),
                        "a host needs relays to publish to"
                    );
                }
                other => panic!("expected a clipboard host, got {other:?}"),
            }
            match app.client_dial_spec() {
                Some(DialSpec::Key {
                    channel: dialed,
                    identity,
                    ..
                }) => {
                    assert_eq!(dialed, channel, "clipboard joiner channel");
                    assert!(
                        !identity.relays.is_empty(),
                        "a joiner needs relays to query"
                    );
                }
                other => panic!("expected a clipboard dial, got {other:?}"),
            }
            cleanup(app, path);
        }
    }

    /// The screen explains the channel it is actually running on — the LAN-only
    /// promise ("no third-party server") must not be shown by a build that will
    /// fall back to public relays.
    #[test]
    fn the_screen_describes_the_channel_in_use() {
        let (mut app, path) = configured_app();

        // One canonical phrase, matched case-insensitively, so the positive and
        // negative checks are genuinely complementary: comparing two different
        // spellings would let the negative one pass on capitalisation alone.
        const LAN_PROMISE: &str = "no third-party server";

        app.signal_channel = SignalChannel::LanOnly;
        let (_, lan_note) = app.signal_channel_text();
        assert!(lan_note.to_lowercase().contains(LAN_PROMISE));

        app.signal_channel = SignalChannel::LanThenNostr;
        let (_, default_note) = app.signal_channel_text();
        assert!(default_note.contains("Nostr relays"));
        assert!(
            !default_note.to_lowercase().contains(LAN_PROMISE),
            "the default channel must not claim the LAN-only guarantee"
        );

        app.signal_channel = SignalChannel::NostrOnly;
        let (_, nostr_note) = app.signal_channel_text();
        assert!(nostr_note.contains("Nostr relays"));

        cleanup(app, path);
    }

    /// The dial spec needs a complete, checksum-valid PIN; a partial or
    /// mistyped one keeps Join disabled.
    #[test]
    fn joining_needs_a_valid_pin() {
        let (mut app, path) = configured_app();
        app.open_card_setup();

        assert!(app.card_setup_dial_spec().is_none(), "empty entry");
        app.in_pin_a = "ABCD".into();
        assert!(app.card_setup_dial_spec().is_none(), "half a PIN");

        // A generated PIN always passes its own checksum.
        let pin = duocb_core::pin::generate_pin();
        app.in_pin_a = pin[..4].to_string();
        app.in_pin_b = pin[4..].to_string();
        match app.card_setup_dial_spec() {
            Some(duocb_core::net::DialSpec::CardSetup {
                canonical_pin,
                self_card,
                target_ip,
                ..
            }) => {
                assert_eq!(canonical_pin, pin);
                assert_eq!(self_card.public_key(), app.identity.public_key());
                assert_eq!(target_ip, None, "blank host IP resolves via mDNS");
            }
            other => panic!("expected a card-setup dial, got {other:?}"),
        }

        // Flip one character: the check digit no longer matches.
        let mut typo = pin.clone().into_bytes();
        typo[0] = if typo[0] == b'2' { b'3' } else { b'2' };
        let typo = String::from_utf8(typo).unwrap();
        app.in_pin_a = typo[..4].to_string();
        app.in_pin_b = typo[4..].to_string();
        assert!(app.card_setup_dial_spec().is_none(), "a typo must not dial");

        cleanup(app, path);
    }

    /// The Join button is disabled on an invalid entry, but the keyboard
    /// shortcut is not — so joining on a bad PIN has to explain itself rather
    /// than look like a dead key.
    #[test]
    fn joining_on_an_invalid_pin_says_why_instead_of_nothing() {
        let (mut app, path) = configured_app();
        app.open_card_setup();
        app.in_pin_a = "ABCD".into();

        app.join_card_setup();

        assert!(!app.client_active, "a bad PIN must not dial");
        assert_eq!(app.screen, Screen::CardSetup, "and must not advance a screen");
        assert!(
            app.error.as_deref().is_some_and(|e| e.contains("PIN")),
            "the banner must name the PIN, got {:?}",
            app.error
        );
        cleanup(app, path);
    }

    /// A received card opens the confirmation screen and is *not* trusted yet.
    #[test]
    fn a_received_card_opens_the_confirmation_screen_without_trusting_it() {
        let (mut app, path) = configured_app();
        let card = peer_card("laptop", 0);

        app.apply_event(NetEvent::PeerCardReceived(Box::new(card.clone())));

        assert_eq!(app.screen, Screen::CardConfirm);
        assert_eq!(
            app.pending_peer_card.as_ref().map(IdentityCard::public_key),
            Some(card.public_key())
        );
        assert!(app.peers.is_empty(), "arriving is not the same as trusted");
        cleanup(app, path);
    }

    /// The runtime ends a card-setup session the instant the cards cross, so the
    /// `Idle` that follows must not wipe out the confirmation the user is
    /// looking at. This is the one ordering bug that would silently lose the
    /// card between the exchange and the screen.
    #[test]
    fn session_teardown_does_not_discard_a_pending_card() {
        let (mut app, path) = configured_app();
        let card = peer_card("laptop", 0);

        app.apply_event(NetEvent::PeerCardReceived(Box::new(card.clone())));
        app.apply_event(NetEvent::PinCleared);
        app.apply_event(NetEvent::Status(ConnStatus::Idle));

        assert_eq!(app.screen, Screen::CardConfirm, "the user is still deciding");
        assert_eq!(
            app.pending_peer_card.as_ref().map(IdentityCard::public_key),
            Some(card.public_key())
        );
        cleanup(app, path);
    }

    /// Importing trusts the card and persists it, so the pairing survives a
    /// restart.
    #[test]
    fn importing_a_received_card_trusts_and_persists_it() {
        let (mut app, path) = configured_app();
        let card = peer_card("laptop", 0);
        app.apply_event(NetEvent::PeerCardReceived(Box::new(card.clone())));

        app.import_received_card();

        assert_eq!(app.peers.len(), 1);
        assert_eq!(app.peers[0].public_key(), card.public_key());
        assert!(app.pending_peer_card.is_none());
        assert_eq!(app.screen, Screen::Home);
        assert_eq!(app.configure_step, ConfigureStep::Ready);

        // It really reached disk, not just memory.
        let saved = app.config_lock.load().unwrap();
        assert_eq!(saved.peers.len(), 1);
        assert_eq!(
            IdentityCard::parse(&saved.peers[0]).unwrap().public_key(),
            card.public_key()
        );
        cleanup(app, path);
    }

    /// Cancelling — the fingerprints did not match — must leave no trace.
    #[test]
    fn cancelling_discards_the_card_without_trusting_it() {
        let (mut app, path) = configured_app();
        app.apply_event(NetEvent::PeerCardReceived(Box::new(peer_card("laptop", 0))));

        app.cancel_received_card();

        assert!(app.pending_peer_card.is_none());
        assert!(app.peers.is_empty());
        assert_eq!(app.screen, Screen::CardSetup);
        assert!(app.config_lock.load().unwrap().peers.is_empty());
        cleanup(app, path);
    }

    /// Backing out of the confirmation screen is a refusal too.
    #[test]
    fn going_back_from_the_confirmation_discards_the_card() {
        let (mut app, path) = configured_app();
        app.apply_event(NetEvent::PeerCardReceived(Box::new(peer_card("laptop", 0))));

        app.go_back();

        assert!(app.pending_peer_card.is_none());
        assert!(app.peers.is_empty());
        assert_eq!(app.screen, Screen::CardSetup);
        cleanup(app, path);
    }

    /// A card that arrives already lapsed is refused: storing it would record
    /// trust that can never pair.
    #[test]
    fn an_expired_received_card_is_refused() {
        let (mut app, path) = configured_app();
        let stale = peer_card("laptop", duocb_core::auth::CARD_TTL_SECS + 1);
        assert!(stale.is_expired());
        app.apply_event(NetEvent::PeerCardReceived(Box::new(stale)));

        app.import_received_card();

        assert!(app.peers.is_empty(), "a lapsed card must not be trusted");
        assert!(app.error.is_some(), "and the user must be told why");
        assert_eq!(app.screen, Screen::CardSetup);
        cleanup(app, path);
    }

    /// Our own card reflected back — the shape a confused setup or a reflection
    /// attack would take — is refused rather than self-trusted.
    #[test]
    fn our_own_card_coming_back_is_refused() {
        let (mut app, path) = configured_app();
        let own = app.self_card.clone().unwrap();
        app.apply_event(NetEvent::PeerCardReceived(Box::new(own)));

        app.import_received_card();

        assert!(app.peers.is_empty());
        assert!(app.error.is_some());
        cleanup(app, path);
    }

    /// Re-running card setup with a device already trusted replaces its entry
    /// rather than adding a second one for the same key — this is the renewal
    /// path once a card nears its 30-day expiry.
    #[test]
    fn importing_again_renews_the_existing_entry() {
        let (mut app, path) = configured_app();
        let identity = Identity::generate();
        let old = identity
            .card_issued_at(
                "laptop",
                "x9Y8z7W6",
                duocb_core::auth::unix_now() - duocb_core::auth::CARD_TTL_SECS + 60,
            )
            .unwrap();
        app.apply_event(NetEvent::PeerCardReceived(Box::new(old.clone())));
        app.import_received_card();
        assert_eq!(app.peers.len(), 1);

        let fresh = identity.card("laptop", "x9Y8z7W6").unwrap();
        app.apply_event(NetEvent::PeerCardReceived(Box::new(fresh.clone())));
        app.import_received_card();

        assert_eq!(app.peers.len(), 1, "same key, same slot");
        assert_eq!(app.peers[0].expires_at(), fresh.expires_at());
        assert!(app.peers[0].expires_at() > old.expires_at());
        cleanup(app, path);
    }

    /// The confirmation screen's whole job is to display the incoming card, so
    /// assert the values it will actually show — holding the card in state is
    /// not the same as projecting it, and an unprojected card renders as a blank
    /// panel with a reassuring "import" button under it.
    #[test]
    fn a_pending_card_projects_the_values_the_user_compares() {
        let (mut app, path) = configured_app();
        let card = peer_card("laptop", 0);
        app.apply_event(NetEvent::PeerCardReceived(Box::new(card.clone())));

        let (name, fingerprint, expiry) = app.incoming_card_display();
        assert_eq!(name, card.name());
        assert_eq!(fingerprint, card.fingerprint());
        assert!(!fingerprint.is_empty(), "the user must have something to compare");
        assert_eq!(expiry, card_expiry_note(&card));

        // And it clears once the card is dealt with, so a stale fingerprint
        // cannot linger on screen.
        app.cancel_received_card();
        assert_eq!(
            app.incoming_card_display(),
            (String::new(), String::new(), String::new())
        );
        cleanup(app, path);
    }

    /// The fingerprint shown beside a trusted device is the one that device
    /// shows for itself — otherwise the comparison the user made at import time
    /// could not be repeated later.
    #[test]
    fn the_displayed_fingerprint_matches_the_peers_own() {
        let (mut app, path) = configured_app();
        let card = peer_card("laptop", 0);
        let expected = card.fingerprint();
        app.apply_event(NetEvent::PeerCardReceived(Box::new(card)));
        app.import_received_card();

        assert_eq!(app.peers[0].fingerprint(), expected);
        assert_eq!(
            duocb_core::auth::key_fingerprint(&app.identity.public_key()),
            app.self_card.as_ref().unwrap().fingerprint(),
            "and this device's own fingerprint is its card's"
        );
        cleanup(app, path);
    }

    /// The trusted-device row carries the same fingerprint the user compared at
    /// import time, so the pairing can be re-verified out of band later — a
    /// truncated npub there would be a different value with no relationship to
    /// what the other device displays.
    #[test]
    fn trusted_rows_show_the_comparable_fingerprint() {
        let (mut app, path) = configured_app();
        let card = peer_card("laptop", 0);
        let expected = card.fingerprint();
        app.apply_event(NetEvent::PeerCardReceived(Box::new(card)));
        app.import_received_card();

        let row = app.peer_row_line(0).expect("one trusted device");
        assert!(
            row.contains(&expected),
            "row {row:?} must show the fingerprint {expected:?}"
        );
        cleanup(app, path);
    }
}
