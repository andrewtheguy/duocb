//! The single push-style projection of [`App`] state into the `UiState`
//! global. Called after every mutation (action callback, event drain, timer
//! tick); idempotent, so nothing tracks *what* changed. The application private
//! key is only mirrored while the user explicitly restores it.

use slint::{Color, ComponentHandle, Model, ModelRc, SharedString, VecModel};
use std::time::Instant;

use super::{
    App, CopyTarget, card_expiry_date, card_expiry_note, item::ClipItem, item::PEEK_LIMIT, short_id,
};
use crate::{ClipRow, MainWindow, PathRow, PeerRow, UiState};
use duocb_core::auth::IdentityCard;
use duocb_core::net::ConnStatus;
use duocb_core::net::endpoint::ConnPathKind;
use duocb_core::subnet::JoinIpOutcome;

impl App {
    pub(crate) fn sync(&self, ui: &MainWindow) {
        let s = ui.global::<UiState>();

        // Navigation / shared status.
        s.set_screen(self.screen);
        s.set_configure_step(self.configure_step);
        s.set_status_text(self.status_text().into());
        s.set_connected(self.status == ConnStatus::Connected);
        s.set_server_running(self.server_running);
        s.set_client_active(self.client_active);
        s.set_error(str_or_empty(&self.error));

        // Configure identity / wizard.
        s.set_display_identity(self.display_identity().into());
        s.set_has_identity(self.self_card.is_some());
        s.set_own_fingerprint(
            duocb_core::auth::key_fingerprint(&self.identity.public_key()).into(),
        );
        s.set_public_key(self.identity.to_npub().into());
        s.set_config_path(self.config_lock.path().display().to_string().into());
        let copied = self.copied_target();
        s.set_copied_card(copied == Some(CopyTarget::Card));
        s.set_copied_private_key(copied == Some(CopyTarget::PrivateKey));
        s.set_copied_pin(copied == Some(CopyTarget::Pin));
        let name = self.in_my_name.trim();
        match duocb_core::identity::validate_name(name) {
            Ok(()) => {
                s.set_name_valid(true);
                s.set_name_preview(
                    duocb_core::identity::display_identity(name, &self.device_suffix).into(),
                );
                s.set_name_error(SharedString::default());
            }
            Err(e) => {
                s.set_name_valid(false);
                s.set_name_preview(SharedString::default());
                s.set_name_error(if name.is_empty() {
                    SharedString::default()
                } else {
                    e.to_string().into()
                });
            }
        }
        s.set_can_cancel_name(self.has_saved_identity());
        s.set_name_rules(
            format!(
                "Choose the short name; the permanent random suffix shown below is appended automatically. Letters, digits, and '-' only (max {} characters).",
                duocb_core::identity::NAME_MAX_LEN
            )
            .into(),
        );
        let (import_valid, import_fingerprint, import_error) =
            match duocb_core::auth::Identity::parse_nsec(&self.in_private_key) {
                Ok(identity) => (true, identity.to_npub(), String::new()),
                Err(_) if self.in_private_key.trim().is_empty() => {
                    (false, String::new(), String::new())
                }
                Err(e) => (false, String::new(), format!("{e:#}")),
            };
        s.set_import_valid(import_valid);
        s.set_import_public_key(import_fingerprint.into());
        s.set_import_error(import_error.into());
        let (peer_card_valid, peer_card_error) = match IdentityCard::parse(&self.in_peer_card) {
            Ok(card) if card.public_key() == self.identity.public_key() => {
                (false, "That is this device's own identity card".to_string())
            }
            Ok(card) if card.is_expired() => (
                false,
                format!(
                    "That identity card expired on {} — copy a fresh one from the other device",
                    card_expiry_date(&card)
                ),
            ),
            Ok(_) => (true, String::new()),
            Err(_) if self.in_peer_card.trim().is_empty() => (false, String::new()),
            Err(error) => (false, format!("{error:#}")),
        };
        s.set_peer_card_valid(peer_card_valid);
        s.set_peer_card_error(peer_card_error.into());

        // Device picker.
        let rows: Vec<PeerRow> = self
            .peers
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let key = p.public_key().to_hex();
                PeerRow {
                    public_key: key.clone().into(),
                    // The fingerprint, not a truncated npub: it is the value the
                    // user compared at import time, so showing the same one here
                    // lets the pairing be re-verified out of band later.
                    line: self.peer_row_line(i).unwrap_or_default().into(),
                    note: card_expiry_note(p).into(),
                    expired: p.is_expired(),
                    selected: self.selected_peer.as_deref() == Some(key.as_str()),
                }
            })
            .collect();
        if let Some(model) = diffed_model(&s.get_peers(), rows) {
            s.set_peers(model);
        }
        s.set_peers_updated(format!("{} trusted peer(s)", self.peers.len()).into());
        s.set_peers_empty_text(if !self.peers.is_empty() {
            SharedString::default()
        } else {
            "No trusted peers yet. Paste the other device's signed card above, or use Trade cards to send it over the network.".into()
        });
        s.set_join_ready(self.selected_peer_card().is_some());

        // Server / running-session identity.
        s.set_joined_peer(str_or_empty(&self.joined_peer));
        s.set_node_id_short(
            self.node_id
                .as_deref()
                .map(short_id)
                .unwrap_or_default()
                .into(),
        );
        s.set_peer_node_id_short(
            self.peer_node_id
                .as_deref()
                .map(short_id)
                .unwrap_or_default()
                .into(),
        );
        s.set_session_public_key(
            self.identity_public_key
                .clone()
                .or_else(|| Some(self.identity.to_npub()))
                .unwrap_or_default()
                .into(),
        );
        s.set_host_lan_ip(str_or_empty(&self.host_lan_ip));
        s.set_pin_display(str_or_empty(&self.pin_display));
        s.set_pin_countdown(match (&self.pin_display, self.pin_deadline) {
            (Some(_), Some(deadline)) => {
                let left = deadline.saturating_duration_since(Instant::now()).as_secs();
                format!("refreshes in {left}s").into()
            }
            _ => SharedString::default(),
        });

        // Card-setup confirmation: the incoming card beside this device's own
        // identity. Blank whenever no card is pending, so a stale fingerprint
        // can never linger on screen for the user to compare against.
        let (incoming_name, incoming_fingerprint, incoming_expiry) = self.incoming_card_display();
        s.set_incoming_name(incoming_name.into());
        s.set_incoming_fingerprint(incoming_fingerprint.into());
        s.set_incoming_expiry(incoming_expiry.into());

        // Client join forms. The two group fields together make the PIN.
        // Distinguish "still typing" (fewer than a full PIN's characters) from
        // "full length but a typo" so the hint under the fields is a neutral
        // progress line while typing and only turns into a validation warning
        // once the whole code is in.
        let combined = format!("{}{}", self.in_pin_a, self.in_pin_b);
        let pin_len = duocb_core::pin::pin_input_len(&combined);
        let pin_full = pin_len == duocb_core::pin::PIN_LEN;
        s.set_pin_incomplete(if pin_len > 0 && !pin_full {
            format!("Keep typing — {pin_len} of {} characters", duocb_core::pin::PIN_LEN).into()
        } else {
            SharedString::default()
        });
        let canonical_pin = duocb_core::pin::normalize_pin(&combined);
        s.set_pin_invalid(pin_full && canonical_pin.is_none());
        // Drives the joiner's auto-advance from the first group to the second.
        s.set_pin_a_full(
            duocb_core::pin::pin_input_len(&self.in_pin_a) == duocb_core::pin::PIN_GROUP_LEN,
        );
        // The optional host-IP entry is constrained to this device's own
        // subnet: `join-ip-prefix` is the locked network part the user types
        // after, `join-ip-hint` a range hint for a partial-octet subnet, and
        // `join-ip-error` the out-of-range / malformed message. `dial_ready`
        // (below) folds validity in via `card_setup_dial_spec`.
        s.set_join_ip_prefix(self.join_ip_ctx.locked_prefix().into());
        s.set_join_ip_placeholder(self.join_ip_ctx.host_placeholder().into());
        s.set_join_ip_hint(self.join_ip_ctx.hint().into());
        s.set_join_ip_error(match self.join_ip_outcome() {
            JoinIpOutcome::OutOfRange => {
                format!("IP out of range for {}", self.join_ip_ctx.label()).into()
            }
            JoinIpOutcome::Malformed => "Not a valid IPv4 address".into(),
            JoinIpOutcome::Empty | JoinIpOutcome::InRange(_) => SharedString::default(),
        });
        s.set_dial_ready(self.card_setup_dial_spec().is_some());

        // Card setup's channel: what the screen tells the user about how the
        // devices find each other, and whether the manual host-IP path (which
        // only exists on the local-network channel) is offered at all.
        let (channel_title, channel_note) = self.setup_channel_text();
        s.set_setup_channel_title(channel_title.into());
        s.set_setup_channel_note(channel_note.into());
        s.set_setup_lan_enabled(self.setup_channel.lan());

        // Session panel.
        s.set_sent_flash(self.sent_flash_active());
        s.set_outbox_present(self.outbox.is_some());
        s.set_outbox(
            self.outbox
                .as_ref()
                .map(|item| {
                    let mut row = clip_row(item);
                    row.copied = copied == Some(CopyTarget::Outbox);
                    row
                })
                .unwrap_or_default(),
        );
        let inbox: Vec<ClipRow> = self
            .inbox
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let mut row = clip_row(item);
                row.copied = copied == Some(CopyTarget::Inbox(i));
                row
            })
            .collect();
        s.set_inbox_title(format!("Inbox ({})", inbox.len()).into());
        if let Some(model) = diffed_model(&s.get_inbox(), inbox) {
            s.set_inbox(model);
        }

        // Modals.
        s.set_show_reset_identity(self.confirm_reset_identity);
        s.set_show_conn_path(self.conn_path.is_some());
        let paths: Vec<PathRow> = self
            .conn_path
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|p| PathRow {
                marker: if p.selected { "●" } else { "○" }.into(),
                color: match p.kind {
                    ConnPathKind::Direct => Color::from_rgb_u8(0x2e, 0xa0, 0x43),
                    ConnPathKind::Relay => Color::from_rgb_u8(0xd2, 0x92, 0x22),
                    ConnPathKind::Other => Color::from_rgb_u8(0x88, 0x88, 0x88),
                },
                display: p.display.clone().into(),
            })
            .collect();
        if let Some(model) = diffed_model(&s.get_conn_paths(), paths) {
            s.set_conn_paths(model);
        }

        // Field texts: the Rust mirrors are authoritative (updated on every
        // edit), so writing them back is a no-op while typing and applies
        // resets (wizard cancels, compose clear) to the actual fields.
        s.set_in_my_name(self.in_my_name.clone().into());
        s.set_in_private_key(self.in_private_key.clone().into());
        s.set_in_peer_card(self.in_peer_card.clone().into());
        s.set_in_pin_a(self.in_pin_a.clone().into());
        s.set_in_pin_b(self.in_pin_b.clone().into());
        s.set_in_join_ip(self.in_join_ip.clone().into());
        s.set_in_compose(self.in_compose.clone().into());
    }
}

fn str_or_empty(value: &Option<String>) -> SharedString {
    value.clone().unwrap_or_default().into()
}

/// Update a list property in place: rows are diffed against the existing
/// `VecModel` so unchanged rows don't re-instantiate their elements (the
/// heartbeat re-syncs twice a second — wholesale model replacement would
/// reset hover/press state and flicker). Returns a fresh model only on the
/// first sync, when the property still holds the compiler default.
fn diffed_model<T: Clone + PartialEq + 'static>(
    current: &ModelRc<T>,
    rows: Vec<T>,
) -> Option<ModelRc<T>> {
    let Some(vec) = current.as_any().downcast_ref::<VecModel<T>>() else {
        return Some(ModelRc::new(VecModel::from(rows)));
    };
    while vec.row_count() > rows.len() {
        vec.remove(rows.len());
    }
    for (i, row) in rows.into_iter().enumerate() {
        if i >= vec.row_count() {
            vec.push(row);
        } else if vec.row_data(i).as_ref() != Some(&row) {
            vec.set_row_data(i, row);
        }
    }
    None
}

/// Project one inbox/outbox item. The content is only shipped while expanded
/// (peeked); collapsed rows carry metadata alone.
fn clip_row(item: &ClipItem) -> ClipRow {
    let (peek_text, peek_lines, truncated_note) = if item.expanded() {
        let (shown, truncated) = item.peek_text();
        let lines = shown.lines().count().clamp(2, 14) as i32;
        let note = if truncated {
            format!(
                "… truncated — showing the first {PEEK_LIMIT} characters. Use Copy for the full {}.",
                item.size_hint()
            )
        } else {
            String::new()
        };
        (shown.to_string(), lines, note)
    } else {
        (String::new(), 0, String::new())
    };
    ClipRow {
        time: item.timestamp.strftime("%H:%M:%S").to_string().into(),
        size: item.size_hint().into(),
        crc: item.crc32_display().into(),
        expanded: item.expanded(),
        peek_text: peek_text.into(),
        peek_lines,
        truncated_note: truncated_note.into(),
        // Set by the caller from the active copy flash; not derivable from the item.
        copied: false,
    }
}
