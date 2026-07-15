//! The single push-style projection of [`App`] state into the `UiState`
//! global. Called after every mutation (action callback, event drain, timer
//! tick); idempotent, so nothing tracks *what* changed. Secrets are never
//! pushed in full — only masked hints and fingerprints.

use slint::{Color, ComponentHandle, Model, ModelRc, SharedString, VecModel};
use std::time::Instant;

use super::{
    App, CopyTarget, ago, item::ClipItem, item::PEEK_LIMIT, masked_secret_hint, now_unix, short_id,
};
use crate::{ClipRow, MainWindow, PathRow, PeerRow, UiState};
use duocb_core::net::ConnStatus;
use duocb_core::net::endpoint::ConnPathKind;
use duocb_core::subnet::JoinIpOutcome;

impl App {
    pub(crate) fn sync(&self, ui: &MainWindow) {
        let s = ui.global::<UiState>();

        // Navigation / shared status.
        s.set_screen(self.screen);
        s.set_configure_step(self.configure_step);
        s.set_mode(self.mode);
        s.set_pin_channel(self.pin_channel);
        s.set_quick_advanced_open(self.quick_advanced_open());
        s.set_status_text(self.status_text().into());
        s.set_connected(self.status == ConnStatus::Connected);
        s.set_server_running(self.server_running);
        s.set_client_active(self.client_active);
        s.set_error(str_or_empty(&self.error));

        // Configure identity / wizard.
        s.set_display_identity(self.display_identity().into());
        s.set_has_secret(self.secret.is_some());
        s.set_secret_hint(
            self.secret
                .as_deref()
                .map(masked_secret_hint)
                .unwrap_or_default()
                .into(),
        );
        s.set_secret_fingerprint(
            self.secret
                .as_deref()
                .map(duocb_core::auth::token_fingerprint)
                .unwrap_or_default()
                .into(),
        );
        s.set_config_path(self.config_lock.path().display().to_string().into());
        s.set_presence_conflict(str_or_empty(&self.presence_conflict));
        let copied = self.copied_target();
        s.set_copied_secret(copied == Some(CopyTarget::Secret));
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
                "A short name plus this device's permanent id — other devices will see it in their list. Letters, digits, and '-' only (max {} characters).",
                duocb_core::identity::NAME_MAX_LEN
            )
            .into(),
        );
        let import = self.in_import_token.trim();
        let import_valid = duocb_core::auth::validate_token(import).is_ok();
        s.set_import_valid(import_valid);
        s.set_import_fingerprint(if import_valid {
            duocb_core::auth::token_fingerprint(import).into()
        } else {
            SharedString::default()
        });
        s.set_import_invalid(!import.is_empty() && !import_valid);

        // Device picker.
        let rows: Vec<PeerRow> = self
            .peers
            .iter()
            .map(|p| {
                let mut line = p.display();
                // The record's age, not an online/offline verdict — relay
                // timing is too unreliable for one, and joining never
                // requires it.
                let age = now_unix().saturating_sub(p.last_seen_unix);
                line.push_str(&format!("  · seen {}", ago(age)));
                PeerRow {
                    suffix: p.suffix.clone().into(),
                    line: line.into(),
                    selected: self.selected_peer.as_deref() == Some(p.suffix.as_str()),
                }
            })
            .collect();
        if let Some(model) = diffed_model(&s.get_peers(), rows) {
            s.set_peers(model);
        }
        s.set_peers_updated(
            self.peers_refreshed_at
                .map(|at| format!("updated {}", ago(at.elapsed().as_secs())))
                .unwrap_or_default()
                .into(),
        );
        s.set_peers_empty_text(if !self.peers.is_empty() {
            SharedString::default()
        } else if self.peers_refreshed_at.is_some() {
            "No other devices found yet. Import the same secret on your other device and it will appear here.".into()
        } else {
            "Looking for your other devices…".into()
        });
        s.set_join_ready(self.selected_peer_display().is_some());

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
        s.set_session_fingerprint(
            self.token_fingerprint
                .clone()
                .or_else(|| {
                    self.secret
                        .as_deref()
                        .map(duocb_core::auth::token_fingerprint)
                })
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
        s.set_pin_paired(self.pin_paired);

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
        s.set_pin_invalid(pin_full && duocb_core::pin::normalize_pin(&combined).is_none());
        // Drives the joiner's auto-advance from the first group to the second.
        s.set_pin_a_full(
            duocb_core::pin::pin_input_len(&self.in_pin_a) == duocb_core::pin::PIN_GROUP_LEN,
        );
        // The optional host-IP entry shows only for a LAN-only PIN (its first
        // character marks the channel — see `duocb_core::pin`). It is constrained
        // to this device's own subnet: `join-ip-prefix` is the locked network
        // part the user types after, `join-ip-hint` a range hint for a
        // partial-octet subnet, and `join-ip-error` the out-of-range / malformed
        // message. `dial_ready` (below) folds validity in via `client_dial_spec`.
        s.set_pin_is_lan_only(duocb_core::pin::pin_is_lan_only(&combined));
        s.set_join_ip_prefix(self.join_ip_ctx.locked_prefix().into());
        s.set_join_ip_hint(self.join_ip_ctx.hint().into());
        s.set_join_ip_error(match self.join_ip_outcome() {
            JoinIpOutcome::OutOfRange => {
                format!("IP out of range for {}", self.join_ip_ctx.label()).into()
            }
            JoinIpOutcome::Malformed => "Not a valid IPv4 address".into(),
            JoinIpOutcome::Empty | JoinIpOutcome::InRange(_) => SharedString::default(),
        });
        s.set_dial_ready(self.client_dial_spec().is_some());

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
        s.set_show_clear_secret(self.confirm_clear_secret);
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
        s.set_in_import_token(self.in_import_token.clone().into());
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
