//! The single push-style projection of [`App`] state into the `UiState`
//! global. Called after every mutation (action callback, event drain, timer
//! tick); idempotent, so nothing tracks *what* changed. Secrets are never
//! pushed in full — only masked hints and fingerprints.

use slint::{ComponentHandle, Color, ModelRc, SharedString, VecModel};
use std::time::Instant;

use super::{App, ago, item::ClipItem, item::PEEK_LIMIT, masked_secret_hint, now_unix, short_id};
use crate::{ClipRow, MainWindow, PathRow, PeerRow, UiState};
use duocb_core::net::ConnStatus;
use duocb_core::net::endpoint::ConnPathKind;

impl App {
    pub(crate) fn sync(&self, ui: &MainWindow) {
        let s = ui.global::<UiState>();

        // Navigation / shared status.
        s.set_screen(self.screen);
        s.set_configure_step(self.configure_step);
        s.set_mode(self.mode);
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
        s.set_copied_flash(self.copied_flash_active());
        s.set_wizard_secret_hint(
            self.wizard_token
                .as_deref()
                .map(masked_secret_hint)
                .unwrap_or_default()
                .into(),
        );
        s.set_wizard_fingerprint(
            self.wizard_token
                .as_deref()
                .map(duocb_core::auth::token_fingerprint)
                .unwrap_or_default()
                .into(),
        );
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
        s.set_name_max_len(duocb_core::identity::NAME_MAX_LEN as i32);
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
                if p.node_id.is_some() {
                    line.push_str("  — hosting");
                }
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
        s.set_peers(ModelRc::new(VecModel::from(rows)));
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
        s.set_manual_token_present(self.manual_token.is_some());
        s.set_manual_token_fingerprint(
            self.manual_token
                .as_deref()
                .map(duocb_core::auth::token_fingerprint)
                .unwrap_or_default()
                .into(),
        );
        s.set_pin_display(str_or_empty(&self.pin_display));
        s.set_pin_remaining(self.pin_deadline.map_or(0, |d| {
            d.saturating_duration_since(Instant::now()).as_secs() as i32
        }));
        s.set_pin_paired(self.pin_paired);

        // Client join forms.
        let pin = self.in_pin.trim();
        s.set_pin_invalid(!pin.is_empty() && duocb_core::pin::normalize_pin(pin).is_none());
        let manual = self.in_manual_token.trim();
        let manual_valid = duocb_core::auth::validate_token(manual).is_ok();
        s.set_manual_entry_fingerprint(if manual_valid {
            duocb_core::auth::token_fingerprint(manual).into()
        } else {
            SharedString::default()
        });
        s.set_manual_entry_invalid(!manual.is_empty() && !manual_valid);
        s.set_dial_ready(self.client_dial_spec().is_some());

        // Session panel.
        s.set_sent_flash(self.sent_flash_active());
        s.set_outbox_present(self.outbox.is_some());
        s.set_outbox(self.outbox.as_ref().map(clip_row).unwrap_or_default());
        let inbox: Vec<ClipRow> = self.inbox.iter().map(clip_row).collect();
        s.set_inbox_count(inbox.len() as i32);
        s.set_inbox(ModelRc::new(VecModel::from(inbox)));

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
        s.set_conn_paths(ModelRc::new(VecModel::from(paths)));

        // Field texts: the Rust mirrors are authoritative (updated on every
        // edit), so writing them back is a no-op while typing and applies
        // resets (wizard cancels, compose clear) to the actual fields.
        s.set_in_my_name(self.in_my_name.clone().into());
        s.set_in_import_token(self.in_import_token.clone().into());
        s.set_in_pin(self.in_pin.clone().into());
        s.set_in_node_id(self.in_node_id.clone().into());
        s.set_in_manual_token(self.in_manual_token.clone().into());
        s.set_in_compose(self.in_compose.clone().into());
    }
}

fn str_or_empty(value: &Option<String>) -> SharedString {
    value.clone().unwrap_or_default().into()
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
    }
}
