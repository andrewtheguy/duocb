//! The single push-style projection of [`App`] state into the `UiState`
//! global. Called after every mutation (action callback, event drain, timer
//! tick); idempotent, so nothing tracks *what* changed. The application private
//! key is only mirrored while the user explicitly restores it.

use slint::{Color, ComponentHandle, Model, ModelRc, SharedString, VecModel};
use std::time::Instant;

use super::{App, CopyTarget, item::ClipItem, item::PEEK_LIMIT, short_id};
use crate::{ClipRow, MainWindow, PathRow, PeerRow, UiState};
use duocb_core::auth::{DirectoryChannel, IdentityCard};
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
        s.set_status_text(self.status_text().into());
        s.set_connected(self.status == ConnStatus::Connected);
        s.set_server_running(self.server_running);
        s.set_client_active(self.client_active);
        s.set_error(str_or_empty(&self.error));

        // Configure identity / wizard.
        s.set_display_identity(self.display_identity().into());
        s.set_has_identity(self.self_card.is_some());
        s.set_public_key_short(
            short_id(&self.identity.to_npub())
                .into(),
        );
        s.set_public_key(self.identity.to_npub().into());
        s.set_config_path(self.config_lock.path().display().to_string().into());
        s.set_presence_conflict(SharedString::default());
        let copied = self.copied_target();
        s.set_copied_card(copied == Some(CopyTarget::Card));
        s.set_copied_private_key(copied == Some(CopyTarget::PrivateKey));
        s.set_copied_channel(copied == Some(CopyTarget::Channel));
        s.set_copied_pin(copied == Some(CopyTarget::Pin));
        let name = self.in_my_name.trim();
        match duocb_core::identity::validate_name(name) {
            Ok(()) => {
                s.set_name_valid(true);
                s.set_name_preview(name.into());
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
                "The name signed into this device's identity card. Letters, digits, and '-' only (max {} characters).",
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
            Ok(_) => (true, String::new()),
            Err(_) if self.in_peer_card.trim().is_empty() => (false, String::new()),
            Err(error) => (false, format!("{error:#}")),
        };
        s.set_peer_card_valid(peer_card_valid);
        s.set_peer_card_error(peer_card_error.into());
        let (channel_valid, channel_error) =
            match DirectoryChannel::parse(&self.in_directory_channel) {
                Ok(_) => (true, String::new()),
                Err(_) if self.in_directory_channel.trim().is_empty() => {
                    (false, String::new())
                }
                Err(error) => (false, format!("{error:#}")),
            };
        s.set_channel_valid(channel_valid);
        s.set_channel_error(channel_error.into());
        s.set_has_channel(self.directory_channel.is_some());
        s.set_channel_display(
            self.directory_channel
                .map(|channel| channel.encode())
                .unwrap_or_default()
                .into(),
        );
        s.set_backup_status(if self.directory_channel.is_none() {
            "No Nostr backup channel configured".into()
        } else if self.backup_check_pending {
            "Checking for an encrypted peer-list backup…".into()
        } else if self.backup_publish_blocked {
            "Backup publication is paused until recovery is resolved or a check succeeds".into()
        } else if self.backup_dirty {
            "Peer-list backup pending".into()
        } else {
            "Peer-list backup is current".into()
        });
        s.set_backup_found(self.recovery_snapshot.is_some());
        s.set_backup_summary(
            self.recovery_snapshot
                .as_ref()
                .map(|snapshot| {
                    format!(
                        "Backup generation {} for “{}” contains {} peer(s). Choose which peers to restore.",
                        snapshot.generation,
                        snapshot.self_card.name(),
                        snapshot.peers.len()
                    )
                })
                .unwrap_or_default()
                .into(),
        );
        s.set_backup_selected_count(self.recovery_selected.len() as i32);
        let backup_rows: Vec<PeerRow> = self
            .recovery_snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .peers
                    .iter()
                    .map(|peer| {
                        let key = peer.public_key().to_hex();
                        PeerRow {
                            public_key: key.clone().into(),
                            line: format!("{}  · {}", peer.name(), short_id(&peer.npub())).into(),
                            selected: self.recovery_selected.contains(&key),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        if let Some(model) = diffed_model(&s.get_backup_peers(), backup_rows) {
            s.set_backup_peers(model);
        }
        let candidate_rows: Vec<PeerRow> = self
            .directory_candidates
            .iter()
            .filter(|candidate| {
                !self
                    .peers
                    .iter()
                    .any(|peer| peer.public_key() == candidate.public_key())
            })
            .map(|candidate| PeerRow {
                public_key: candidate.public_key().to_hex().into(),
                line: format!(
                    "{}  · {}",
                    candidate.name(),
                    short_id(&candidate.npub())
                )
                .into(),
                selected: false,
            })
            .collect();
        if let Some(model) = diffed_model(&s.get_directory_candidates(), candidate_rows) {
            s.set_directory_candidates(model);
        }

        // Device picker.
        let rows: Vec<PeerRow> = self
            .peers
            .iter()
            .map(|p| {
                let line = format!("{}  · {}", p.name(), short_id(&p.npub()));
                let key = p.public_key().to_hex();
                PeerRow {
                    public_key: key.clone().into(),
                    line: line.into(),
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
            "No trusted peers yet. Paste the other device's signed card on the hub.".into()
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
        let canonical_pin = duocb_core::pin::normalize_pin(&combined);
        s.set_pin_invalid(pin_full && canonical_pin.is_none());
        s.set_pin_not_local(
            canonical_pin
                .as_deref()
                .is_some_and(|pin| !duocb_core::pin::pin_is_lan_only(pin)),
        );
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
        s.set_join_ip_placeholder(self.join_ip_ctx.host_placeholder().into());
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
        s.set_in_directory_channel(self.in_directory_channel.clone().into());
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
