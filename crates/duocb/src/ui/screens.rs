//! Home / start / join screens.
//!
//! The two roles are only about who sets up the connection — once paired, both
//! devices can send and receive. One device *starts* a connection and shows a
//! PIN/code (the transport server/listener); the other *joins* by entering it
//! (the client/dialer).
//!
//! Keyboard shortcuts (also listed in the UI): home picks quick mode with 1
//! (then P for PIN / M for manual) or config with 2, and role with S (start) /
//! C (join); Ctrl/Command+Enter starts/joins; Esc goes back;
//! starting-device credentials can be copied with Ctrl/Command+I (node id) /
//! Ctrl/Command+T (token) whenever they are available.

use eframe::egui::{self, RichText, TextEdit, Ui};

use duocb_core::nostr::DEFAULT_NOSTR_RELAYS;
use crate::ui::app::{DuocbApp, session_panel_if_connected};
use crate::ui::{PairMode, Screen};

pub(crate) fn default_relays() -> Vec<String> {
    DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect()
}

/// Shorten a node id for display.
fn short_id(id: &str) -> String {
    if id.len() <= 16 {
        id.to_string()
    } else {
        format!("{}…{}", &id[..8], &id[id.len() - 8..])
    }
}

/// Feedback shown beneath a masked token entry field. The token itself is never
/// rendered: once the input is a complete, checksum-valid token its fingerprint
/// appears (so both devices can confirm they share it); a non-empty but invalid
/// input shows a warning instead. Nothing is shown for an empty field.
fn token_entry_feedback(ui: &mut Ui, token: &str) {
    let token = token.trim();
    if token.is_empty() {
        return;
    }
    if duocb_core::auth::validate_token(token).is_ok() {
        ui.horizontal(|ui| {
            ui.label("Token fingerprint:");
            ui.monospace(duocb_core::auth::token_fingerprint(token));
        });
        ui.label(
            RichText::new("Confirm this matches on the other device.")
                .weak()
                .small(),
        );
    } else {
        ui.colored_label(ui.visuals().warn_fg_color, "That is not a valid token");
    }
}

/// Keep the standing-pairing identity visible after the editable form is gone.
/// Mirrors duopipe's persistent config-mode header without showing or exposing
/// the token while a session is running.
fn show_token_pairing_summary(app: &DuocbApp, ui: &mut Ui) {
    let token = app.in_token.trim().to_string();
    let fingerprint = app.token_fingerprint.clone().or_else(|| {
        duocb_core::auth::validate_token(&token)
            .is_ok()
            .then(|| duocb_core::auth::token_fingerprint(&token))
    });

    ui.group(|ui| {
        ui.label(RichText::new("Token pairing").strong());
        if let Some(name) = Some(app.in_my_name.trim()).filter(|name| !name.is_empty()) {
            ui.horizontal(|ui| {
                ui.label("This device:");
                ui.label(RichText::new(name).strong());
            });
        }
        if let Some(node_id) = &app.node_id {
            ui.horizontal(|ui| {
                ui.label("This node:");
                ui.monospace(short_id(node_id));
            });
        }
        if let Some(peer) = &app.peer_node_id {
            ui.horizontal(|ui| {
                ui.label("Paired with:");
                ui.monospace(short_id(peer));
            });
        }
        if let Some(fingerprint) = fingerprint {
            ui.horizontal(|ui| {
                ui.label("Token fingerprint:");
                ui.monospace(fingerprint);
                ui.label("(must match on both devices)");
            });
        }
        if app.token_settings_saved {
            ui.horizontal_wrapped(|ui| {
                ui.label("Saved settings:");
                ui.monospace(app.config_lock.path().display().to_string());
            });
        } else if app.status == duocb_core::net::ConnStatus::Connected {
            ui.label(
                RichText::new("Settings could not be saved; see the error above.")
                    .weak()
                    .small(),
            );
        } else if app.client_active {
            ui.label(
                RichText::new("Settings will be saved after a successful connection.")
                    .weak()
                    .small(),
            );
        }
    });
}

pub fn show_home(app: &mut DuocbApp, ui: &mut Ui) {
    ui.add_space(8.0);
    ui.heading("duocb");
    ui.label("Peer-to-peer clipboard sharing between two devices.");
    ui.label(
        RichText::new(
            "Both devices can send and receive. One device starts a connection \
             and shows a code; the other joins by entering it.",
        )
        .weak(),
    );
    ui.add_space(16.0);

    ui.group(|ui| {
        ui.label(RichText::new("Pairing mode").strong());

        // Two-step choice (mirrors duopipe): pick quick vs. config first, then —
        // for quick — the signaling. Both quick sub-modes map to a `PairMode`
        // that never touches the saved config; "use config" is the token pairing.
        let quick_selected = matches!(app.mode, PairMode::NostrPin | PairMode::Manual);
        if ui
            .radio(quick_selected, "1  Quick mode — pair on the spot, nothing saved")
            .clicked()
            && !quick_selected
        {
            // Entering quick mode leads with the headline rotating-PIN flow.
            app.mode = PairMode::NostrPin;
        }
        if quick_selected {
            ui.indent("quick_submode", |ui| {
                ui.radio_value(
                    &mut app.mode,
                    PairMode::NostrPin,
                    "P  PIN quick pair — type a short rotating code (internet)",
                );
                ui.radio_value(
                    &mut app.mode,
                    PairMode::Manual,
                    "M  Manual — node id + token (works offline on the same LAN)",
                );
            });
        }
        if ui
            .radio(
                app.mode == PairMode::NostrToken,
                "2  Use config — standing pairing with a shared token (internet)",
            )
            .clicked()
        {
            app.mode = PairMode::NostrToken;
        }
    });
    ui.add_space(16.0);

    ui.vertical_centered_justified(|ui| {
        if ui
            .add_sized(
                [0.0, 40.0],
                egui::Button::new("🚀 Start a connection  —  S"),
            )
            .clicked()
        {
            app.begin_server();
        }
        ui.add_space(6.0);
        if ui
            .add_sized(
                [0.0, 40.0],
                egui::Button::new("🔗 Join a connection  —  C"),
            )
            .clicked()
        {
            app.screen = Screen::Client;
        }
    });
}

fn back_button(app: &mut DuocbApp, ui: &mut Ui) {
    if ui.button("← Back (Esc)").clicked() {
        app.go_back();
    }
}

/// A selectable monospace value with a copy button next to it.
fn copyable_value(app: &mut DuocbApp, ui: &mut Ui, label: &str, copy_label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(label);
        if ui.small_button(copy_label).clicked() {
            app.copy_to_clipboard(value);
        }
    });
    let mut shown = value;
    ui.add(
        TextEdit::singleline(&mut shown)
            .font(egui::TextStyle::Monospace)
            .desired_width(f32::INFINITY),
    );
}

/// Show a token without rendering the secret itself, while still giving the
/// starting device an explicit way to transfer it to the joining device.
fn token_copy_action(app: &mut DuocbApp, ui: &mut Ui, token: &str) {
    ui.horizontal(|ui| {
        ui.label("Token:");
        ui.monospace("*".repeat(12));
        if ui.small_button("Copy token (Ctrl/⌘+T)").clicked() {
            app.copy_to_clipboard(token);
        }
    });
}

pub fn show_server(app: &mut DuocbApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        back_button(app, ui);
        ui.heading("Start a connection");
    });
    ui.label(format!("Status: {}", app.status_text()));
    ui.add_space(8.0);

    if !app.server_running {
        // Only token mode has anything to configure before starting. Quick modes
        // (PIN, manual) launch straight from the home screen, so this pre-start
        // form is token-only.
        if app.mode == PairMode::NostrToken {
            ui.label("Shared auth token (same on both devices):");
            let token = app.in_token.trim().to_string();
            let token_valid = duocb_core::auth::validate_token(&token).is_ok();
            if token_valid {
                token_copy_action(app, ui, &token);
                ui.horizontal(|ui| {
                    ui.label("Token fingerprint:");
                    ui.monospace(duocb_core::auth::token_fingerprint(&token));
                });
            } else if !token.is_empty() {
                ui.colored_label(
                    ui.visuals().warn_fg_color,
                    "The saved token is invalid; generate a new one",
                );
            }
            let generate_label = if token_valid {
                "Generate new token"
            } else {
                "Generate token"
            };
            if ui.button(generate_label).clicked() {
                app.in_token = duocb_core::auth::generate_token();
            }
            ui.label("This device's unique name:");
            ui.add(TextEdit::singleline(&mut app.in_my_name).hint_text("e.g. desktop"));
            ui.label(
                RichText::new("Token and name are saved automatically when you start.")
                    .weak()
                    .small(),
            );
            ui.add_space(8.0);
            if ui
                .add_enabled(
                    app.server_mode_spec().is_some(),
                    egui::Button::new("▶ Start (Ctrl/⌘+Enter)"),
                )
                .clicked()
            {
                app.start_server();
            }
        }
        return;
    }

    // Server running: mode-specific credentials display.
    match app.mode {
        PairMode::NostrToken => {
            show_token_pairing_summary(app, ui);
            ui.label(
                RichText::new("The other device must use a different name.")
                    .weak()
                    .small(),
            );
        }
        PairMode::NostrPin => {
            if let Some(pin) = app.pin_display.clone() {
                ui.add_space(8.0);
                ui.vertical_centered(|ui| {
                    ui.label("Type this PIN on the other device:");
                    ui.label(RichText::new(pin).monospace().size(36.0).strong());
                    let remaining = app
                        .pin_deadline
                        .map(|d| d.saturating_duration_since(std::time::Instant::now()).as_secs())
                        .unwrap_or(0);
                    ui.label(format!("refreshes in {remaining}s"));
                });
                ui.add_space(8.0);
            } else if app.pin_paired {
                // Paired: the PIN is spent. Show this device's node id — the
                // same value the other device displays as "Paired with:" — so
                // the user can eyeball that the two match.
                if let Some(node_id) = app.node_id.clone() {
                    ui.horizontal(|ui| {
                        ui.label("This device's id:");
                        ui.monospace(short_id(&node_id));
                    });
                    ui.label(
                        RichText::new("Confirm this matches “Paired with” on the other device.")
                            .weak()
                            .small(),
                    );
                }
            }
        }
        PairMode::Manual => {
            if let Some(node_id) = app.node_id.clone() {
                copyable_value(app, ui, "Node id:", "Copy (Ctrl/⌘+I)", &node_id);
            }
            // The token is never shown in plain text — a mask stands in for it,
            // with a copy CTA — and its fingerprint is shown so the other device
            // can confirm the match. It stays valid (and copyable) for the whole
            // session so the paired peer can be re-sent it and reconnect after a
            // drop.
            if let Some(token) = app.manual_token.clone() {
                token_copy_action(app, ui, &token);
                ui.horizontal(|ui| {
                    ui.label("Token fingerprint:");
                    ui.monospace(duocb_core::auth::token_fingerprint(&token));
                });
            }
            ui.label("Enter both on the other device. No internet needed on the same LAN.");
        }
    }

    ui.add_space(8.0);
    if ui.button("⏹ Stop").clicked() {
        app.net.send(duocb_core::net::UiCommand::StopServer);
        // Quick modes have no pre-start form to return to, so stopping goes all
        // the way home rather than showing a bare restart button.
        if app.mode != PairMode::NostrToken {
            app.screen = Screen::Home;
        }
    }

    session_panel_if_connected(app, ui);
}

pub fn show_client(app: &mut DuocbApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        back_button(app, ui);
        ui.heading("Join a connection");
    });
    ui.label(format!("Status: {}", app.status_text()));
    ui.add_space(8.0);

    if !app.client_active {
        match app.mode {
            PairMode::NostrToken => {
                ui.label("Token copied from the starting device:");
                ui.add(
                    TextEdit::singleline(&mut app.in_token)
                        .font(egui::TextStyle::Monospace)
                        .password(true)
                        .desired_width(f32::INFINITY)
                        .hint_text("…"),
                );
                ui.label(
                    RichText::new(
                        "Paste the token itself (from “Copy token”) — not the fingerprint \
                         shown on the other device.",
                    )
                    .weak()
                    .small(),
                );
                token_entry_feedback(ui, &app.in_token);
                ui.label("This device's unique name:");
                ui.add(TextEdit::singleline(&mut app.in_my_name).hint_text("e.g. laptop"));
                ui.label(
                    RichText::new("Token and name are saved after a successful connection.")
                        .weak()
                        .small(),
                );
            }
            PairMode::NostrPin => {
                ui.label("PIN shown on the other device:");
                ui.add(
                    TextEdit::singleline(&mut app.in_pin)
                        .font(egui::TextStyle::Monospace)
                        .hint_text("XXXX-XXXX"),
                );
                if !app.in_pin.trim().is_empty() && duocb_core::pin::normalize_pin(&app.in_pin).is_none()
                {
                    ui.colored_label(
                        ui.visuals().warn_fg_color,
                        "Not a valid PIN (check for typos)",
                    );
                }
            }
            PairMode::Manual => {
                ui.label("Node id shown on the other device:");
                ui.add(
                    TextEdit::singleline(&mut app.in_node_id)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );
                ui.label("Token copied from the other device:");
                ui.add(
                    TextEdit::singleline(&mut app.in_manual_token)
                        .font(egui::TextStyle::Monospace)
                        .password(true)
                        .desired_width(f32::INFINITY)
                        .hint_text("…"),
                );
                ui.label(
                    RichText::new(
                        "Paste the token itself (from “Copy token”) — not the fingerprint \
                         shown on the other device.",
                    )
                    .weak()
                    .small(),
                );
                token_entry_feedback(ui, &app.in_manual_token);
            }
        }

        ui.add_space(8.0);
        if ui
            .add_enabled(
                app.client_dial_spec().is_some(),
                egui::Button::new("▶ Connect (Ctrl/⌘+Enter)"),
            )
            .clicked()
        {
            app.connect_client();
        }
        return;
    }

    if app.mode == PairMode::NostrToken {
        show_token_pairing_summary(app, ui);
    } else if let Some(peer) = app.peer_node_id.clone() {
        ui.horizontal(|ui| {
            ui.label("Paired with:");
            ui.monospace(short_id(&peer));
        });
    }
    if ui.button("✕ Disconnect").clicked() {
        app.net.send(duocb_core::net::UiCommand::Disconnect);
    }

    session_panel_if_connected(app, ui);
}
