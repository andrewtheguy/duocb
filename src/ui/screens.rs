//! Home / start / join screens.
//!
//! The two roles are only about who sets up the connection — once paired, both
//! devices can send and receive. One device *starts* a connection and shows a
//! PIN/code (the transport server/listener); the other *joins* by entering it
//! (the client/dialer).
//!
//! Keyboard shortcuts (also listed in the UI): home selects mode with 1/2/3
//! and role with S (start) / C (join); Ctrl+Enter starts/joins; Esc goes back;
//! the manual start screen copies its credentials with Ctrl+I (node id) /
//! Ctrl+T (token).

use eframe::egui::{self, RichText, TextEdit, Ui};

use crate::nostr::DEFAULT_NOSTR_RELAYS;
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
        ui.radio_value(
            &mut app.mode,
            PairMode::NostrPin,
            "1  PIN quick pair — type a short rotating code (internet)",
        );
        ui.radio_value(
            &mut app.mode,
            PairMode::NostrToken,
            "2  Token + name — standing pairing with a shared token (internet)",
        );
        ui.radio_value(
            &mut app.mode,
            PairMode::Manual,
            "3  Manual — type the node id + token (works offline on the same LAN)",
        );
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
            app.screen = Screen::Server;
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

pub fn show_server(app: &mut DuocbApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        back_button(app, ui);
        ui.heading("Start a connection");
    });
    ui.label(format!("Status: {}", app.status_text()));
    ui.add_space(8.0);

    if !app.server_running {
        match app.mode {
            PairMode::NostrToken => {
                ui.label("Shared auth token (same on both devices):");
                ui.horizontal(|ui| {
                    ui.add(
                        TextEdit::singleline(&mut app.in_token)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(360.0)
                            .hint_text("d…"),
                    );
                    if ui.button("Generate").clicked() {
                        app.in_token = crate::auth::generate_token();
                    }
                });
                ui.label("This device's name (the other device looks it up by this):");
                ui.add(TextEdit::singleline(&mut app.in_my_name).hint_text("e.g. desktop"));
                if ui
                    .button("Remember these settings")
                    .on_hover_text("Saves the token and names to ~/.config/duocb/config.toml")
                    .clicked()
                {
                    app.remember_token_settings();
                }
                if !app.in_token.trim().is_empty()
                    && crate::auth::validate_token(app.in_token.trim()).is_err()
                {
                    ui.colored_label(ui.visuals().warn_fg_color, "That is not a valid token");
                }
            }
            PairMode::NostrPin => {
                ui.label("A short PIN will be shown; type it on the other device.");
            }
            PairMode::Manual => {
                ui.label(
                    "A node id and a one-time token will be shown; enter both on the other \
                     device. Works with no internet on the same LAN (mDNS).",
                );
            }
        }
        ui.add_space(8.0);
        if ui
            .add_enabled(
                app.server_mode_spec().is_some(),
                egui::Button::new("▶ Start (Ctrl+Enter)"),
            )
            .clicked()
        {
            app.start_server();
        }
        return;
    }

    // Server running: mode-specific credentials display.
    match app.mode {
        PairMode::NostrToken => {
            if let Some(node_id) = app.node_id.clone() {
                ui.horizontal(|ui| {
                    ui.label("Node id:");
                    ui.monospace(short_id(&node_id));
                });
            }
            if let Some(fp) = app.token_fingerprint.clone() {
                ui.horizontal(|ui| {
                    ui.label("Token fingerprint:");
                    ui.monospace(fp);
                    ui.label("(must match on both devices)");
                });
            }
            if let Some(name) = Some(app.in_my_name.trim().to_string()).filter(|s| !s.is_empty()) {
                ui.label(format!("The other device connects using the name “{name}”."));
            }
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
                copyable_value(app, ui, "Node id:", "Copy (Ctrl+I)", &node_id);
            }
            if let Some(token) = app.manual_token.clone() {
                copyable_value(app, ui, "One-time token:", "Copy (Ctrl+T)", &token);
            }
            ui.label("Enter both on the other device. No internet needed on the same LAN.");
        }
    }

    ui.add_space(8.0);
    if ui.button("⏹ Stop").clicked() {
        app.net.send(crate::net::UiCommand::StopServer);
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
                ui.label("Shared auth token (same on both devices):");
                ui.add(
                    TextEdit::singleline(&mut app.in_token)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .hint_text("d…"),
                );
                ui.label("The other device's name:");
                ui.add(TextEdit::singleline(&mut app.in_peer_name).hint_text("e.g. desktop"));
                if ui
                    .button("Remember these settings")
                    .on_hover_text("Saves the token and names to ~/.config/duocb/config.toml")
                    .clicked()
                {
                    app.remember_token_settings();
                }
                if !app.in_token.trim().is_empty()
                    && crate::auth::validate_token(app.in_token.trim()).is_err()
                {
                    ui.colored_label(ui.visuals().warn_fg_color, "That is not a valid token");
                }
            }
            PairMode::NostrPin => {
                ui.label("PIN shown on the other device:");
                ui.add(
                    TextEdit::singleline(&mut app.in_pin)
                        .font(egui::TextStyle::Monospace)
                        .hint_text("XXXX-XXXX"),
                );
                if !app.in_pin.trim().is_empty() && crate::pin::normalize_pin(&app.in_pin).is_none()
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
                ui.label("One-time token shown on the other device:");
                ui.add(
                    TextEdit::singleline(&mut app.in_manual_token)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .hint_text("d…"),
                );
                if !app.in_manual_token.trim().is_empty()
                    && crate::auth::validate_token(app.in_manual_token.trim()).is_err()
                {
                    ui.colored_label(ui.visuals().warn_fg_color, "That is not a valid token");
                }
            }
        }

        ui.add_space(8.0);
        if ui
            .add_enabled(
                app.client_dial_spec().is_some(),
                egui::Button::new("▶ Connect (Ctrl+Enter)"),
            )
            .clicked()
        {
            app.connect_client();
        }
        return;
    }

    if let Some(peer) = app.peer_node_id.clone() {
        ui.horizontal(|ui| {
            ui.label("Paired with:");
            ui.monospace(short_id(&peer));
        });
    }
    if ui.button("✕ Disconnect").clicked() {
        app.net.send(crate::net::UiCommand::Disconnect);
    }

    session_panel_if_connected(app, ui);
}
