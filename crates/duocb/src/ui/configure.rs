//! The configure mode's home-screen flow: the secret setup wizard (generate or
//! import, gated until a secret exists), the configured hub (device identity +
//! start/join actions), and the device picker behind the Join action (the
//! discovered peer list, only relevant when joining).

use eframe::egui::{self, RichText, TextEdit, Ui};

use crate::ui::app::DuocbApp;
use crate::ui::ConfigureStep;

/// Render the configure-mode home flow for the current [`ConfigureStep`].
pub fn show_configure(app: &mut DuocbApp, ui: &mut Ui) {
    match app.configure_step {
        ConfigureStep::SetupChoice => setup_choice(app, ui),
        ConfigureStep::SetupGenerate => setup_generate(app, ui),
        ConfigureStep::SetupImport => setup_import(app, ui),
        ConfigureStep::SetupName => setup_name(app, ui),
        ConfigureStep::Ready => hub(app, ui),
        ConfigureStep::Join => join_picker(app, ui),
    }
    clear_secret_modal(app, ui.ctx());
}

fn setup_choice(app: &mut DuocbApp, ui: &mut Ui) {
    ui.group(|ui| {
        ui.label(RichText::new("Set up the shared secret").strong());
        ui.label(
            RichText::new(
                "All of your devices share one secret. Create it on the first \
                 device, then import the same secret on every other one.",
            )
            .weak(),
        );
        ui.add_space(8.0);
        ui.vertical_centered_justified(|ui| {
            if ui
                .add_sized([0.0, 36.0], egui::Button::new("🔑 Create a new secret  —  G"))
                .clicked()
            {
                app.begin_generate_secret();
            }
            ui.add_space(4.0);
            if ui
                .add_sized(
                    [0.0, 36.0],
                    egui::Button::new("📥 Use an existing secret  —  I"),
                )
                .clicked()
            {
                app.configure_step = ConfigureStep::SetupImport;
            }
        });
    });
}

fn setup_generate(app: &mut DuocbApp, ui: &mut Ui) {
    let Some(token) = app.wizard_token.clone() else {
        // Nothing generated (e.g. after a cancel): fall back to the choice.
        app.configure_step = ConfigureStep::SetupChoice;
        return;
    };
    ui.group(|ui| {
        ui.label(RichText::new("Your new secret").strong());
        ui.label(
            RichText::new(
                "Copy it somewhere safe now — you will paste it into your \
                 other device. The last four characters are shown so you can \
                 spot-check a paste where no fingerprint is available.",
            )
            .weak(),
        );
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label("Secret:");
            ui.monospace(masked_secret_hint(&token));
        });
        ui.horizontal(|ui| {
            ui.label("Fingerprint:");
            ui.monospace(duocb_core::auth::token_fingerprint(&token));
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let copy_label = if app.copied_flash_active() {
                "✔ Copied"
            } else {
                "Copy secret"
            };
            if ui.button(copy_label).clicked() {
                app.copy_secret_to_clipboard(&token);
            }
            if ui.button("✔ I saved it — continue").clicked() {
                app.wizard_token = None;
                app.set_secret(token.clone());
            }
            if ui.button("Cancel (Esc)").clicked() {
                app.wizard_token = None;
                app.configure_step = ConfigureStep::SetupChoice;
            }
        });
    });
}

fn setup_import(app: &mut DuocbApp, ui: &mut Ui) {
    ui.group(|ui| {
        ui.label(RichText::new("Import the shared secret").strong());
        ui.label("Paste the secret copied from your other device:");
        ui.add(
            TextEdit::singleline(&mut app.in_import_token)
                .font(egui::TextStyle::Monospace)
                .password(true)
                .desired_width(f32::INFINITY)
                .hint_text("…"),
        );
        crate::ui::screens::token_entry_feedback(ui, &app.in_import_token);
        let token = app.in_import_token.trim().to_string();
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    duocb_core::auth::validate_token(&token).is_ok(),
                    egui::Button::new("✔ Use this secret"),
                )
                .clicked()
            {
                app.in_import_token.clear();
                app.set_secret(token);
            }
            if ui.button("Cancel (Esc)").clicked() {
                app.in_import_token.clear();
                app.configure_step = ConfigureStep::SetupChoice;
            }
        });
    });
}

fn setup_name(app: &mut DuocbApp, ui: &mut Ui) {
    ui.group(|ui| {
        ui.label(RichText::new("Name this device").strong());
        ui.label(
            RichText::new(format!(
                "A short name plus this device's permanent id — other devices \
                 will see it in their list. Letters, digits, and '-' only \
                 (max {} characters).",
                duocb_core::identity::NAME_MAX_LEN
            ))
            .weak(),
        );
        ui.add(TextEdit::singleline(&mut app.in_my_name).hint_text("e.g. mac-book"));
        let name = app.in_my_name.trim().to_string();
        match duocb_core::identity::validate_name(&name) {
            Ok(()) => {
                ui.horizontal(|ui| {
                    ui.label("Broadcast as:");
                    ui.monospace(duocb_core::identity::display_identity(
                        &name,
                        &app.device_suffix,
                    ));
                });
            }
            Err(e) if !name.is_empty() => {
                ui.colored_label(ui.visuals().warn_fg_color, e.to_string());
            }
            Err(_) => {}
        }
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    duocb_core::identity::validate_name(&name).is_ok(),
                    egui::Button::new("✔ Save name"),
                )
                .clicked()
            {
                app.save_name();
            }
            if app.has_saved_identity() && ui.button("Cancel (Esc)").clicked() {
                app.reset_name_field();
                app.configure_step = ConfigureStep::Ready;
            }
        });
    });
}

fn hub(app: &mut DuocbApp, ui: &mut Ui) {
    identity_group(app, ui);
    ui.add_space(12.0);

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
                egui::Button::new("🔗 Join another device  —  C"),
            )
            .clicked()
        {
            app.enter_join_picker();
        }
        ui.label(
            RichText::new(
                "Start makes this device host the connection — the other device \
                 joins it. Join shows your other devices and connects to the one \
                 that started.",
            )
            .weak()
            .small(),
        );
    });
}

/// The device picker behind the Join action: the discovered peer list plus
/// the join button (enabled once a hosting device is selected).
fn join_picker(app: &mut DuocbApp, ui: &mut Ui) {
    peer_list_group(app, ui);
    ui.add_space(12.0);

    let join_ready = app.selected_peer_display().is_some();
    ui.vertical_centered_justified(|ui| {
        if ui
            .add_enabled(
                join_ready,
                egui::Button::new("🔗 Join the selected device  —  C / Enter")
                    .min_size([0.0, 40.0].into()),
            )
            .clicked()
        {
            app.join_selected_peer();
        }
        if !join_ready {
            ui.label(
                RichText::new("Select the device to join.").weak().small(),
            );
        } else {
            ui.label(
                RichText::new(
                    "If it isn't hosting yet, press Start there — the join \
                     keeps retrying until it is.",
                )
                .weak()
                .small(),
            );
        }
        ui.add_space(6.0);
        if ui.button("Back (Esc)").clicked() {
            app.configure_step = ConfigureStep::Ready;
        }
    });
}

fn identity_group(app: &mut DuocbApp, ui: &mut Ui) {
    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.label("This device:");
            ui.label(RichText::new(app.display_identity()).strong().monospace());
            if ui.small_button("Rename").clicked() {
                app.reset_name_field();
                app.configure_step = ConfigureStep::SetupName;
            }
        });
        if let Some(secret) = app.secret.clone() {
            ui.horizontal(|ui| {
                ui.label("Secret:");
                ui.monospace(masked_secret_hint(&secret));
                let copy_label = if app.copied_flash_active() {
                    "✔ Copied"
                } else {
                    "Copy secret"
                };
                if ui.small_button(copy_label).clicked() {
                    app.copy_secret_to_clipboard(&secret);
                }
                if ui.small_button("Clear secret…").clicked() {
                    app.confirm_clear_secret = true;
                }
            });
            ui.horizontal(|ui| {
                ui.label("Fingerprint:");
                ui.monospace(duocb_core::auth::token_fingerprint(&secret));
                ui.label(RichText::new("(must match on every device)").weak().small());
            });
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Config:").weak().small());
            ui.label(
                RichText::new(app.config_lock.path().display().to_string())
                    .weak()
                    .small(),
            );
        });
        if let Some(conflict) = app.presence_conflict.clone() {
            ui.colored_label(ui.visuals().warn_fg_color, conflict);
        }
    });
}

fn peer_list_group(app: &mut DuocbApp, ui: &mut Ui) {
    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Your devices").strong());
            if ui.small_button("⟳ Refresh (R)").clicked() {
                app.refresh_peers();
            }
            if let Some(at) = app.peers_refreshed_at {
                ui.label(
                    RichText::new(format!("updated {}", ago(at.elapsed().as_secs())))
                        .weak()
                        .small(),
                );
            }
        });
        ui.add_space(4.0);

        if app.peers.is_empty() {
            let text = if app.peers_refreshed_at.is_some() {
                "No other devices found yet. Import the same secret on your \
                 other device and it will appear here."
            } else {
                "Looking for your other devices…"
            };
            ui.label(RichText::new(text).weak());
            return;
        }

        let peers = app.peers.clone();
        for peer in &peers {
            let selected = app.selected_peer.as_deref() == Some(peer.suffix.as_str());
            let mut row = peer.display();
            if peer.node_id.is_some() {
                row.push_str("  — hosting");
            }
            // The record's age, not an online/offline verdict — relay timing
            // is too unreliable for one, and joining never requires it.
            let age = now_unix().saturating_sub(peer.last_seen_unix);
            row.push_str(&format!("  · seen {}", ago(age)));
            if ui
                .selectable_label(selected, RichText::new(row).monospace())
                .clicked()
            {
                app.selected_peer = if selected {
                    None
                } else {
                    Some(peer.suffix.clone())
                };
            }
        }
    });
}

fn clear_secret_modal(app: &mut DuocbApp, ctx: &egui::Context) {
    if !app.confirm_clear_secret {
        return;
    }
    let mut close = false;
    let response = egui::Modal::new(egui::Id::new("clear_secret_modal")).show(ctx, |ui| {
        ui.set_max_width(420.0);
        ui.heading("Clear the shared secret?");
        ui.add_space(4.0);
        ui.label(
            "This device will stop broadcasting and can no longer pair with \
             your other devices until a secret is set up again. The device's \
             permanent id is kept.",
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.button("Clear secret").clicked() {
                app.clear_secret();
                close = true;
            }
            if ui.button("Cancel").clicked() {
                close = true;
            }
        });
    });
    if close || response.backdrop_response.clicked() {
        app.confirm_clear_secret = false;
    }
}

/// Mask a secret for display: asterisks plus its last four characters — never
/// the whole value, but enough of a hint to spot-check that a paste into a
/// place without fingerprint support (a password manager, a note) took the
/// right one.
fn masked_secret_hint(secret: &str) -> String {
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
fn ago(secs: u64) -> String {
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
