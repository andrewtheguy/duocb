//! The paired session panel: send button, path info, and the in-memory inbox
//! with peek (view without copying) and per-item Copy.

use eframe::egui::{self, RichText, ScrollArea, TextEdit, Ui};

use crate::ui::app::DuocbApp;

pub fn show_session(app: &mut DuocbApp, ui: &mut Ui) {
    ui.add_space(8.0);
    ui.separator();

    if let Some(path) = &app.path_display {
        ui.label(RichText::new(path.clone()).small().weak());
    }

    ui.horizontal(|ui| {
        if ui.button("📤 Send clipboard (Ctrl+S)").clicked() {
            app.send_clipboard();
        }
        if app.sent_flash_active() {
            ui.colored_label(egui::Color32::from_rgb(0x2e, 0xa0, 0x43), "sent ✓");
        }
    });

    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("Inbox ({})", app.inbox.len())).strong());
        if !app.inbox.is_empty() && ui.small_button("Clear inbox (Ctrl+L)").clicked() {
            app.inbox.clear();
        }
        ui.label(
            RichText::new("newest: peek Ctrl+P · copy Ctrl+Y")
                .weak()
                .small(),
        );
    });
    if app.inbox.is_empty() {
        ui.label(RichText::new("Nothing received yet.").weak());
        return;
    }

    // Deferred actions so the inbox borrow ends before touching the clipboard.
    let mut copy_text: Option<String> = None;

    ScrollArea::vertical()
        .auto_shrink([false, true])
        .show(ui, |ui| {
            for item in &mut app.inbox {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(item.received_at.strftime("%H:%M:%S").to_string())
                                .weak()
                                .monospace(),
                        );
                        ui.label(RichText::new(item.size_hint()).weak().small());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Copy").clicked() {
                                copy_text = Some(item.text.clone());
                            }
                            let peek_label = if item.expanded { "Hide" } else { "Peek" };
                            if ui.small_button(peek_label).clicked() {
                                item.expanded = !item.expanded;
                            }
                        });
                    });
                    if item.expanded {
                        // Read-only, selectable, never touches the system clipboard
                        // unless the user selects + copies deliberately.
                        let mut shown = item.text.as_str();
                        ui.add(
                            TextEdit::multiline(&mut shown)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY)
                                .desired_rows(item.text.lines().count().clamp(2, 14)),
                        );
                    } else {
                        ui.label(RichText::new(item.preview()).monospace());
                    }
                });
            }
        });

    if let Some(text) = copy_text {
        app.copy_to_clipboard(&text);
    }
}
