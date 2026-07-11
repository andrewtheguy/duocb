//! The paired session panel: send button, path info, the last-sent outbox
//! item, and the in-memory inbox. Every item supports peek (view without
//! copying, truncated when large) and per-item Copy.

use eframe::egui::{self, RichText, ScrollArea, TextEdit, Ui};

use crate::ui::app::DuocbApp;
use crate::ui::{ClipItem, PEEK_LIMIT};

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

    // Deferred so the item borrow ends before touching the clipboard.
    let mut copy_text: Option<String> = None;

    // Outbox: the last item sent, shown so the receiver can compare its
    // size/CRC against the matching inbox item on the other device.
    ui.add_space(6.0);
    ui.label(RichText::new("Outbox (last sent)").strong());
    match app.outbox.as_mut() {
        Some(item) => {
            if let Some(text) = show_item(ui, item) {
                copy_text = Some(text);
            }
        }
        None => {
            ui.label(RichText::new("Nothing sent yet.").weak());
        }
    }

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
    } else {
        ScrollArea::vertical()
            .auto_shrink([false, true])
            .show(ui, |ui| {
                for item in &mut app.inbox {
                    if let Some(text) = show_item(ui, item) {
                        copy_text = Some(text);
                    }
                }
            });
    }

    if let Some(text) = copy_text {
        app.copy_to_clipboard(&text);
    }
}

/// Render one clipboard item: a metadata row (time, size, CRC-16) plus Peek and
/// Copy buttons, and — when peeked — a read-only view of the content, truncated
/// if it exceeds [`PEEK_LIMIT`]. Returns the text to copy if Copy was clicked.
fn show_item(ui: &mut Ui, item: &mut ClipItem) -> Option<String> {
    let mut copy_text = None;
    ui.group(|ui| {
        // Metadata only until the user peeks: time, size, and CRC-16 — enough
        // to identify an item, or compare it against the peer, without
        // revealing its content.
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(item.timestamp.strftime("%H:%M:%S").to_string())
                    .weak()
                    .monospace(),
            );
            ui.label(RichText::new(item.size_hint()).weak().small());
            ui.label(
                RichText::new(format!("CRC {:04X}", item.crc16))
                    .weak()
                    .small()
                    .monospace(),
            );
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
            // Read-only, selectable, never touches the system clipboard unless
            // the user selects + copies deliberately. Large payloads are
            // truncated (see PEEK_LIMIT); Copy still yields the full content.
            let (shown, truncated) = item.peek_text();
            let rows = shown.lines().count().clamp(2, 14);
            let mut shown = shown;
            ui.add(
                TextEdit::multiline(&mut shown)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .desired_rows(rows),
            );
            if truncated {
                ui.label(
                    RichText::new(format!(
                        "… truncated — showing the first {PEEK_LIMIT} characters. \
                         Use Copy for the full {}.",
                        item.size_hint()
                    ))
                    .weak()
                    .small(),
                );
            }
        }
    });
    copy_text
}
