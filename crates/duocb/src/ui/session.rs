//! The paired session panel: send actions (the clipboard, or typed text via
//! the compose field), path info, the last-sent outbox item, and the
//! in-memory inbox. Every item supports peek (view without copying, truncated
//! when large) and per-item Copy.

use eframe::egui::{self, RichText, ScrollArea, TextEdit, Ui};

use crate::ui::app::DuocbApp;
use crate::ui::{ClipItem, PEEK_LIMIT};

pub fn show_session(app: &mut DuocbApp, ui: &mut Ui) {
    ui.add_space(8.0);
    ui.separator();

    ui.horizontal(|ui| {
        if ui.button("📤 Send clipboard (Ctrl/⌘+S)").clicked() {
            app.send_clipboard();
        }
        if ui
            .button("🌐 Connection path")
            .on_hover_text("Show how this session is currently routed (direct vs. relay)")
            .clicked()
        {
            app.query_conn_path();
        }
        if app.sent_flash_active() {
            ui.colored_label(egui::Color32::from_rgb(0x2e, 0xa0, 0x43), "sent ✓");
        }
    });

    // Compose row: send typed text without touching the clipboard (iOS parity).
    // Laid out right-to-left so the field takes whatever the button leaves.
    ui.add_space(4.0);
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        let clicked = ui
            .add_enabled(!app.in_compose.is_empty(), egui::Button::new("Send"))
            .clicked();
        let field = ui.add(
            TextEdit::singleline(&mut app.in_compose)
                .hint_text("Or type text to send… (Enter)")
                .desired_width(ui.available_width()),
        );
        let entered = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if (clicked || entered) && !app.in_compose.is_empty() && app.pending_outbox.is_none() {
            let text = std::mem::take(&mut app.in_compose);
            app.send_text(text);
            if entered {
                // Keep typing: consecutive sends without re-clicking the field.
                field.request_focus();
            }
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
        if !app.inbox.is_empty() && ui.small_button("Clear inbox (Ctrl/⌘+L)").clicked() {
            app.inbox.clear();
        }
        ui.label(
            RichText::new("newest: peek Ctrl/⌘+P · copy Ctrl/⌘+Y")
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

/// Render one clipboard item: a metadata row (time, size, CRC-32) plus Peek and
/// Copy buttons, and — when peeked — a read-only view of the content, truncated
/// if it exceeds [`PEEK_LIMIT`]. Returns the text to copy if Copy was clicked.
fn show_item(ui: &mut Ui, item: &mut ClipItem) -> Option<String> {
    let mut copy_text = None;
    ui.group(|ui| {
        // Metadata only until the user peeks: time, size, and CRC-32 — enough
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
                RichText::new(format!("CRC {}", item.crc32_display()))
                    .weak()
                    .small()
                    .monospace(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Copy").clicked() {
                    copy_text = Some(item.text.clone());
                }
                let peek_label = if item.expanded() { "Hide" } else { "Peek" };
                if ui.small_button(peek_label).clicked() {
                    item.toggle_peek();
                }
            });
        });
        if item.expanded() {
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
