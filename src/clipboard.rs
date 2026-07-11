//! Thin wrapper around the system clipboard (arboard), held by the UI thread.
//!
//! One long-lived `arboard::Clipboard` instance lives for the whole process.
//! This matters on X11: clipboard ownership is tied to the providing
//! connection, so text copied from a short-lived instance would vanish the
//! moment it is dropped (unless a clipboard manager is running). The instance
//! is created lazily so a missing display server only errors when the user
//! actually touches the clipboard.

use anyhow::{Context, Result};

#[derive(Default)]
pub struct SystemClipboard(Option<arboard::Clipboard>);

impl SystemClipboard {
    pub fn new() -> Self {
        Self(None)
    }

    fn get(&mut self) -> Result<&mut arboard::Clipboard> {
        if self.0.is_none() {
            self.0 = Some(arboard::Clipboard::new().context("opening the system clipboard")?);
        }
        Ok(self.0.as_mut().expect("initialized above"))
    }

    /// Read the current clipboard text.
    pub fn read_text(&mut self) -> Result<String> {
        self.get()?.get_text().context("reading the clipboard")
    }

    /// Write `text` to the system clipboard. The only place duocb ever writes
    /// the clipboard is the per-item Copy button — never automatically.
    pub fn write_text(&mut self, text: &str) -> Result<()> {
        self.get()?
            .set_text(text.to_string())
            .context("writing the clipboard")
    }
}
