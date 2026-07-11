//! egui user interface: screen routing and shared UI types.

pub mod app;
pub mod screens;
pub mod session;

/// Which screen is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Home,
    Server,
    Client,
}

/// The pairing mode selected on the home screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairMode {
    /// Shared auth token + names, rendezvous via nostr (internet).
    NostrToken,
    /// Rotating PIN quick pair via nostr (internet).
    NostrPin,
    /// Manually typed node id + token; works offline on the same LAN (mDNS).
    Manual,
}

/// A received clipboard item. Lives only in memory — never written to disk.
pub struct InboxItem {
    pub text: String,
    pub received_at: jiff::Zoned,
    /// Whether the peek view is expanded in the UI.
    pub expanded: bool,
}

impl InboxItem {
    /// One-line preview: the first line, truncated to a sane width.
    pub fn preview(&self) -> String {
        const MAX_CHARS: usize = 80;
        let first = self.text.lines().next().unwrap_or("");
        let mut out: String = first.chars().take(MAX_CHARS).collect();
        if first.chars().count() > MAX_CHARS || self.text.lines().nth(1).is_some() {
            out.push('…');
        }
        out
    }

    /// Human-readable size of the text payload.
    pub fn size_hint(&self) -> String {
        let bytes = self.text.len();
        if bytes < 1024 {
            format!("{bytes} B")
        } else if bytes < 1024 * 1024 {
            format!("{:.1} KB", bytes as f64 / 1024.0)
        } else {
            format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
        }
    }
}
