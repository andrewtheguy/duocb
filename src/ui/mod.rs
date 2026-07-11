//! egui user interface: screen routing and shared UI types.

use std::time::{Duration, Instant};

pub mod app;
pub mod screens;
pub mod session;

/// Which screen is showing. The two non-home screens are the two connection
/// roles; both peers send and receive once paired — the role only decides who
/// sets the connection up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Home,
    /// Start a connection: this device shows the PIN/auth code and listens
    /// (the transport server).
    Server,
    /// Join a connection: this device enters the PIN/auth code and dials
    /// (the transport client).
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

/// Max characters shown in the peek view. Larger payloads are truncated to
/// this many chars so the read-only editor stays responsive — laying out a
/// multi-MB string is expensive, and a peek is a glance, not a full viewer.
pub const PEEK_LIMIT: usize = 4096;

/// How long a peeked item stays open before auto-hiding, so revealed content
/// doesn't linger on screen after a glance.
pub const PEEK_TIMEOUT: Duration = Duration::from_secs(15);

/// A clipboard item that passed through the session — a received item in the
/// inbox, or the last item sent in the outbox. Lives only in memory, never
/// written to disk.
pub struct ClipItem {
    pub text: String,
    /// When it was received (inbox) or sent (outbox).
    pub timestamp: jiff::Zoned,
    /// CRC-16 of the payload, computed once on creation (see [`crc16`]).
    pub crc16: u16,
    /// When the peek view was opened, or `None` if collapsed. The peek
    /// auto-hides [`PEEK_TIMEOUT`] after this (see [`tick_peek`](Self::tick_peek)).
    peeked_at: Option<Instant>,
}

impl ClipItem {
    pub fn new(text: String, timestamp: jiff::Zoned) -> Self {
        let crc16 = crc16(text.as_bytes());
        Self {
            text,
            timestamp,
            crc16,
            peeked_at: None,
        }
    }

    /// Whether the peek view is currently expanded.
    pub fn expanded(&self) -> bool {
        self.peeked_at.is_some()
    }

    /// Toggle the peek view. Opening stamps the time so it auto-hides.
    pub fn toggle_peek(&mut self) {
        self.peeked_at = self.peeked_at.is_none().then(Instant::now);
    }

    /// Collapse the peek if it has been open longer than [`PEEK_TIMEOUT`].
    /// Returns whether it is still expanded afterward, so the caller can keep
    /// requesting repaints while any peek is counting down.
    pub fn tick_peek(&mut self) -> bool {
        if self.peeked_at.is_some_and(|t| t.elapsed() >= PEEK_TIMEOUT) {
            self.peeked_at = None;
        }
        self.peeked_at.is_some()
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

    /// The text to show while peeking, truncated to [`PEEK_LIMIT`] chars.
    /// The bool is whether truncation occurred (borrowed, so the common
    /// small-payload case allocates nothing).
    pub fn peek_text(&self) -> (&str, bool) {
        match self.text.char_indices().nth(PEEK_LIMIT) {
            Some((byte_idx, _)) => (&self.text[..byte_idx], true),
            None => (&self.text, false),
        }
    }
}

/// CRC-16/CCITT-FALSE (poly `0x1021`, init `0xFFFF`) over the payload bytes — a
/// short fingerprint the user can eyeball to tell inbox items apart, or to
/// confirm a paste matches, without peeking at (and thus revealing) the content.
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_matches_known_check_value() {
        // CRC-16/CCITT-FALSE check value for the ASCII string "123456789".
        assert_eq!(crc16(b"123456789"), 0x29B1);
        assert_eq!(crc16(b""), 0xFFFF);
    }

    #[test]
    fn peek_text_truncates_past_limit() {
        let long = "a".repeat(PEEK_LIMIT + 100);
        let item = ClipItem::new(long, jiff::Zoned::now());
        let (shown, truncated) = item.peek_text();
        assert!(truncated);
        assert_eq!(shown.chars().count(), PEEK_LIMIT);

        let item = ClipItem::new("short".to_string(), jiff::Zoned::now());
        let (shown, truncated) = item.peek_text();
        assert!(!truncated);
        assert_eq!(shown, "short");
    }
}
