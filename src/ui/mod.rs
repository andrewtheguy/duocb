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
    /// CRC-32 of the payload, computed once on creation (see [`crc32`]).
    pub crc32: u32,
    /// When the peek view was opened, or `None` if collapsed. The peek
    /// auto-hides [`PEEK_TIMEOUT`] after this (see [`tick_peek`](Self::tick_peek)).
    peeked_at: Option<Instant>,
}

impl ClipItem {
    pub fn new(text: String, timestamp: jiff::Zoned) -> Self {
        let crc32 = crc32(text.as_bytes());
        Self {
            text,
            timestamp,
            crc32,
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

    /// CRC-32 fingerprint formatted as two four-hex groups for readability.
    pub fn crc32_display(&self) -> String {
        format!("{:04X}-{:04X}", self.crc32 >> 16, self.crc32 & 0xFFFF)
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

/// CRC-32/ISO-HDLC over the payload bytes — a short fingerprint the user can
/// eyeball to tell inbox items apart, or to confirm a paste matches, without
/// peeking at (and thus revealing) the content.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_known_check_value() {
        // CRC-32/ISO-HDLC check value for the ASCII string "123456789".
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn crc32_display_uses_middle_dash() {
        let item = ClipItem::new("123456789".to_string(), jiff::Zoned::now());

        assert_eq!(item.crc32_display(), "CBF4-3926");
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
