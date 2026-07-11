//! egui user interface: screen routing and shared UI types.

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

/// A clipboard item that passed through the session — a received item in the
/// inbox, or the last item sent in the outbox. Lives only in memory, never
/// written to disk.
pub struct ClipItem {
    pub text: String,
    /// When it was received (inbox) or sent (outbox).
    pub timestamp: jiff::Zoned,
    /// CRC-16 of the payload, computed once on creation (see [`crc16`]).
    pub crc16: u16,
    /// Whether the peek view is expanded in the UI.
    pub expanded: bool,
}

impl ClipItem {
    pub fn new(text: String, timestamp: jiff::Zoned) -> Self {
        let crc16 = crc16(text.as_bytes());
        Self {
            text,
            timestamp,
            crc16,
            expanded: false,
        }
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
