//! The standing secret shared by all of one user's devices (configure mode).
//!
//! The secret carries **two independent halves** so that nothing published on a
//! relay is derived from the credential that authorizes a clipboard session:
//!
//! - a 128-bit **channel** ([`Channel`]) — the *only* input to the nostr
//!   rendezvous keypair and to the presence/hosting `d` tags (see
//!   [`crate::nostr`]). Its public key is visible to relays, so it is
//!   deliberately not a function of the token.
//! - a 256-bit **token** ([`Secret::wire_token`]) — the *only* thing that
//!   crosses the wire, inside the TLS-encrypted auth handshake
//!   ([`crate::protocol::AuthRequest::Token`]). It never touches a relay.
//!
//! Users still handle one opaque string and never see the halves.
//!
//! ## Secret Format
//! A JWT-shaped envelope of three dot-separated base64url (no padding)
//! segments, exactly [`SECRET_LENGTH`] characters:
//!
//! ```text
//! eyJ2IjoxfQ.<110 chars>.<3 chars>
//! │          │            └─ CRC16-CCITT-FALSE(channel ‖ token), big-endian u16
//! │          └─ {"ch":"<22 chars>","tk":"<43 chars>"}
//! └─ {"v":1}
//! ```
//!
//! - `ch` is base64url(16 random bytes), `tk` is base64url(32 random bytes).
//! - The checksum covers the **raw** channel and token bytes, so it is
//!   independent of the encoding. A mangled header segment is caught by the
//!   strict `{"v":1}` check rather than by the checksum.
//! - Segment lengths (10/110/3) are fixed, so the canonical encoding is pinned:
//!   there is exactly one valid rendering of a given secret.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Required length of an encoded secret, in characters.
pub const SECRET_LENGTH: usize =
    HEADER_SEGMENT_LEN + 1 + PAYLOAD_SEGMENT_LEN + 1 + CHECKSUM_SEGMENT_LEN;

/// The only envelope version this build accepts (strict no backward compatibility).
const SECRET_VERSION: u32 = 1;

/// Bytes of entropy in the channel half.
const CHANNEL_BYTES_LEN: usize = 16;
/// Bytes of entropy in the token half.
const TOKEN_BYTES_LEN: usize = 32;

/// Encoded length of the version header segment (`{"v":1}`).
const HEADER_SEGMENT_LEN: usize = 10;
/// Encoded length of the payload segment (`{"ch":"…","tk":"…"}`).
const PAYLOAD_SEGMENT_LEN: usize = 110;
/// Encoded length of the checksum segment (2 bytes).
const CHECKSUM_SEGMENT_LEN: usize = 3;

/// Number of hex digits in a secret fingerprint, before group separators
/// (see [`Secret::fingerprint`]).
pub const FINGERPRINT_HEX_DIGITS: usize = 16;

/// The envelope's first segment: `{"v":1}`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    v: u32,
}

/// The envelope's second segment: the two halves, base64url encoded.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    ch: String,
    tk: String,
}

/// Compute CRC16-CCITT-FALSE.
///
/// Parameters:
/// - Poly: 0x1021
/// - Init: 0xFFFF
/// - RefIn: false
/// - RefOut: false
/// - XorOut: 0x0000
fn crc16_ccitt_false(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;

    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }

    crc
}

/// The 128-bit rendezvous half of a [`Secret`].
///
/// It is the sole input to every relay-visible value (the nostr keypair and the
/// presence/hosting `d` tags). Handing `nostr` a `Channel` instead of the whole
/// secret makes the token bytes *unreachable* from the code that publishes to
/// relays, so the decoupling is enforced by the type system rather than by
/// convention.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Channel([u8; CHANNEL_BYTES_LEN]);

impl Channel {
    /// The raw channel bytes, for domain-separated key derivation.
    pub fn as_bytes(&self) -> &[u8; CHANNEL_BYTES_LEN] {
        &self.0
    }
}

#[cfg(test)]
impl Channel {
    /// Test-only: a channel with fixed bytes, for deterministic derivation vectors.
    pub(crate) fn for_tests(bytes: [u8; CHANNEL_BYTES_LEN]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for Channel {
    /// Redacted: the channel is half of the standing secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Channel(***)")
    }
}

/// The standing secret: a rendezvous [`Channel`] plus the auth token.
///
/// Deliberately has no `Display` or `Serialize`: [`Secret::encode`] must be
/// called explicitly, so no format string or serializer can leak it by accident.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret {
    channel: [u8; CHANNEL_BYTES_LEN],
    token: [u8; TOKEN_BYTES_LEN],
}

impl std::fmt::Debug for Secret {
    /// Redacted: this is the standing secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl Secret {
    /// Mint a fresh secret: two independently random halves.
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let mut channel = [0u8; CHANNEL_BYTES_LEN];
        let mut token = [0u8; TOKEN_BYTES_LEN];
        rng.fill_bytes(&mut channel);
        rng.fill_bytes(&mut token);
        Self { channel, token }
    }

    /// The encoded envelope — the single opaque string the user copies between
    /// devices. Exactly [`SECRET_LENGTH`] characters.
    pub fn encode(&self) -> String {
        let header = serde_json::to_string(&Header { v: SECRET_VERSION })
            .expect("serializing the secret header cannot fail");
        let payload = serde_json::to_string(&Payload {
            ch: URL_SAFE_NO_PAD.encode(self.channel),
            tk: URL_SAFE_NO_PAD.encode(self.token),
        })
        .expect("serializing the secret payload cannot fail");

        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(self.checksum().to_be_bytes()),
        )
    }

    /// Parse and fully validate an encoded secret.
    ///
    /// ASCII whitespace is stripped first: a 125-character string pasted out of
    /// a chat or an email often arrives line-wrapped, and re-joining it is
    /// unambiguous here because no valid character is whitespace.
    pub fn parse(input: &str) -> Result<Self> {
        let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();

        if !compact.is_ascii() {
            anyhow::bail!("Secret must contain only ASCII characters");
        }
        if compact.len() != SECRET_LENGTH {
            anyhow::bail!(
                "Secret must be exactly {} characters, got {} characters",
                SECRET_LENGTH,
                compact.len()
            );
        }

        let segments: Vec<&str> = compact.split('.').collect();
        if segments.len() != 3 {
            anyhow::bail!(
                "Secret must have 3 dot-separated sections, got {}",
                segments.len()
            );
        }
        let (header, payload, checksum) = (segments[0], segments[1], segments[2]);
        for (label, segment, expected) in [
            ("version", header, HEADER_SEGMENT_LEN),
            ("payload", payload, PAYLOAD_SEGMENT_LEN),
            ("checksum", checksum, CHECKSUM_SEGMENT_LEN),
        ] {
            if segment.len() != expected {
                anyhow::bail!(
                    "Secret's {label} section must be {expected} characters, got {}",
                    segment.len()
                );
            }
        }

        let header: Header = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(header)
                .context("Secret's version section is not valid base64url without padding")?,
        )
        .context("Secret's version section is not a valid duocb secret header")?;
        if header.v != SECRET_VERSION {
            anyhow::bail!(
                "Secret has version {}, this build only accepts version {}",
                header.v,
                SECRET_VERSION
            );
        }

        let payload: Payload = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(payload)
                .context("Secret's payload section is not valid base64url without padding")?,
        )
        .context("Secret's payload section is not a valid duocb secret payload")?;

        let channel = decode_half("channel", &payload.ch, CHANNEL_BYTES_LEN)?;
        let token = decode_half("token", &payload.tk, TOKEN_BYTES_LEN)?;
        let secret = Self {
            channel: channel.try_into().expect("checked length"),
            token: token.try_into().expect("checked length"),
        };

        let expected = URL_SAFE_NO_PAD
            .decode(checksum)
            .context("Secret's checksum section is not valid base64url without padding")?;
        if expected != secret.checksum().to_be_bytes() {
            anyhow::bail!("Secret checksum is invalid");
        }

        Ok(secret)
    }

    /// The rendezvous half — see [`Channel`].
    pub fn channel(&self) -> Channel {
        Channel(self.channel)
    }

    /// The auth half, as the 43-character base64url string that crosses the
    /// wire in [`crate::protocol::AuthRequest::Token`] and that the listener
    /// compares against its accepted set. Always re-encoded from the raw bytes,
    /// so both peers compare the same canonical form.
    pub fn wire_token(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.token)
    }

    /// Short, stable fingerprint of the secret for cross-device verification.
    ///
    /// The secret is never revealed in plain text, so two devices cannot compare
    /// it directly. This fingerprint — the first 8 bytes of the SHA-256 of the
    /// channel and token bytes, as 16 uppercase hex digits grouped into four
    /// dash-separated quads (`XXXX-XXXX-XXXX-XXXX`) — is displayed instead: if
    /// it matches on both devices then **both halves** match, without ever
    /// exposing the secret. It stays local (never sent over the wire), so 8
    /// bytes is ample against accidental collision.
    pub fn fingerprint(&self) -> String {
        use std::fmt::Write as _;
        let mut hasher = Sha256::new();
        hasher.update(self.channel);
        hasher.update(self.token);
        let digest = hasher.finalize();
        // 16 hex digits + 3 group separators.
        let mut out = String::with_capacity(FINGERPRINT_HEX_DIGITS + FINGERPRINT_HEX_DIGITS / 4 - 1);
        for (i, b) in digest[..FINGERPRINT_HEX_DIGITS / 2].iter().enumerate() {
            // A separator before every second byte (every 4 hex digits), except first.
            if i > 0 && i % 2 == 0 {
                out.push('-');
            }
            let _ = write!(out, "{b:02X}");
        }
        out
    }

    /// CRC16 over the raw channel bytes followed by the raw token bytes.
    fn checksum(&self) -> u16 {
        let mut bytes = [0u8; CHANNEL_BYTES_LEN + TOKEN_BYTES_LEN];
        bytes[..CHANNEL_BYTES_LEN].copy_from_slice(&self.channel);
        bytes[CHANNEL_BYTES_LEN..].copy_from_slice(&self.token);
        crc16_ccitt_false(&bytes)
    }
}

/// Decode one base64url half of the payload and check its byte length.
fn decode_half(label: &str, encoded: &str, expected: usize) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .with_context(|| format!("Secret's {label} is not valid base64url without padding"))?;
    if bytes.len() != expected {
        anyhow::bail!(
            "Secret's {label} must decode to exactly {expected} bytes, got {} bytes",
            bytes.len()
        );
    }
    Ok(bytes)
}

/// Check if a wire token (see [`Secret::wire_token`]) is in the accepted set.
///
/// Returns true if the token is accepted, false otherwise.
/// An empty `valid_tokens` set means no tokens are authorized.
#[inline]
pub fn is_token_valid(token: &str, valid_tokens: &HashSet<String>) -> bool {
    valid_tokens.contains(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_secret(channel: u8, token: u8) -> Secret {
        Secret {
            channel: [channel; CHANNEL_BYTES_LEN],
            token: [token; TOKEN_BYTES_LEN],
        }
    }

    /// Re-encode a secret with one section replaced verbatim.
    fn with_section(secret: &Secret, index: usize, section: &str) -> String {
        let encoded = secret.encode();
        let mut sections: Vec<String> = encoded.split('.').map(str::to_string).collect();
        sections[index] = section.to_string();
        sections.join(".")
    }

    #[test]
    fn test_crc16_ccitt_false_known_vector() {
        // Standard check value for CRC16-CCITT-FALSE with "123456789".
        assert_eq!(crc16_ccitt_false(b"123456789"), 0x29B1);
    }

    #[test]
    fn test_generate_encodes_to_the_canonical_shape() {
        let encoded = Secret::generate().encode();
        assert_eq!(encoded.len(), SECRET_LENGTH);
        assert_eq!(encoded.len(), 125);

        let sections: Vec<&str> = encoded.split('.').collect();
        assert_eq!(sections.len(), 3);
        // The version section is a constant, so it doubles as the duocb marker.
        assert_eq!(sections[0], "eyJ2IjoxfQ");
        assert_eq!(
            sections.iter().map(|s| s.len()).collect::<Vec<_>>(),
            vec![
                HEADER_SEGMENT_LEN,
                PAYLOAD_SEGMENT_LEN,
                CHECKSUM_SEGMENT_LEN
            ]
        );
        assert!(Secret::parse(&encoded).is_ok());
    }

    #[test]
    fn test_generate_uniqueness() {
        let a = Secret::generate();
        let b = Secret::generate();
        assert_ne!(a.channel, b.channel);
        assert_ne!(a.token, b.token);
        // The two halves of one secret are independently random.
        assert_ne!(&a.channel[..], &a.token[..CHANNEL_BYTES_LEN]);
    }

    #[test]
    fn test_parse_roundtrips_both_halves() {
        let secret = Secret::generate();
        let encoded = secret.encode();
        let parsed = Secret::parse(&encoded).expect("parse own encoding");
        assert_eq!(parsed, secret);
        assert_eq!(parsed.encode(), encoded);
        assert_eq!(parsed.channel().as_bytes(), secret.channel().as_bytes());
        assert_eq!(parsed.wire_token(), secret.wire_token());
    }

    #[test]
    fn test_wire_token_is_43_chars_of_the_token_half_only() {
        let secret = make_test_secret(0xAB, 0xCD);
        let token = secret.wire_token();
        assert_eq!(token.len(), 43);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&token).unwrap(),
            [0xCDu8; TOKEN_BYTES_LEN]
        );
        // The channel half is nowhere in the wire token.
        assert!(!token.contains(&URL_SAFE_NO_PAD.encode([0xABu8; CHANNEL_BYTES_LEN])));
    }

    #[test]
    fn test_halves_are_independent() {
        // Same channel, different tokens: the rendezvous half is identical while
        // the credential and the fingerprint differ.
        let a = make_test_secret(0x11, 0x22);
        let b = make_test_secret(0x11, 0x33);
        assert_eq!(a.channel().as_bytes(), b.channel().as_bytes());
        assert_ne!(a.wire_token(), b.wire_token());
        assert_ne!(a.fingerprint(), b.fingerprint());

        // Same token, different channels: the credential is identical while the
        // rendezvous half and the fingerprint differ.
        let c = make_test_secret(0x44, 0x22);
        assert_eq!(a.wire_token(), c.wire_token());
        assert_ne!(a.channel().as_bytes(), c.channel().as_bytes());
        assert_ne!(a.fingerprint(), c.fingerprint());
    }

    #[test]
    fn test_fingerprint_grouped_16_upper_hex() {
        let secret = make_test_secret(0xAB, 0xCD);
        let fp = secret.fingerprint();
        // 16 hex digits grouped into four dash-separated quads: XXXX-XXXX-XXXX-XXXX.
        assert_eq!(fp.len(), FINGERPRINT_HEX_DIGITS + 3);
        let groups: Vec<&str> = fp.split('-').collect();
        assert_eq!(groups.len(), 4);
        assert!(groups.iter().all(|g| {
            g.len() == 4
                && g.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
        }));
        // Deterministic: the same secret always yields the same fingerprint.
        assert_eq!(fp, secret.fingerprint());
        // It is the first 8 bytes of SHA-256(channel ‖ token), as uppercase hex.
        let mut hasher = Sha256::new();
        hasher.update([0xABu8; CHANNEL_BYTES_LEN]);
        hasher.update([0xCDu8; TOKEN_BYTES_LEN]);
        let digest = hasher.finalize();
        let expected: String = digest[..FINGERPRINT_HEX_DIGITS / 2]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        assert_eq!(fp.replace('-', ""), expected);
    }

    #[test]
    fn test_fingerprint_differs_for_different_secrets() {
        assert_ne!(
            make_test_secret(0x01, 0x01).fingerprint(),
            make_test_secret(0x02, 0x02).fingerprint()
        );
    }

    #[test]
    fn test_parse_rejects_non_ascii() {
        let err = Secret::parse("🔐notascii").unwrap_err().to_string();
        assert!(err.contains("ASCII"), "{err}");
    }

    #[test]
    fn test_parse_rejects_wrong_length() {
        let secret = Secret::generate();
        let encoded = secret.encode();

        let err = Secret::parse(&encoded[..encoded.len() - 1])
            .unwrap_err()
            .to_string();
        assert!(err.contains("exactly 125 characters"), "{err}");

        let err = Secret::parse(&format!("{encoded}A")).unwrap_err().to_string();
        assert!(err.contains("exactly 125 characters"), "{err}");
    }

    #[test]
    fn test_parse_rejects_the_old_47_char_token_and_a_bare_token() {
        // The pre-envelope format and a bare 43-char token both fail on length,
        // which is the clearest message available for them.
        let old = format!("d{}", "A".repeat(46));
        let err = Secret::parse(&old).unwrap_err().to_string();
        assert!(err.contains("exactly 125 characters"), "{err}");

        let bare = Secret::generate().wire_token();
        let err = Secret::parse(&bare).unwrap_err().to_string();
        assert!(err.contains("exactly 125 characters"), "{err}");
    }

    #[test]
    fn test_parse_rejects_wrong_section_count() {
        let secret = Secret::generate();
        let encoded = secret.encode();

        // Two sections: drop a dot but keep the length by borrowing a character.
        let two = encoded.replacen('.', "A", 1);
        assert_eq!(two.len(), SECRET_LENGTH);
        let err = Secret::parse(&two).unwrap_err().to_string();
        assert!(err.contains("3 dot-separated sections"), "{err}");

        // Four sections: split the payload with an extra dot.
        let four = format!("{}.{}", &encoded[..40], &encoded[41..]);
        assert_eq!(four.len(), SECRET_LENGTH);
        let err = Secret::parse(&four).unwrap_err().to_string();
        assert!(err.contains("3 dot-separated sections"), "{err}");
    }

    #[test]
    fn test_parse_rejects_misplaced_section_boundaries() {
        // Three sections, right total length, wrong split: caught by the
        // per-section length check before any decoding happens.
        let encoded = Secret::generate().encode();
        let raw: String = encoded.chars().filter(|c| *c != '.').collect();
        let shifted = format!(
            "{}.{}.{}",
            &raw[..HEADER_SEGMENT_LEN - 1],
            &raw[HEADER_SEGMENT_LEN - 1..raw.len() - CHECKSUM_SEGMENT_LEN],
            &raw[raw.len() - CHECKSUM_SEGMENT_LEN..]
        );
        assert_eq!(shifted.len(), SECRET_LENGTH);
        let err = Secret::parse(&shifted).unwrap_err().to_string();
        assert!(err.contains("section must be"), "{err}");
    }

    #[test]
    fn test_parse_rejects_a_tampered_version_section() {
        // `{"v":2}` — a well-formed header of the wrong version.
        let secret = Secret::generate();
        let header = URL_SAFE_NO_PAD.encode(br#"{"v":2}"#);
        let err = Secret::parse(&with_section(&secret, 0, &header))
            .unwrap_err()
            .to_string();
        assert!(err.contains("version 2"), "{err}");

        // `{"z":1}` — right shape, unknown field.
        let header = URL_SAFE_NO_PAD.encode(br#"{"z":1}"#);
        let err = Secret::parse(&with_section(&secret, 0, &header))
            .unwrap_err()
            .to_string();
        assert!(err.contains("secret header"), "{err}");
    }

    #[test]
    fn test_parse_rejects_a_tampered_payload_section() {
        let secret = Secret::generate();
        let encoded = secret.encode();
        let mut payload: Vec<char> = encoded.split('.').nth(1).unwrap().chars().collect();
        // Flip a character inside the base64 of the channel half.
        payload[20] = if payload[20] == 'A' { 'B' } else { 'A' };
        let payload: String = payload.into_iter().collect();

        let err = Secret::parse(&with_section(&secret, 1, &payload))
            .unwrap_err()
            .to_string();
        // Either the JSON no longer parses or the checksum catches it; both are
        // hard errors, and a payload edit must never yield a usable secret.
        assert!(
            err.contains("checksum") || err.contains("payload") || err.contains("channel"),
            "{err}"
        );
    }

    #[test]
    fn test_parse_rejects_a_tampered_checksum_section() {
        let secret = Secret::generate();
        let good = URL_SAFE_NO_PAD.encode(secret.checksum().to_be_bytes());
        let bad = URL_SAFE_NO_PAD.encode((secret.checksum() ^ 0x0001).to_be_bytes());
        assert_ne!(good, bad);
        let err = Secret::parse(&with_section(&secret, 2, &bad))
            .unwrap_err()
            .to_string();
        assert!(err.contains("checksum"), "{err}");
    }

    #[test]
    fn test_parse_rejects_a_swapped_half() {
        // A channel paired with a foreign token: the checksum covers both halves,
        // so a spliced secret is rejected outright.
        let a = Secret::generate();
        let b = Secret::generate();
        let spliced = Secret {
            channel: a.channel,
            token: b.token,
        };
        let forged = with_section(
            &spliced,
            2,
            &URL_SAFE_NO_PAD.encode(a.checksum().to_be_bytes()),
        );
        let err = Secret::parse(&forged).unwrap_err().to_string();
        assert!(err.contains("checksum"), "{err}");
        // And a genuinely re-checksummed splice is a different secret, so the
        // displayed fingerprint diverges from both originals.
        assert_ne!(spliced.fingerprint(), a.fingerprint());
        assert_ne!(spliced.fingerprint(), b.fingerprint());
    }

    #[test]
    fn test_parse_rejects_non_canonical_encodings() {
        let secret = Secret::generate();

        // An extra JSON field in the payload. Fixed section lengths mean the
        // longer payload trips the length gate before serde ever sees it — the
        // point is only that a non-canonical payload can never parse.
        let payload = serde_json::to_string(&serde_json::json!({
            "ch": URL_SAFE_NO_PAD.encode(secret.channel),
            "tk": URL_SAFE_NO_PAD.encode(secret.token),
            "x": 1,
        }))
        .unwrap();
        assert!(
            Secret::parse(&with_section(
                &secret,
                1,
                &URL_SAFE_NO_PAD.encode(&payload)
            ))
            .is_err()
        );

        // An unknown field that keeps the payload's length: serde rejects it.
        let ch = URL_SAFE_NO_PAD.encode(secret.channel);
        let padded = serde_json::to_string(&serde_json::json!({
            "ch": ch,
            "xk": URL_SAFE_NO_PAD.encode(secret.token),
        }))
        .unwrap();
        let err = Secret::parse(&with_section(
            &secret,
            1,
            &URL_SAFE_NO_PAD.encode(&padded),
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("payload"), "{err}");

        // Base64 padding is rejected by URL_SAFE_NO_PAD.
        let padded = format!("{}==", &secret.encode()[..SECRET_LENGTH - 2]);
        assert!(Secret::parse(&padded).is_err());
    }

    #[test]
    fn test_parse_joins_a_line_wrapped_paste() {
        let secret = Secret::generate();
        let encoded = secret.encode();
        let wrapped = format!("  {}\n{}\t{}  ", &encoded[..40], &encoded[40..90], &encoded[90..]);
        assert_eq!(Secret::parse(&wrapped).expect("parse wrapped"), secret);
    }

    #[test]
    fn test_debug_redacts_both_the_secret_and_the_channel() {
        let secret = Secret::generate();
        let debug = format!("{secret:?}");
        assert_eq!(debug, "Secret(***)");
        assert!(!debug.contains(&secret.wire_token()));
        assert!(!debug.contains(&URL_SAFE_NO_PAD.encode(secret.channel)));

        let channel = format!("{:?}", secret.channel());
        assert_eq!(channel, "Channel(***)");
        assert!(!channel.contains(&URL_SAFE_NO_PAD.encode(secret.channel)));
    }

    #[test]
    fn test_is_token_valid_empty_set_rejects_all() {
        let secret = Secret::generate();
        assert!(!is_token_valid(&secret.wire_token(), &HashSet::new()));
    }

    #[test]
    fn test_is_token_valid_in_set() {
        let secret = Secret::generate();
        let valid_tokens = HashSet::from([secret.wire_token()]);
        assert!(is_token_valid(&secret.wire_token(), &valid_tokens));
    }

    #[test]
    fn test_is_token_valid_not_in_set() {
        let a = Secret::generate();
        let b = Secret::generate();
        let valid_tokens = HashSet::from([a.wire_token()]);
        assert!(!is_token_valid(&b.wire_token(), &valid_tokens));
    }

    #[test]
    fn test_is_token_valid_rejects_a_shared_channel_with_a_foreign_token() {
        // The listener accepts the token half only: sharing a channel does not
        // get you a session.
        let a = Secret::generate();
        let impostor = Secret {
            channel: a.channel,
            token: Secret::generate().token,
        };
        let valid_tokens = HashSet::from([a.wire_token()]);
        assert!(!is_token_valid(&impostor.wire_token(), &valid_tokens));
    }
}
