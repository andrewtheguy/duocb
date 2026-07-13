//! Token-based authentication for iroh clipboard connections.
//!
//! Provides pre-shared token authentication for the duocb peer runtime.
//!
//! ## Token Format
//! - Exactly 47 characters
//! - Starts with lowercase `d` (for duocb)
//! - Remaining 46 characters are Base64URL (no padding)
//! - Decoded payload is exactly 34 bytes:
//!   - First 32 bytes: random entropy
//!   - Last 2 bytes: CRC16-CCITT-FALSE checksum (big-endian) of the 32 random bytes

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Required length for authentication tokens.
pub const TOKEN_LENGTH: usize = 47;

/// Required prefix character for tokens.
pub const TOKEN_PREFIX: char = 'd';

/// Number of random bytes in token payload.
const RANDOM_BYTES_LEN: usize = 32;

/// Number of checksum bytes in token payload.
const CHECKSUM_BYTES_LEN: usize = 2;

/// Number of decoded bytes in token payload.
const TOKEN_PAYLOAD_LEN: usize = RANDOM_BYTES_LEN + CHECKSUM_BYTES_LEN;

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

/// Generate a new authentication token.
///
/// Format: `d` + base64url_no_pad(32 random bytes + 2-byte CRC16) = 47 characters total.
pub fn generate_token() -> String {
    let mut random = [0u8; RANDOM_BYTES_LEN];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut random);

    let checksum = crc16_ccitt_false(&random).to_be_bytes();
    let mut payload = [0u8; TOKEN_PAYLOAD_LEN];
    payload[..RANDOM_BYTES_LEN].copy_from_slice(&random);
    payload[RANDOM_BYTES_LEN..].copy_from_slice(&checksum);

    format!("{}{}", TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(payload))
}

/// Short, stable fingerprint of a token for cross-device verification.
///
/// The token is never revealed in plain text, so two devices cannot compare the
/// secret directly. This fingerprint — the first 8 bytes of the SHA-256 of the
/// token string, as 16 uppercase hex digits grouped into four dash-separated
/// quads (`XXXX-XXXX-XXXX-XXXX`) — is displayed instead: if it matches on both
/// devices the tokens match, without ever exposing the secret. It stays local
/// (never sent over the wire), so 8 bytes is ample against accidental collision.
pub fn token_fingerprint(token: &str) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(token.as_bytes());
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

/// Number of hex digits in a token fingerprint, before group separators
/// (see [`token_fingerprint`]).
pub const FINGERPRINT_HEX_DIGITS: usize = 16;

/// Validate token format.
///
/// Returns Ok(()) if valid, Err with description if invalid.
pub fn validate_token(token: &str) -> Result<()> {
    // Early ASCII check - all valid tokens are ASCII
    if !token.is_ascii() {
        anyhow::bail!("Token must contain only ASCII characters");
    }

    if token.len() != TOKEN_LENGTH {
        anyhow::bail!(
            "Token must be exactly {} characters, got {} characters",
            TOKEN_LENGTH,
            token.len()
        );
    }

    // Check prefix
    if !token.starts_with(TOKEN_PREFIX) {
        anyhow::bail!(
            "Token must start with '{}', got '{}'",
            TOKEN_PREFIX,
            token.chars().next().unwrap_or('?')
        );
    }

    let encoded_payload = &token[TOKEN_PREFIX.len_utf8()..];
    let payload = URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .context("Token payload is not valid base64url without padding")?;

    if payload.len() != TOKEN_PAYLOAD_LEN {
        anyhow::bail!(
            "Token payload must decode to exactly {} bytes, got {} bytes",
            TOKEN_PAYLOAD_LEN,
            payload.len()
        );
    }

    let random = &payload[..RANDOM_BYTES_LEN];
    let checksum = &payload[RANDOM_BYTES_LEN..];
    let expected_checksum = crc16_ccitt_false(random).to_be_bytes();

    if checksum != expected_checksum {
        anyhow::bail!("Token checksum is invalid");
    }

    Ok(())
}

/// Check if a token is in the valid tokens set.
///
/// Returns true if the token is valid, false otherwise.
/// An empty valid_tokens set means no tokens are authorized.
#[inline]
pub fn is_token_valid(token: &str, valid_tokens: &HashSet<String>) -> bool {
    valid_tokens.contains(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_token(random: [u8; RANDOM_BYTES_LEN]) -> String {
        let checksum = crc16_ccitt_false(&random).to_be_bytes();
        let mut payload = [0u8; TOKEN_PAYLOAD_LEN];
        payload[..RANDOM_BYTES_LEN].copy_from_slice(&random);
        payload[RANDOM_BYTES_LEN..].copy_from_slice(&checksum);
        format!("{}{}", TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(payload))
    }

    fn decode_payload(token: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(&token[TOKEN_PREFIX.len_utf8()..])
            .unwrap()
    }

    #[test]
    fn test_crc16_ccitt_false_known_vector() {
        // Standard check value for CRC16-CCITT-FALSE with "123456789".
        assert_eq!(crc16_ccitt_false(b"123456789"), 0x29B1);
    }

    #[test]
    fn test_token_fingerprint_grouped_16_upper_hex() {
        let token = make_test_token([0xAB; RANDOM_BYTES_LEN]);
        let fp = token_fingerprint(&token);
        // 16 hex digits grouped into four dash-separated quads: XXXX-XXXX-XXXX-XXXX.
        assert_eq!(fp.len(), FINGERPRINT_HEX_DIGITS + 3);
        let groups: Vec<&str> = fp.split('-').collect();
        assert_eq!(groups.len(), 4);
        assert!(groups.iter().all(|g| {
            g.len() == 4
                && g.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
        }));
        // Deterministic: same token always yields the same fingerprint.
        assert_eq!(fp, token_fingerprint(&token));
        // It is the first 8 bytes of the SHA-256 of the token string, as uppercase hex.
        let digest = Sha256::digest(token.as_bytes());
        let expected: String = digest[..FINGERPRINT_HEX_DIGITS / 2]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        assert_eq!(fp.replace('-', ""), expected);
    }

    #[test]
    fn test_token_fingerprint_differs_for_different_tokens() {
        let a = make_test_token([0x01; RANDOM_BYTES_LEN]);
        let b = make_test_token([0x02; RANDOM_BYTES_LEN]);
        assert_ne!(token_fingerprint(&a), token_fingerprint(&b));
    }

    #[test]
    fn test_generate_token_format() {
        let token = generate_token();
        assert_eq!(token.len(), TOKEN_LENGTH);
        assert!(token.starts_with(TOKEN_PREFIX));
        assert!(validate_token(&token).is_ok());
    }

    #[test]
    fn test_generate_token_uniqueness() {
        let token1 = generate_token();
        let token2 = generate_token();
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_validate_token_valid() {
        let token = make_test_token([0xAB; RANDOM_BYTES_LEN]);
        assert!(validate_token(&token).is_ok());
    }

    #[test]
    fn test_validate_token_too_short() {
        let result = validate_token("dshort");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("exactly 47 characters")
        );
    }

    #[test]
    fn test_validate_token_too_long() {
        let token = format!("{}{}", TOKEN_PREFIX, "A".repeat(TOKEN_LENGTH));
        let result = validate_token(&token);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("exactly 47 characters")
        );
    }

    #[test]
    fn test_validate_token_wrong_prefix() {
        let mut token = generate_token().chars().collect::<Vec<_>>();
        token[0] = 'x';
        let token: String = token.into_iter().collect();

        let result = validate_token(&token);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must start with 'd'")
        );
    }

    #[test]
    fn test_validate_token_invalid_base64url_chars() {
        let token = format!("{}{}", TOKEN_PREFIX, "!".repeat(TOKEN_LENGTH - 1));
        let result = validate_token(&token);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("base64url"));
    }

    #[test]
    fn test_validate_token_non_ascii() {
        let result = validate_token("d🔐notascii");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ASCII"));
    }

    #[test]
    fn test_validate_token_bad_checksum() {
        let mut payload = decode_payload(&generate_token());
        payload[RANDOM_BYTES_LEN] ^= 0x01;
        let bad = format!("{}{}", TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(payload));

        let result = validate_token(&bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("checksum"));
    }

    #[test]
    fn test_validate_token_rejects_mutated_random_byte() {
        let mut payload = decode_payload(&generate_token());
        payload[0] ^= 0x80;
        let bad = format!("{}{}", TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(payload));

        let result = validate_token(&bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("checksum"));
    }

    #[test]
    fn test_is_token_valid_empty_set_rejects_all() {
        let token = generate_token();
        let valid_tokens = HashSet::new();
        assert!(!is_token_valid(&token, &valid_tokens));
    }

    #[test]
    fn test_is_token_valid_in_set() {
        let token = generate_token();
        let mut valid_tokens = HashSet::new();
        valid_tokens.insert(token.clone());

        assert!(is_token_valid(&token, &valid_tokens));
    }

    #[test]
    fn test_is_token_valid_not_in_set() {
        let token_a = generate_token();
        let token_b = generate_token();
        let mut valid_tokens = HashSet::new();
        valid_tokens.insert(token_a.clone());

        assert!(!is_token_valid(&token_b, &valid_tokens));
    }
}
