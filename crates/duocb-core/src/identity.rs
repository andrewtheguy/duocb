//! Per-device identity for the configure mode: a short user-chosen name plus a
//! permanent random suffix, displayed and broadcast as `<name>_<suffix>` (e.g.
//! `mac-book_a7B2c3D4`).
//!
//! The suffix is minted once, on the first launch with a given config file, and
//! never changes afterwards — it survives clearing or regenerating the secret.
//! Because every device carries its own random suffix, the full display identity
//! is unique by construction, which is what makes the per-device nostr record
//! tags collision-free (two devices may freely pick the same short name).
//!
//! The suffix alphabet is mixed-case letters and digits minus the ambiguous
//! `0 O o 1 l I`, so an identity read aloud or eyeballed across two screens
//! cannot be mistranscribed. The short name deliberately allows only
//! `A-Z a-z 0-9 -`, keeping [`IDENTITY_SEPARATOR`] out of the name alphabet so
//! `<name>_<suffix>` splits unambiguously.

use anyhow::{Result, bail};
use rand::Rng;

/// Unambiguous mixed-case alphanumerics: ASCII digits and letters minus
/// `0 O o 1 l I` (8 digits + 24 uppercase + 24 lowercase = 56 chars).
pub const UNAMBIGUOUS_ALPHANUM: &[u8; 56] =
    b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";

/// Length of the permanent per-device suffix (~46 bits of randomness).
pub const SUFFIX_LEN: usize = 8;

/// Maximum length of the user-chosen short name, in characters.
pub const NAME_MAX_LEN: usize = 24;

/// Separator between the short name and the suffix in a display identity. Not
/// part of the name alphabet, so the identity parses unambiguously.
pub const IDENTITY_SEPARATOR: char = '_';

/// Mint a fresh random suffix: [`SUFFIX_LEN`] characters drawn uniformly from
/// [`UNAMBIGUOUS_ALPHANUM`].
pub fn generate_suffix() -> String {
    let mut rng = rand::rng();
    (0..SUFFIX_LEN)
        .map(|_| UNAMBIGUOUS_ALPHANUM[rng.random_range(0..UNAMBIGUOUS_ALPHANUM.len())] as char)
        .collect()
}

/// Whether `s` has the exact shape of a generated suffix.
pub fn is_valid_suffix(s: &str) -> bool {
    s.len() == SUFFIX_LEN && s.bytes().all(|b| UNAMBIGUOUS_ALPHANUM.contains(&b))
}

/// Validate a user-chosen short device name: 1..=[`NAME_MAX_LEN`] characters,
/// each one of `A-Z a-z 0-9 -`.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("device name must not be empty");
    }
    if name.chars().count() > NAME_MAX_LEN {
        bail!("device name must be at most {NAME_MAX_LEN} characters");
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '-'))
    {
        bail!("device name may only contain letters, digits, and '-' (found {bad:?})");
    }
    Ok(())
}

/// The full display identity broadcast to peers: `<name>_<suffix>`.
pub fn display_identity(name: &str, suffix: &str) -> String {
    format!("{name}{IDENTITY_SEPARATOR}{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabet_has_no_ambiguous_chars_and_declared_size() {
        assert_eq!(UNAMBIGUOUS_ALPHANUM.len(), 56);
        for ambiguous in [b'0', b'O', b'o', b'1', b'l', b'I'] {
            assert!(
                !UNAMBIGUOUS_ALPHANUM.contains(&ambiguous),
                "alphabet must not contain {:?}",
                ambiguous as char
            );
        }
        let mut sorted = UNAMBIGUOUS_ALPHANUM.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 56, "alphabet chars must be distinct");
        assert!(
            UNAMBIGUOUS_ALPHANUM
                .iter()
                .all(|b| b.is_ascii_alphanumeric())
        );
    }

    #[test]
    fn generated_suffix_is_valid_and_varies() {
        let a = generate_suffix();
        let b = generate_suffix();
        assert!(is_valid_suffix(&a), "generated suffix {a:?} must validate");
        assert!(is_valid_suffix(&b));
        // 56^8 values: two draws colliding means the generator is broken.
        assert_ne!(a, b);
    }

    #[test]
    fn suffix_validation_rejects_wrong_shape() {
        assert!(is_valid_suffix("a7B2c3D4"));
        assert!(!is_valid_suffix(""));
        assert!(!is_valid_suffix("a7B2c3D")); // too short
        assert!(!is_valid_suffix("a7B2c3D45")); // too long
        assert!(!is_valid_suffix("a7B2c3D0")); // ambiguous '0'
        assert!(!is_valid_suffix("a7B2c3Dl")); // ambiguous 'l'
        assert!(!is_valid_suffix("a7B2c3D_")); // separator
    }

    #[test]
    fn name_validation_accepts_letters_digits_dash_only() {
        assert!(validate_name("mac-book").is_ok());
        assert!(validate_name("Desktop2").is_ok());
        assert!(validate_name("a").is_ok());
        assert!(validate_name(&"x".repeat(NAME_MAX_LEN)).is_ok());

        assert!(validate_name("").is_err());
        assert!(validate_name(&"x".repeat(NAME_MAX_LEN + 1)).is_err());
        assert!(validate_name("mac book").is_err()); // space
        assert!(validate_name("mac_book").is_err()); // separator char
        assert!(validate_name("café").is_err()); // non-ASCII
    }

    #[test]
    fn display_identity_joins_name_and_suffix() {
        assert_eq!(display_identity("mac-book", "a7B2c3D4"), "mac-book_a7B2c3D4");
    }
}
