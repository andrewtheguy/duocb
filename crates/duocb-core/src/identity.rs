//! Human-readable names attached to persistent application identities.
//!
//! A user chooses a short name and each installation carries a permanent
//! random suffix. The final name signed into its identity card is
//! `<short-name>_<suffix>` (for example, `mac-book_a7B2c3D4`).

use anyhow::{Result, bail};
use rand::Rng;

/// Unambiguous mixed-case alphanumerics: ASCII digits and letters minus
/// `0 O o 1 l I` (8 digits + 24 uppercase + 24 lowercase = 56 chars).
pub const UNAMBIGUOUS_ALPHANUM: &[u8; 56] =
    b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";
pub const SUFFIX_LEN: usize = 8;
pub const NAME_MAX_LEN: usize = 24;
pub const IDENTITY_SEPARATOR: char = '_';

/// Mint a fresh permanent per-installation suffix.
pub fn generate_suffix() -> String {
    let mut rng = rand::rng();
    (0..SUFFIX_LEN)
        .map(|_| UNAMBIGUOUS_ALPHANUM[rng.random_range(0..UNAMBIGUOUS_ALPHANUM.len())] as char)
        .collect()
}

pub fn is_valid_suffix(suffix: &str) -> bool {
    suffix.len() == SUFFIX_LEN
        && suffix
            .bytes()
            .all(|byte| UNAMBIGUOUS_ALPHANUM.contains(&byte))
}

/// Validate a user-chosen device name: 1..=24 ASCII letters, digits, or `-`.
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

pub fn display_identity(name: &str, suffix: &str) -> String {
    format!("{name}{IDENTITY_SEPARATOR}{suffix}")
}

/// Validate and split the final name stored in an identity card.
pub fn split_display_identity(display: &str) -> Result<(&str, &str)> {
    let Some((name, suffix)) = display.split_once(IDENTITY_SEPARATOR) else {
        bail!("device identity must contain a permanent suffix");
    };
    if suffix.contains(IDENTITY_SEPARATOR) {
        bail!("device identity contains more than one separator");
    }
    validate_name(name)?;
    if !is_valid_suffix(suffix) {
        bail!("device identity has an invalid permanent suffix");
    }
    Ok((name, suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_suffix_is_valid_and_varies() {
        let a = generate_suffix();
        let b = generate_suffix();
        assert!(is_valid_suffix(&a));
        assert!(is_valid_suffix(&b));
        assert_ne!(a, b);
    }

    #[test]
    fn name_validation_accepts_letters_digits_dash_only() {
        assert!(validate_name("mac-book").is_ok());
        assert!(validate_name("Desktop2").is_ok());
        assert!(validate_name(&"x".repeat(NAME_MAX_LEN)).is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name(&"x".repeat(NAME_MAX_LEN + 1)).is_err());
        assert!(validate_name("mac book").is_err());
        assert!(validate_name("mac_book").is_err());
        assert!(validate_name("café").is_err());
    }

    #[test]
    fn final_identity_roundtrips_short_name_and_suffix() {
        let display = display_identity("mac-book", "a7B2c3D4");
        assert_eq!(display, "mac-book_a7B2c3D4");
        assert_eq!(
            split_display_identity(&display).unwrap(),
            ("mac-book", "a7B2c3D4")
        );
        assert!(split_display_identity("mac-book").is_err());
        assert!(split_display_identity("mac-book_bad").is_err());
        assert!(split_display_identity("mac_book_a7B2c3D4").is_err());
    }
}
