//! Human-readable names attached to persistent application identities.

use anyhow::{Result, bail};

pub const NAME_MAX_LEN: usize = 24;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
