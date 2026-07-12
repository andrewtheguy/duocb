//! The manual mode pairing code: the out-of-band sibling of the PIN
//! rendezvous. Manual mode has no signaling channel at all — the user carries
//! the session-establishment data between devices themselves (copy/paste over
//! any private channel). One code bundles everything the joiner needs: the
//! server's ephemeral node id (where to dial) and a fresh session secret in
//! canonical PIN form (what to prove in-band — the same Argon2id
//! challenge-response the PIN quick mode runs, see `crate::pin_auth`). No
//! token, no record, nothing published anywhere.

use iroh::EndpointId;

use crate::pin;

/// Build the display/copy form of a pairing code: the 64-hex node id followed
/// by the secret in grouped PIN form, dash-separated (`<node id>-XXXX-XXXX`).
/// Dashes are cosmetic — [`decode`] strips them.
pub fn encode(node_id: &EndpointId, canonical_secret: &str) -> String {
    format!("{node_id}-{}", pin::format_pin(canonical_secret))
}

/// Parse user input back into `(node id, canonical secret)`. Strips whitespace
/// and dashes and is case-tolerant; the node id must parse (64 hex chars) and
/// the secret must pass the PIN check digit, so a truncated or mistyped paste
/// is rejected here rather than later as a failed dial or auth. `None` when
/// anything is off.
pub fn decode(input: &str) -> Option<(String, String)> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    if cleaned.len() <= 64 {
        return None;
    }
    let (id_part, secret_part) = cleaned.split_at(64);
    let node_id: EndpointId = id_part.to_ascii_lowercase().parse().ok()?;
    let secret = pin::normalize_pin(secret_part)?;
    Some((node_id.to_string(), secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_round_trips_and_tolerates_formatting() {
        let node_id = iroh::SecretKey::generate().public();
        let secret = pin::generate_pin();
        let code = encode(&node_id, &secret);

        let (got_id, got_secret) = decode(&code).expect("own code must decode");
        assert_eq!(got_id, node_id.to_string());
        assert_eq!(got_secret, secret);

        // Pastes survive extra whitespace, dropped dashes, and case changes.
        let mangled = format!(" {} \n", code.to_ascii_uppercase().replace('-', " "));
        assert_eq!(decode(&mangled), Some((got_id, got_secret)));
    }

    #[test]
    fn truncated_or_mistyped_codes_are_rejected() {
        let node_id = iroh::SecretKey::generate().public();
        let secret = pin::generate_pin();
        let code = encode(&node_id, &secret);

        // Missing tail characters (a partial copy).
        assert_eq!(decode(&code[..code.len() - 2]), None);
        // Node id alone (the old two-field habit).
        assert_eq!(decode(&node_id.to_string()), None);
        // A flipped secret character fails the check digit.
        let mut chars: Vec<char> = code.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '2' { '3' } else { '2' };
        let flipped: String = chars.into_iter().collect();
        assert_eq!(decode(&flipped), None);
        assert_eq!(decode(""), None);
    }
}
