//! The manual mode pairing code: the out-of-band sibling of the PIN
//! rendezvous. Manual mode has no signaling channel at all — the user carries
//! the session-establishment data between devices themselves (copy/paste over
//! any private channel). One code bundles everything the joiner needs: the
//! server's ephemeral node id (where to dial), a fresh session secret in
//! canonical PIN form (what to prove in-band — the same Argon2id
//! challenge-response the PIN quick mode runs, see `crate::pin_auth`), and the
//! server's direct socket addresses. The addresses are dialed as-is, needing
//! no discovery of any kind — the fallback that still pairs on networks where
//! mDNS/multicast is blocked, with no internet. No token, no record, nothing
//! published anywhere.

use std::net::SocketAddr;

use iroh::EndpointId;

use crate::pin;

/// Build the display/copy form of a pairing code: the 64-hex node id, the
/// secret in grouped PIN form, then the comma-separated direct addresses and
/// their crc32 — `<node id>-XXXX-XXXX@ip:port,[v6]:port!crc32hex`. The
/// checksum guards the address tail the way the node-id parse and the PIN
/// check digit guard the front: a clipped paste could otherwise still parse
/// (a truncated port is a valid port). Dashes are cosmetic and [`decode`]
/// strips them; without addresses the `@` part is omitted.
pub fn encode(node_id: &EndpointId, canonical_secret: &str, addrs: &[SocketAddr]) -> String {
    let base = format!("{node_id}-{}", pin::format_pin(canonical_secret));
    if addrs.is_empty() {
        return base;
    }
    let addrs: Vec<String> = addrs.iter().map(SocketAddr::to_string).collect();
    let addrs = addrs.join(",");
    let crc = crc32fast::hash(addrs.as_bytes());
    format!("{base}@{addrs}!{crc:08x}")
}

/// Parse user input back into `(node id, canonical secret, direct addrs)`.
/// Strips whitespace and dashes and is case-tolerant; the node id must parse
/// (64 hex chars), the secret must pass the PIN check digit, and every
/// embedded address must parse, so a truncated or mistyped paste is rejected
/// here rather than later as a failed dial or auth. `None` when anything is
/// off.
pub fn decode(input: &str) -> Option<(String, String, Vec<SocketAddr>)> {
    let (code, addr_part) = match input.split_once('@') {
        Some((code, addrs)) => (code, Some(addrs)),
        None => (input, None),
    };
    let cleaned: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    if cleaned.len() <= 64 {
        return None;
    }
    let (id_part, secret_part) = cleaned.split_at(64);
    let node_id: EndpointId = id_part.to_ascii_lowercase().parse().ok()?;
    let secret = pin::normalize_pin(secret_part)?;

    let mut addrs = Vec::new();
    if let Some(addr_part) = addr_part {
        // Normalize to what `encode` hashed: no whitespace (a line-wrapped
        // paste is forgiven), lowercase (v6 hex and the crc are case-tolerant
        // like the rest of the code; `SocketAddr` renders lowercase).
        let cleaned: String = addr_part
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        let (list, crc) = cleaned.rsplit_once('!')?;
        if crc.len() != 8 || u32::from_str_radix(crc, 16).ok()? != crc32fast::hash(list.as_bytes())
        {
            return None;
        }
        for part in list.split(',') {
            addrs.push(part.parse().ok()?);
        }
    }
    Some((node_id.to_string(), secret, addrs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addrs() -> Vec<SocketAddr> {
        vec![
            "192.168.1.10:4433".parse().unwrap(),
            "[2001:db8::1]:4433".parse().unwrap(),
        ]
    }

    #[test]
    fn code_round_trips_and_tolerates_formatting() {
        let node_id = iroh::SecretKey::generate().public();
        let secret = pin::generate_pin();
        let addrs = test_addrs();
        let code = encode(&node_id, &secret, &addrs);

        let (got_id, got_secret, got_addrs) = decode(&code).expect("own code must decode");
        assert_eq!(got_id, node_id.to_string());
        assert_eq!(got_secret, secret);
        assert_eq!(got_addrs, addrs);

        // Pastes survive extra whitespace, dropped dashes, and case changes.
        let mangled = format!(" {} \n", code.to_ascii_uppercase().replace('-', " "));
        assert_eq!(decode(&mangled), Some((got_id, got_secret, got_addrs)));
    }

    #[test]
    fn addressless_code_round_trips() {
        let node_id = iroh::SecretKey::generate().public();
        let secret = pin::generate_pin();
        let code = encode(&node_id, &secret, &[]);
        assert!(!code.contains('@'), "no addrs → no @ part: {code}");
        let (got_id, got_secret, got_addrs) = decode(&code).expect("own code must decode");
        assert_eq!(got_id, node_id.to_string());
        assert_eq!(got_secret, secret);
        assert!(got_addrs.is_empty());
    }

    #[test]
    fn truncated_or_mistyped_codes_are_rejected() {
        let node_id = iroh::SecretKey::generate().public();
        let secret = pin::generate_pin();
        let code = encode(&node_id, &secret, &test_addrs());

        // Missing tail characters (a partial copy — clips the last address).
        assert_eq!(decode(&code[..code.len() - 2]), None);
        // Node id alone (the old two-field habit).
        assert_eq!(decode(&node_id.to_string()), None);
        // A mangled address.
        assert_eq!(decode(&format!("{code},not-an-addr")), None);
        // A flipped secret character fails the check digit.
        let addrless = encode(&node_id, &secret, &[]);
        let mut chars: Vec<char> = addrless.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '2' { '3' } else { '2' };
        let flipped: String = chars.into_iter().collect();
        assert_eq!(decode(&flipped), None);
        assert_eq!(decode(""), None);
    }
}
