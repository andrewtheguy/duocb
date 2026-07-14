//! The manual mode pairing code: the out-of-band sibling of the PIN
//! rendezvous. Manual mode has no signaling channel at all — the user carries
//! the session-establishment data between devices themselves (copy/paste over
//! any private channel). One code bundles everything the joiner needs: the
//! server's ephemeral node id (where to dial), a fresh session secret (what to
//! prove in-band — the same Argon2id challenge-response the PIN quick mode
//! runs, see `crate::pin_auth`), and the server's direct socket addresses. The
//! addresses are dialed as-is, needing no discovery of any kind — the fallback
//! that still pairs on networks where mDNS/multicast is blocked, with no
//! internet. No token, no record, nothing published anywhere.
//!
//! The code is a small **JSON** document. Unlike the PIN, the manual secret is
//! never typed by hand — it rides inside the copied code — so it is a
//! full-strength [`crate::auth`] token rather than a short, human-typable PIN
//! (the PIN's Crockford shape and check digit would only weaken it here, and it
//! is interoperable with nothing else anyway). The token's own CRC16 guards
//! against a corrupted paste the way the node-id and address parses guard the
//! rest: a clipped or mangled code fails to decode rather than dialing wrong.

use std::net::SocketAddr;

use iroh::EndpointId;
use serde::{Deserialize, Serialize};

/// Current manual-code format version. Bumped if the shape ever changes;
/// [`decode`] rejects anything else (strict no backward compatibility).
const MANUAL_CODE_VERSION: u8 = 1;

/// Wire shape of a manual pairing code. `node` is the 64-hex ephemeral node id,
/// `secret` a full-strength [`crate::auth`] token, `addrs` the server's direct
/// socket addresses rendered as strings (empty when none are known).
#[derive(Serialize, Deserialize)]
struct ManualCode {
    v: u8,
    node: String,
    secret: String,
    addrs: Vec<String>,
}

/// Generate a fresh manual-mode session secret: a full-strength auth token
/// (not a PIN). Fed to `crate::pin_auth` for the in-band challenge-response.
pub fn generate_secret() -> String {
    crate::auth::generate_token()
}

/// Build the display/copy form of a pairing code: a pretty-printed JSON
/// document carrying the node id, the session secret, and the direct addresses.
pub fn encode(node_id: &EndpointId, secret: &str, addrs: &[SocketAddr]) -> String {
    let code = ManualCode {
        v: MANUAL_CODE_VERSION,
        node: node_id.to_string(),
        secret: secret.to_string(),
        addrs: addrs.iter().map(SocketAddr::to_string).collect(),
    };
    // Serializing our own owned struct never fails.
    serde_json::to_string_pretty(&code).expect("manual code serializes")
}

/// Parse user input back into `(node id, secret, direct addrs)`. Tolerant of
/// surrounding whitespace (a line-wrapped paste is forgiven). The version must
/// match, the node id must parse (64 hex chars), the secret must pass the auth
/// token check (its CRC16 catches a corrupted paste), and every embedded
/// address must parse — so a truncated or mistyped paste is rejected here
/// rather than later as a failed dial or auth. `None` when anything is off.
pub fn decode(input: &str) -> Option<(String, String, Vec<SocketAddr>)> {
    let code: ManualCode = serde_json::from_str(input.trim()).ok()?;
    if code.v != MANUAL_CODE_VERSION {
        return None;
    }
    let node_id: EndpointId = code.node.to_ascii_lowercase().parse().ok()?;
    crate::auth::validate_token(&code.secret).ok()?;
    let addrs: Vec<SocketAddr> = code
        .addrs
        .iter()
        .map(|a| a.parse())
        .collect::<Result<_, _>>()
        .ok()?;
    Some((node_id.to_string(), code.secret, addrs))
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
    fn code_round_trips_and_tolerates_whitespace() {
        let node_id = iroh::SecretKey::generate().public();
        let secret = generate_secret();
        let addrs = test_addrs();
        let code = encode(&node_id, &secret, &addrs);

        let (got_id, got_secret, got_addrs) = decode(&code).expect("own code must decode");
        assert_eq!(got_id, node_id.to_string());
        assert_eq!(got_secret, secret);
        assert_eq!(got_addrs, addrs);

        // A line-wrapped/padded paste still decodes.
        let mangled = format!("\n  {code}  \n");
        assert_eq!(decode(&mangled), Some((got_id, got_secret, got_addrs)));
    }

    #[test]
    fn addressless_code_round_trips() {
        let node_id = iroh::SecretKey::generate().public();
        let secret = generate_secret();
        let code = encode(&node_id, &secret, &[]);
        let (got_id, got_secret, got_addrs) = decode(&code).expect("own code must decode");
        assert_eq!(got_id, node_id.to_string());
        assert_eq!(got_secret, secret);
        assert!(got_addrs.is_empty());
    }

    #[test]
    fn manual_secret_is_a_token_not_a_pin() {
        // A manual secret is a full-strength auth token, and the code embeds it
        // verbatim (no PIN normalization anywhere).
        let secret = generate_secret();
        assert!(crate::auth::validate_token(&secret).is_ok());
        let code = encode(&iroh::SecretKey::generate().public(), &secret, &[]);
        let (_, got_secret, _) = decode(&code).unwrap();
        assert_eq!(got_secret, secret);
    }

    #[test]
    fn truncated_or_mistyped_codes_are_rejected() {
        let node_id = iroh::SecretKey::generate().public();
        let secret = generate_secret();
        let code = encode(&node_id, &secret, &test_addrs());

        // Missing tail characters (a partial copy — clips the closing brace).
        assert_eq!(decode(&code[..code.len() - 2]), None);
        // Not JSON at all (the old node-id-only habit).
        assert_eq!(decode(&node_id.to_string()), None);
        // A mangled address fails to parse.
        let bad_addr = encode(&node_id, &secret, &[]).replace(
            "\"addrs\": []",
            "\"addrs\": [\"not-an-addr\"]",
        );
        assert_eq!(decode(&bad_addr), None);
        // A corrupted secret fails the token check (here the required prefix).
        let mut corrupt: ManualCode = serde_json::from_str(&code).unwrap();
        let b = corrupt.secret.as_bytes()[0];
        let repl = if b == b'z' { 'y' } else { 'z' };
        corrupt.secret.replace_range(..1, &repl.to_string());
        assert!(crate::auth::validate_token(&corrupt.secret).is_err());
        assert_eq!(decode(&serde_json::to_string(&corrupt).unwrap()), None);
        // A wrong version is rejected.
        let wrong_v = code.replacen("\"v\": 1", "\"v\": 2", 1);
        assert_eq!(decode(&wrong_v), None);
        assert_eq!(decode(""), None);
    }
}
