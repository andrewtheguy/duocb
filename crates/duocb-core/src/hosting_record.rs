//! The encrypted pairwise hosting record, shared by both transports that carry
//! it: the local network (`crate::lan`, DNS-SD) and nostr relays
//! (`crate::nostr`). It is the clipboard-session sibling of `crate::pin_record`
//! and holds the same thing — the host's **ephemeral node id**, never a token —
//! but it is addressed to a standing application identity instead of a PIN.
//!
//! One record exists per *ordered pair* of application keys. Its lookup label is
//! a domain-separated hash of `(host, peer)`, so only a device that already
//! knows both keys can look for it, and its content is NIP-44 encrypted from the
//! host's application key to that one peer's — a host with several trusted peers
//! publishes several records, and no peer can read another's.
//!
//! Encrypting the node id is defense in depth, not the security boundary: the
//! node id is not a credential. Dialing it still has to pass the mutual
//! application-key handshake (`crate::net::runtime`), which is what actually
//! decides who may connect.

use anyhow::{Context, Result};
use iroh::EndpointId;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::Identity;

/// Payload version. A record from a future version is treated as a miss, not an
/// error: the peer is simply not hosting anything this build can dial.
const HOSTING_VERSION: u32 = 1;

/// Domain separator for the nostr `d` tag.
const NOSTR_TAG_DOMAIN: &[u8] = b"duocb:pairwise-hosting:v1";
/// Domain separator for the DNS-SD instance label. Distinct from the nostr one
/// so the same pairing yields unrelated identifiers on the two transports — a
/// LAN observer and a relay operator cannot link a device across them.
const LAN_LABEL_DOMAIN: &[u8] = b"duocb:pairwise-hosting-lan:v1";

/// The record: the host's ephemeral node id under a version stamp.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostingRecord {
    version: u32,
    node_id: String,
}

/// Domain-separated hash over the **ordered** pair of application keys. Ordered
/// so a device's own "I am hosting for you" label differs from the one it looks
/// for, which is what keeps two paired devices from colliding on one identifier.
fn pair_hash(domain: &[u8], host: PublicKey, peer: PublicKey) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(host.as_bytes());
    hasher.update(peer.as_bytes());
    hasher.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The nostr parameterized-replaceable `d` tag for a `(host, peer)` pair.
pub(crate) fn nostr_dtag(host: PublicKey, peer: PublicKey) -> String {
    format!(
        "duocb:hosting:v1:{}",
        hex(&pair_hash(NOSTR_TAG_DOMAIN, host, peer))
    )
}

/// The DNS-SD instance label for a `(host, peer)` pair: the first 32 hex chars
/// of the pair hash. The full 64 would exceed the 63-byte DNS label limit; 128
/// bits keeps accidental collisions negligible, and the payload decrypt is the
/// real verification anyway (exactly as for the PIN rendezvous label).
pub(crate) fn lan_instance(host: PublicKey, peer: PublicKey) -> String {
    hex(&pair_hash(LAN_LABEL_DOMAIN, host, peer))[..32].to_string()
}

/// Encrypt this host's node id for exactly one trusted peer.
pub(crate) fn encrypt(
    identity: &Identity,
    peer: PublicKey,
    node_id: &EndpointId,
) -> Result<String> {
    let payload = serde_json::to_string(&HostingRecord {
        version: HOSTING_VERSION,
        node_id: node_id.to_string(),
    })
    .context("serializing hosting record")?;
    nip44::encrypt(
        identity.keys().secret_key(),
        &peer,
        &payload,
        nip44::Version::V2,
    )
    .context("encrypting pairwise hosting record")
}

/// Decrypt a record `host` published for this identity. `None` on any failure —
/// content encrypted to someone else, a malformed or future-version payload, an
/// unparsable node id — because a lookup treats an unreadable record exactly
/// like an absent one: whatever it is, this device cannot dial it, and a relay
/// or a LAN neighbour must not be able to turn a lookup into a hard error.
pub(crate) fn decrypt(
    identity: &Identity,
    host: PublicKey,
    content: &str,
) -> Option<EndpointId> {
    let plaintext = nip44::decrypt(identity.keys().secret_key(), &host, content).ok()?;
    let record: HostingRecord = serde_json::from_str(&plaintext).ok()?;
    if record.version != HOSTING_VERSION {
        return None;
    }
    record.node_id.trim().parse::<EndpointId>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_ordered_transport_specific_and_stable() {
        let a = Identity::generate();
        let b = Identity::generate();
        let (a, b) = (a.public_key(), b.public_key());

        for label in [nostr_dtag, lan_instance] {
            assert_eq!(label(a, b), label(a, b), "must be deterministic");
            assert_ne!(label(a, b), label(b, a), "the pair is ordered");
        }
        // The two transports must not share an identifier for one pairing.
        assert!(!nostr_dtag(a, b).contains(&lan_instance(a, b)));
        assert_eq!(lan_instance(a, b).len(), 32, "must fit a DNS label");
    }

    #[test]
    fn only_the_addressed_peer_reads_the_record() {
        let host = Identity::generate();
        let peer = Identity::generate();
        let stranger = Identity::generate();
        let node_id = iroh::SecretKey::generate().public();

        let content = encrypt(&host, peer.public_key(), &node_id).unwrap();
        // The ciphertext must not leak the node id.
        assert!(!content.contains(&node_id.to_string()));

        assert_eq!(decrypt(&peer, host.public_key(), &content), Some(node_id));
        // A third party holding the record cannot read it, and neither can the
        // addressed peer if it attributes the record to the wrong author.
        assert_eq!(decrypt(&stranger, host.public_key(), &content), None);
        assert_eq!(decrypt(&peer, stranger.public_key(), &content), None);
    }
}
