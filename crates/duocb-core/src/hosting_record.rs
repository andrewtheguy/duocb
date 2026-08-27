//! The encrypted pairwise hosting record, shared by both carriers that move
//! it: the local network (`crate::lan`, DNS-SD) and nostr relays
//! (`crate::nostr`). It is the clipboard-session sibling of `crate::pin_record`
//! and holds the same kind of thing — the host's **current transport address**,
//! never a token — but it is addressed to a standing application identity
//! instead of a PIN.
//!
//! The address is a [`TransportAddr`]: the name of the transport that minted it
//! plus that transport's own address text. This module never parses the
//! address, which is what keeps rendezvous transport-agnostic — iroh puts a
//! node id in it (`crate::transport::iroh_quic::rendezvous_addr`), the TCP demo
//! transport puts a socket address in it
//! (`crate::transport::dummy::rendezvous_addr`), and a looking device that does
//! not speak the named transport treats the record as a miss.
//!
//! One record exists per *ordered pair* of application keys. Its lookup label is
//! a domain-separated hash of `(host, peer)`. The label is deterministic, not
//! secret: anyone who knows both public keys can derive it, and a Nostr relay
//! sees those keys as the event author and public `p` tag. The content remains
//! NIP-44 encrypted from the host's application key to that one peer's. A
//! session publishes only the record for the device the user selected; another
//! trusted peer derives a different label and cannot decrypt this record.
//!
//! Encrypting the address is defense in depth, not the security boundary: a
//! transport address is not a credential. Dialing it still has to pass the
//! mutual application-key handshake (`crate::key_auth`), which is what actually
//! decides who may connect.

use anyhow::{Context, Result};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::Identity;
use crate::transport::TransportAddr;

/// Payload version. A record from another version is treated as a miss, not an
/// error: the peer is simply not hosting anything this build can dial. The
/// transport name inside the payload is versioned separately by being data —
/// a new transport does not need a new version here.
const HOSTING_VERSION: u32 = 2;

/// Domain separator for the nostr `d` tag.
const NOSTR_TAG_DOMAIN: &[u8] = b"duocb:pairwise-hosting:v1";
/// Domain separator for the DNS-SD instance label. Distinct from the nostr one
/// so the same pairing does not expose the same label string on both transports.
/// This prevents direct string matching, not linkage by an observer that knows
/// both application public keys and can derive both labels.
const LAN_LABEL_DOMAIN: &[u8] = b"duocb:pairwise-hosting-lan:v1";

/// The record: the host's current transport address under a version stamp.
///
/// The JSON keys are single letters because the payload has a hard budget. A
/// LAN advertisement carries the ciphertext in one DNS-SD TXT attribute, capped
/// at 255 bytes including the key, and NIP-44 pads plaintext to 32-byte chunks
/// — so a few bytes of field name are what decides whether a record fits at
/// all. `lan::tests::a_hosting_record_fits_one_txt_attribute` holds the line.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostingRecord {
    #[serde(rename = "v")]
    version: u32,
    /// The transport that minted `address` — `SessionTransport::KIND`.
    #[serde(rename = "t")]
    transport: String,
    #[serde(rename = "a")]
    address: String,
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

/// Encrypt this host's transport address for exactly one trusted peer.
pub fn encrypt(identity: &Identity, peer: PublicKey, addr: &TransportAddr) -> Result<String> {
    let payload = serde_json::to_string(&HostingRecord {
        version: HOSTING_VERSION,
        transport: addr.kind().to_string(),
        address: addr.address().to_string(),
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
/// content encrypted to someone else, a malformed or unknown-version payload —
/// because a lookup treats an unreadable record exactly like an absent one:
/// whatever it is, this device cannot dial it, and a relay or a LAN neighbour
/// must not be able to turn a lookup into a hard error.
///
/// A readable record whose transport this build does not speak still comes back
/// here: it decrypted, so it is a real record from the peer, and telling "not
/// hosting" apart from "hosting somewhere I cannot follow" is the dialer's call
/// (`crate::net::runtime` logs the second and keeps looking).
pub fn decrypt(identity: &Identity, host: PublicKey, content: &str) -> Option<TransportAddr> {
    let plaintext = nip44::decrypt(identity.keys().secret_key(), &host, content).ok()?;
    let record: HostingRecord = serde_json::from_str(&plaintext).ok()?;
    if record.version != HOSTING_VERSION {
        return None;
    }
    Some(TransportAddr::new(record.transport, record.address))
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
        let addr = crate::transport::iroh_quic::rendezvous_addr(&node_id);

        let content = encrypt(&host, peer.public_key(), &addr).unwrap();
        // The ciphertext must not leak the node id.
        assert!(!content.contains(&node_id.to_string()));

        assert_eq!(decrypt(&peer, host.public_key(), &content), Some(addr));
        // A third party holding the record cannot read it, and neither can the
        // addressed peer if it attributes the record to the wrong author.
        assert_eq!(decrypt(&stranger, host.public_key(), &content), None);
        assert_eq!(decrypt(&peer, stranger.public_key(), &content), None);
    }

    /// The payload is a transport name plus that transport's own address text,
    /// and this module never looks inside the second half: an address no
    /// transport in this build could parse still round-trips, and reading it
    /// back as another transport's address is refused by the name, not by a
    /// parse attempt.
    #[test]
    fn the_record_carries_any_transport_address() {
        let host = Identity::generate();
        let peer = Identity::generate();
        let addr = crate::transport::dummy::rendezvous_addr("192.168.1.9:7801".parse().unwrap());

        let content = encrypt(&host, peer.public_key(), &addr).unwrap();
        let read = decrypt(&peer, host.public_key(), &content).unwrap();
        assert_eq!(read, addr);
        assert_eq!(
            crate::transport::dummy::socket_addr(&read),
            Some("192.168.1.9:7801".parse().unwrap())
        );
        assert_eq!(crate::transport::iroh_quic::endpoint_id(&read), None);

        // Unknown to every transport this build speaks, and still a record.
        let exotic = TransportAddr::new("bluetooth", "AA:BB:CC:DD:EE:FF");
        let content = encrypt(&host, peer.public_key(), &exotic).unwrap();
        assert_eq!(decrypt(&peer, host.public_key(), &content), Some(exotic));
    }
}
