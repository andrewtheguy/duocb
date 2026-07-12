//! The encrypted PIN rendezvous record, shared by both transports that carry
//! it: nostr relays (`crate::nostr`, internet) and mDNS (`crate::lan`, local
//! network). The record holds only the server's **ephemeral node id** — never a
//! token — NIP-44 self-encrypted under a keypair both peers derive from the
//! `(pin, bucket)` pair via Argon2id (see `crate::pin`). The derived public key
//! doubles as the lookup key on either transport: only someone holding the PIN
//! can derive it and find (let alone decrypt) the record.
//!
//! Encrypting the node id is **defense in depth, not the security boundary**:
//! the node id is not a credential (dialing it still requires passing the
//! in-band PIN auth, `crate::pin_auth`), and the intended client needs the PIN
//! to derive the lookup key anyway.

use anyhow::{Context, Result};
use iroh::EndpointId;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};

use crate::pin;

/// The payload carried (NIP-44 encrypted) in a PIN rendezvous record: the
/// server's ephemeral node id.
#[derive(Serialize, Deserialize)]
struct PinPayload {
    node_id: String,
}

/// Derive the record keypair for a `(pin, bucket)` pair. Both peers run this on
/// the same canonical PIN and bucket and get the same keypair, whose public key
/// is the lookup key and whose secret key (self-)encrypts the payload.
pub(crate) fn pin_keys(canonical_pin: &str, bucket: u64) -> Result<Keys> {
    let material = pin::derive_key_material(canonical_pin, bucket)?;
    let secret = SecretKey::from_slice(&material).context("deriving record key from PIN")?;
    Ok(Keys::new(secret))
}

/// Derive the candidate keypairs a lookup should try, in search-preference
/// order: the current bucket, then the previous (the common late-read case),
/// then the next (clock skew where our clock trails the publisher's). Derived
/// once per resolve and handed to every enabled transport, so racing channels
/// never repeats the Argon2id work. Three runs — off the async executor.
pub(crate) async fn candidate_keys(canonical_pin: &str) -> Result<Vec<Keys>> {
    let current = pin::current_bucket();
    let buckets = [current, current.wrapping_sub(1), current + 1];
    tokio::task::spawn_blocking({
        let pin = canonical_pin.to_string();
        move || buckets.iter().map(|&b| pin_keys(&pin, b)).collect()
    })
    .await
    .context("PIN key-derivation task failed")?
}

/// Encrypt a node id into record content under a `(pin, bucket)`-derived key.
pub(crate) fn encrypt_pin_payload(keys: &Keys, node_id: &EndpointId) -> Result<String> {
    let payload = serde_json::to_string(&PinPayload {
        node_id: node_id.to_string(),
    })
    .context("serializing PIN payload")?;
    nip44::encrypt(
        keys.secret_key(),
        &keys.public_key(),
        payload,
        nip44::Version::V2,
    )
    .context("encrypting PIN payload")
}

/// Decrypt record content with a candidate `(pin, bucket)`-derived key. `None`
/// on any failure — a record encrypted under a different pin/bucket, malformed
/// payload, or unparsable node id — since candidates are tried in turn.
pub(crate) fn decrypt_pin_payload(keys: &Keys, content: &str) -> Option<EndpointId> {
    let plaintext = nip44::decrypt(keys.secret_key(), &keys.public_key(), content).ok()?;
    let payload: PinPayload = serde_json::from_str(&plaintext).ok()?;
    payload.node_id.trim().parse::<EndpointId>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_payload_round_trips_and_wrong_pin_fails() {
        // Mirror publish/lookup without touching a transport: encrypt under one
        // (pin, bucket) key and confirm the same pin+bucket decrypts while a
        // different pin does not.
        let pin = "K7P29QXM";
        let bucket = 12345;
        let node_id = iroh::SecretKey::generate().public();

        let keys = pin_keys(pin, bucket).unwrap();
        let content = encrypt_pin_payload(&keys, &node_id).unwrap();
        // The ciphertext must not leak the node id.
        assert!(!content.contains(&node_id.to_string()));

        // Same pin + bucket recovers the payload.
        assert_eq!(decrypt_pin_payload(&keys, &content), Some(node_id));

        // A different pin derives a different key and cannot decrypt.
        let wrong = pin_keys("9QXMK7P2", bucket).unwrap();
        assert_eq!(decrypt_pin_payload(&wrong, &content), None);
        // The right pin at the wrong bucket also fails.
        let wrong_bucket = pin_keys(pin, bucket + 1).unwrap();
        assert_eq!(decrypt_pin_payload(&wrong_bucket, &content), None);
    }
}
