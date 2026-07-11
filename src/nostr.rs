//! Nostr side channel for discovering a peer's current ephemeral iroh node id.
//!
//! duocb keeps the iroh identity ephemeral (a fresh node id every run) and uses
//! nostr to publish & look it up. Both peers derive the *same* nostr keypair from
//! the shared `auth_token`, so the server publishes a replaceable event carrying
//! its current node id and the client derives the same key to look it up. The node
//! id is encrypted in the event content (NIP-44; see below), and the `auth_token`
//! still gates the actual connection.
//!
//! Each device has its own short **identifier** (name), while all devices in the
//! pairing share one `auth_token` and therefore one nostr author key. A device
//! publishes under a kind-30078 `d` tag of
//! `duocb:nodeid:<sha256(auth||its-own-name)>`. A joining device queries by the
//! shared author key alone, excludes the record for its own name, and dials the
//! newest other-device record. The user never has to know or enter the other
//! device's name. The hash is salted with the token so names cannot be enumerated
//! without it, and a restart replaces that device's own stable record.
//!
//! The node id in the event content is **encrypted** (NIP-44) under the shared
//! auth-token-derived keypair — the server encrypts to its own derived public key
//! and any peer with the same `auth_token` derives the same key to decrypt. This
//! keeps the node id off the relays in the clear (the `auth_token` still gates the
//! actual connection).

use std::time::Duration;

use anyhow::{Context, Result};
use iroh::EndpointId;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::pin;

/// Default public relays used when none are configured.
pub const DEFAULT_NOSTR_RELAYS: &[&str] = &[
    "wss://nos.lol",
    "wss://relay.nostr.net",
    "wss://relay.primal.net",
    "wss://relay.snort.social",
];

/// Parameterized-replaceable event kind (NIP-78 application-specific data) used to
/// carry the node id. Replaceable, so the latest publish supersedes the previous.
const NODEID_KIND_U16: u16 = 30078;
/// Base of the `d` tag identifying duocb node-id records; the per-peer identifier
/// hash is appended (see [`identifier_dtag`]).
const NODEID_DTAG_BASE: &str = "duocb:nodeid";
/// Domain separation for deriving the nostr key from the auth token.
const KEY_DERIVATION_DOMAIN: &[u8] = b"duocb:nostr-rendezvous:v1";
/// Domain separation for hashing a peer identifier into its `d` tag.
const IDENTIFIER_DOMAIN: &[u8] = b"duocb:peer-id:v1";

/// Timeout for establishing relay connections.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for a node-id lookup query.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);

fn nodeid_kind() -> Kind {
    Kind::from_u16(NODEID_KIND_U16)
}

/// Build the `d` tag for a peer's node-id record: the base tag plus a hex
/// SHA-256 of the (trimmed) identifier, salted with the shared `auth_token`. The
/// salt means a short identifier cannot be guessed or enumerated on relays without
/// the token; both parties share the token, so both derive the same tag.
fn identifier_dtag(auth_token: &str, identifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(IDENTIFIER_DOMAIN);
    hasher.update(auth_token.as_bytes());
    hasher.update(identifier.trim().as_bytes());
    let digest = hasher.finalize();
    let mut tag = String::with_capacity(NODEID_DTAG_BASE.len() + 1 + digest.len() * 2);
    tag.push_str(NODEID_DTAG_BASE);
    tag.push(':');
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(tag, "{b:02x}");
    }
    tag
}

/// Derive the shared nostr identity from the `auth_token`. Both peers run this on
/// the same token and get the same keypair, so the server publishes and the
/// client looks up under one author key with no extra identifier exchanged.
pub fn derive_keys(auth_token: &str) -> Result<Keys> {
    let mut hasher = Sha256::new();
    hasher.update(KEY_DERIVATION_DOMAIN);
    hasher.update(auth_token.as_bytes());
    let digest = hasher.finalize();
    let secret =
        SecretKey::from_slice(&digest).context("deriving nostr secret key from auth token")?;
    Ok(Keys::new(secret))
}

/// Connect a no-signer nostr client to the given relays. Events are signed by the
/// caller before sending, so no signer is configured here. Bails if none connect.
async fn connect_client(relays: &[String]) -> Result<Client> {
    let client = Client::default();
    let mut added = 0;
    for relay in relays {
        if client.add_relay(relay.clone()).await.is_ok() {
            added += 1;
        }
    }
    if added == 0 {
        anyhow::bail!(
            "no usable nostr relays among {} configured",
            relays.len().max(1)
        );
    }
    client.connect().await;
    client.wait_for_connection(CONNECT_TIMEOUT).await;
    Ok(client)
}

/// Publish this peer's current ephemeral node id under the auth-token-derived key,
/// tagged with this peer's `identifier` so peers sharing the token stay distinct.
pub async fn publish_node_id(
    auth_token: &str,
    identifier: &str,
    node_id: &EndpointId,
    relays: &[String],
) -> Result<()> {
    let keys = derive_keys(auth_token)?;
    // Encrypt the node id under the shared (auth-token-derived) keypair so it does
    // not appear on relays in the clear. Self-encryption: encrypt to our own derived
    // public key — any peer with the same auth token derives the same key to decrypt.
    let content = nip44::encrypt(
        keys.secret_key(),
        &keys.public_key(),
        node_id.to_string(),
        nip44::Version::V2,
    )
    .context("encrypting node id for nostr")?;
    let client = connect_client(relays).await?;
    let event = EventBuilder::new(nodeid_kind(), content)
        .tags([Tag::identifier(identifier_dtag(auth_token, identifier))])
        .sign_with_keys(&keys)
        .context("signing node-id event")?;
    let res = client.send_event(&event).await;
    client.disconnect().await;
    res.context("publishing node-id event to relays")?;
    Ok(())
}

/// Look up the node id published under `identifier` by a peer sharing the auth token.
/// Returns the most recently published node id for that identifier, or `Ok(None)` when
/// no record exists. A query/decrypt failure is an `Err` — callers that need to tell
/// "no record yet" (fine) from "the relays errored" (skip the check) rely on this
/// distinction.
pub async fn lookup_node_id_opt(
    auth_token: &str,
    identifier: &str,
    relays: &[String],
) -> Result<Option<EndpointId>> {
    let keys = derive_keys(auth_token)?;
    let client = connect_client(relays).await?;
    let filter = Filter::new()
        .kind(nodeid_kind())
        .author(keys.public_key())
        .identifier(identifier_dtag(auth_token, identifier))
        .limit(1);
    let events = client.fetch_events(filter, LOOKUP_TIMEOUT).await;
    client.disconnect().await;
    let events = events.context("querying nostr relays for the peer's node id")?;
    let Some(latest) = events.iter().max_by_key(|e| e.created_at) else {
        return Ok(None);
    };
    let node_id = nip44::decrypt(keys.secret_key(), &keys.public_key(), &latest.content)
        .context("decrypting nostr node-id record (wrong auth token?)")?;
    let node_id = node_id
        .trim()
        .parse::<EndpointId>()
        .context("nostr node-id record is not a valid node id")?;
    Ok(Some(node_id))
}

fn peer_node_id_from_events<'a>(
    keys: &Keys,
    own_dtag: &str,
    events: impl IntoIterator<Item = &'a Event>,
) -> Option<EndpointId> {
    let dtag_prefix = format!("{NODEID_DTAG_BASE}:");
    let mut candidates: Vec<_> = events
        .into_iter()
        .filter(|event| {
            event.tags.identifier().is_some_and(|dtag| {
                dtag.starts_with(&dtag_prefix) && dtag != own_dtag
            })
        })
        .collect();
    candidates.sort_by_key(|event| std::cmp::Reverse(event.created_at));
    for event in candidates {
        let Ok(plaintext) =
            nip44::decrypt(keys.secret_key(), &keys.public_key(), &event.content)
        else {
            continue;
        };
        if let Ok(node_id) = plaintext.trim().parse::<EndpointId>() {
            return Some(node_id);
        }
    }
    None
}

/// Look up the other device under the shared auth-derived author key. `own_identifier`
/// is this joining device's name; its record is excluded so the field never means
/// "the name to look up." The newest valid other-device record wins, which also
/// leaves stale records from older device runs behind the active publisher.
pub async fn lookup_peer_node_id(
    auth_token: &str,
    own_identifier: &str,
    relays: &[String],
) -> Result<EndpointId> {
    let keys = derive_keys(auth_token)?;
    let own_dtag = identifier_dtag(auth_token, own_identifier);
    let client = connect_client(relays).await?;
    let filter = Filter::new()
        .kind(nodeid_kind())
        .author(keys.public_key());
    let events = client.fetch_events(filter, LOOKUP_TIMEOUT).await;
    client.disconnect().await;
    let events = events.context("querying nostr relays for the other device's node id")?;
    peer_node_id_from_events(&keys, &own_dtag, events.iter()).with_context(|| {
        "no other-device record found on nostr (is the other device running with the same auth token and a different name?)"
    })
}

// ============================================================================
// Quick-mode PIN rendezvous
// ============================================================================
//
// Quick mode shares only the server's **ephemeral node id** through nostr — never a token. The
// server shows a short PIN (see `crate::pin`) that rotates every 60s. Unlike the node-id
// discovery above (keyed off the shared auth token), here the client starts with nothing but
// the PIN. Both sides derive the same nostr keypair from `(pin, bucket)` via Argon2id, so the
// server publishes a record under that key and a client holding the PIN derives the same key to
// find and decrypt it. The lookup is by **author key** (only someone with the PIN can derive
// it); no extra tag is needed.
//
// The record is a regular (stored, non-replaceable) event carrying the NIP-44 encrypted
// `{node_id}` payload, with a NIP-40 expiration so per-bucket records coexist briefly (for
// boundary look-back) then self-clean.
//
// Encrypting the node id is **defense in depth, not the security boundary**: the node id is not
// a credential (dialing it still requires passing the in-band PIN auth), and the intended client
// needs the PIN to derive the author key and find the record anyway.

/// Regular (stored, non-replaceable) event kind for PIN rendezvous records. Deliberately
/// *not* the replaceable 30078 used above, so each 60s bucket's record coexists long
/// enough for the client's adjacent-bucket look-back.
const PIN_KIND_U16: u16 = 9421;
/// How long a published PIN record stays on relays (NIP-40). A few rotation periods so a
/// client that reads the PIN late still finds the prior bucket's record, but stale records
/// self-clean soon after.
const PIN_EVENT_TTL_SECS: u64 = 3 * pin::BUCKET_SECS;
/// Lookup timeout for a PIN record fetch. Shorter than the node-id lookup: the client
/// queries all adjacent buckets in one round-trip, and a wrong/expired PIN should fail
/// fast so the user can re-read the current code.
const PIN_LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);

fn pin_kind() -> Kind {
    Kind::from_u16(PIN_KIND_U16)
}

/// The payload carried (NIP-44 encrypted) in a PIN rendezvous record: the server's ephemeral
/// node id. No token is here — the PIN authenticates the connection in-band (see
/// `crate::pin_auth`).
#[derive(Serialize, Deserialize)]
struct PinPayload {
    node_id: String,
}

/// Derive the nostr keypair for a `(pin, bucket)` pair. Both peers run this on the same
/// canonical PIN and bucket and get the same keypair, whose public key is the relay lookup
/// key and whose secret key (self-)encrypts the payload.
fn pin_keys(canonical_pin: &str, bucket: u64) -> Result<Keys> {
    let material = pin::derive_key_material(canonical_pin, bucket)?;
    let secret = SecretKey::from_slice(&material).context("deriving nostr key from PIN")?;
    Ok(Keys::new(secret))
}

/// Publish a PIN rendezvous record for the current bucket: the server's ephemeral node id,
/// NIP-44 self-encrypted under the PIN-derived key, as a stored event that expires after a few
/// rotation periods.
pub async fn publish_pin_record(
    canonical_pin: &str,
    bucket: u64,
    node_id: &EndpointId,
    relays: &[String],
) -> Result<()> {
    let keys = pin_keys(canonical_pin, bucket)?;
    let payload = serde_json::to_string(&PinPayload {
        node_id: node_id.to_string(),
    })
    .context("serializing PIN payload")?;
    let content = nip44::encrypt(
        keys.secret_key(),
        &keys.public_key(),
        payload,
        nip44::Version::V2,
    )
    .context("encrypting PIN payload")?;

    let expiration = Timestamp::now() + PIN_EVENT_TTL_SECS;
    let client = connect_client(relays).await?;
    let event = EventBuilder::new(pin_kind(), content)
        .tag(Tag::expiration(expiration))
        .sign_with_keys(&keys)
        .context("signing PIN record")?;
    let res = client.send_event(&event).await;
    client.disconnect().await;
    res.context("publishing PIN record to relays")?;
    Ok(())
}

/// Look up the PIN rendezvous record for `canonical_pin`, searching the current bucket and
/// its immediate neighbors (covers the rotation boundary and small clock skew). Returns the
/// decrypted node id, or `Ok(None)` when no matching record is found (wrong or expired PIN).
/// All adjacent buckets are queried in a single relay round-trip. The connection is then
/// authenticated in-band with the same PIN (see `crate::pin_auth`).
pub async fn lookup_pin_record(
    canonical_pin: &str,
    relays: &[String],
) -> Result<Option<EndpointId>> {
    let current = pin::current_bucket();
    // Search order favors the current bucket, then the previous (the common late-read case),
    // then the next (clock skew where our clock trails the publisher's).
    let buckets = [current, current.wrapping_sub(1), current + 1];

    // Derive each bucket's keypair once; map public key -> keys so we can decrypt a returned
    // event with the right bucket's secret.
    let mut by_pubkey: std::collections::HashMap<PublicKey, Keys> =
        std::collections::HashMap::new();
    for b in buckets {
        let keys = pin_keys(canonical_pin, b)?;
        by_pubkey.insert(keys.public_key(), keys);
    }

    let client = connect_client(relays).await?;
    let filter = Filter::new()
        .kind(pin_kind())
        .authors(by_pubkey.keys().copied());
    let events = client.fetch_events(filter, PIN_LOOKUP_TIMEOUT).await;
    client.disconnect().await;
    let events = events.context("querying nostr relays for the PIN record")?;

    // Prefer the most recent record across all matching buckets.
    let mut candidates: Vec<_> = events.iter().collect();
    candidates.sort_by_key(|e| std::cmp::Reverse(e.created_at));
    for event in candidates {
        let Some(keys) = by_pubkey.get(&event.pubkey) else {
            continue;
        };
        let Ok(plaintext) = nip44::decrypt(keys.secret_key(), &keys.public_key(), &event.content)
        else {
            continue;
        };
        let Ok(payload) = serde_json::from_str::<PinPayload>(&plaintext) else {
            continue;
        };
        let Ok(node_id) = payload.node_id.trim().parse::<EndpointId>() else {
            continue;
        };
        return Ok(Some(node_id));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_keys_is_deterministic_and_token_specific() {
        let a = derive_keys("token-one").unwrap();
        let a_again = derive_keys("token-one").unwrap();
        let b = derive_keys("token-two").unwrap();
        assert_eq!(
            a.public_key(),
            a_again.public_key(),
            "same token must derive the same key"
        );
        assert_ne!(
            a.public_key(),
            b.public_key(),
            "different tokens must derive different keys"
        );
    }

    #[test]
    fn identifier_dtag_is_deterministic_identifier_and_token_specific() {
        let token = "the-auth-token";
        let a = identifier_dtag(token, "web1");
        let a_again = identifier_dtag(token, "web1");
        let b = identifier_dtag(token, "web2");
        assert_eq!(
            a, a_again,
            "same token + identifier must derive the same d tag"
        );
        assert_ne!(a, b, "different identifiers must derive different d tags");
        // The d tag carries the base prefix.
        assert!(a.starts_with(NODEID_DTAG_BASE), "d tag was: {a}");

        // Trimming: surrounding whitespace must not change the tag.
        assert_eq!(a, identifier_dtag(token, "  web1  "));

        // Salt: the same identifier under a different token derives a different tag.
        let other_token = identifier_dtag("other-token", "web1");
        assert_ne!(a, other_token, "the auth token salts the identifier hash");
    }

    #[test]
    fn node_id_round_trips_through_encrypted_event_content() {
        let token = "round-trip-token";
        let keys = derive_keys(token).unwrap();
        let node_id = iroh::SecretKey::generate().public();
        // Mirror publish: encrypt the node id to our own derived key.
        let content = nip44::encrypt(
            keys.secret_key(),
            &keys.public_key(),
            node_id.to_string(),
            nip44::Version::V2,
        )
        .expect("encrypt node id");
        let event = EventBuilder::new(nodeid_kind(), content)
            .tags([Tag::identifier(identifier_dtag(token, "web1"))])
            .sign_with_keys(&keys)
            .expect("sign node-id event");
        // The ciphertext must not contain the cleartext node id.
        assert!(
            !event.content.contains(&node_id.to_string()),
            "node id leaked in cleartext"
        );
        // Mirror lookup: decrypt with the same shared key.
        let decrypted = nip44::decrypt(keys.secret_key(), &keys.public_key(), &event.content)
            .expect("decrypt node id");
        let parsed: EndpointId = decrypted.trim().parse().expect("decrypts to a node id");
        assert_eq!(parsed.to_string(), node_id.to_string());
    }

    #[test]
    fn peer_lookup_excludes_own_name_and_selects_other_device() {
        let token = "shared-token";
        let keys = derive_keys(token).unwrap();
        let own_node_id = iroh::SecretKey::generate().public();
        let peer_node_id = iroh::SecretKey::generate().public();

        let event_for = |name: &str, node_id: EndpointId| {
            let content = nip44::encrypt(
                keys.secret_key(),
                &keys.public_key(),
                node_id.to_string(),
                nip44::Version::V2,
            )
            .unwrap();
            EventBuilder::new(nodeid_kind(), content)
                .tags([Tag::identifier(identifier_dtag(token, name))])
                .sign_with_keys(&keys)
                .unwrap()
        };
        let own_event = event_for("mac2", own_node_id);
        let peer_event = event_for("mac1", peer_node_id);
        let events = [&own_event, &peer_event];

        let found = peer_node_id_from_events(
            &keys,
            &identifier_dtag(token, "mac2"),
            events,
        );
        assert_eq!(found, Some(peer_node_id));
        assert_eq!(
            peer_node_id_from_events(
                &keys,
                &identifier_dtag(token, "mac2"),
                [&own_event],
            ),
            None
        );
    }

    #[test]
    fn wrong_auth_token_cannot_decrypt_node_id() {
        let node_id = iroh::SecretKey::generate().public();
        let publisher = derive_keys("the-real-token").unwrap();
        let content = nip44::encrypt(
            publisher.secret_key(),
            &publisher.public_key(),
            node_id.to_string(),
            nip44::Version::V2,
        )
        .expect("encrypt node id");
        // A peer with a different auth token derives a different key and cannot read it.
        let attacker = derive_keys("a-different-token").unwrap();
        assert!(
            nip44::decrypt(attacker.secret_key(), &attacker.public_key(), &content).is_err(),
            "decryption must fail under a different auth token"
        );
    }

    #[test]
    fn pin_payload_round_trips_and_wrong_pin_fails() {
        // Mirror publish/lookup without touching relays: encrypt under one (pin, bucket)
        // key and confirm the same pin+bucket decrypts while a different pin does not.
        let pin = "K7P29QXM";
        let bucket = 12345;
        let node_id = iroh::SecretKey::generate().public();

        let keys = pin_keys(pin, bucket).unwrap();
        let payload = serde_json::to_string(&PinPayload {
            node_id: node_id.to_string(),
        })
        .unwrap();
        let content = nip44::encrypt(
            keys.secret_key(),
            &keys.public_key(),
            payload,
            nip44::Version::V2,
        )
        .unwrap();
        // The ciphertext must not leak the node id.
        assert!(!content.contains(&node_id.to_string()));

        // Same pin + bucket recovers the payload.
        let plaintext = nip44::decrypt(keys.secret_key(), &keys.public_key(), &content).unwrap();
        let got: PinPayload = serde_json::from_str(&plaintext).unwrap();
        assert_eq!(got.node_id, node_id.to_string());

        // A different pin derives a different key and cannot decrypt.
        let wrong = pin_keys("9QXMK7P2", bucket).unwrap();
        assert!(nip44::decrypt(wrong.secret_key(), &wrong.public_key(), &content).is_err());
        // The right pin at the wrong bucket also fails.
        let wrong_bucket = pin_keys(pin, bucket + 1).unwrap();
        assert!(
            nip44::decrypt(
                wrong_bucket.secret_key(),
                &wrong_bucket.public_key(),
                &content
            )
            .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "uses public nostr relays"]
    async fn public_relay_token_record_round_trip() {
        let relays: Vec<String> = DEFAULT_NOSTR_RELAYS
            .iter()
            .map(|relay| relay.to_string())
            .collect();
        let token = crate::auth::generate_token();
        let peer_name = "relay-round-trip-peer";
        let own_name = "relay-round-trip-self";
        let node_id = iroh::SecretKey::generate().public();

        publish_node_id(&token, peer_name, &node_id, &relays)
            .await
            .expect("publish token record");
        let found = lookup_peer_node_id(&token, own_name, &relays)
            .await
            .expect("look up the other device without its name");
        assert_eq!(found, node_id);
    }
}
