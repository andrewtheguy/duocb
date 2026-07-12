//! Nostr side channel for the configure mode's device presence and rendezvous.
//!
//! All devices sharing one `auth_token` (the standing secret) derive the *same*
//! nostr keypair from it, so authorship of an event under that key **is** the
//! proof of secret possession — a presence record is "a message signed by the
//! secret". Each running device publishes one kind-30078 parameterized-
//! replaceable **presence record** under a `d` tag of
//! `duocb:presence:<sha256(auth||identity)>`, where `identity` is the device's
//! unique display identity `<name>_<suffix>` (see `crate::identity`). The hash
//! is salted with the token so identities cannot be enumerated on relays.
//!
//! The record content is NIP-44 **self-encrypted** under the token-derived
//! keypair and carries a JSON [`PresenceRecord`]: the plaintext display name
//! (readable only by token holders), the permanent per-device suffix, a random
//! per-publisher-run id, and — while the device is hosting a connection — its
//! current ephemeral iroh node id. One record therefore serves both presence
//! ("this device exists / was last seen at `created_at`") and rendezvous ("dial
//! this node id"): a peer fetches every record under the shared author key,
//! decrypts them into a device list, and the user picks the specific hosting
//! device to join. The `auth_token` still gates the actual connection in-band.

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
/// carry presence records. Replaceable, so the latest publish supersedes the previous.
const PRESENCE_KIND_U16: u16 = 30078;
/// Base of the `d` tag identifying duocb presence records; the per-device identity
/// hash is appended (see [`presence_dtag`]).
const PRESENCE_DTAG_BASE: &str = "duocb:presence";
/// Domain separation for deriving the nostr key from the auth token.
const KEY_DERIVATION_DOMAIN: &[u8] = b"duocb:nostr-rendezvous:v1";
/// Domain separation for hashing a device's display identity into its `d` tag.
const PRESENCE_DOMAIN: &[u8] = b"duocb:presence-id:v1";

/// Payload schema version; records with any other value are rejected on decode
/// (strict no backward compatibility).
pub const PRESENCE_VERSION: u32 = 1;

/// Steady-state heartbeat between presence republishes.
pub const PRESENCE_REPUBLISH_INTERVAL: Duration = Duration::from_secs(120);
/// Faster republish cadence right after the publisher starts, so a fresh device
/// shows up quickly even if a relay dropped the first publish.
pub const PRESENCE_STARTUP_INTERVAL: Duration = Duration::from_secs(10);
/// Number of startup-cadence cycles before settling on the steady heartbeat.
pub const PRESENCE_STARTUP_CYCLES: u32 = 6;
/// A device whose record is at most this old counts as online (≥ 2 missed
/// heartbeats tolerated).
pub const PRESENCE_ONLINE_WINDOW_SECS: u64 = 300;
/// Records older than this are dropped from the peer list entirely.
pub const PRESENCE_HIDE_AFTER_SECS: u64 = 7 * 24 * 3600;

/// Timeout for establishing relay connections.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for a presence fetch/lookup query.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);

fn presence_kind() -> Kind {
    Kind::from_u16(PRESENCE_KIND_U16)
}

/// Build the `d` tag for a device's presence record: the base tag plus a hex
/// SHA-256 of the (trimmed) display identity, salted with the shared `auth_token`.
/// The salt means an identity cannot be guessed or enumerated on relays without
/// the token; all parties share the token, so all derive the same tag.
fn presence_dtag(auth_token: &str, identity: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PRESENCE_DOMAIN);
    hasher.update(auth_token.as_bytes());
    hasher.update(identity.trim().as_bytes());
    let digest = hasher.finalize();
    let mut tag = String::with_capacity(PRESENCE_DTAG_BASE.len() + 1 + digest.len() * 2);
    tag.push_str(PRESENCE_DTAG_BASE);
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
/// caller before sending, so no signer is configured here. Bails if none can be
/// added, or if none is actually connected once the connect wait elapses.
async fn connect_client(relays: &[String]) -> Result<Client> {
    let client = Client::default();
    let mut added = 0;
    for relay in relays {
        if client.add_relay(relay.clone()).await.is_ok() {
            added += 1;
        }
    }
    if added == 0 {
        anyhow::bail!("no usable nostr relays among {} configured", relays.len());
    }
    client.connect().await;
    client.wait_for_connection(CONNECT_TIMEOUT).await;
    let connected = client
        .relays()
        .await
        .values()
        .filter(|relay| relay.status() == RelayStatus::Connected)
        .count();
    if connected == 0 {
        client.disconnect().await;
        anyhow::bail!(
            "could not connect to any of {added} nostr relays within {}s",
            CONNECT_TIMEOUT.as_secs()
        );
    }
    Ok(client)
}

/// The NIP-44-encrypted content of a presence record. Authorship under the
/// token-derived key proves secret possession; the payload itself carries the
/// plaintext display name (readable only by token holders) plus everything a
/// peer needs to list and dial this device.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PresenceRecord {
    /// Must equal [`PRESENCE_VERSION`]; anything else is rejected on decode.
    pub version: u32,
    /// The user-chosen short name (without the suffix).
    pub name: String,
    /// The permanent per-device suffix — the stable key peers dedupe by.
    pub suffix: String,
    /// Random id minted per publisher start. A record under our own `d` tag
    /// carrying a foreign `run_id` means another live process publishes as us.
    pub run_id: String,
    /// The device's current ephemeral iroh node id while it hosts a connection.
    pub node_id: Option<String>,
}

impl PresenceRecord {
    /// The full display identity `<name>_<suffix>` this record is tagged under.
    pub fn display(&self) -> String {
        crate::identity::display_identity(&self.name, &self.suffix)
    }
}

/// A peer as shown in the device list, decoded from its newest presence record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    /// The peer's short name.
    pub name: String,
    /// The peer's permanent suffix (stable selection key).
    pub suffix: String,
    /// `Some` while the peer hosts a connection — the id a joiner dials.
    pub node_id: Option<String>,
    /// `created_at` of the peer's newest record, unix seconds.
    pub last_seen_unix: u64,
    /// Whether the record is fresher than [`PRESENCE_ONLINE_WINDOW_SECS`].
    pub online: bool,
}

impl PeerInfo {
    /// The peer's full display identity `<name>_<suffix>`.
    pub fn display(&self) -> String {
        crate::identity::display_identity(&self.name, &self.suffix)
    }
}

/// Publish (or replace) this device's presence record under the auth-token-derived
/// key, tagged with its display identity so every device stays distinct.
pub async fn publish_presence(
    auth_token: &str,
    record: &PresenceRecord,
    relays: &[String],
) -> Result<()> {
    let keys = derive_keys(auth_token)?;
    let payload = serde_json::to_string(record).context("serializing presence record")?;
    // Self-encryption under the shared (auth-token-derived) keypair: any peer with
    // the same token derives the same key to decrypt; relays see only ciphertext.
    let content = nip44::encrypt(
        keys.secret_key(),
        &keys.public_key(),
        payload,
        nip44::Version::V2,
    )
    .context("encrypting presence record for nostr")?;
    let client = connect_client(relays).await?;
    let event = EventBuilder::new(presence_kind(), content)
        .tags([Tag::identifier(presence_dtag(auth_token, &record.display()))])
        .sign_with_keys(&keys)
        .context("signing presence event")?;
    let res = client.send_event(&event).await;
    client.disconnect().await;
    res.context("publishing presence event to relays")?;
    Ok(())
}

/// Decode presence records out of fetched events: keep only duocb presence `d`
/// tags, silently skip anything that does not decrypt or parse to a
/// current-version [`PresenceRecord`] (old record formats are rejected, not
/// migrated). Returns each record with its event `created_at` in unix seconds.
fn presence_from_events<'a>(
    keys: &Keys,
    events: impl IntoIterator<Item = &'a Event>,
) -> Vec<(PresenceRecord, u64)> {
    let dtag_prefix = format!("{PRESENCE_DTAG_BASE}:");
    events
        .into_iter()
        .filter(|event| {
            event
                .tags
                .identifier()
                .is_some_and(|dtag| dtag.starts_with(&dtag_prefix))
        })
        .filter_map(|event| {
            let plaintext =
                nip44::decrypt(keys.secret_key(), &keys.public_key(), &event.content).ok()?;
            let record: PresenceRecord = serde_json::from_str(&plaintext).ok()?;
            (record.version == PRESENCE_VERSION).then_some((record, event.created_at.as_secs()))
        })
        .collect()
}

/// Fetch every presence record published under the shared auth-derived author key
/// (including this device's own — see [`build_peer_list`] for self-exclusion).
pub async fn fetch_presence_records(
    auth_token: &str,
    relays: &[String],
) -> Result<Vec<(PresenceRecord, u64)>> {
    let keys = derive_keys(auth_token)?;
    let client = connect_client(relays).await?;
    let filter = Filter::new()
        .kind(presence_kind())
        .author(keys.public_key());
    let events = client.fetch_events(filter, LOOKUP_TIMEOUT).await;
    client.disconnect().await;
    let events = events.context("querying nostr relays for presence records")?;
    Ok(presence_from_events(&keys, events.iter()))
}

/// Look up the presence record published under a specific display identity.
/// Returns the newest valid record, or `Ok(None)` when none exists (or the
/// stored record is unreadable — indistinguishable from absent, by design). A
/// relay failure is an `Err`, so callers can tell "no record" from "no answer".
pub async fn lookup_presence(
    auth_token: &str,
    identity: &str,
    relays: &[String],
) -> Result<Option<(PresenceRecord, u64)>> {
    let keys = derive_keys(auth_token)?;
    let client = connect_client(relays).await?;
    let filter = Filter::new()
        .kind(presence_kind())
        .author(keys.public_key())
        .identifier(presence_dtag(auth_token, identity))
        .limit(1);
    let events = client.fetch_events(filter, LOOKUP_TIMEOUT).await;
    client.disconnect().await;
    let events = events.context("querying nostr relays for the peer's presence record")?;
    let latest = events.iter().max_by_key(|e| e.created_at);
    Ok(latest.and_then(|event| presence_from_events(&keys, [event]).pop()))
}

/// Assemble the UI-facing peer list from fetched records: drop records older
/// than [`PRESENCE_HIDE_AFTER_SECS`], keep only the newest record per suffix (a
/// renamed device's old-identity record loses to its new one), exclude this
/// device's own suffix, and compute the online flag. Sorted online-first, then
/// by display name.
pub fn build_peer_list(
    records: Vec<(PresenceRecord, u64)>,
    own_suffix: &str,
    now_secs: u64,
) -> Vec<PeerInfo> {
    let mut newest_by_suffix: std::collections::HashMap<String, (PresenceRecord, u64)> =
        std::collections::HashMap::new();
    for (record, created_at) in records {
        if record.suffix == own_suffix {
            continue;
        }
        if now_secs.saturating_sub(created_at) > PRESENCE_HIDE_AFTER_SECS {
            continue;
        }
        match newest_by_suffix.entry(record.suffix.clone()) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert((record, created_at));
            }
            std::collections::hash_map::Entry::Occupied(mut slot) => {
                if created_at > slot.get().1 {
                    slot.insert((record, created_at));
                }
            }
        }
    }
    let mut peers: Vec<PeerInfo> = newest_by_suffix
        .into_values()
        .map(|(record, created_at)| PeerInfo {
            name: record.name,
            suffix: record.suffix,
            node_id: record.node_id,
            last_seen_unix: created_at,
            online: now_secs.saturating_sub(created_at) <= PRESENCE_ONLINE_WINDOW_SECS,
        })
        .collect();
    peers.sort_by(|a, b| {
        b.online
            .cmp(&a.online)
            .then_with(|| a.display().cmp(&b.display()))
    });
    peers
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
    // The PIN KDF is Argon2id (slow, memory-hard by design); derive off the
    // async executor.
    let keys = tokio::task::spawn_blocking({
        let pin = canonical_pin.to_string();
        move || pin_keys(&pin, bucket)
    })
    .await
    .context("PIN key-derivation task failed")??;
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
    // event with the right bucket's secret. Three Argon2id runs — off the async executor.
    let all_keys = tokio::task::spawn_blocking({
        let pin = canonical_pin.to_string();
        move || -> Result<Vec<Keys>> { buckets.iter().map(|&b| pin_keys(&pin, b)).collect() }
    })
    .await
    .context("PIN key-derivation task failed")??;
    let mut by_pubkey: std::collections::HashMap<PublicKey, Keys> =
        std::collections::HashMap::new();
    for keys in all_keys {
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

    fn record(name: &str, suffix: &str, run_id: &str, node_id: Option<&str>) -> PresenceRecord {
        PresenceRecord {
            version: PRESENCE_VERSION,
            name: name.to_string(),
            suffix: suffix.to_string(),
            run_id: run_id.to_string(),
            node_id: node_id.map(str::to_string),
        }
    }

    fn presence_event(
        token: &str,
        keys: &Keys,
        record: &PresenceRecord,
        created_at: u64,
    ) -> Event {
        let content = nip44::encrypt(
            keys.secret_key(),
            &keys.public_key(),
            serde_json::to_string(record).unwrap(),
            nip44::Version::V2,
        )
        .unwrap();
        EventBuilder::new(presence_kind(), content)
            .tags([Tag::identifier(presence_dtag(token, &record.display()))])
            .custom_created_at(Timestamp::from_secs(created_at))
            .sign_with_keys(keys)
            .unwrap()
    }

    #[test]
    fn presence_dtag_is_deterministic_identity_and_token_specific() {
        let token = "the-auth-token";
        let a = presence_dtag(token, "web1_a7B2c3D4");
        let a_again = presence_dtag(token, "web1_a7B2c3D4");
        let b = presence_dtag(token, "web2_x9Y8z7W6");
        assert_eq!(
            a, a_again,
            "same token + identity must derive the same d tag"
        );
        assert_ne!(a, b, "different identities must derive different d tags");
        assert!(a.starts_with(PRESENCE_DTAG_BASE), "d tag was: {a}");

        // Trimming: surrounding whitespace must not change the tag.
        assert_eq!(a, presence_dtag(token, "  web1_a7B2c3D4  "));

        // Salt: the same identity under a different token derives a different tag.
        let other_token = presence_dtag("other-token", "web1_a7B2c3D4");
        assert_ne!(a, other_token, "the auth token salts the identity hash");
    }

    #[test]
    fn presence_record_round_trips_through_encrypted_event_content() {
        let token = "round-trip-token";
        let keys = derive_keys(token).unwrap();
        let node_id = iroh::SecretKey::generate().public();
        let rec = record("mac-book", "a7B2c3D4", "run1", Some(&node_id.to_string()));
        let event = presence_event(token, &keys, &rec, 100);

        // Neither the plaintext name nor the node id may appear on the relay.
        assert!(!event.content.contains("mac-book"), "name leaked in clear");
        assert!(
            !event.content.contains(&node_id.to_string()),
            "node id leaked in clear"
        );

        let decoded = presence_from_events(&keys, [&event]);
        assert_eq!(decoded, vec![(rec, 100)]);
    }

    #[test]
    fn presence_decoding_skips_foreign_and_malformed_records() {
        let token = "shared-token";
        let keys = derive_keys(token).unwrap();

        let good = record("mac1", "a7B2c3D4", "run1", None);
        let good_event = presence_event(token, &keys, &good, 300);

        // Encrypted under a different token: must be skipped, not error.
        let foreign_keys = derive_keys("wrong-token").unwrap();
        let undecryptable = presence_event("wrong-token", &foreign_keys, &good, 400);
        // Re-sign under our author key so only decryption distinguishes it.
        let undecryptable = EventBuilder::new(presence_kind(), undecryptable.content.clone())
            .tags([Tag::identifier(presence_dtag(token, "x"))])
            .sign_with_keys(&keys)
            .unwrap();

        // Old bare-node-id payload shape: decrypts but is not a PresenceRecord.
        let legacy_content = nip44::encrypt(
            keys.secret_key(),
            &keys.public_key(),
            iroh::SecretKey::generate().public().to_string(),
            nip44::Version::V2,
        )
        .unwrap();
        let legacy = EventBuilder::new(presence_kind(), legacy_content)
            .tags([Tag::identifier(presence_dtag(token, "legacy"))])
            .sign_with_keys(&keys)
            .unwrap();

        // Wrong payload version: parses but must be rejected.
        let mut future = record("mac9", "q5R6s7T8", "run9", None);
        future.version = PRESENCE_VERSION + 1;
        let future_event = presence_event(token, &keys, &future, 500);

        // Wrong d-tag base (an unrelated 30078 record): filtered before decrypting.
        let unrelated = EventBuilder::new(presence_kind(), "junk")
            .tags([Tag::identifier("someapp:other:abc".to_string())])
            .sign_with_keys(&keys)
            .unwrap();

        let decoded = presence_from_events(
            &keys,
            [&good_event, &undecryptable, &legacy, &future_event, &unrelated],
        );
        assert_eq!(decoded, vec![(good, 300)]);
    }

    #[test]
    fn build_peer_list_dedupes_by_suffix_excludes_self_and_ages_records() {
        let now = 1_000_000u64;
        let host_id = iroh::SecretKey::generate().public().to_string();
        let records = vec![
            // Own record: excluded regardless of freshness.
            (record("me", "meMEmeM2", "r0", None), now),
            // A device renamed from "old-name" to "new-name": same suffix, the
            // newer record must win and carry the new name.
            (record("old-name", "a7B2c3D4", "r1", None), now - 5_000),
            (
                record("new-name", "a7B2c3D4", "r1", Some(&host_id)),
                now - 10,
            ),
            // Offline but recent enough to list.
            (
                record("laptop", "x9Y8z7W6", "r2", None),
                now - PRESENCE_ONLINE_WINDOW_SECS - 100,
            ),
            // Ancient record: hidden entirely.
            (
                record("dusty", "q5R6s7T8", "r3", None),
                now - PRESENCE_HIDE_AFTER_SECS - 1,
            ),
        ];

        let peers = build_peer_list(records, "meMEmeM2", now);
        assert_eq!(peers.len(), 2, "peers were: {peers:?}");

        let renamed = &peers[0];
        assert_eq!(renamed.display(), "new-name_a7B2c3D4");
        assert!(renamed.online);
        assert_eq!(renamed.node_id.as_deref(), Some(host_id.as_str()));
        assert_eq!(renamed.last_seen_unix, now - 10);

        let offline = &peers[1];
        assert_eq!(offline.display(), "laptop_x9Y8z7W6");
        assert!(!offline.online, "stale record must show as offline");
        assert_eq!(offline.node_id, None);
    }

    #[test]
    fn wrong_auth_token_cannot_decrypt_presence() {
        let publisher = derive_keys("the-real-token").unwrap();
        let rec = record("mac1", "a7B2c3D4", "run1", None);
        let event = presence_event("the-real-token", &publisher, &rec, 100);
        // A peer with a different auth token derives a different key and cannot read it.
        let attacker = derive_keys("a-different-token").unwrap();
        assert!(
            nip44::decrypt(attacker.secret_key(), &attacker.public_key(), &event.content)
                .is_err(),
            "decryption must fail under a different auth token"
        );
        assert!(presence_from_events(&attacker, [&event]).is_empty());
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
    async fn public_relay_presence_round_trip() {
        let relays: Vec<String> = DEFAULT_NOSTR_RELAYS
            .iter()
            .map(|relay| relay.to_string())
            .collect();
        let token = crate::auth::generate_token();
        let node_id = iroh::SecretKey::generate().public();
        let host = record(
            "relay-host",
            &crate::identity::generate_suffix(),
            "run1",
            Some(&node_id.to_string()),
        );

        publish_presence(&token, &host, &relays)
            .await
            .expect("publish presence record");

        let fetched = fetch_presence_records(&token, &relays)
            .await
            .expect("fetch presence records");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let peers = build_peer_list(fetched, "notMYsfx", now);
        let listed = peers
            .iter()
            .find(|p| p.suffix == host.suffix)
            .expect("published device appears in the peer list");
        assert!(listed.online);
        assert_eq!(listed.node_id.as_deref(), Some(node_id.to_string().as_str()));

        let (looked_up, _) = lookup_presence(&token, &host.display(), &relays)
            .await
            .expect("lookup presence")
            .expect("record exists");
        assert_eq!(looked_up, host);
    }
}
