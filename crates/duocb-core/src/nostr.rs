//! Nostr side channel for the configure mode's device presence and rendezvous.
//!
//! All devices sharing one `auth_token` (the standing secret) derive the *same*
//! nostr keypair from it, so authorship of an event under that key **is** the
//! proof of secret possession — a presence record is "a message signed by the
//! secret". Each running device publishes one kind-30078 parameterized-
//! replaceable **presence record** under a `d` tag of
//! `duocb:presence:<sha256(auth||identity)>`, where `identity` is the device's
//! collision-resistant display identity `<name>_<suffix>` (see
//! `crate::identity`). The hash is salted with the token so identities cannot
//! be enumerated on relays.
//!
//! The record content is NIP-44 **self-encrypted** under the token-derived
//! keypair and carries a JSON [`PresenceRecord`]: the plaintext display name
//! (readable only by token holders), the permanent per-device suffix, and a
//! random per-publisher-run id. It is a directory entry only — it says "this
//! device exists / was last seen at `created_at`" and carries **no** dial target
//! or hosting/liveness signal. A peer fetches every record under the shared
//! author key, decrypts them into a device list, and the user picks a device to
//! join.
//!
//! The dial target is negotiated separately, out of the directory: while a
//! device is hosting a connection it publishes a short-lived **hosting record**
//! (see [`publish_hosting`]) keyed off the same token+identity, carrying only its
//! current ephemeral iroh node id and self-expiring via NIP-40 so it leaves no
//! standing liveness on relays. On join, the client resolves that record for the
//! selected identity (see [`lookup_hosting`]) to learn the node id to dial; its
//! absence means the device is not currently hosting. The `auth_token` still
//! gates the actual connection in-band.

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
/// Base of the `d` tag identifying duocb presence (directory) records; the
/// per-device identity hash is appended (see [`presence_dtag`]).
const PRESENCE_DTAG_BASE: &str = "duocb:presence";
/// Base of the `d` tag identifying duocb hosting records; the per-device identity
/// hash is appended (see [`hosting_dtag`]). A separate slot from presence so the
/// dial target lives outside the directory listing.
const HOSTING_DTAG_BASE: &str = "duocb:hosting";
/// Domain separation for deriving the nostr key from the auth token.
const KEY_DERIVATION_DOMAIN: &[u8] = b"duocb:nostr-rendezvous:v1";
/// Domain separation for hashing a device's display identity into its presence `d` tag.
const PRESENCE_DOMAIN: &[u8] = b"duocb:presence-id:v1";
/// Domain separation for hashing a device's display identity into its hosting `d`
/// tag. Distinct from [`PRESENCE_DOMAIN`] so the two records for one device hash
/// to unrelated tags and cannot be correlated on relays.
const HOSTING_DOMAIN: &[u8] = b"duocb:hosting-id:v1";

/// Payload schema version; records with any other value are rejected on decode
/// (strict no backward compatibility).
pub const PRESENCE_VERSION: u32 = 2;

/// How long a hosting record stays on relays (NIP-40). Comfortably longer than
/// [`PRESENCE_REPUBLISH_INTERVAL`] so it stays alive across the heartbeat while a
/// device keeps hosting, then self-cleans shortly after hosting stops.
const HOSTING_EVENT_TTL_SECS: u64 = 300;

/// Steady-state heartbeat between presence republishes.
pub const PRESENCE_REPUBLISH_INTERVAL: Duration = Duration::from_secs(120);
/// Faster republish cadence right after the publisher starts, so a fresh device
/// shows up quickly even if a relay dropped the first publish.
pub const PRESENCE_STARTUP_INTERVAL: Duration = Duration::from_secs(10);
/// Number of startup-cadence cycles before settling on the steady heartbeat.
pub const PRESENCE_STARTUP_CYCLES: u32 = 6;
/// Records older than this are dropped from the peer list entirely.
pub const PRESENCE_HIDE_AFTER_SECS: u64 = 7 * 24 * 3600;

/// Timeout for establishing relay connections.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for a presence fetch/lookup query.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);

fn presence_kind() -> Kind {
    Kind::from_u16(PRESENCE_KIND_U16)
}

/// Build a `d` tag for a device: the given `base` tag plus a hex SHA-256 of the
/// (trimmed) display identity, salted with the `domain` and the shared
/// `auth_token`. The salt means an identity cannot be guessed or enumerated on
/// relays without the token; all parties share the token, so all derive the same
/// tag. The `domain` also decouples the presence and hosting tags for one device.
fn identity_dtag(base: &str, domain: &[u8], auth_token: &str, identity: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(auth_token.as_bytes());
    hasher.update(identity.trim().as_bytes());
    let digest = hasher.finalize();
    let mut tag = String::with_capacity(base.len() + 1 + digest.len() * 2);
    tag.push_str(base);
    tag.push(':');
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(tag, "{b:02x}");
    }
    tag
}

/// The `d` tag for a device's presence (directory) record.
fn presence_dtag(auth_token: &str, identity: &str) -> String {
    identity_dtag(PRESENCE_DTAG_BASE, PRESENCE_DOMAIN, auth_token, identity)
}

/// The `d` tag for a device's hosting record (the out-of-directory dial target).
fn hosting_dtag(auth_token: &str, identity: &str) -> String {
    identity_dtag(HOSTING_DTAG_BASE, HOSTING_DOMAIN, auth_token, identity)
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

/// The NIP-44-encrypted content of a presence (directory) record. Authorship
/// under the token-derived key proves secret possession; the payload carries the
/// plaintext display name (readable only by token holders) plus the minimum a
/// peer needs to *list* this device. It deliberately carries no dial target or
/// hosting/liveness signal — that is the hosting record's job (see
/// [`publish_hosting`]).
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
}

impl PresenceRecord {
    /// The full display identity `<name>_<suffix>` this record is tagged under.
    pub fn display(&self) -> String {
        crate::identity::display_identity(&self.name, &self.suffix)
    }
}

/// A peer as shown in the device list, decoded from its newest presence record.
/// Deliberately carries no hosting/liveness signal: relay timing is too
/// unreliable to derive an online/offline verdict from, so every listed device
/// is joinable and the join re-resolves the record and lets iroh's dial be the
/// actual liveness check (the dial target lives in the record, not here — see
/// [`crate::net`]'s client session).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    /// The peer's short name.
    pub name: String,
    /// The peer's permanent suffix (stable selection key).
    pub suffix: String,
    /// `created_at` of the peer's newest record, unix seconds.
    pub last_seen_unix: u64,
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

/// Publish (or replace) this device's hosting record: its current ephemeral iroh
/// node id, NIP-44 self-encrypted under the token-derived key and tagged under
/// this device's hosting `d` tag. A parameterized-replaceable event (same kind as
/// presence, distinct `d` tag) so a new node id supersedes the previous, with a
/// NIP-40 expiration so the record self-cleans once the device stops refreshing
/// it (i.e. stops hosting) — leaving no standing dial target or liveness behind.
pub async fn publish_hosting(
    auth_token: &str,
    identity: &str,
    node_id: &EndpointId,
    relays: &[String],
) -> Result<()> {
    let keys = derive_keys(auth_token)?;
    // Same `{node_id}` self-encrypted payload the PIN rendezvous uses; reused
    // here for the out-of-directory hosting record (see `crate::pin_record`).
    let content = crate::pin_record::encrypt_pin_payload(&keys, node_id)?;
    let expiration = Timestamp::now() + HOSTING_EVENT_TTL_SECS;
    let client = connect_client(relays).await?;
    let event = EventBuilder::new(presence_kind(), content)
        .tags([Tag::identifier(hosting_dtag(auth_token, identity))])
        .tag(Tag::expiration(expiration))
        .sign_with_keys(&keys)
        .context("signing hosting event")?;
    let res = client.send_event(&event).await;
    client.disconnect().await;
    res.context("publishing hosting event to relays")?;
    Ok(())
}

/// Resolve the dial target for a device by its display identity: the node id from
/// its current hosting record. Returns `Ok(None)` when no readable record exists
/// — the device is not hosting (or has stopped and the record expired). A relay
/// failure is an `Err`, so callers can tell "not hosting" from "no answer".
pub async fn lookup_hosting(
    auth_token: &str,
    identity: &str,
    relays: &[String],
) -> Result<Option<EndpointId>> {
    let keys = derive_keys(auth_token)?;
    let client = connect_client(relays).await?;
    let filter = Filter::new()
        .kind(presence_kind())
        .author(keys.public_key())
        .identifier(hosting_dtag(auth_token, identity))
        .limit(1);
    let events = client.fetch_events(filter, LOOKUP_TIMEOUT).await;
    client.disconnect().await;
    let events = events.context("querying nostr relays for the peer's hosting record")?;
    let latest = events.iter().max_by_key(|e| e.created_at);
    Ok(latest.and_then(|event| crate::pin_record::decrypt_pin_payload(&keys, &event.content)))
}

/// Assemble the UI-facing peer list from fetched records: drop records older
/// than [`PRESENCE_HIDE_AFTER_SECS`], keep only the newest record per suffix (a
/// renamed device's old-identity record loses to its new one), and exclude this
/// device's own suffix. Sorted by display name. Deliberately no online/offline
/// or hosting verdict — relay freshness is not reliable enough to gate anything
/// on, so every listed device is joinable.
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
            last_seen_unix: created_at,
        })
        .collect();
    peers.sort_by_key(|p| p.display());
    peers
}

// ============================================================================
// Quick-mode PIN rendezvous
// ============================================================================
//
// The nostr transport for the encrypted PIN record (see `crate::pin_record`
// for the shared codec, and `crate::lan` for the mDNS transport). Unlike the
// node-id discovery above (keyed off the shared auth token), here the client
// starts with nothing but the PIN; the lookup is by **author key** — the
// `(pin, bucket)`-derived public key — so no extra tag is needed.
//
// The record is a regular (stored, non-replaceable) event carrying the NIP-44
// encrypted `{node_id}` payload, with a NIP-40 expiration so per-bucket records
// coexist briefly (for boundary look-back) then self-clean.

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

/// Publish a PIN rendezvous record for one bucket: the server's ephemeral node id,
/// NIP-44 self-encrypted under `keys` (the `(pin, bucket)`-derived keypair, derived
/// by the caller — the KDF is Argon2id and must run off the async executor), as a
/// stored event that expires after a few rotation periods.
pub async fn publish_pin_record(keys: &Keys, node_id: &EndpointId, relays: &[String]) -> Result<()> {
    let content = crate::pin_record::encrypt_pin_payload(keys, node_id)?;

    let expiration = Timestamp::now() + PIN_EVENT_TTL_SECS;
    let client = connect_client(relays).await?;
    let event = EventBuilder::new(pin_kind(), content)
        .tag(Tag::expiration(expiration))
        .sign_with_keys(keys)
        .context("signing PIN record")?;
    let res = client.send_event(&event).await;
    client.disconnect().await;
    res.context("publishing PIN record to relays")?;
    Ok(())
}

/// Look up the PIN rendezvous record on nostr relays, trying each candidate
/// keypair (the caller derives one per adjacent bucket — see
/// `pin_record::candidate_keys`; all are queried in a single relay
/// round-trip). Returns the decrypted node id, or `Ok(None)` when no matching
/// record is found (wrong or expired PIN). The connection is then
/// authenticated in-band with the same PIN (see `crate::pin_auth`).
pub async fn lookup_pin_record(
    candidates: &[Keys],
    relays: &[String],
) -> Result<Option<EndpointId>> {
    // Map public key -> keys so a returned event decrypts with the right
    // bucket's secret.
    let by_pubkey: std::collections::HashMap<PublicKey, &Keys> = candidates
        .iter()
        .map(|keys| (keys.public_key(), keys))
        .collect();

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
        let Some(node_id) = crate::pin_record::decrypt_pin_payload(keys, &event.content) else {
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

    fn record(name: &str, suffix: &str, run_id: &str) -> PresenceRecord {
        PresenceRecord {
            version: PRESENCE_VERSION,
            name: name.to_string(),
            suffix: suffix.to_string(),
            run_id: run_id.to_string(),
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
        let rec = record("mac-book", "a7B2c3D4", "run1");
        let event = presence_event(token, &keys, &rec, 100);

        // The plaintext name must not appear on the relay.
        assert!(!event.content.contains("mac-book"), "name leaked in clear");

        let decoded = presence_from_events(&keys, [&event]);
        assert_eq!(decoded, vec![(rec, 100)]);
    }

    #[test]
    fn presence_decoding_skips_foreign_and_malformed_records() {
        let token = "shared-token";
        let keys = derive_keys(token).unwrap();

        let good = record("mac1", "a7B2c3D4", "run1");
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
        let mut future = record("mac9", "q5R6s7T8", "run9");
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
        let records = vec![
            // Own record: excluded regardless of freshness.
            (record("me", "meMEmeM2", "r0"), now),
            // A device renamed from "old-name" to "new-name": same suffix, the
            // newer record must win and carry the new name.
            (record("old-name", "a7B2c3D4", "r1"), now - 5_000),
            (record("new-name", "a7B2c3D4", "r1"), now - 10),
            (record("laptop", "x9Y8z7W6", "r2"), now - 5_000),
            // Ancient record: hidden entirely.
            (
                record("dusty", "q5R6s7T8", "r3"),
                now - PRESENCE_HIDE_AFTER_SECS - 1,
            ),
        ];

        let peers = build_peer_list(records, "meMEmeM2", now);
        assert_eq!(peers.len(), 2, "peers were: {peers:?}");

        // Sorted by display name.
        let laptop = &peers[0];
        assert_eq!(laptop.display(), "laptop_x9Y8z7W6");
        assert_eq!(laptop.last_seen_unix, now - 5_000);

        // The renamed device keeps its newer record's name and timestamp.
        let renamed = &peers[1];
        assert_eq!(renamed.display(), "new-name_a7B2c3D4");
        assert_eq!(renamed.last_seen_unix, now - 10);
    }

    #[test]
    fn wrong_auth_token_cannot_decrypt_presence() {
        let publisher = derive_keys("the-real-token").unwrap();
        let rec = record("mac1", "a7B2c3D4", "run1");
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

    #[tokio::test]
    #[ignore = "uses public nostr relays"]
    async fn public_relay_presence_round_trip() {
        let relays: Vec<String> = DEFAULT_NOSTR_RELAYS
            .iter()
            .map(|relay| relay.to_string())
            .collect();
        let token = crate::auth::generate_token();
        let host = record("relay-host", &crate::identity::generate_suffix(), "run1");

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
        peers
            .iter()
            .find(|p| p.suffix == host.suffix)
            .expect("published device appears in the peer list");

        // The directory record round-trips as-is (no dial target inside it).
        let (looked_up, _) = lookup_presence(&token, &host.display(), &relays)
            .await
            .expect("lookup presence")
            .expect("record exists");
        assert_eq!(looked_up, host);

        // The dial target is negotiated out-of-directory: before hosting, no
        // hosting record exists; after publishing one, the node id round-trips.
        assert_eq!(
            lookup_hosting(&token, &host.display(), &relays)
                .await
                .expect("lookup hosting"),
            None,
            "no hosting record before the device hosts"
        );
        let node_id = iroh::SecretKey::generate().public();
        publish_hosting(&token, &host.display(), &node_id, &relays)
            .await
            .expect("publish hosting record");
        assert_eq!(
            lookup_hosting(&token, &host.display(), &relays)
                .await
                .expect("lookup hosting"),
            Some(node_id),
            "the hosting record resolves the dial target",
        );
    }
}
