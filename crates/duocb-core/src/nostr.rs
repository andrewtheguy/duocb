//! Nostr signaling: pairwise hosting records for configured peers and the
//! card-setup PIN rendezvous.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::EndpointId;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::{Identity, IdentityCard};

pub const DEFAULT_NOSTR_RELAYS: &[&str] = &[
    "wss://nos.lol",
    "wss://relay.nostr.net",
    "wss://relay.primal.net",
    "wss://relay.snort.social",
];

const HOSTING_KIND_U16: u16 = 30385;
const HOSTING_VERSION: u32 = 1;
const PAIR_TAG_DOMAIN: &[u8] = b"duocb:pairwise-hosting:v1";
const HOSTING_EVENT_TTL_SECS: u64 = 300;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);

fn hosting_kind() -> Kind {
    Kind::from_u16(HOSTING_KIND_U16)
}

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

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn pair_dtag(host: PublicKey, peer: PublicKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PAIR_TAG_DOMAIN);
    hasher.update(host.as_bytes());
    hasher.update(peer.as_bytes());
    format!("duocb:hosting:v1:{}", sha256_hex(&hasher.finalize()))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostingRecord {
    version: u32,
    node_id: String,
}

/// Publish the host's ephemeral iroh endpoint separately and privately for each
/// trusted application identity.
pub async fn publish_hosting(
    identity: &Identity,
    peers: &[IdentityCard],
    node_id: &EndpointId,
    relays: &[String],
) -> Result<()> {
    if peers.is_empty() {
        return Ok(());
    }
    let payload = serde_json::to_string(&HostingRecord {
        version: HOSTING_VERSION,
        node_id: node_id.to_string(),
    })
    .context("serializing hosting record")?;
    let expiration = Timestamp::now() + HOSTING_EVENT_TTL_SECS;
    let client = connect_client(relays).await?;
    let mut first_error = None;
    for peer in peers {
        let content = nip44::encrypt(
            identity.keys().secret_key(),
            &peer.public_key(),
            &payload,
            nip44::Version::V2,
        )
        .context("encrypting pairwise hosting record")?;
        let event = EventBuilder::new(hosting_kind(), content)
            .tags([
                Tag::identifier(pair_dtag(identity.public_key(), peer.public_key())),
                Tag::public_key(peer.public_key()),
                Tag::expiration(expiration),
            ])
            .sign_with_keys(identity.keys())
            .context("signing pairwise hosting record")?;
        if let Err(error) = client.send_event(&event).await
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    client.disconnect().await;
    if let Some(error) = first_error {
        return Err(error).context("publishing pairwise hosting record");
    }
    Ok(())
}

/// Resolve a selected trusted peer's current ephemeral iroh endpoint.
pub async fn lookup_hosting(
    identity: &Identity,
    peer: PublicKey,
    relays: &[String],
) -> Result<Option<EndpointId>> {
    let client = connect_client(relays).await?;
    let filter = Filter::new()
        .kind(hosting_kind())
        .author(peer)
        .identifier(pair_dtag(peer, identity.public_key()))
        .limit(1);
    let events = client.fetch_events(filter, LOOKUP_TIMEOUT).await;
    client.disconnect().await;
    let events = events.context("querying Nostr for pairwise hosting record")?;
    let Some(event) = events.iter().max_by_key(|event| event.created_at) else {
        return Ok(None);
    };
    event.verify().context("hosting record signature is invalid")?;
    let plaintext = nip44::decrypt(
        identity.keys().secret_key(),
        &peer,
        &event.content,
    )
    .context("decrypting pairwise hosting record")?;
    let record: HostingRecord =
        serde_json::from_str(&plaintext).context("hosting record payload is invalid")?;
    if record.version != HOSTING_VERSION {
        return Ok(None);
    }
    Ok(record.node_id.parse().ok())
}

// ============================================================================
// Card-setup PIN rendezvous
// ============================================================================

const PIN_KIND_U16: u16 = 9421;
/// How long a published PIN record stays useful: three rotation periods, which
/// covers the look-back window a joiner searches (`pin_record::candidate_keys`)
/// without leaving stale records resolvable much beyond it. A resolved stale
/// record leads to an auth rejection anyway — the auth key rotates with the
/// displayed code.
const PIN_EVENT_TTL_SECS: u64 = 3 * crate::pin::BUCKET_SECS;
/// Shorter than the hosting lookup: this one is on the critical path of a
/// person waiting with a 60-second code on screen.
const PIN_LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);

fn pin_kind() -> Kind {
    Kind::from_u16(PIN_KIND_U16)
}

/// Publish the card-setup rendezvous record — the same encrypted node-id record
/// the LAN backends carry (see `crate::pin_record`) — to the relays, signed by
/// (and addressed under) the `(pin, bucket)`-derived keypair.
///
/// This is the fallback path that lets two devices on different networks trade
/// cards. It puts the record where anyone can fetch it, so its secrecy rests
/// entirely on the PIN: the lookup key is Argon2id-derived, and the record only
/// yields an ephemeral node id, which is not a credential — dialing it still
/// has to pass the in-band PIN auth, and the card that crosses is not trusted
/// until a human compares fingerprints (`crate::card_exchange`).
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

/// Fetch the card-setup rendezvous record from the relays, trying each
/// candidate keypair (one per adjacent rotation bucket — see
/// `pin_record::candidate_keys`), newest event first. `Ok(None)` when no
/// candidate's record answered or none decrypted, i.e. a wrong or expired PIN.
///
/// Unlike the LAN backends this returns a bare node id: the record carries no
/// direct addresses, so the dialer's own discovery (n0 DNS/pkarr, relays)
/// resolves it — which is what makes this the cross-network path.
pub async fn lookup_pin_record(
    candidates: &[Keys],
    relays: &[String],
) -> Result<Option<EndpointId>> {
    let by_pubkey: HashMap<PublicKey, &Keys> = candidates
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
    let mut found: Vec<_> = events.iter().collect();
    found.sort_by_key(|event| std::cmp::Reverse(event.created_at));
    for event in found {
        let Some(keys) = by_pubkey.get(&event.pubkey) else {
            continue;
        };
        if let Some(node_id) = crate::pin_record::decrypt_pin_payload(keys, &event.content) {
            return Ok(Some(node_id));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_tags_are_ordered_and_transport_independent() {
        let a = Identity::generate();
        let b = Identity::generate();
        assert_eq!(
            pair_dtag(a.public_key(), b.public_key()),
            pair_dtag(a.public_key(), b.public_key())
        );
        assert_ne!(
            pair_dtag(a.public_key(), b.public_key()),
            pair_dtag(b.public_key(), a.public_key())
        );
    }
}
