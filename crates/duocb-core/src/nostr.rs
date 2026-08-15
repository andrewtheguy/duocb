//! Nostr signaling: pairwise hosting records for configured peers and
//! quick-mode PIN rendezvous.

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
