//! Nostr signaling for configured peers, encrypted peer-list backups, and
//! quick-mode PIN rendezvous.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::EndpointId;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::{
    DirectoryChannel, Identity, IdentityCard, MAX_TRUSTED_PEERS,
};
use crate::pin;

pub const DEFAULT_NOSTR_RELAYS: &[&str] = &[
    "wss://nos.lol",
    "wss://relay.nostr.net",
    "wss://relay.primal.net",
    "wss://relay.snort.social",
];

const BACKUP_HEADER_KIND_U16: u16 = 30383;
const BACKUP_CHUNK_KIND_U16: u16 = 30384;
const HOSTING_KIND_U16: u16 = 30385;
const BACKUP_VERSION: u32 = 1;
const HOSTING_VERSION: u32 = 1;
const CHANNEL_KEY_DOMAIN: &[u8] = b"duocb:directory-channel-key:v1";
const PAIR_TAG_DOMAIN: &[u8] = b"duocb:pairwise-hosting:v1";
const BACKUP_HEADER_DTAG: &str = "duocb:backup-header:v1";
const BACKUP_CHUNK_DTAG: &str = "duocb:backup-chunk:v1";
const MAX_BACKUP_BYTES: usize = 128 * 1024;
const BACKUP_CHUNK_BYTES: usize = 8 * 1024;
const MAX_BACKUP_CHUNKS: usize = 16;
const MAX_CARRIER_CONTENT: usize = 16 * 1024;
const BACKUP_QUERY_LIMIT: usize = 128;
const HOSTING_EVENT_TTL_SECS: u64 = 300;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);

fn backup_header_kind() -> Kind {
    Kind::from_u16(BACKUP_HEADER_KIND_U16)
}

fn backup_chunk_kind() -> Kind {
    Kind::from_u16(BACKUP_CHUNK_KIND_U16)
}

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

/// Derive the encryption recipient used by one optional backup channel.
pub fn derive_channel_keys(channel: DirectoryChannel) -> Result<Keys> {
    let mut hasher = Sha256::new();
    hasher.update(CHANNEL_KEY_DOMAIN);
    hasher.update(channel.as_bytes());
    let secret =
        SecretKey::from_slice(&hasher.finalize()).context("deriving directory channel key")?;
    Ok(Keys::new(secret))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupBody {
    version: u32,
    generation: u64,
    self_card: String,
    peers: Vec<String>,
}

/// Fully validated recovery material owned by one application identity.
#[derive(Clone, Debug)]
pub struct BackupSnapshot {
    pub generation: u64,
    pub self_card: IdentityCard,
    pub peers: Vec<IdentityCard>,
}

impl BackupSnapshot {
    pub fn new(
        generation: u64,
        self_card: IdentityCard,
        peers: Vec<IdentityCard>,
    ) -> Result<Self> {
        if peers.len() > MAX_TRUSTED_PEERS {
            anyhow::bail!("backup has more than {MAX_TRUSTED_PEERS} peers");
        }
        let mut seen = HashSet::new();
        for peer in &peers {
            if peer.public_key() == self_card.public_key() {
                anyhow::bail!("backup peer list contains its owner");
            }
            if !seen.insert(peer.public_key()) {
                anyhow::bail!("backup peer list contains a duplicate public key");
            }
        }
        let snapshot = Self {
            generation,
            self_card,
            peers,
        };
        snapshot.encoded_body()?;
        Ok(snapshot)
    }

    fn encoded_body(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(&BackupBody {
            version: BACKUP_VERSION,
            generation: self.generation,
            self_card: self.self_card.encode(),
            peers: self.peers.iter().map(IdentityCard::encode).collect(),
        })
        .context("serializing peer backup")?;
        if bytes.len() > MAX_BACKUP_BYTES {
            anyhow::bail!("peer backup exceeds {MAX_BACKUP_BYTES} bytes");
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8], owner: PublicKey) -> Result<Self> {
        if bytes.len() > MAX_BACKUP_BYTES {
            anyhow::bail!("peer backup exceeds {MAX_BACKUP_BYTES} bytes");
        }
        let body: BackupBody =
            serde_json::from_slice(bytes).context("peer backup payload is invalid")?;
        if body.version != BACKUP_VERSION {
            anyhow::bail!("peer backup version {} is unsupported", body.version);
        }
        let self_card = IdentityCard::parse(&body.self_card)?;
        if self_card.public_key() != owner {
            anyhow::bail!("peer backup owner does not match its signed self-card");
        }
        let peers = body
            .peers
            .iter()
            .map(|card| IdentityCard::parse(card))
            .collect::<Result<Vec<_>>>()?;
        Self::new(body.generation, self_card, peers)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupHeader {
    version: u32,
    generation: u64,
    slot: u8,
    snapshot_id: String,
    chunks: u8,
    peer_count: u16,
    self_card: String,
    chunk_hashes: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupChunk {
    version: u32,
    generation: u64,
    slot: u8,
    snapshot_id: String,
    index: u8,
    data: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn backup_dtag(base: &str, slot: u8, index: Option<usize>) -> String {
    match index {
        Some(index) => format!("{base}:{slot}:{index}"),
        None => format!("{base}:{slot}"),
    }
}

fn encrypted_carrier(
    identity: &Identity,
    recipient: PublicKey,
    kind: Kind,
    dtag: String,
    plaintext: String,
) -> Result<Event> {
    let content = nip44::encrypt(
        identity.keys().secret_key(),
        &recipient,
        plaintext,
        nip44::Version::V2,
    )
    .context("encrypting Nostr carrier")?;
    if content.len() > MAX_CARRIER_CONTENT {
        anyhow::bail!("encrypted Nostr carrier exceeds {MAX_CARRIER_CONTENT} bytes");
    }
    EventBuilder::new(kind, content)
        .tags([Tag::identifier(dtag), Tag::public_key(recipient)])
        .sign_with_keys(identity.keys())
        .context("signing Nostr carrier")
}

fn decrypt_channel_carrier(
    channel_keys: &Keys,
    event: &Event,
) -> Result<String> {
    event.verify().context("Nostr carrier signature is invalid")?;
    nip44::decrypt(
        channel_keys.secret_key(),
        &event.pubkey,
        &event.content,
    )
    .context("decrypting Nostr carrier")
}

/// Publish a complete, bounded peer-list backup. Two alternating replaceable
/// slots retain one fallback generation without unbounded relay growth.
pub async fn publish_backup(
    identity: &Identity,
    channel: DirectoryChannel,
    snapshot: &BackupSnapshot,
    relays: &[String],
) -> Result<()> {
    if snapshot.self_card.public_key() != identity.public_key() {
        anyhow::bail!("cannot publish a backup owned by another identity");
    }
    let body = snapshot.encoded_body()?;
    let chunks: Vec<&[u8]> = body.chunks(BACKUP_CHUNK_BYTES).collect();
    if chunks.is_empty() || chunks.len() > MAX_BACKUP_CHUNKS {
        anyhow::bail!("peer backup needs too many chunks");
    }
    let slot = (snapshot.generation % 2) as u8;
    let snapshot_id = sha256_hex(&body);
    let channel_keys = derive_channel_keys(channel)?;
    let recipient = channel_keys.public_key();
    let chunk_hashes: Vec<String> = chunks.iter().map(|chunk| sha256_hex(chunk)).collect();

    let client = connect_client(relays).await?;
    for (index, bytes) in chunks.iter().enumerate() {
        let payload = serde_json::to_string(&BackupChunk {
            version: BACKUP_VERSION,
            generation: snapshot.generation,
            slot,
            snapshot_id: snapshot_id.clone(),
            index: index as u8,
            data: URL_SAFE_NO_PAD.encode(bytes),
        })
        .context("serializing peer backup chunk")?;
        let event = encrypted_carrier(
            identity,
            recipient,
            backup_chunk_kind(),
            backup_dtag(BACKUP_CHUNK_DTAG, slot, Some(index)),
            payload,
        )?;
        client
            .send_event(&event)
            .await
            .context("publishing peer backup chunk")?;
    }

    let header = serde_json::to_string(&BackupHeader {
        version: BACKUP_VERSION,
        generation: snapshot.generation,
        slot,
        snapshot_id,
        chunks: chunks.len() as u8,
        peer_count: snapshot.peers.len() as u16,
        self_card: snapshot.self_card.encode(),
        chunk_hashes,
    })
    .context("serializing peer backup header")?;
    let event = encrypted_carrier(
        identity,
        recipient,
        backup_header_kind(),
        backup_dtag(BACKUP_HEADER_DTAG, slot, None),
        header,
    )?;
    let sent = client.send_event(&event).await;
    client.disconnect().await;
    sent.context("publishing peer backup header")?;
    Ok(())
}

fn decode_header(channel_keys: &Keys, event: &Event) -> Result<BackupHeader> {
    if event.kind != backup_header_kind() {
        anyhow::bail!("not a peer backup header");
    }
    let plaintext = decrypt_channel_carrier(channel_keys, event)?;
    let header: BackupHeader =
        serde_json::from_str(&plaintext).context("peer backup header is invalid")?;
    if header.version != BACKUP_VERSION
        || header.slot > 1
        || header.chunks == 0
        || header.chunks as usize > MAX_BACKUP_CHUNKS
        || header.peer_count as usize > MAX_TRUSTED_PEERS
        || header.chunk_hashes.len() != header.chunks as usize
    {
        anyhow::bail!("peer backup header violates protocol bounds");
    }
    let card = IdentityCard::parse(&header.self_card)?;
    if card.public_key() != event.pubkey {
        anyhow::bail!("peer backup header owner does not match its self-card");
    }
    Ok(header)
}

fn assemble_snapshot(
    channel_keys: &Keys,
    owner: PublicKey,
    header: &BackupHeader,
    events: &[Event],
) -> Result<BackupSnapshot> {
    let mut by_index: HashMap<usize, Vec<u8>> = HashMap::new();
    for event in events {
        if event.pubkey != owner || event.kind != backup_chunk_kind() {
            continue;
        }
        let Ok(plaintext) = decrypt_channel_carrier(channel_keys, event) else {
            continue;
        };
        let Ok(chunk) = serde_json::from_str::<BackupChunk>(&plaintext) else {
            continue;
        };
        if chunk.version != BACKUP_VERSION
            || chunk.generation != header.generation
            || chunk.slot != header.slot
            || chunk.snapshot_id != header.snapshot_id
            || chunk.index as usize >= header.chunks as usize
        {
            continue;
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&chunk.data)
            .context("peer backup chunk data is invalid")?;
        let index = chunk.index as usize;
        if sha256_hex(&bytes) == header.chunk_hashes[index] {
            by_index.insert(index, bytes);
        }
    }
    if by_index.len() != header.chunks as usize {
        anyhow::bail!("peer backup snapshot is incomplete");
    }
    let mut body = Vec::new();
    for index in 0..header.chunks as usize {
        body.extend_from_slice(&by_index.remove(&index).expect("all indices checked"));
    }
    if sha256_hex(&body) != header.snapshot_id {
        anyhow::bail!("peer backup snapshot hash does not match its header");
    }
    let snapshot = BackupSnapshot::decode(&body, owner)?;
    if snapshot.generation != header.generation
        || snapshot.peers.len() != header.peer_count as usize
        || snapshot.self_card.encode() != header.self_card
    {
        anyhow::bail!("peer backup snapshot does not match its header");
    }
    Ok(snapshot)
}

/// Find, but do not apply, the newest complete backup for one restored identity.
pub async fn lookup_backup(
    owner: PublicKey,
    channel: DirectoryChannel,
    relays: &[String],
) -> Result<Option<BackupSnapshot>> {
    let channel_keys = derive_channel_keys(channel)?;
    let client = connect_client(relays).await?;
    let filter = Filter::new()
        .authors([owner])
        .kinds([backup_header_kind(), backup_chunk_kind()])
        .limit(2 + 2 * MAX_BACKUP_CHUNKS);
    let events = client.fetch_events(filter, LOOKUP_TIMEOUT).await;
    client.disconnect().await;
    let events = events.context("querying Nostr for peer backup")?;
    let all: Vec<Event> = events.into_iter().collect();
    let mut headers: Vec<(u64, BackupHeader)> = all
        .iter()
        .filter_map(|event| {
            decode_header(&channel_keys, event)
                .ok()
                .map(|header| (event.created_at.as_secs(), header))
        })
        .collect();
    headers.sort_by_key(|(created_at, header)| {
        std::cmp::Reverse((header.generation, *created_at))
    });
    for (_, header) in headers {
        if let Ok(snapshot) = assemble_snapshot(&channel_keys, owner, &header, &all) {
            return Ok(Some(snapshot));
        }
    }
    Ok(None)
}

/// Fetch backup owners as signed-card candidates. Applying or restoring any
/// candidate remains a caller/UI decision.
pub async fn fetch_directory_cards(
    channel: DirectoryChannel,
    relays: &[String],
) -> Result<Vec<IdentityCard>> {
    let channel_keys = derive_channel_keys(channel)?;
    let client = connect_client(relays).await?;
    let filter = Filter::new()
        .kind(backup_header_kind())
        .pubkey(channel_keys.public_key())
        .limit(2 * BACKUP_QUERY_LIMIT);
    let events = client.fetch_events(filter, LOOKUP_TIMEOUT).await;
    client.disconnect().await;
    let events = events.context("querying Nostr backup directory")?;
    let mut newest: HashMap<PublicKey, (u64, IdentityCard)> = HashMap::new();
    for event in events.iter() {
        let Ok(header) = decode_header(&channel_keys, event) else {
            continue;
        };
        let Ok(card) = IdentityCard::parse(&header.self_card) else {
            continue;
        };
        match newest.entry(card.public_key()) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert((header.generation, card));
            }
            std::collections::hash_map::Entry::Occupied(mut slot) => {
                if header.generation > slot.get().0 {
                    slot.insert((header.generation, card));
                }
            }
        }
    }
    let mut cards: Vec<IdentityCard> = newest.into_values().map(|(_, card)| card).collect();
    cards.sort_by(|a, b| a.name().cmp(b.name()).then(a.npub().cmp(&b.npub())));
    cards.truncate(MAX_TRUSTED_PEERS);
    Ok(cards)
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
// Quick-mode PIN rendezvous
// ============================================================================

const PIN_KIND_U16: u16 = 9421;
const PIN_EVENT_TTL_SECS: u64 = 3 * pin::BUCKET_SECS;
const PIN_LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);

fn pin_kind() -> Kind {
    Kind::from_u16(PIN_KIND_U16)
}

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
    let mut candidates: Vec<_> = events.iter().collect();
    candidates.sort_by_key(|event| std::cmp::Reverse(event.created_at));
    for event in candidates {
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
    fn backup_round_trip_validation_and_bounds() {
        let owner = Identity::generate();
        let peer = Identity::generate();
        let snapshot = BackupSnapshot::new(
            7,
            owner.card("owner").unwrap(),
            vec![peer.card("peer").unwrap()],
        )
        .unwrap();
        let decoded = BackupSnapshot::decode(&snapshot.encoded_body().unwrap(), owner.public_key())
            .unwrap();
        assert_eq!(decoded.generation, 7);
        assert_eq!(decoded.self_card.name(), "owner");
        assert_eq!(decoded.peers[0].public_key(), peer.public_key());

        let too_many = (0..=MAX_TRUSTED_PEERS)
            .map(|index| {
                Identity::generate()
                    .card(&format!("peer-{index}"))
                    .unwrap()
            })
            .collect();
        assert!(
            BackupSnapshot::new(8, owner.card("owner").unwrap(), too_many).is_err()
        );
    }

    #[test]
    fn backup_rejects_duplicates_and_wrong_owner() {
        let owner = Identity::generate();
        let peer = Identity::generate().card("peer").unwrap();
        assert!(
            BackupSnapshot::new(
                1,
                owner.card("owner").unwrap(),
                vec![peer.clone(), peer]
            )
            .is_err()
        );
    }

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

    #[test]
    fn encrypted_chunk_snapshot_requires_a_complete_hash_committed_set() {
        let owner = Identity::generate();
        let channel = DirectoryChannel::generate();
        let snapshot = BackupSnapshot::new(
            12,
            owner.card("owner").unwrap(),
            vec![
                Identity::generate().card("phone").unwrap(),
                Identity::generate().card("laptop").unwrap(),
            ],
        )
        .unwrap();
        let body = snapshot.encoded_body().unwrap();
        let chunks: Vec<&[u8]> = body.chunks(BACKUP_CHUNK_BYTES).collect();
        let slot = (snapshot.generation % 2) as u8;
        let snapshot_id = sha256_hex(&body);
        let channel_keys = derive_channel_keys(channel).unwrap();
        let recipient = channel_keys.public_key();
        let chunk_hashes: Vec<String> =
            chunks.iter().map(|chunk| sha256_hex(chunk)).collect();
        let chunk_events: Vec<Event> = chunks
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                let payload = serde_json::to_string(&BackupChunk {
                    version: BACKUP_VERSION,
                    generation: snapshot.generation,
                    slot,
                    snapshot_id: snapshot_id.clone(),
                    index: index as u8,
                    data: URL_SAFE_NO_PAD.encode(bytes),
                })
                .unwrap();
                encrypted_carrier(
                    &owner,
                    recipient,
                    backup_chunk_kind(),
                    backup_dtag(BACKUP_CHUNK_DTAG, slot, Some(index)),
                    payload,
                )
                .unwrap()
            })
            .collect();
        let header_event = encrypted_carrier(
            &owner,
            recipient,
            backup_header_kind(),
            backup_dtag(BACKUP_HEADER_DTAG, slot, None),
            serde_json::to_string(&BackupHeader {
                version: BACKUP_VERSION,
                generation: snapshot.generation,
                slot,
                snapshot_id,
                chunks: chunks.len() as u8,
                peer_count: snapshot.peers.len() as u16,
                self_card: snapshot.self_card.encode(),
                chunk_hashes,
            })
            .unwrap(),
        )
        .unwrap();

        let header = decode_header(&channel_keys, &header_event).unwrap();
        let restored =
            assemble_snapshot(&channel_keys, owner.public_key(), &header, &chunk_events).unwrap();
        assert_eq!(restored.generation, 12);
        assert_eq!(restored.peers.len(), 2);

        assert!(
            assemble_snapshot(
                &channel_keys,
                owner.public_key(),
                &header,
                &chunk_events[1..],
            )
            .is_err()
        );
        assert!(
            decrypt_channel_carrier(
                Identity::generate().keys(),
                &header_event,
            )
            .is_err()
        );
    }
}
