//! Persistent configure-mode identity, portable signed peer cards, and the
//! optional Nostr backup channel.
//!
//! These credentials are deliberately unrelated to iroh's endpoint key. An
//! [`Identity`] authenticates a duocb installation for its lifetime; iroh keys
//! are short-lived transport identities used only to establish QUIC.

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nostr_sdk::prelude::*;
use ::rand::RngCore as _;
use nostr_sdk::prelude::secp256k1::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::validate_name;

pub const MAX_TRUSTED_PEERS: usize = 128;
pub const MAX_CARD_SIZE: usize = 2 * 1024;
pub const IDENTITY_CARD_KIND: u16 = 30382;
const IDENTITY_CARD_DTAG: &str = "duocb:identity-card:v1";
const IDENTITY_CARD_VERSION: u32 = 1;
const AUTH_SIGNATURE_DOMAIN: &[u8] = b"duocb:key-auth:v3\0";

/// Persisted, application-level identity. Debug output never exposes the secret.
#[derive(Clone)]
pub struct Identity {
    keys: Keys,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("public_key", &self.keys.public_key())
            .finish()
    }
}

impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        self.public_key() == other.public_key()
    }
}

impl Eq for Identity {}

impl Identity {
    pub fn generate() -> Self {
        Self {
            keys: Keys::generate(),
        }
    }

    pub fn parse_nsec(input: &str) -> Result<Self> {
        let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        if !compact.starts_with("nsec1") {
            anyhow::bail!("identity private key must be an nsec");
        }
        let keys = Keys::parse(&compact).context("invalid identity private key")?;
        Ok(Self { keys })
    }

    pub fn to_nsec(&self) -> String {
        self.keys
            .secret_key()
            .to_bech32()
            .expect("a valid secret key always has a bech32 representation")
    }

    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    pub fn to_npub(&self) -> String {
        self.public_key()
            .to_bech32()
            .expect("a valid public key always has a bech32 representation")
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    pub fn card(&self, name: &str) -> Result<IdentityCard> {
        validate_name(name)?;
        let content = serde_json::to_string(&CardContent {
            version: IDENTITY_CARD_VERSION,
            name: name.to_string(),
        })
        .context("serializing identity card")?;
        let event = EventBuilder::new(Kind::from_u16(IDENTITY_CARD_KIND), content)
            .tags([Tag::identifier(IDENTITY_CARD_DTAG)])
            .sign_with_keys(&self.keys)
            .context("signing identity card")?;
        IdentityCard::from_event(event)
    }

    pub fn sign_auth(&self, transcript: &[u8]) -> String {
        let message = Message::from_digest(auth_digest(transcript));
        self.keys.sign_schnorr(&message).to_string()
    }
}

fn auth_digest(transcript: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUTH_SIGNATURE_DOMAIN);
    hasher.update(transcript);
    hasher.finalize().into()
}

pub fn verify_auth_signature(
    public_key: PublicKey,
    transcript: &[u8],
    signature: &str,
) -> Result<()> {
    let signature: Signature = signature
        .parse()
        .context("authentication proof is not a Schnorr signature")?;
    let xonly = public_key
        .xonly()
        .context("authentication public key is invalid")?;
    let message = Message::from_digest(auth_digest(transcript));
    SECP256K1
        .verify_schnorr(&signature, &message, &xonly)
        .context("authentication proof did not verify")
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CardContent {
    version: u32,
    name: String,
}

/// A verified portable identity card.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityCard {
    event: Event,
    name: String,
}

impl IdentityCard {
    fn from_event(event: Event) -> Result<Self> {
        event.verify().context("identity card signature is invalid")?;
        if event.kind != Kind::from_u16(IDENTITY_CARD_KIND) {
            anyhow::bail!("identity card has the wrong event kind");
        }
        if event.tags.identifier() != Some(IDENTITY_CARD_DTAG) {
            anyhow::bail!("identity card has the wrong identifier");
        }
        let content: CardContent =
            serde_json::from_str(&event.content).context("identity card payload is invalid")?;
        if content.version != IDENTITY_CARD_VERSION {
            anyhow::bail!(
                "identity card version {} is unsupported",
                content.version
            );
        }
        validate_name(&content.name)?;
        let card = Self {
            event,
            name: content.name,
        };
        if card.encode().len() > MAX_CARD_SIZE {
            anyhow::bail!("identity card exceeds {MAX_CARD_SIZE} bytes");
        }
        Ok(card)
    }

    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.len() > MAX_CARD_SIZE {
            anyhow::bail!("identity card exceeds {MAX_CARD_SIZE} bytes");
        }
        let event = Event::from_json(trimmed).context("identity card is not valid JSON")?;
        Self::from_event(event)
    }

    pub fn encode(&self) -> String {
        self.event.as_json()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn public_key(&self) -> PublicKey {
        self.event.pubkey
    }

    pub fn npub(&self) -> String {
        self.public_key()
            .to_bech32()
            .expect("verified public key is encodable")
    }

    pub fn created_at(&self) -> u64 {
        self.event.created_at.as_secs()
    }
}

/// Standalone, non-authenticating channel used only for Nostr peer backups.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DirectoryChannel([u8; 16]);

impl std::fmt::Debug for DirectoryChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DirectoryChannel(***)")
    }
}

impl DirectoryChannel {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        ::rand::rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn parse(input: &str) -> Result<Self> {
        let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        let parts: Vec<&str> = compact.split('.').collect();
        if parts.len() != 3 || parts[0] != "dc1" {
            anyhow::bail!("channel must have the form dc1.<channel>.<checksum>");
        }
        if parts[1].len() != 22 || parts[2].len() != 3 {
            anyhow::bail!("channel has an invalid length");
        }
        let raw = URL_SAFE_NO_PAD
            .decode(parts[1])
            .context("channel is not valid base64url")?;
        let bytes: [u8; 16] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("channel must contain exactly 128 bits"))?;
        let checksum = URL_SAFE_NO_PAD
            .decode(parts[2])
            .context("channel checksum is not valid base64url")?;
        if checksum != channel_checksum(&bytes).to_be_bytes() {
            anyhow::bail!("channel checksum is invalid");
        }
        Ok(Self(bytes))
    }

    pub fn encode(&self) -> String {
        format!(
            "dc1.{}.{}",
            URL_SAFE_NO_PAD.encode(self.0),
            URL_SAFE_NO_PAD.encode(channel_checksum(&self.0).to_be_bytes())
        )
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

fn channel_checksum(channel: &[u8; 16]) -> u16 {
    let mut bytes = b"duocb:directory-channel:v1".to_vec();
    bytes.extend_from_slice(channel);
    crc16_ccitt_false(&bytes)
}

fn crc16_ccitt_false(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_nsec_round_trip_and_card_verifies() {
        let identity = Identity::generate();
        let restored = Identity::parse_nsec(&identity.to_nsec()).unwrap();
        assert_eq!(identity.public_key(), restored.public_key());
        assert_eq!(identity.to_npub(), restored.to_npub());

        let card = identity.card("mac-book").unwrap();
        let parsed = IdentityCard::parse(&card.encode()).unwrap();
        assert_eq!(parsed.name(), "mac-book");
        assert_eq!(parsed.public_key(), identity.public_key());
    }

    #[test]
    fn card_tampering_is_rejected() {
        let card = Identity::generate().card("desktop").unwrap().encode();
        assert!(IdentityCard::parse(&card.replace("desktop", "laptop")).is_err());
    }

    #[test]
    fn channel_round_trip_checksum_and_uniqueness() {
        let first = DirectoryChannel::generate();
        let second = DirectoryChannel::generate();
        assert_ne!(first, second);
        assert_eq!(DirectoryChannel::parse(&first.encode()).unwrap(), first);

        let mut broken = first.encode();
        let last = broken.pop().unwrap();
        broken.push(if last == 'A' { 'B' } else { 'A' });
        assert!(DirectoryChannel::parse(&broken).is_err());
    }

    #[test]
    fn authentication_signatures_are_identity_bound() {
        let a = Identity::generate();
        let b = Identity::generate();
        let transcript = b"client|server|nonce-a|nonce-b";
        let signature = a.sign_auth(transcript);
        verify_auth_signature(a.public_key(), transcript, &signature).unwrap();
        assert!(verify_auth_signature(b.public_key(), transcript, &signature).is_err());
        assert!(verify_auth_signature(a.public_key(), b"other", &signature).is_err());
    }
}
