//! Persistent configure-mode identity, portable signed peer cards, and the
//! optional Nostr backup channel.
//!
//! These credentials are deliberately unrelated to iroh's endpoint key. An
//! [`Identity`] authenticates a duocb installation for its lifetime; iroh keys
//! are short-lived transport identities used only to establish QUIC.
//!
//! An [`IdentityCard`] — the token one device hands another to be trusted —
//! carries a mandatory expiry and lasts [`CARD_TTL_SECS`]. Cards never travel
//! over the wire, so expiry is enforced by each side against its own stored
//! copy: pairing is refused once that copy lapses, and the only way back is for
//! the owner to hand over a fresh card.

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nostr_sdk::prelude::*;
use ::rand::RngCore as _;
use nostr_sdk::prelude::secp256k1::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::{display_identity, split_display_identity, validate_name};

pub const MAX_TRUSTED_PEERS: usize = 128;
pub const MAX_CARD_SIZE: usize = 2 * 1024;
pub const IDENTITY_CARD_KIND: u16 = 30382;
const IDENTITY_CARD_DTAG: &str = "duocb:identity-card:v3";
const IDENTITY_CARD_VERSION: u32 = 3;
const AUTH_SIGNATURE_DOMAIN: &[u8] = b"duocb:key-auth:v3\0";

/// How long a freshly minted card stays usable. Trust is not permanent: a
/// pairing that nobody refreshes lapses on its own, and there is no renewal
/// path other than the owner handing over a new card.
pub const CARD_TTL_SECS: u64 = 30 * 24 * 60 * 60;
/// A card issued slightly in the future — the peer's clock runs fast — is still
/// honoured within this window. Beyond it the issue time is treated as bogus,
/// which bounds how far a broken clock can stretch a card's real lifetime.
pub const CLOCK_SKEW_GRACE_SECS: u64 = 5 * 60;
/// Re-mint the local self-card once it has less than this left, so the card the
/// user copies always has most of its life ahead of it.
pub const CARD_RENEW_BEFORE_SECS: u64 = 7 * 24 * 60 * 60;

/// Seconds since the Unix epoch, the clock all card expiry is judged against.
pub fn unix_now() -> u64 {
    Timestamp::now().as_secs()
}

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

    /// Mint a card valid for [`CARD_TTL_SECS`] from now.
    pub fn card(&self, name: &str, suffix: &str) -> Result<IdentityCard> {
        self.card_issued_at(name, suffix, unix_now())
    }

    /// Mint a card with an explicit issue time. Backdating one past
    /// [`CARD_TTL_SECS`] is how tests produce an expired card without waiting;
    /// production code wants [`Self::card`].
    pub fn card_issued_at(&self, name: &str, suffix: &str, issued_at: u64) -> Result<IdentityCard> {
        validate_name(name)?;
        let name = display_identity(name, suffix);
        split_display_identity(&name)?;
        let expires_at = issued_at + CARD_TTL_SECS;
        let content = serde_json::to_string(&CardContent {
            version: IDENTITY_CARD_VERSION,
            name,
            expires_at,
        })
        .context("serializing identity card")?;
        // The issue time is pinned rather than left to the builder's clock so
        // `expires_at - created_at` is exactly the TTL, which `from_event`
        // re-checks on the other side.
        let event = EventBuilder::new(Kind::from_u16(IDENTITY_CARD_KIND), content)
            .tags([
                Tag::identifier(IDENTITY_CARD_DTAG),
                Tag::expiration(Timestamp::from_secs(expires_at)),
            ])
            .custom_created_at(Timestamp::from_secs(issued_at))
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
    /// Absolute Unix expiry. Mandatory: a card without one does not parse.
    expires_at: u64,
}

/// A verified portable identity card.
///
/// Parsing is deliberately clock-free: it proves the card is well formed and
/// authentic, never that it is still current. Expiry is a separate decision
/// made by [`Self::is_valid_at`] at the points that act on trust, so a lapsed
/// card still loads from disk and can be shown to the user instead of silently
/// vanishing from the config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityCard {
    event: Event,
    name: String,
    expires_at: u64,
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
        split_display_identity(&content.name)?;
        // Expiry checks that compare only signed fields against each other, so
        // parsing stays deterministic and independent of the local clock.
        let issued_at = event.created_at.as_secs();
        if content.expires_at <= issued_at {
            anyhow::bail!("identity card expires no later than it was issued");
        }
        if content.expires_at - issued_at > CARD_TTL_SECS {
            anyhow::bail!("identity card claims a lifetime longer than {CARD_TTL_SECS} seconds");
        }
        // The NIP-40 tag is redundant with the payload, but only if it agrees:
        // a card must not read as long-lived to one reader and short-lived to
        // another depending on which copy of the expiry it happens to trust.
        if event.tags.expiration().map(Timestamp::as_secs) != Some(content.expires_at) {
            anyhow::bail!("identity card expiration tag does not match its payload");
        }
        let card = Self {
            event,
            name: content.name,
            expires_at: content.expires_at,
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

    pub fn short_name(&self) -> &str {
        split_display_identity(&self.name)
            .expect("verified identity-card name remains valid")
            .0
    }

    pub fn suffix(&self) -> &str {
        split_display_identity(&self.name)
            .expect("verified identity-card name remains valid")
            .1
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

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Whether this card may still be acted on at `now` (Unix seconds).
    ///
    /// The issue-time half rejects a card stamped implausibly far in the
    /// future: the payload check in `from_event` bounds a card's lifetime
    /// relative to its own issue time, so without this a peer whose clock is
    /// years fast could hand out a card that outlives the policy by exactly
    /// that skew.
    pub fn is_valid_at(&self, now: u64) -> bool {
        now < self.expires_at && self.created_at() <= now.saturating_add(CLOCK_SKEW_GRACE_SECS)
    }

    /// [`Self::is_valid_at`] against the local clock.
    pub fn is_expired(&self) -> bool {
        !self.is_valid_at(unix_now())
    }

    /// Seconds of life left at `now`; zero once the card is unusable.
    pub fn remaining_secs_at(&self, now: u64) -> u64 {
        if self.is_valid_at(now) {
            self.expires_at - now
        } else {
            0
        }
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

        let card = identity.card("mac-book", "a7B2c3D4").unwrap();
        let parsed = IdentityCard::parse(&card.encode()).unwrap();
        assert_eq!(parsed.name(), "mac-book_a7B2c3D4");
        assert_eq!(parsed.short_name(), "mac-book");
        assert_eq!(parsed.suffix(), "a7B2c3D4");
        assert_eq!(parsed.public_key(), identity.public_key());
        assert_eq!(parsed.expires_at(), parsed.created_at() + CARD_TTL_SECS);
        assert!(!parsed.is_expired());
    }

    /// A card is usable up to its expiry and dead the second after, and the
    /// whole judgement comes from the caller's clock rather than the card.
    #[test]
    fn card_validity_is_bounded_by_its_expiry() {
        let issued_at = 1_700_000_000;
        let card = Identity::generate()
            .card_issued_at("desktop", "a7B2c3D4", issued_at)
            .unwrap();
        let expires_at = issued_at + CARD_TTL_SECS;
        assert_eq!(card.expires_at(), expires_at);

        assert!(card.is_valid_at(issued_at));
        assert!(card.is_valid_at(expires_at - 1));
        assert!(!card.is_valid_at(expires_at));
        assert_eq!(card.remaining_secs_at(expires_at - 90), 90);
        assert_eq!(card.remaining_secs_at(expires_at), 0);
    }

    /// An aged-out card must still parse — config load and backup decode run
    /// through the same path and cannot be allowed to fail on stale trust.
    #[test]
    fn expired_cards_still_parse_but_are_not_valid() {
        let issued_at = unix_now() - CARD_TTL_SECS - 1;
        let card = Identity::generate()
            .card_issued_at("laptop", "a7B2c3D4", issued_at)
            .unwrap();
        let parsed = IdentityCard::parse(&card.encode()).unwrap();
        assert_eq!(parsed.name(), "laptop_a7B2c3D4");
        assert!(parsed.is_expired());
    }

    /// A peer whose clock is far ahead cannot mint a card that outlives the
    /// policy, even though the payload's own lifetime check passes.
    #[test]
    fn future_dated_cards_are_not_valid() {
        let now = unix_now();
        let card = Identity::generate()
            .card_issued_at("desktop", "a7B2c3D4", now + 10 * CARD_TTL_SECS)
            .unwrap();
        assert!(IdentityCard::parse(&card.encode()).is_ok());
        assert!(card.is_expired());
        assert!(card.is_valid_at(now + 10 * CARD_TTL_SECS));
    }

    /// Hand-built cards that disagree with the format's expiry rules are
    /// rejected outright, so a peer cannot self-assert unbounded trust.
    #[test]
    fn cards_with_dishonest_expiry_are_rejected() {
        let keys = Keys::generate();
        let issued_at = 1_700_000_000;
        let mint = |expires_at: u64, tag_expires_at: u64| {
            let content = serde_json::to_string(&CardContent {
                version: IDENTITY_CARD_VERSION,
                name: "desktop_a7B2c3D4".to_string(),
                expires_at,
            })
            .unwrap();
            EventBuilder::new(Kind::from_u16(IDENTITY_CARD_KIND), content)
                .tags([
                    Tag::identifier(IDENTITY_CARD_DTAG),
                    Tag::expiration(Timestamp::from_secs(tag_expires_at)),
                ])
                .custom_created_at(Timestamp::from_secs(issued_at))
                .sign_with_keys(&keys)
                .unwrap()
                .as_json()
        };

        let honest = issued_at + CARD_TTL_SECS;
        assert!(IdentityCard::parse(&mint(honest, honest)).is_ok());
        // Longer than policy allows.
        assert!(IdentityCard::parse(&mint(honest + 1, honest + 1)).is_err());
        // Already dead when signed.
        assert!(IdentityCard::parse(&mint(issued_at, issued_at)).is_err());
        // Payload and NIP-40 tag disagree.
        assert!(IdentityCard::parse(&mint(honest, honest - 60)).is_err());
    }

    /// The expiry is signed material, not an annotation a holder can edit.
    #[test]
    fn extending_a_card_expiry_breaks_its_signature() {
        let card = Identity::generate()
            .card_issued_at("desktop", "a7B2c3D4", 1_700_000_000)
            .unwrap();
        let stretched = card.encode().replace(
            &(1_700_000_000u64 + CARD_TTL_SECS).to_string(),
            &(1_700_000_000u64 + 10 * CARD_TTL_SECS).to_string(),
        );
        assert!(IdentityCard::parse(&stretched).is_err());
    }

    #[test]
    fn card_tampering_is_rejected() {
        let card = Identity::generate()
            .card("desktop", "a7B2c3D4")
            .unwrap()
            .encode();
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
