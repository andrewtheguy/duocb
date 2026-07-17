//! Short, human-typable PIN used by quick mode's nostr signaling.
//!
//! In PIN quick mode the server shares its ephemeral node id through nostr without
//! any copy-paste: it shows a short PIN that **rotates every 60 seconds**. The PIN
//! is the only secret the client types; both sides turn it into a nostr keypair
//! (via [`derive_key_material`]) that locates and decrypts a single relay record
//! carrying the node id (see `crate::nostr`).
//!
//! The PIN alphabet is **Crockford base32** — unambiguous letters/numbers only (no
//! `I L O U`). It is always *displayed* uppercase and grouped (`XXXX-XXXX`); input is
//! case-insensitive, ignores dashes/spaces, and maps the look-alikes `I`/`L` → `1` and
//! `O` → `0` as a courtesy. The canonical form fed to the KDF is the de-grouped uppercase
//! string.
//!
//! The **first character partitions the alphabet by channel**: a first char in the lower
//! half (`0123456789ABCDEF`) marks a nostr-carrying PIN (the default nostr+LAN or the
//! internet-only channel), while the upper half (`GHJKMNPQRSTVWXYZ`) marks a
//! **LAN-only** PIN. The LAN-only channel speaks a DNS-SD/Bonjour dialect that is not
//! wire-compatible with the default channel's LAN responder (see `crate::lan`), so a joiner
//! must know which discovery to run *before* it resolves. Encoding that one bit in the PIN
//! lets the joiner infer the channel from the typed code alone — it never has to pick one.
//! See [`generate_pin`] (mint side) and [`pin_is_lan_only`] (join side).
//!
//! The last of the PIN's characters is a **check digit** (a position-weighted sum of the
//! preceding data characters), so a mistyped PIN is rejected on input rather than silently
//! deriving the wrong key. That leaves 7 random data characters, but the first carries only
//! ~4 bits (one of 16, not 32) because of the channel partition, so ~34 random bits total;
//! the check digit adds no secrecy, only typo rejection. The PIN is a quick-mode ephemeral
//! secret, rotated every 60s, so the 1-bit reduction is inconsequential.
//!
//! Because the PIN is short (~35 bits) and the encrypted record sits on public relays,
//! the key derivation is deliberately slow and memory-hard (**Argon2id**): a captured
//! record resists offline brute-force, and the 60-second rotation plus a short record TTL
//! bound the exposure window.
//!
//! Two independent keys are derived from a PIN, both with the same Argon2id work factor but
//! **domain-separated** salts (see [`derive_key_material`] and [`derive_auth_key_material`]):
//! - the *rendezvous* key ([`derive_key_material`], bucketed) locates & decrypts the relay
//!   record carrying the server's ephemeral node id, and
//! - the *auth* key ([`derive_auth_key_material`], **not** bucketed) proves mutual PIN
//!   possession in-band over the established connection (see `crate::pin_auth`).
//!
//! The auth key is deliberately bucket-independent: the client types one PIN and must derive
//! the same auth key regardless of which rotation bucket the server published under, so it
//! never has to guess the bucket. The server instead remembers the current and previous buckets'
//! PINs.

use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::Rng;

/// Crockford base32 alphabet: digits + uppercase letters minus the ambiguous `I L O U`.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Index into [`ALPHABET`] that splits it in half by channel. A PIN's first character comes
/// from the lower half (`< HALF`) for a nostr-carrying channel and the upper half (`>= HALF`)
/// for the LAN-only channel; see the module docs and [`pin_is_lan_only`].
const HALF: usize = ALPHABET.len() / 2;

/// Number of significant characters in a PIN (the canonical, de-grouped form). The last
/// is a check digit, leaving 7 random data characters (~35 bits).
pub const PIN_LEN: usize = 8;

/// Trailing characters of a PIN that form the check digit (typo detection).
const PIN_CHECK_LEN: usize = 1;
/// Random data characters: the PIN minus its check digit.
const PIN_DATA_LEN: usize = PIN_LEN - PIN_CHECK_LEN;

/// Rotation period, in seconds. A fresh PIN is minted (and displayed) this often; its relay
/// record is keyed under the wall-clock bucket at mint time, and the client searches a small
/// window of adjacent buckets, so a displayed PIN stays resolvable for its full period even
/// when the display window straddles a bucket boundary.
pub const BUCKET_SECS: u64 = 60;

/// Argon2id memory cost, in KiB (64 MiB).
const ARGON2_MEM_KIB: u32 = 64 * 1024;
/// Argon2id time cost (passes).
const ARGON2_TIME: u32 = 3;
/// Argon2id parallelism.
const ARGON2_LANES: u32 = 1;

/// Domain-separating salt prefix for the PIN *rendezvous* key derivation; the time bucket
/// is appended so each rotation derives an independent nostr key (see [`derive_key_material`]).
const KDF_SALT_DOMAIN: &[u8] = b"duocb:pin-rendezvous:v1";
/// Domain-separating salt for the PIN *auth* key derivation ([`derive_auth_key_material`]).
/// Deliberately carries **no** time bucket so both peers derive the same key from the PIN
/// string alone, and is distinct from [`KDF_SALT_DOMAIN`] so the auth key can never collide
/// with a rendezvous key.
const AUTH_KDF_SALT: &[u8] = b"duocb:pin-auth:v1";

/// Position-weighted check character over canonical data chars:
/// `sum(index(c) * (i + 1)) mod 32`, mapped back into the alphabet.
/// `data` must contain only `ALPHABET` bytes (guaranteed for canonical PINs). It catches
/// the common single-character typo and many transpositions — it is not a cryptographic
/// integrity check.
fn check_char(data: &[u8]) -> u8 {
    let mut sum: usize = 0;
    for (i, &b) in data.iter().enumerate() {
        let idx = ALPHABET.iter().position(|&a| a == b).unwrap_or(0);
        sum += idx * (i + 1);
    }
    ALPHABET[sum % ALPHABET.len()]
}

/// Generate a fresh random PIN in canonical form (`PIN_LEN` uppercase Crockford chars, no
/// grouping): `PIN_DATA_LEN` random data characters followed by a check digit. The **first**
/// character is drawn from the alphabet half selected by `lan_only` (upper half for the
/// LAN-only channel, lower half otherwise), so [`pin_is_lan_only`] can recover the channel
/// on the join side; the remaining data characters are uniform over the whole alphabet.
pub fn generate_pin(lan_only: bool) -> String {
    let mut rng = rand::rng();
    let mut out = String::with_capacity(PIN_LEN);
    // First data char: pick from the channel's 16-char half. 256 is a multiple of 16, so
    // `byte % HALF` is unbiased; the `lan_only` offset lands it in the upper or lower half.
    let base = if lan_only { HALF } else { 0 };
    let first: u8 = rng.random();
    out.push(ALPHABET[base + (first as usize % HALF)] as char);
    while out.len() < PIN_DATA_LEN {
        // 256 is a multiple of 32, so `byte % 32` is already unbiased; no rejection needed.
        let byte: u8 = rng.random();
        out.push(ALPHABET[(byte % 32) as usize] as char);
    }
    out.push(check_char(out.as_bytes()) as char);
    out
}

/// Whether a canonical PIN marks the **LAN-only** channel — i.e. its first character is in
/// the upper half of the alphabet (see [`generate_pin`] and the module docs). Input is
/// expected in canonical form (from [`normalize_pin`]); a leading char outside the alphabet
/// reads as not-LAN-only.
pub fn pin_is_lan_only(canonical_pin: &str) -> bool {
    canonical_pin
        .bytes()
        .next()
        .and_then(|b| ALPHABET.iter().position(|&a| a == b))
        .is_some_and(|idx| idx >= HALF)
}

/// Normalize user-typed input to the canonical PIN form, or `None` if it is not a valid
/// PIN. Strips spaces/dashes, uppercases, maps the look-alikes `I`/`L` → `1` and `O` → `0`,
/// requires exactly `PIN_LEN` Crockford characters, and verifies the trailing check digit
/// so a typo is rejected here rather than later as a failed lookup.
pub fn normalize_pin(input: &str) -> Option<String> {
    let mut out = String::with_capacity(PIN_LEN);
    for ch in input.chars() {
        match ch {
            ' ' | '-' | '\t' => continue,
            _ => {}
        }
        let up = ch.to_ascii_uppercase();
        let mapped = match up {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        };
        if !ALPHABET.contains(&(mapped as u8)) {
            return None;
        }
        out.push(mapped);
        if out.len() > PIN_LEN {
            return None;
        }
    }
    if out.len() != PIN_LEN {
        return None;
    }
    let (data, check) = out.as_bytes().split_at(PIN_DATA_LEN);
    if check[0] != check_char(data) {
        return None; // right shape, wrong check digit => typo
    }
    Some(out)
}

/// Format a canonical PIN for display: uppercase, split into two dash-separated groups
/// (`XXXX-XXXX` for the default 8-char PIN). Non-canonical input is returned uppercased
/// as-is.
pub fn format_pin(canonical: &str) -> String {
    if canonical.len() != PIN_LEN {
        return canonical.to_ascii_uppercase();
    }
    let mid = PIN_LEN / 2;
    format!("{}-{}", &canonical[..mid], &canonical[mid..])
}

/// Characters per display group: a PIN shows as two dash-separated groups of this many
/// (`XXXX-XXXX`), and the joiner's entry uses one text field per group.
pub const PIN_GROUP_LEN: usize = PIN_LEN / 2;

/// Sanitize user input to canonical PIN characters — uppercase, map the look-alikes
/// `I`/`L` → `1` and `O` → `0`, and drop separators and anything else outside the alphabet —
/// without a length cap or grouping. The two-group PIN entry feeds each field through this
/// and caps each to [`PIN_GROUP_LEN`] itself. Unlike [`normalize_pin`] it never rejects, so a
/// partially typed PIN keeps its valid characters; completeness (`pin_input_len`) and validity
/// ([`normalize_pin`]) are judged separately.
pub fn sanitize_pin_chars(input: &str) -> String {
    input
        .chars()
        .filter_map(|ch| {
            let mapped = match ch.to_ascii_uppercase() {
                'I' | 'L' => '1',
                'O' => '0',
                other => other,
            };
            ALPHABET.contains(&(mapped as u8)).then_some(mapped)
        })
        .collect()
}

/// Count the significant (canonical) characters in a PIN entry, ignoring dashes, spaces, and
/// anything else that isn't a real PIN character — so the caller can tell "still typing"
/// (`< PIN_LEN`) apart from "full length, verify the checksum" (`== PIN_LEN`).
pub fn pin_input_len(input: &str) -> usize {
    sanitize_pin_chars(input).chars().count()
}

/// Place two already-[`sanitize_pin_chars`]d entry groups into their final `(first, second)`
/// form, each capped to [`PIN_GROUP_LEN`]. When the first group has overflowed past a group's
/// length and the second is still empty — a paste of the whole code into the first field — the
/// overflow spills into the second group; otherwise each group is truncated independently. The
/// returned pair is what the two entry fields should hold.
pub fn split_pin_groups(first: &str, second: &str) -> (String, String) {
    let cap = |s: &str| -> String { s.chars().take(PIN_GROUP_LEN).collect() };
    if first.chars().count() > PIN_GROUP_LEN && second.is_empty() {
        let overflow = first.chars().skip(PIN_GROUP_LEN).take(PIN_GROUP_LEN).collect();
        (cap(first), overflow)
    } else {
        (cap(first), cap(second))
    }
}

/// The current rotation bucket: whole 60-second windows since the Unix epoch. The server
/// publishes under the current bucket; the client searches adjacent buckets.
pub fn current_bucket() -> u64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    secs / BUCKET_SECS
}

/// Run the shared Argon2id KDF over `canonical_pin` with the given `salt`, producing 32 bytes.
/// Both key derivations below use identical work factors and differ only in their salt.
fn argon2_key(canonical_pin: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(ARGON2_MEM_KIB, ARGON2_TIME, ARGON2_LANES, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; 32];
    argon2
        .hash_password_into(canonical_pin.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow::anyhow!("argon2 key derivation failed: {e}"))
        .context("deriving key material from PIN")?;
    Ok(out)
}

/// Derive 32 bytes of *rendezvous* key material from a canonical PIN and a rotation bucket via
/// Argon2id. Both peers run this on the same `(pin, bucket)` and get identical output, which
/// `crate::nostr` turns into the shared nostr keypair used to locate & decrypt the relay record.
pub fn derive_key_material(canonical_pin: &str, bucket: u64) -> Result<[u8; 32]> {
    let mut salt = Vec::with_capacity(KDF_SALT_DOMAIN.len() + 8);
    salt.extend_from_slice(KDF_SALT_DOMAIN);
    salt.extend_from_slice(&bucket.to_be_bytes());
    argon2_key(canonical_pin, &salt)
}

/// Derive 32 bytes of *auth* key material from a canonical PIN via Argon2id, **without** a time
/// bucket. Both peers run this on the same PIN string and get identical output, which
/// `crate::pin_auth` turns into the keypair that proves mutual PIN possession in-band. Being
/// bucket-independent lets the client derive the right key without knowing which rotation
/// bucket the server published under.
pub fn derive_auth_key_material(canonical_pin: &str) -> Result<[u8; 32]> {
    argon2_key(canonical_pin, AUTH_KDF_SALT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_pin_is_canonical_and_unambiguous() {
        for lan_only in [false, true] {
            for _ in 0..50 {
                let pin = generate_pin(lan_only);
                assert_eq!(pin.len(), PIN_LEN);
                assert!(pin.chars().all(|c| ALPHABET.contains(&(c as u8))));
                // No ambiguous characters are ever emitted.
                assert!(!pin.contains(['I', 'L', 'O', 'U']));
                // Normalizing a generated PIN is the identity.
                assert_eq!(normalize_pin(&pin).as_deref(), Some(pin.as_str()));
            }
        }
    }

    #[test]
    fn first_char_encodes_the_channel() {
        for _ in 0..200 {
            let lan = generate_pin(true);
            assert!(pin_is_lan_only(&lan), "LAN-only PIN {lan} must read as LAN-only");
            let first = lan.as_bytes()[0];
            assert!(
                ALPHABET[HALF..].contains(&first),
                "LAN-only first char {} must be in the upper half",
                first as char
            );

            let net = generate_pin(false);
            assert!(!pin_is_lan_only(&net), "default PIN {net} must not read as LAN-only");
            let first = net.as_bytes()[0];
            assert!(
                ALPHABET[..HALF].contains(&first),
                "default first char {} must be in the lower half",
                first as char
            );
        }
        // The two halves are disjoint and cover the whole alphabet.
        assert_eq!(HALF, 16);
        assert!(!pin_is_lan_only(""));
    }

    /// Build a valid canonical PIN from a 7-char data prefix by appending its check digit.
    fn pin_with_checksum(data: &str) -> String {
        assert_eq!(data.len(), PIN_DATA_LEN);
        let mut out = data.to_string();
        out.push(check_char(out.as_bytes()) as char);
        out
    }

    #[test]
    fn normalize_strips_grouping_and_maps_lookalikes() {
        // Use a valid canonical PIN so the checksum holds while the mapping is exercised.
        let canonical = pin_with_checksum("K7P29QX"); // 7 data chars + check digit
        let lower = canonical.to_ascii_lowercase();
        let mid = PIN_LEN / 2;
        // Dashes/spaces ignored, lowercase uppercased.
        let grouped = format!("{}-{}", &lower[..mid], &lower[mid..]);
        assert_eq!(normalize_pin(&grouped).as_deref(), Some(canonical.as_str()));
        let spaced = format!(" {} {} ", &canonical[..mid], &canonical[mid..]);
        assert_eq!(normalize_pin(&spaced).as_deref(), Some(canonical.as_str()));

        // Look-alikes map to digits: data "1100000" typed as "iLoO000".
        let mapped = pin_with_checksum("1100000");
        let check = &mapped[PIN_DATA_LEN..];
        // Re-type the 7 data chars with look-alikes ('i','L'->'1', 'o','O'->'0') and keep
        // the (look-alike-free) check digit; it must normalize back to the canonical PIN.
        let typed = format!("iLoO000{check}");
        assert_eq!(normalize_pin(&typed).as_deref(), Some(mapped.as_str()));
    }

    #[test]
    fn normalize_rejects_wrong_length_and_bad_chars() {
        assert!(normalize_pin("K7P29QX").is_none()); // too short
        assert!(normalize_pin("K7P29QXMZ").is_none()); // too long
        assert!(normalize_pin("K7P29QX!").is_none()); // bad char
        assert!(normalize_pin("").is_none());
    }

    #[test]
    fn normalize_rejects_single_char_typo() {
        let pin = generate_pin(false);
        // Flip the first data char to a different alphabet symbol; the check digit no
        // longer matches, so the typo is caught.
        let first = pin.as_bytes()[0];
        let replacement = if first == b'0' { '1' } else { '0' };
        let mut bytes = pin.clone().into_bytes();
        bytes[0] = replacement as u8;
        let typoed = String::from_utf8(bytes).unwrap();
        assert_ne!(typoed, pin);
        assert!(
            normalize_pin(&typoed).is_none(),
            "a single-character typo must fail the checksum"
        );
    }

    #[test]
    fn generated_pins_always_validate() {
        for _ in 0..200 {
            let pin = generate_pin(rand::rng().random());
            assert_eq!(
                normalize_pin(&pin).as_deref(),
                Some(pin.as_str()),
                "a freshly generated PIN must pass its own checksum"
            );
        }
    }

    #[test]
    fn format_groups_into_two_halves() {
        let canonical = pin_with_checksum("K7P29QX");
        let mid = PIN_LEN / 2;
        let expected = format!("{}-{}", &canonical[..mid], &canonical[mid..]);
        assert_eq!(format_pin(&canonical), expected);
        // Round-trips back through normalize.
        assert_eq!(
            normalize_pin(&format_pin(&canonical)).as_deref(),
            Some(canonical.as_str())
        );
    }

    #[test]
    fn sanitize_pin_chars_uppercases_maps_and_drops_noise() {
        assert_eq!(sanitize_pin_chars("ab"), "AB");
        // Uppercases and preserves order; no length cap here (the caller caps per group).
        assert_eq!(sanitize_pin_chars("abcdefghjk"), "ABCDEFGHJK");
        // Separators and stray characters are dropped; look-alikes map to digits.
        assert_eq!(sanitize_pin_chars("ab cd-e"), "ABCDE");
        assert_eq!(sanitize_pin_chars("iLoO12!3"), "1100123");
        // Already-canonical input is a fixed point (safe to reapply every keystroke).
        assert_eq!(sanitize_pin_chars("K7P29QX"), "K7P29QX");
        // The length count ignores dashes/spaces and matches the significant chars.
        assert_eq!(pin_input_len(""), 0);
        assert_eq!(pin_input_len("ab-c"), 3);
        assert_eq!(pin_input_len("K7P2-9QX!"), 7);
        assert_eq!(PIN_GROUP_LEN * 2, PIN_LEN);
    }

    #[test]
    fn split_pin_groups_spills_overflow_and_truncates() {
        let g = PIN_GROUP_LEN;
        // Overflow: a full code pasted into the first field spills into the
        // empty second group, each capped to a group's length.
        assert_eq!(
            split_pin_groups("ABCDEFGH", ""),
            ("ABCD".to_string(), "EFGH".to_string())
        );
        // Overflow beyond a full PIN drops the excess (second group still caps).
        assert_eq!(
            split_pin_groups("ABCDEFGHJK", ""),
            ("ABCD".to_string(), "EFGH".to_string())
        );
        // Empty second group, first within a group's length: no spill.
        assert_eq!(
            split_pin_groups("AB", ""),
            ("AB".to_string(), String::new())
        );
        // Normal truncation: the second group is non-empty, so the first never
        // spills into it — each is truncated independently.
        assert_eq!(
            split_pin_groups("ABCDEF", "GHIJKL"),
            ("ABCD".to_string(), "GHIJ".to_string())
        );
        // Both already within bounds: returned unchanged.
        assert_eq!(
            split_pin_groups("ABCD", "EFGH"),
            ("ABCD".to_string(), "EFGH".to_string())
        );
        assert_eq!(g, "ABCD".chars().count());
    }

    #[test]
    fn key_material_is_deterministic_and_bucket_pin_specific() {
        let pin = pin_with_checksum("K7P29QX");
        let a = derive_key_material(&pin, 100).unwrap();
        let a_again = derive_key_material(&pin, 100).unwrap();
        assert_eq!(a, a_again, "same pin + bucket must derive the same key");

        let other_bucket = derive_key_material(&pin, 101).unwrap();
        assert_ne!(
            a, other_bucket,
            "a different bucket must derive a different key"
        );

        let other_pin = pin_with_checksum("9QXMK7P");
        let other = derive_key_material(&other_pin, 100).unwrap();
        assert_ne!(a, other, "a different pin must derive a different key");
    }

    #[test]
    fn auth_key_material_is_deterministic_bucket_independent_and_pin_specific() {
        let pin = pin_with_checksum("K7P29QX");
        let a = derive_auth_key_material(&pin).unwrap();
        let a_again = derive_auth_key_material(&pin).unwrap();
        assert_eq!(a, a_again, "same pin must derive the same auth key");

        let other = derive_auth_key_material(&pin_with_checksum("9QXMK7P")).unwrap();
        assert_ne!(a, other, "a different pin must derive a different auth key");

        // Domain separation: the auth key must never equal a rendezvous key for the same pin,
        // at any bucket.
        for bucket in [0u64, 100, 12345] {
            assert_ne!(
                a,
                derive_key_material(&pin, bucket).unwrap(),
                "auth key collided with the rendezvous key at bucket {bucket}"
            );
        }
    }
}
