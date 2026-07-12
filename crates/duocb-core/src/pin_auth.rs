//! Quick-mode PIN mutual authentication, carried in-band over the established connection.
//!
//! In PIN quick mode the relay record carries **only** the server's ephemeral node id (encrypted
//! under the PIN rendezvous key; see `crate::nostr`). No token is ever placed on a relay.
//! Instead, once the client has dialed that node id, both peers prove they hold the same PIN
//! with a short challenge-response on the first bidirectional stream — the same stream the
//! token handshake uses, just a different [`AuthRequest`] method.
//!
//! ```text
//! D→L: AuthRequest::Pin { nonce_d }          # dialer opens with a random nonce
//! L→D: PinChallenge     { nonce_l }          # listener's random nonce
//! D→L: PinResponse      { proof_d }          # proof_d = seal(k, "dialer"   || nonce_d || nonce_l)
//! L→D: PinConfirm       { accepted, proof_l } # proof_l = seal(k, "listener" || nonce_d || nonce_l)
//! ```
//!
//! `k` is a keypair derived from the **PIN string alone** ([`derive_auth_keys`], bucket-independent),
//! and `seal`/`open` are NIP-44 self-encryption under `k` — the same authenticated primitive used
//! for the relay record. NIP-44's MAC means a wrong PIN yields a wrong `k` and `open` fails, so an
//! impostor cannot forge a proof. The direction strings domain-separate the two proofs (a proof for
//! one direction can't be replayed as the other) and both nonces bind the exchange to this one
//! handshake (no cross-handshake replay).
//!
//! Because the listener mints a fresh PIN every rotation bucket, it verifies `proof_d` against the
//! last few buckets' keys (its recent-PIN cache) — mirroring the dialer's adjacent-bucket look-back
//! when it fetched the node id. QUIC/TLS hides these proofs from passive network and relay observers
//! and binds the connection to the peer's node id (its public key). This construction is not a PAKE:
//! a party that can observe a decrypted proof transcript can test PIN guesses offline, as can anyone
//! archiving the public PIN-derived rendezvous event. Argon2id and the short recent-PIN acceptance
//! window mitigate that risk; they do not eliminate the offline verifier. Once the first peer has
//! claimed the server, however, the PIN-derived proof is insufficient on its own: a reconnect must
//! also present the claimed endpoint identity through QUIC/TLS. The PIN does not derive or reveal
//! QUIC's independently negotiated traffic-encryption keys.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nostr_sdk::prelude::*;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

// `nostr_sdk::prelude` glob-imports its own (older) `rand`, so refer to our crate's rand
// explicitly via the leading `::`.
use ::rand::RngCore;

use crate::protocol::{
    AuthRequest, MAX_CONTROL_MESSAGE_SIZE, PinChallenge, PinConfirm, PinResponse,
    decode_pin_challenge, decode_pin_confirm, decode_pin_response, encode_auth_request,
    encode_pin_challenge, encode_pin_confirm, encode_pin_response, read_length_prefixed,
};

/// Domain separator baked into every proof plaintext, versioning the construction.
const PROOF_DOMAIN: &str = "duocb:pin-auth:v1";
/// Length of a challenge nonce, in bytes (before base64url encoding).
const NONCE_LEN: usize = 32;

/// Which side produced a proof. Domain-separates the two directions so a proof sealed by one side
/// can never be accepted as the other's.
#[derive(Clone, Copy)]
enum Direction {
    Dialer,
    Listener,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::Dialer => "dialer",
            Direction::Listener => "listener",
        }
    }
}

/// Derive the PIN auth keypair from a canonical PIN string. Both peers run this on the same PIN and
/// get the same keypair, which seals/opens the challenge-response proofs. Bucket-independent, so the
/// dialer never has to know which rotation bucket the listener published under.
pub fn derive_auth_keys(canonical_pin: &str) -> Result<Keys> {
    let material = crate::pin::derive_auth_key_material(canonical_pin)?;
    let secret = SecretKey::from_slice(&material).context("deriving PIN auth secret key")?;
    Ok(Keys::new(secret))
}

/// Generate a fresh random challenge nonce, base64url-encoded for JSON transport.
pub fn generate_nonce() -> String {
    let mut bytes = [0u8; NONCE_LEN];
    ::rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The exact plaintext a proof authenticates: domain, direction, and both nonces.
fn proof_plaintext(dir: Direction, nonce_d: &str, nonce_l: &str) -> String {
    format!("{PROOF_DOMAIN}|{}|{nonce_d}|{nonce_l}", dir.as_str())
}

/// Seal a proof for `dir` binding both nonces, under the PIN-derived key (NIP-44 self-encryption).
fn seal_proof(keys: &Keys, dir: Direction, nonce_d: &str, nonce_l: &str) -> Result<String> {
    nip44::encrypt(
        keys.secret_key(),
        &keys.public_key(),
        proof_plaintext(dir, nonce_d, nonce_l),
        nip44::Version::V2,
    )
    .context("sealing PIN auth proof")
}

/// Verify a proof for `dir`: it must decrypt under `keys` (NIP-44 MAC) *and* the plaintext must
/// match the expected domain/direction/nonces. Constant-time plaintext compare.
fn verify_proof(keys: &Keys, dir: Direction, nonce_d: &str, nonce_l: &str, proof: &str) -> bool {
    let Ok(plaintext) = nip44::decrypt(keys.secret_key(), &keys.public_key(), proof) else {
        return false;
    };
    let expected = proof_plaintext(dir, nonce_d, nonce_l);
    plaintext.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// Drive the dialer's half of the PIN handshake to completion on an opened bi stream.
///
/// Writes the initial [`AuthRequest::Pin`], answers the listener's challenge, and verifies the
/// listener's proof. Returns `Ok(())` only when the listener both accepted our proof and proved it
/// holds the same PIN. Imposes no timeout — the caller wraps the whole exchange.
pub async fn dialer_handshake<W, R>(send: &mut W, recv: &mut R, canonical_pin: &str) -> Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    // Argon2id is deliberately slow and memory-hard; run it off the async
    // executor so it cannot stall other tasks on this worker.
    let keys = tokio::task::spawn_blocking({
        let pin = canonical_pin.to_string();
        move || derive_auth_keys(&pin)
    })
    .await
    .context("PIN key-derivation task failed")??;
    let nonce_d = generate_nonce();

    // 1. Open with the PIN method + our nonce.
    write_frame(send, &encode_auth_request(&AuthRequest::pin(&nonce_d))?).await?;

    // 2. Listener's challenge.
    let challenge =
        decode_pin_challenge(&read_length_prefixed(recv, MAX_CONTROL_MESSAGE_SIZE).await?)
            .context("reading PIN challenge")?;
    let nonce_l = challenge.nonce;

    // 3. Prove we hold the PIN.
    let proof_d = seal_proof(&keys, Direction::Dialer, &nonce_d, &nonce_l)?;
    write_frame(send, &encode_pin_response(&PinResponse::new(proof_d))?).await?;

    // 4. Verdict + the listener's own proof.
    let confirm = decode_pin_confirm(&read_length_prefixed(recv, MAX_CONTROL_MESSAGE_SIZE).await?)
        .context("reading PIN confirm")?;
    if !confirm.accepted {
        let reason = confirm.reason.unwrap_or_else(|| "unknown".to_string());
        anyhow::bail!("PIN authentication rejected: {reason}");
    }
    let proof_l = confirm
        .proof
        .context("listener accepted but sent no proof")?;
    if !verify_proof(&keys, Direction::Listener, &nonce_d, &nonce_l, &proof_l) {
        anyhow::bail!("listener failed to prove PIN possession (wrong peer?)");
    }
    Ok(())
}

/// Drive the listener's half of the PIN handshake, after the opening [`AuthRequest::Pin`] has
/// already been read off the stream (the listener reads it to choose the auth method).
///
/// `candidates` are the PIN auth keypairs for the recent rotation buckets; the dialer's proof is
/// verified against each. Once a candidate verifies the proof, `commit` is invoked with it **before**
/// acceptance is sent: returning `false` (e.g. another peer won the one-pair claim first) turns this
/// into a rejection, so a race loser is never told it was accepted. Returns `Ok(matched_key)` — the
/// candidate key that verified the proof — when one matches and `commit` accepts it (and our proof
/// has been sent), so the caller can retain it to re-authenticate a reconnecting peer after the PIN
/// has rotated out of the recent cache. Otherwise sends a rejection and returns `Err`.
pub async fn listener_handshake<W, R, F>(
    send: &mut W,
    recv: &mut R,
    candidates: &[Keys],
    nonce_d: &str,
    commit: F,
) -> Result<Keys>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    F: FnOnce(&Keys) -> bool,
{
    let nonce_l = generate_nonce();

    // 2. Send our challenge.
    write_frame(send, &encode_pin_challenge(&PinChallenge::new(&nonce_l))?).await?;

    // 3. Read the dialer's proof and match it against each recent PIN.
    let response =
        decode_pin_response(&read_length_prefixed(recv, MAX_CONTROL_MESSAGE_SIZE).await?)
            .context("reading PIN response")?;
    let matched = candidates
        .iter()
        .find(|k| verify_proof(k, Direction::Dialer, nonce_d, &nonce_l, &response.proof));

    // 4. Confirm (with our own proof) or reject. Even once the proof verifies, `commit` has the
    //    final say *before* acceptance is written, so a peer that loses the one-pair race is
    //    rejected rather than briefly told it was accepted and then dropped.
    match matched {
        Some(keys) if commit(keys) => {
            let proof_l = seal_proof(keys, Direction::Listener, nonce_d, &nonce_l)?;
            write_frame(send, &encode_pin_confirm(&PinConfirm::accepted(proof_l))?).await?;
            Ok((*keys).clone())
        }
        Some(_) => {
            write_frame(
                send,
                &encode_pin_confirm(&PinConfirm::rejected(
                    "listener already paired with another device",
                ))?,
            )
            .await?;
            anyhow::bail!("valid PIN but the listener paired with another device first");
        }
        None => {
            write_frame(
                send,
                &encode_pin_confirm(&PinConfirm::rejected("PIN authentication failed"))?,
            )
            .await?;
            anyhow::bail!("no recent PIN verified the dialer's proof (wrong or expired PIN)");
        }
    }
}

/// Write a length-prefixed frame and flush, so a single-stream request/response never stalls with
/// bytes stuck in a local send buffer.
async fn write_frame<W>(send: &mut W, frame: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    send.write_all(frame).await?;
    send.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A valid canonical PIN (7 data chars + check digit) for tests.
    fn test_pin() -> String {
        crate::pin::generate_pin()
    }

    /// Read the opening AuthRequest and return its PIN nonce, mirroring how the runtime reads the
    /// request before dispatching to the listener half.
    async fn read_pin_request<R: AsyncRead + Unpin>(recv: &mut R) -> Result<String> {
        match crate::protocol::decode_auth_request(
            &read_length_prefixed(recv, MAX_CONTROL_MESSAGE_SIZE).await?,
        )? {
            AuthRequest::Pin { nonce, .. } => Ok(nonce),
            AuthRequest::Token { .. } => anyhow::bail!("expected a PIN auth request"),
        }
    }

    #[test]
    fn proof_round_trips_and_rejects_tampering() {
        let keys = derive_auth_keys(&test_pin()).unwrap();
        let (nd, nl) = (generate_nonce(), generate_nonce());

        let proof = seal_proof(&keys, Direction::Dialer, &nd, &nl).unwrap();
        assert!(verify_proof(&keys, Direction::Dialer, &nd, &nl, &proof));

        // Wrong direction, swapped nonces, or a different key must all fail.
        assert!(!verify_proof(&keys, Direction::Listener, &nd, &nl, &proof));
        assert!(!verify_proof(&keys, Direction::Dialer, &nl, &nd, &proof));
        let other = derive_auth_keys(&test_pin()).unwrap();
        assert!(!verify_proof(&other, Direction::Dialer, &nd, &nl, &proof));
    }

    #[test]
    fn different_pins_derive_different_keys() {
        let a = derive_auth_keys("K7P29QXM").unwrap();
        let b = derive_auth_keys("9QXMK7P2").unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }

    /// Run a full dialer/listener handshake over an in-memory duplex, mirroring how the runtime
    /// reads the opening request before dispatching to the listener half.
    async fn run_handshake(dialer_pin: &str, listener_pins: &[&str]) -> (Result<()>, Result<()>) {
        let (a, b) = tokio::io::duplex(4096);
        let (mut a_read, mut a_write) = tokio::io::split(a);
        let (mut b_read, mut b_write) = tokio::io::split(b);

        let candidates: Vec<Keys> = listener_pins
            .iter()
            .map(|p| derive_auth_keys(p).unwrap())
            .collect();

        let dialer = dialer_pin.to_string();
        let dialer_task = async move { dialer_handshake(&mut a_write, &mut a_read, &dialer).await };
        let listener_task = async move {
            let nonce_d = read_pin_request(&mut b_read).await?;
            listener_handshake(&mut b_write, &mut b_read, &candidates, &nonce_d, |_| true)
                .await
                .map(|_| ())
        };
        tokio::join!(dialer_task, listener_task)
    }

    #[tokio::test]
    async fn handshake_succeeds_with_matching_pin() {
        let pin = test_pin();
        let (d, l) = run_handshake(&pin, &[&pin]).await;
        assert!(d.is_ok(), "dialer: {d:?}");
        assert!(l.is_ok(), "listener: {l:?}");
    }

    #[tokio::test]
    async fn handshake_succeeds_when_pin_is_a_recent_bucket() {
        // The listener has rotated; the dialer's PIN is one of the retained recent PINs.
        let dialer_pin = test_pin();
        let newer = test_pin();
        let (d, l) = run_handshake(&dialer_pin, &[&newer, &dialer_pin]).await;
        assert!(d.is_ok(), "dialer: {d:?}");
        assert!(l.is_ok(), "listener: {l:?}");
    }

    #[tokio::test]
    async fn handshake_rejects_when_commit_denies() {
        // Even with a valid PIN, a `commit` that returns false (e.g. a lost one-pair race) must
        // turn into a rejection — the dialer is told rejected, never accepted-then-dropped.
        let pin = test_pin();
        let (a, b) = tokio::io::duplex(4096);
        let (mut a_read, mut a_write) = tokio::io::split(a);
        let (mut b_read, mut b_write) = tokio::io::split(b);
        let candidates = vec![derive_auth_keys(&pin).unwrap()];

        let dialer = pin.clone();
        let dialer_task = async move { dialer_handshake(&mut a_write, &mut a_read, &dialer).await };
        let listener_task = async move {
            let nonce_d = read_pin_request(&mut b_read).await?;
            listener_handshake(&mut b_write, &mut b_read, &candidates, &nonce_d, |_| false)
                .await
                .map(|_| ())
        };
        let (d, l) = tokio::join!(dialer_task, listener_task);
        // Match the explicit rejection message rather than just `is_err()`, which would also pass
        // on an EOF/stream drop — the contract is that the dialer is *told* rejected, not
        // accepted-then-dropped.
        let err = d.expect_err("dialer must be rejected when the commit is denied");
        assert!(
            err.to_string().contains("PIN authentication rejected"),
            "dialer must see an explicit PIN rejection, got: {err:#}"
        );
        assert!(l.is_err(), "listener must reject when the commit is denied");
    }

    #[tokio::test]
    async fn handshake_fails_with_wrong_pin() {
        let (d, l) = run_handshake(&test_pin(), &[&test_pin()]).await;
        assert!(d.is_err(), "dialer should be rejected");
        assert!(l.is_err(), "listener should reject");
    }
}
