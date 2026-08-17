//! Card-setup PIN mutual authentication: a SPAKE2 PAKE carried in-band over the established
//! connection.
//!
//! In card setup the rendezvous record carries **only** the server's ephemeral node id (encrypted
//! under the PIN rendezvous key; see `crate::nostr`). No authentication material is ever placed on
//! a relay. Instead, once the client has dialed that node id, both peers run a balanced PAKE
//! (SPAKE2 over Ed25519) on the first bidirectional stream — the same stream the application-key
//! handshake uses, just a different [`AuthRequest`] method:
//!
//! ```text
//! D→L: AuthRequest::Pin { pakes:    [msg_a per slot] }   # dialer's SPAKE2 messages
//! L→D: PinChallenge     { pakes:    [msg_b per slot] }   # listener's SPAKE2 messages
//! D→L: PinResponse      { confirms: [mac_d per slot] }   # dialer's key confirmations
//! L→D: PinConfirm       { accepted, slot, confirm }      # verdict + listener's confirmation
//! ```
//!
//! The PAKE password is the Argon2id-stretched PIN material
//! ([`crate::pin::derive_auth_key_material`], bucket-independent). SPAKE2's guarantee is the
//! point: no message reveals anything offline-testable about the password.
//! A party that does not hold the PIN learns, per handshake, only whether its **one** guess per
//! slot was right — and each guess costs it a full Argon2id derivation. Combined with the
//! one-claim-per-PIN rule and the 60-second rotation, a wrong-PIN counterparty is limited to a few
//! online guesses against a ~35-bit code. (The public rendezvous *record* remains an offline
//! surface by nature — its lookup key must be derivable from the PIN — which Argon2id and the
//! short TTL mitigate; see `crate::pin_record`.)
//!
//! **Slots.** The listener honors the current and previous rotations' PINs (its recent-PIN cache),
//! but a PAKE commits each side to a single password per instance, so the handshake runs
//! [`PAKE_SLOTS`] independent instances: the dialer enters its one PIN in every slot, the listener
//! enters its i-th most recent PIN in slot i (a random password fills slots beyond its cache, so
//! the wire shape never reveals how many PINs are live and a dummy slot can never verify). The
//! slot whose confirmations match on both sides is the PIN they share.
//!
//! **Key confirmation and node-id binding.** Each side proves it derived the same SPAKE2 key with
//! an HMAC-SHA256 over a direction- and slot-separated transcript, so a confirmation for one
//! direction or slot can never be accepted as another's. Both peers' node ids — `id_d` the
//! dialer's, `id_l` the listener's, each side taking the remote one from the QUIC/TLS-authenticated
//! `Connection::remote_id()` — are folded into the SPAKE2 identity strings *and* the confirmation
//! transcript, so the exchange only completes when both peers agree on the two authenticated
//! endpoints: a handshake relayed onto a connection with different endpoints derives different
//! keys and fails. As before, that binding only defends against a party that does **not** hold the
//! PIN; anyone who knows the PIN can run the PAKE afresh for whatever node ids it presents, which
//! is why the human pairing-code check (`crate::card_exchange`) stays load-bearing.
//!
//! The dialer never has to know which rotation bucket the listener published under: the password
//! derivation is bucket-independent, and the slot mechanism absorbs rotation races. QUIC/TLS hides
//! the handshake from passive network and relay observers. Once the first peer has claimed the
//! server, the PIN is insufficient on its own: a reconnect must also present the claimed endpoint
//! identity through QUIC/TLS. The PIN does not derive or reveal QUIC's independently negotiated
//! traffic-encryption keys.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

// `rand` is also glob-exported by nostr crates elsewhere in this crate; the leading `::` keeps
// this bound to our workspace `rand`.
use ::rand::RngCore;

use crate::protocol::{
    AuthRequest, MAX_CONTROL_MESSAGE_SIZE, PinChallenge, PinConfirm, PinResponse,
    decode_pin_challenge, decode_pin_confirm, decode_pin_response, encode_auth_request,
    encode_pin_challenge, encode_pin_confirm, encode_pin_response, read_length_prefixed,
};

/// Domain separator baked into the SPAKE2 identity strings and every confirmation transcript,
/// versioning the construction.
const PAKE_DOMAIN: &str = "duocb:pin-pake:v1";

/// Independent SPAKE2 instances per handshake — one per PIN the listener may still honor, so its
/// recent-PIN look-back survives the PAKE's one-password-per-instance commitment. Also the number
/// of online PIN guesses a wrong-PIN counterparty gets per connection. The listener's cache
/// (`RECENT_PIN_CACHE`) is sized to this, so every retained PIN gets a slot.
pub const PAKE_SLOTS: usize = 2;

/// The PAKE password: 32 bytes of Argon2id-stretched PIN material
/// ([`crate::pin::derive_auth_key_material`]). The listener's recent-PIN cache stores these.
pub type PinPassword = [u8; 32];

/// Which side produced a confirmation. Domain-separates the two directions so a MAC computed by
/// one side can never be accepted as the other's.
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

/// The SPAKE2 identity pair for one slot: role, slot index, and that side's node id. Both peers
/// construct the identical pair, so disagreeing on either authenticated endpoint (or the slot)
/// derives a different key and fails confirmation. Node ids are fixed-format hex, so `|` never
/// appears inside one and the fields stay unambiguous.
fn pake_identities(slot: usize, id_d: &str, id_l: &str) -> (Identity, Identity) {
    (
        Identity::new(format!("{PAKE_DOMAIN}|dialer|{slot}|{id_d}").as_bytes()),
        Identity::new(format!("{PAKE_DOMAIN}|listener|{slot}|{id_l}").as_bytes()),
    )
}

/// The key-confirmation MAC for `dir` at `slot`: HMAC-SHA256 under that slot's SPAKE2 key over
/// the domain, direction, slot, and both node ids (the SPAKE2 key already commits to the password,
/// identities, and both PAKE messages).
fn confirm_mac(
    key: &[u8],
    dir: Direction,
    slot: usize,
    id_d: &str,
    id_l: &str,
) -> Result<[u8; 32]> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).context("keying the PIN confirmation MAC")?;
    mac.update(format!("{PAKE_DOMAIN}|confirm|{}|{slot}|{id_d}|{id_l}", dir.as_str()).as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

/// Decode one base64url wire field, naming it on failure.
fn decode_b64(value: &str, what: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("decoding {what}"))
}

/// Drive the dialer's half of the PIN handshake to completion on an opened bi stream.
///
/// Starts a SPAKE2 instance per slot (all with the typed PIN), confirms every slot's key, and
/// verifies the listener's confirmation for whichever slot it accepted. Returns `Ok(())` only when
/// the listener both accepted a slot and proved it derived the same key there — i.e. holds the
/// same PIN. Imposes no timeout — the caller wraps the whole exchange.
///
/// `dialer_id`/`listener_id` are this dialer's own node id and the id it dialed (the listener's,
/// from `Connection::remote_id()`); both are folded into the PAKE so the exchange is bound to the
/// QUIC-authenticated endpoints (see the module docs).
pub async fn dialer_handshake<W, R>(
    send: &mut W,
    recv: &mut R,
    canonical_pin: &str,
    dialer_id: &str,
    listener_id: &str,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    // Argon2id is deliberately slow and memory-hard; run it off the async
    // executor so it cannot stall other tasks on this worker.
    let password = tokio::task::spawn_blocking({
        let pin = canonical_pin.to_string();
        move || crate::pin::derive_auth_key_material(&pin)
    })
    .await
    .context("PIN key-derivation task failed")??;
    let password = Password::new(password);

    // 1. One SPAKE2 instance per slot, every slot on the same typed PIN — the dialer cannot know
    //    which of the listener's recent PINs it holds.
    let mut states = Vec::with_capacity(PAKE_SLOTS);
    let mut msgs = Vec::with_capacity(PAKE_SLOTS);
    for slot in 0..PAKE_SLOTS {
        let (id_a, id_b) = pake_identities(slot, dialer_id, listener_id);
        let (state, msg) = Spake2::<Ed25519Group>::start_a(&password, &id_a, &id_b);
        states.push(state);
        msgs.push(URL_SAFE_NO_PAD.encode(msg));
    }
    write_frame(send, &encode_auth_request(&AuthRequest::pin(msgs))?).await?;

    // 2. The listener's per-slot messages.
    let challenge =
        decode_pin_challenge(&read_length_prefixed(recv, MAX_CONTROL_MESSAGE_SIZE).await?)
            .context("reading PIN challenge")?;
    anyhow::ensure!(
        challenge.pakes.len() == PAKE_SLOTS,
        "listener sent {} PAKE messages, expected {PAKE_SLOTS}",
        challenge.pakes.len()
    );

    // 3. Finish every slot and confirm its key.
    let mut keys = Vec::with_capacity(PAKE_SLOTS);
    let mut confirms = Vec::with_capacity(PAKE_SLOTS);
    for (slot, (state, msg_b)) in states.into_iter().zip(&challenge.pakes).enumerate() {
        let msg_b = decode_b64(msg_b, "the listener's PAKE message")?;
        let key = state
            .finish(&msg_b)
            .map_err(|e| anyhow::anyhow!("finishing PAKE slot {slot}: {e}"))?;
        let mac = confirm_mac(&key, Direction::Dialer, slot, dialer_id, listener_id)?;
        confirms.push(URL_SAFE_NO_PAD.encode(mac));
        keys.push(key);
    }
    write_frame(send, &encode_pin_response(&PinResponse::new(confirms))?).await?;

    // 4. Verdict + the listener's own confirmation for the slot it matched.
    let confirm = decode_pin_confirm(&read_length_prefixed(recv, MAX_CONTROL_MESSAGE_SIZE).await?)
        .context("reading PIN confirm")?;
    if !confirm.accepted {
        let reason = confirm.reason.unwrap_or_else(|| "unknown".to_string());
        anyhow::bail!("PIN authentication rejected: {reason}");
    }
    let slot = confirm.slot.context("listener accepted but named no slot")?;
    anyhow::ensure!(slot < PAKE_SLOTS, "listener named out-of-range slot {slot}");
    let mac = confirm
        .confirm
        .context("listener accepted but sent no confirmation")?;
    let mac = decode_b64(&mac, "the listener's confirmation")?;
    let expected = confirm_mac(&keys[slot], Direction::Listener, slot, dialer_id, listener_id)?;
    if !bool::from(mac.as_slice().ct_eq(&expected)) {
        anyhow::bail!("listener failed to prove PIN possession (wrong peer?)");
    }
    Ok(())
}

/// Drive the listener's half of the PIN handshake, after the opening [`AuthRequest::Pin`] has
/// already been read off the stream (the listener reads it to choose the auth method).
///
/// `candidates` are the recent rotations' PIN passwords, newest first; slot i runs against the
/// i-th (a random password fills the rest, and a dummy slot never verifies). `dialer_pakes` are
/// the request's per-slot SPAKE2 messages. Once a slot's confirmation verifies, `commit` is
/// invoked **before** acceptance is sent: returning `false` (e.g. another peer won the one-pair
/// claim first) turns this into a rejection, so a race loser is never told it was accepted.
/// Otherwise sends a rejection and returns `Err`.
///
/// `dialer_id`/`listener_id` are the dialer's node id (the QUIC-authenticated
/// `Connection::remote_id()`) and this listener's own id; folding them into the PAKE means the
/// exchange completes only if the dialer's claimed identity matches the one QUIC authenticated
/// (see the module docs).
#[allow(clippy::too_many_arguments)]
pub async fn listener_handshake<W, R, F>(
    send: &mut W,
    recv: &mut R,
    candidates: &[PinPassword],
    dialer_pakes: &[String],
    dialer_id: &str,
    listener_id: &str,
    commit: F,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    F: FnOnce() -> bool,
{
    anyhow::ensure!(
        dialer_pakes.len() == PAKE_SLOTS,
        "dialer sent {} PAKE messages, expected {PAKE_SLOTS}",
        dialer_pakes.len()
    );

    // 2. One SPAKE2 instance per slot: the i-th most recent PIN, or an unguessable dummy so the
    //    reply's shape never reveals how many PINs are live.
    let mut real = [false; PAKE_SLOTS];
    let mut keys = Vec::with_capacity(PAKE_SLOTS);
    let mut msgs = Vec::with_capacity(PAKE_SLOTS);
    for slot in 0..PAKE_SLOTS {
        let password = match candidates.get(slot) {
            Some(material) => {
                real[slot] = true;
                Password::new(material)
            }
            None => {
                let mut dummy = [0u8; 32];
                ::rand::rng().fill_bytes(&mut dummy);
                Password::new(dummy)
            }
        };
        let (id_a, id_b) = pake_identities(slot, dialer_id, listener_id);
        let (state, msg_b) = Spake2::<Ed25519Group>::start_b(&password, &id_a, &id_b);
        let msg_a = decode_b64(&dialer_pakes[slot], "the dialer's PAKE message")?;
        let key = state
            .finish(&msg_a)
            .map_err(|e| anyhow::anyhow!("finishing PAKE slot {slot}: {e}"))?;
        keys.push(key);
        msgs.push(URL_SAFE_NO_PAD.encode(msg_b));
    }
    write_frame(send, &encode_pin_challenge(&PinChallenge::new(msgs))?).await?;

    // 3. The dialer's per-slot confirmations; a real slot whose MAC verifies is the shared PIN.
    let response =
        decode_pin_response(&read_length_prefixed(recv, MAX_CONTROL_MESSAGE_SIZE).await?)
            .context("reading PIN response")?;
    anyhow::ensure!(
        response.confirms.len() == PAKE_SLOTS,
        "dialer sent {} confirmations, expected {PAKE_SLOTS}",
        response.confirms.len()
    );
    let mut matched = None;
    for slot in 0..PAKE_SLOTS {
        let expected = confirm_mac(&keys[slot], Direction::Dialer, slot, dialer_id, listener_id)?;
        let Ok(mac) = URL_SAFE_NO_PAD.decode(&response.confirms[slot]) else {
            continue;
        };
        if real[slot] && bool::from(mac.as_slice().ct_eq(&expected)) && matched.is_none() {
            matched = Some(slot);
        }
    }

    // 4. Confirm (with our own MAC) or reject. Even once a slot verifies, `commit` has the final
    //    say *before* acceptance is written, so a peer that loses the one-pair race is rejected
    //    rather than briefly told it was accepted and then dropped.
    match matched {
        Some(slot) if commit() => {
            let mac = confirm_mac(&keys[slot], Direction::Listener, slot, dialer_id, listener_id)?;
            let confirm = PinConfirm::accepted(slot, URL_SAFE_NO_PAD.encode(mac));
            write_frame(send, &encode_pin_confirm(&confirm)?).await?;
            Ok(())
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
            anyhow::bail!("no recent PIN matched the dialer's PAKE confirmation (wrong or expired PIN)");
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

    fn password(pin: &str) -> PinPassword {
        crate::pin::derive_auth_key_material(pin).unwrap()
    }

    /// Read the opening AuthRequest and return its PAKE messages, mirroring how the runtime reads
    /// the request before dispatching to the listener half.
    async fn read_pin_request<R: AsyncRead + Unpin>(recv: &mut R) -> Result<Vec<String>> {
        match crate::protocol::decode_auth_request(
            &read_length_prefixed(recv, MAX_CONTROL_MESSAGE_SIZE).await?,
        )? {
            AuthRequest::Pin { pakes, .. } => Ok(pakes),
            AuthRequest::Key { .. } => anyhow::bail!("expected a PIN auth request"),
        }
    }

    #[test]
    fn confirm_mac_separates_direction_slot_and_ids() {
        let key = [7u8; 32];
        let base = confirm_mac(&key, Direction::Dialer, 0, "id-d", "id-l").unwrap();
        assert_eq!(base, confirm_mac(&key, Direction::Dialer, 0, "id-d", "id-l").unwrap());
        assert_ne!(base, confirm_mac(&key, Direction::Listener, 0, "id-d", "id-l").unwrap());
        assert_ne!(base, confirm_mac(&key, Direction::Dialer, 1, "id-d", "id-l").unwrap());
        assert_ne!(base, confirm_mac(&key, Direction::Dialer, 0, "other", "id-l").unwrap());
        assert_ne!(base, confirm_mac(&key, Direction::Dialer, 0, "id-d", "other").unwrap());
        assert_ne!(base, confirm_mac(&[8u8; 32], Direction::Dialer, 0, "id-d", "id-l").unwrap());
    }

    // The node ids used across the handshake tests; both halves agree on them in the happy path.
    const ID_D: &str = "dialer-node-id";
    const ID_L: &str = "listener-node-id";

    /// Run a full dialer/listener handshake over an in-memory duplex, mirroring how the runtime
    /// reads the opening request before dispatching to the listener half. `dialer_ids`/`listener_ids`
    /// are the `(id_d, id_l)` each side folds into its PAKE — equal in the happy path, unequal to
    /// simulate a relayed/mismatched identity.
    async fn run_handshake_with_ids(
        dialer_pin: &str,
        listener_pins: &[&str],
        dialer_ids: (&str, &str),
        listener_ids: (&str, &str),
    ) -> (Result<()>, Result<()>) {
        let (a, b) = tokio::io::duplex(4096);
        let (mut a_read, mut a_write) = tokio::io::split(a);
        let (mut b_read, mut b_write) = tokio::io::split(b);

        let candidates: Vec<PinPassword> = listener_pins.iter().map(|p| password(p)).collect();

        let dialer = dialer_pin.to_string();
        let (d_id_d, d_id_l) = (dialer_ids.0.to_string(), dialer_ids.1.to_string());
        let dialer_task = async move {
            dialer_handshake(&mut a_write, &mut a_read, &dialer, &d_id_d, &d_id_l).await
        };
        let (l_id_d, l_id_l) = (listener_ids.0.to_string(), listener_ids.1.to_string());
        let listener_task = async move {
            let pakes = read_pin_request(&mut b_read).await?;
            listener_handshake(
                &mut b_write,
                &mut b_read,
                &candidates,
                &pakes,
                &l_id_d,
                &l_id_l,
                || true,
            )
            .await
        };
        tokio::join!(dialer_task, listener_task)
    }

    /// The happy path: both sides agree on the two node ids.
    async fn run_handshake(dialer_pin: &str, listener_pins: &[&str]) -> (Result<()>, Result<()>) {
        run_handshake_with_ids(dialer_pin, listener_pins, (ID_D, ID_L), (ID_D, ID_L)).await
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
        // The listener has rotated; the dialer's PIN is one of the retained recent PINs, so it
        // matches in a later slot.
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
        let candidates = vec![password(&pin)];

        let dialer = pin.clone();
        let dialer_task = async move {
            dialer_handshake(&mut a_write, &mut a_read, &dialer, ID_D, ID_L).await
        };
        let listener_task = async move {
            let pakes = read_pin_request(&mut b_read).await?;
            listener_handshake(
                &mut b_write,
                &mut b_read,
                &candidates,
                &pakes,
                ID_D,
                ID_L,
                || false,
            )
            .await
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

    #[tokio::test]
    async fn handshake_rejects_cleanly_with_no_candidates() {
        // A listener with no live PINs (configure-mode, or refreshed away) runs dummy slots only
        // and must reject in-band, never accept.
        let pin = test_pin();
        let (d, l) = run_handshake(&pin, &[]).await;
        let err = d.expect_err("dialer must be rejected when no PIN is live");
        assert!(
            err.to_string().contains("PIN authentication rejected"),
            "dialer must see an explicit rejection, got: {err:#}"
        );
        assert!(l.is_err(), "listener must reject with no candidates");
    }

    #[tokio::test]
    async fn handshake_fails_when_the_dialer_node_id_disagrees() {
        // Same PIN, but the listener saw a different dialer node id than the dialer folded in
        // (e.g. a relay whose QUIC session terminates at another id). The PAKE keys diverge and
        // no confirmation can verify.
        let pin = test_pin();
        let (d, l) = run_handshake_with_ids(
            &pin,
            &[&pin],
            (ID_D, ID_L),
            ("some-other-dialer-id", ID_L),
        )
        .await;
        assert!(d.is_err(), "dialer must be rejected on a node-id mismatch");
        assert!(l.is_err(), "listener must reject on a node-id mismatch");
    }

    #[tokio::test]
    async fn handshake_fails_when_the_listener_node_id_disagrees() {
        // The dialer believes it reached a different listener than the one answering.
        let pin = test_pin();
        let (d, l) = run_handshake_with_ids(
            &pin,
            &[&pin],
            (ID_D, "some-other-listener-id"),
            (ID_D, ID_L),
        )
        .await;
        assert!(d.is_err(), "dialer must be rejected on a node-id mismatch");
        assert!(l.is_err(), "listener must reject on a node-id mismatch");
    }

    #[tokio::test]
    async fn listener_rejects_a_wrong_slot_count() {
        // A dialer that sends the wrong number of PAKE messages is a protocol violation, refused
        // before any PAKE work.
        let pin = test_pin();
        let (_a, b) = tokio::io::duplex(4096);
        let (mut b_read, mut b_write) = tokio::io::split(b);
        let candidates = vec![password(&pin)];
        let err = listener_handshake(
            &mut b_write,
            &mut b_read,
            &candidates,
            &["b25seS1vbmU".to_string()],
            ID_D,
            ID_L,
            || true,
        )
        .await
        .expect_err("a short PAKE vector must be refused");
        assert!(err.to_string().contains("PAKE messages"), "got: {err:#}");
    }
}
