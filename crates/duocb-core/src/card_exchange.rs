//! Card setup's payload step: swapping signed identity cards over a connection
//! the PIN handshake has already authenticated.
//!
//! This is the whole point of a card-setup session. Configure mode moves cards by
//! copy-paste, which two devices with no shared clipboard cannot do; here the
//! rotating PIN authenticates a short-lived connection and the cards cross it
//! directly. Once both sides have imported, they are ordinary configure-mode
//! peers and every later connection runs the application-key handshake instead.
//!
//! ```text
//! D→L: CardOffer { card_d }     # both sent immediately after the PIN accepts,
//! L→D: CardOffer { card_l }     # crossing on the wire — neither side waits
//! (each side then reads the peer's card, finishes its own send stream, and
//!  waits for the peer's stream to end)
//! ```
//!
//! Both offers are written before either is read, so the exchange costs one
//! round trip rather than two. The frames are length-prefixed, so simultaneous
//! writes need no turn-taking.
//!
//! **Why the end-of-stream step matters.** Each side finishes its send stream
//! only *after* it has read the peer's card, so seeing the peer's stream end is
//! proof the peer already holds ours. Without that, whichever side finished
//! first would close the connection while the other was still reading, and
//! QUIC's connection close discards undelivered stream data — the exchange
//! would fail intermittently depending on which side won the race.
//!
//! **This transfer grants no trust.** It hands the peer a card; it does not
//! install one. The receiver re-parses the offer through
//! [`IdentityCard::parse`], the same verifying path a pasted card takes, and
//! then the *user* has to check that the pairing code — derived from both keys
//! and rendered identically by both devices ([`crate::auth::pairing_code`]) —
//! matches across the two screens before importing it. That human check is what
//! catches an interposer: the PIN is only ~35 bits, and while the in-band PAKE
//! (`crate::pin_auth`) limits a stranger to a few online guesses, anyone who
//! reads, shoulder-surfs, or grinds it out of the public rendezvous record
//! (see `crate::pin_record`) can complete the handshake — so possession of the
//! PIN alone must never be enough to become a trusted device.
//!
//! Because the offers cross unconditionally, anyone who holds the PIN learns the
//! card of whoever is showing it. A card is public-by-design — it is the thing
//! you hand out — and carries no private key, so the exposure is the device name
//! and public key, never authority.

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::auth::IdentityCard;
use crate::protocol::{
    CardOffer, MAX_CONTROL_MESSAGE_SIZE, decode_card_offer, encode_card_offer,
    read_length_prefixed,
};

/// How many trailing bytes to absorb while waiting for the peer's stream to
/// end. A well-behaved peer sends none — this only bounds how much a misbehaving
/// one can make us read before we give up waiting and close anyway.
const MAX_TRAILING_BYTES: u64 = 1024;

/// Offer `own_card` to the peer and return the card it offered back, verified.
///
/// Identical on both sides — the roles that mattered for authentication do not
/// matter here. Fails if the peer's offer is missing, malformed, or not a
/// validly signed card; the caller ends the session rather than showing the user
/// something unverifiable.
///
/// On return it is safe to close the connection: the peer has been seen to
/// finish its stream, which it does only after reading our card.
pub async fn exchange_cards<W, R>(
    send: &mut W,
    recv: &mut R,
    own_card: &IdentityCard,
) -> Result<IdentityCard>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let frame = encode_card_offer(&CardOffer::new(own_card.encode()))
        .context("encoding this device's identity card")?;
    send.write_all(&frame)
        .await
        .context("sending this device's identity card")?;
    send.flush()
        .await
        .context("flushing this device's identity card")?;

    let offer = decode_card_offer(
        &read_length_prefixed(recv, MAX_CONTROL_MESSAGE_SIZE)
            .await
            .context("reading the peer's identity card")?,
    )
    .context("decoding the peer's identity card")?;

    // Same verifying parse a pasted card gets: signature, kind, identifier,
    // schema, name rules, and the clock-free expiry checks.
    let card = IdentityCard::parse(&offer.card)
        .context("the peer offered an invalid identity card")?;

    // Only now finish our stream — so the peer seeing our end-of-stream proves
    // we already have its card.
    send.shutdown()
        .await
        .context("finishing the identity-card stream")?;

    // Then wait for the peer's end-of-stream, which is what makes it safe for
    // *us* to close. Best-effort: we already hold a verified card, and the one
    // thing that routinely interrupts this wait is the peer closing the
    // connection — which happens only once its own drain saw our end-of-stream,
    // i.e. once it already has our card. Failing here would throw away a
    // completed exchange over a race whose outcome is benign either way.
    let mut trailing = Vec::new();
    if let Err(e) = recv
        .take(MAX_TRAILING_BYTES)
        .read_to_end(&mut trailing)
        .await
    {
        log::debug!("Peer closed while finishing the card exchange (harmless): {e}");
    }

    Ok(card)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Identity;

    /// The exchange is symmetric and both sides run it concurrently, exactly as
    /// the runtime drives it. `duplex` stands in for the QUIC stream pair.
    #[tokio::test]
    async fn both_sides_receive_the_others_card() {
        let (a_io, b_io) = tokio::io::duplex(4096);
        let (mut a_recv, mut a_send) = tokio::io::split(a_io);
        let (mut b_recv, mut b_send) = tokio::io::split(b_io);

        let a_identity = Identity::generate();
        let b_identity = Identity::generate();
        let a_card = a_identity.card("mac-book", "a7B2c3D4").unwrap();
        let b_card = b_identity.card("pixel", "9zKtm4Qp").unwrap();

        let (a_got, b_got) = tokio::join!(
            exchange_cards(&mut a_send, &mut a_recv, &a_card),
            exchange_cards(&mut b_send, &mut b_recv, &b_card),
        );

        let a_got = a_got.unwrap();
        let b_got = b_got.unwrap();
        assert_eq!(a_got.public_key(), b_identity.public_key());
        assert_eq!(a_got.name(), "pixel_9zKtm4Qp");
        assert_eq!(b_got.public_key(), a_identity.public_key());
        assert_eq!(b_got.name(), "mac-book_a7B2c3D4");

        // Each side now derives the pairing code from its own key and the card
        // it received, and both arrive at one identical value — this is the
        // user's cross-check. Pinning both to the code over the two identity
        // keys directly rules out a constant or key-insensitive rendering, which
        // the two-sided equality alone would not catch.
        let expected =
            crate::auth::pairing_code(&a_identity.public_key(), &b_identity.public_key()).unwrap();
        assert_eq!(
            crate::auth::pairing_code(&a_identity.public_key(), &a_got.public_key()).unwrap(),
            expected,
        );
        assert_eq!(
            crate::auth::pairing_code(&b_identity.public_key(), &b_got.public_key()).unwrap(),
            expected,
        );
        let other = Identity::generate();
        assert_ne!(
            crate::auth::pairing_code(&a_identity.public_key(), &other.public_key()).unwrap(),
            expected,
            "the code must bind this specific pair of keys",
        );
    }

    /// A peer that sends something other than a validly signed card is refused
    /// here, so the confirmation screen can never display unverified data.
    #[tokio::test]
    async fn a_malformed_offer_is_rejected() {
        let (a_io, b_io) = tokio::io::duplex(4096);
        let (mut a_recv, mut a_send) = tokio::io::split(a_io);
        let (_b_recv, mut b_send) = tokio::io::split(b_io);

        let frame = encode_card_offer(&CardOffer::new("{\"not\":\"a card\"}")).unwrap();
        b_send.write_all(&frame).await.unwrap();
        b_send.flush().await.unwrap();

        let card = Identity::generate().card("mac-book", "a7B2c3D4").unwrap();
        let err = exchange_cards(&mut a_send, &mut a_recv, &card)
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("invalid identity card"),
            "unexpected error: {err:#}"
        );
    }

    /// A tampered card fails the signature check inside `parse`, not some
    /// separate ad-hoc validation.
    #[tokio::test]
    async fn a_tampered_card_is_rejected() {
        let (a_io, b_io) = tokio::io::duplex(4096);
        let (mut a_recv, mut a_send) = tokio::io::split(a_io);
        let (_b_recv, mut b_send) = tokio::io::split(b_io);

        let good = Identity::generate().card("pixel", "9zKtm4Qp").unwrap();
        let tampered = good.encode().replace("pixel", "spoof");
        let frame = encode_card_offer(&CardOffer::new(tampered)).unwrap();
        b_send.write_all(&frame).await.unwrap();
        b_send.flush().await.unwrap();

        let card = Identity::generate().card("mac-book", "a7B2c3D4").unwrap();
        assert!(
            exchange_cards(&mut a_send, &mut a_recv, &card)
                .await
                .is_err()
        );
    }
}
