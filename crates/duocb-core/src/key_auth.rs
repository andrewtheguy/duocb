//! Configure-mode mutual authentication with the persistent application key —
//! the handshake every clipboard session runs, expressed without reference to
//! any particular transport.
//!
//! Two devices that already hold each other's signed identity card prove
//! possession of the matching application private key to each other, on the
//! session's single bidirectional stream, before a byte of clipboard traffic
//! moves:
//!
//! ```text
//! D→L  AuthRequest::Key {version, public_key, nonce_d}
//! L→D  KeyChallenge     {public_key, nonce_l, proof_l}
//! D→L  KeyProof         {proof_d}
//! L→D  AuthResponse     {accepted}
//! ```
//!
//! Both proofs are Schnorr signatures over a domain-separated transcript
//! ([`auth_transcript`]) covering the protocol version, the signer's role, both
//! application keys, both nonces, and **both transport endpoint ids**. The
//! nonces and the role field stop replay and reflection; the endpoint ids are
//! the channel binding that ties the proof to the connection it was made on.
//!
//! ## What this needs from a transport
//!
//! Only what [`crate::transport`] describes: a reliable, ordered byte stream in
//! each direction, plus a stable id for each end that both sides label the same
//! way. The ids arrive here as opaque strings and are signed verbatim, so a
//! transport picks its own naming (iroh passes node ids; the dummy TCP
//! transport passes socket addresses).
//!
//! How much the binding is *worth* is the transport's contribution, not this
//! module's: with iroh the ids are QUIC/TLS-authenticated, so a peer cannot
//! claim an id it does not hold the key for, and the signature pins the
//! application identity to that authenticated endpoint. Over a transport that
//! authenticates nothing, the ids degrade to labels the two ends must agree on
//! — the application-key proofs still authenticate *who* is on the connection,
//! which is what local trust is checked against.
//!
//! Trust itself is never decided here. The listener is handed two callbacks:
//! `admit`, which runs before this device signs anything, and `commit`, which
//! runs after the dialer's proof verifies and before acceptance goes out.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::auth::{Identity, verify_auth_signature};
use crate::protocol::{
    AuthRequest, AuthResponse, KeyChallenge, KeyProof, MAX_CONTROL_MESSAGE_SIZE, decode_auth_request,
    decode_auth_response, decode_key_challenge, decode_key_proof, encode_auth_request,
    encode_auth_response, encode_key_challenge, encode_key_proof, read_length_prefixed,
};

/// A fresh 256-bit nonce, base64url. One per side per handshake: it is what
/// makes each transcript single-use.
fn random_nonce() -> String {
    let mut nonce = [0u8; 32];
    ::rand::rng().fill_bytes(&mut nonce);
    URL_SAFE_NO_PAD.encode(nonce)
}

async fn write_frame<W>(send: &mut W, frame: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    send.write_all(frame).await?;
    send.flush().await?;
    Ok(())
}

/// The signed transcript. `role` is the half being proven (`"dialer"` or
/// `"listener"`), so one side's proof can never be replayed as the other's, and
/// every field is length-prefixed so no two different field sets can produce
/// the same bytes.
///
/// `client_transport_id`/`server_transport_id` are the transport's names for
/// the two ends of this connection, as each side sees them: the dialer's own id
/// and the id it dialed, the listener's view of the dialer and its own id. A
/// transport that leaves the two ends with different views of the pair — a
/// rewriting proxy, an address the peer cannot observe — produces different
/// transcripts and the handshake fails, which is the intended outcome.
#[allow(clippy::too_many_arguments)]
fn auth_transcript(
    role: &str,
    client_key: nostr_sdk::PublicKey,
    server_key: nostr_sdk::PublicKey,
    client_nonce: &str,
    server_nonce: &str,
    client_transport_id: &str,
    server_transport_id: &str,
) -> Vec<u8> {
    fn field(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(&(value.len() as u32).to_be_bytes());
        output.extend_from_slice(value);
    }

    let mut transcript = Vec::with_capacity(256);
    transcript.extend_from_slice(&crate::protocol::DUOCB_PROTO_VERSION.to_be_bytes());
    field(&mut transcript, role.as_bytes());
    field(&mut transcript, client_key.as_bytes());
    field(&mut transcript, server_key.as_bytes());
    field(&mut transcript, client_nonce.as_bytes());
    field(&mut transcript, server_nonce.as_bytes());
    field(&mut transcript, client_transport_id.as_bytes());
    field(&mut transcript, server_transport_id.as_bytes());
    transcript
}

/// Run the dialing half. Imposes no timeout — the caller bounds the whole
/// exchange (the runtime uses `AUTH_TIMEOUT`).
///
/// `expected_peer` is the application key of the device the user picked: a
/// listener that presents any other key is refused before this side signs
/// anything, so a misdirected rendezvous record cannot even collect a proof.
///
/// `dialer_id`/`listener_id` are this dialer's own transport id and the id of
/// the endpoint it dialed.
pub async fn dialer_handshake<W, R>(
    send: &mut W,
    recv: &mut R,
    identity: &Identity,
    expected_peer: nostr_sdk::PublicKey,
    dialer_id: &str,
    listener_id: &str,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let client_nonce = random_nonce();
    let request = AuthRequest::key(identity.public_key().to_hex(), &client_nonce);
    write_frame(send, &encode_auth_request(&request)?).await?;

    let challenge_bytes = read_length_prefixed(recv, MAX_CONTROL_MESSAGE_SIZE).await?;
    let challenge = decode_key_challenge(&challenge_bytes).context("invalid key-auth challenge")?;
    let server_key = nostr_sdk::PublicKey::parse(&challenge.public_key)
        .context("listener supplied an invalid application key")?;
    if server_key != expected_peer {
        anyhow::bail!("listener application key does not match the selected peer");
    }
    let listener_transcript = auth_transcript(
        "listener",
        identity.public_key(),
        server_key,
        &client_nonce,
        &challenge.nonce,
        dialer_id,
        listener_id,
    );
    verify_auth_signature(server_key, &listener_transcript, &challenge.proof)?;

    let dialer_transcript = auth_transcript(
        "dialer",
        identity.public_key(),
        server_key,
        &client_nonce,
        &challenge.nonce,
        dialer_id,
        listener_id,
    );
    let proof = KeyProof::new(identity.sign_auth(&dialer_transcript));
    write_frame(send, &encode_key_proof(&proof)?).await?;

    let response_bytes = read_length_prefixed(recv, MAX_CONTROL_MESSAGE_SIZE).await?;
    let response = decode_auth_response(&response_bytes).context("invalid key-auth response")?;
    if !response.accepted {
        anyhow::bail!(
            "authentication rejected: {}",
            response.reason.unwrap_or_else(|| "unknown reason".into())
        );
    }
    Ok(())
}

/// Read the dialer's opening frame and require the configure-mode `Key` method,
/// returning its `(public_key, nonce)` fields for [`listener_handshake`].
///
/// A listener that also serves the card-setup PIN method decodes the frame
/// itself and branches on the method instead (that is what the runtime does);
/// this is the one-method shorthand for a transport that only carries clipboard
/// sessions.
pub async fn read_key_request<R>(recv: &mut R) -> Result<(String, String)>
where
    R: AsyncRead + Unpin,
{
    let request_bytes = read_length_prefixed(recv, MAX_CONTROL_MESSAGE_SIZE)
        .await
        .context("Failed to read auth request")?;
    match decode_auth_request(&request_bytes).context("Invalid auth request")? {
        AuthRequest::Key {
            public_key, nonce, ..
        } => Ok((public_key, nonce)),
        AuthRequest::Pin { .. } => {
            anyhow::bail!("dialer asked for PIN authentication on a clipboard listener")
        }
    }
}

/// Run the listening half, given the `public_key`/`nonce` the dialer opened
/// with (see [`read_key_request`]). Returns the authenticated dialer's
/// application key. Imposes no timeout — the caller bounds the exchange.
///
/// The two callbacks are where the host's policy lives, and their order is the
/// security-relevant part:
///
/// - `admit` runs **before this device signs anything**, so an untrusted,
///   lapsed or unasked-for dialer never even collects a proof of our identity.
///   Its error is returned as-is, so a caller can mark it (the runtime
///   downcasts an expired-card marker to pick a close code).
/// - `commit` runs **after** the dialer's proof verifies and **before** the
///   acceptance frame goes out, so a race loser is rejected in-band rather than
///   accepted and then dropped. Returning `false` fails the handshake.
///
/// `dialer_id`/`listener_id` are this listener's view of the dialer's transport
/// id and its own.
#[allow(clippy::too_many_arguments)]
pub async fn listener_handshake<W, R, C, M>(
    send: &mut W,
    recv: &mut R,
    identity: &Identity,
    client_public_key: &str,
    client_nonce: &str,
    dialer_id: &str,
    listener_id: &str,
    admit: C,
    commit: M,
) -> Result<nostr_sdk::PublicKey>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    C: FnOnce(nostr_sdk::PublicKey) -> Result<()>,
    M: FnOnce(nostr_sdk::PublicKey) -> bool,
{
    let client_key = nostr_sdk::PublicKey::parse(client_public_key)
        .context("dialer application key is invalid")?;
    admit(client_key)?;

    let server_nonce = random_nonce();
    let listener_transcript = auth_transcript(
        "listener",
        client_key,
        identity.public_key(),
        client_nonce,
        &server_nonce,
        dialer_id,
        listener_id,
    );
    let challenge = KeyChallenge::new(
        identity.public_key().to_hex(),
        &server_nonce,
        identity.sign_auth(&listener_transcript),
    );
    write_frame(send, &encode_key_challenge(&challenge)?).await?;

    let proof_bytes = read_length_prefixed(recv, MAX_CONTROL_MESSAGE_SIZE).await?;
    let proof = decode_key_proof(&proof_bytes).context("invalid dialer key proof")?;
    let dialer_transcript = auth_transcript(
        "dialer",
        client_key,
        identity.public_key(),
        client_nonce,
        &server_nonce,
        dialer_id,
        listener_id,
    );
    verify_auth_signature(client_key, &dialer_transcript, &proof.proof)?;

    if !commit(client_key) {
        anyhow::bail!("another application identity paired first");
    }
    write_frame(send, &encode_auth_response(&AuthResponse::accepted())?).await?;
    Ok(client_key)
}
