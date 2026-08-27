//! The transport contract: what duocb needs from whatever carries a clipboard
//! session, and what it deliberately does not care about.
//!
//! duocb is not an iroh application that happens to move text. It is a wire
//! protocol ([`crate::protocol`]) and an authentication handshake
//! ([`crate::key_auth`]) between two devices that trust each other's signed
//! identity cards, and iroh is the transport that carries them today — the only
//! one the apps ship with, and the one [`iroh_quic`] implements. Everything a
//! transport has to supply is in this module's trait; everything above it is
//! transport-independent by construction, which is what [`dummy`] demonstrates
//! by running a complete session over plain TCP sockets.
//!
//! # What a transport must provide
//!
//! 1. **One reliable, ordered, bidirectional byte channel per session.** duocb
//!    opens exactly one stream and keeps it for the life of the connection: the
//!    handshake runs on it first, then [`crate::protocol::ClipMsg`] frames flow
//!    both ways. Framing is length-prefixed and self-delimiting, so the channel
//!    need not preserve message boundaries — and the two directions need not
//!    even come from one socket (see [`dummy::UniTcpSession`]).
//! 2. **A stable id for each end, that both ends label identically.** The two
//!    ids are signed into the handshake transcript. A transport that leaves the
//!    peers with different views of the pair (a rewriting proxy, an address one
//!    side cannot observe) makes the handshake fail, by design.
//! 3. **Somewhere to point a dial.** Getting from "the peer I picked" to an
//!    address is rendezvous, not transport, and duocb keeps the two apart: the
//!    encrypted hosting record (`hosting_record`) carries the host's
//!    current transport address over DNS-SD or Nostr, and the transport is
//!    handed the result. Today that payload is an iroh node id, which is the
//!    one place a second transport would need a second payload shape.
//!
//! # What a transport does *not* provide
//!
//! Not identity, and not trust. A duocb installation's identity is its
//! application key ([`crate::auth`]); its transport key is a separate,
//! shorter-lived thing, and the node id it produces is never a credential. The
//! transport's authenticated endpoint id only channel-binds a handshake that
//! authenticates the application keys on its own. That is why a transport with
//! no cryptography at all — [`dummy`] — still runs the same mutual proofs and
//! still refuses an untrusted key.
//!
//! Not confidentiality either, at this layer: duocb relies on the transport for
//! it (QUIC/TLS under iroh), so a transport without encryption is a test and
//! demo tool, never a shipping one.
//!
//! # What is transport-specific in this crate
//!
//! Under iroh today: [`crate::net::endpoint`] (binding endpoints, discovery,
//! relays, connection paths), the session tasks in [`crate::net::runtime`], and
//! the `EndpointId` payload inside the rendezvous records (`hosting_record`,
//! [`crate::lan`], [`crate::nostr`]). Transport-free:
//! [`crate::protocol`], [`crate::key_auth`], [`crate::auth`],
//! [`crate::card_exchange`] and [`crate::net::session_role`].
//!
//! # Optional extras a transport may add
//!
//! Connection close codes (the runtime turns iroh's into precise
//! "untrusted key" / "expired card" / "busy" messages), path introspection for
//! the UI, NAT traversal and relay fallback. None of them are required to carry
//! a session; a transport without them loses diagnostics, not correctness.

pub mod dummy;
pub mod iroh_quic;

use anyhow::Result;
use std::future::Future;
use tokio::io::{AsyncRead, AsyncWrite};

/// Which half of a session an end runs. It decides only who opens the stream
/// and who proves itself first; both sides send and receive once the session is
/// up, and neither user picks it — [`crate::net::session_role`] derives it from
/// the two application keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Dialer,
    Listener,
}

/// One end of an established duocb session, before its stream is opened.
///
/// Implementors are cheap handles over an already-connected transport
/// connection: a `SessionTransport` value means the two devices have found each
/// other and a connection exists, not that either has been authenticated.
pub trait SessionTransport: Sized {
    /// The write half of the session's byte channel.
    type Send: AsyncWrite + Unpin + Send;
    /// The read half of the session's byte channel.
    type Recv: AsyncRead + Unpin + Send;

    /// This end's transport id, signed into the handshake transcript. Its form
    /// is the transport's business (iroh: a node id; TCP: a socket address);
    /// duocb treats it as an opaque label.
    fn local_id(&self) -> String;

    /// The remote end's transport id, as this side sees it. Under a transport
    /// that authenticates its endpoints this is a proven identity; under one
    /// that does not it is merely a label both ends must agree on.
    fn peer_id(&self) -> String;

    /// Take the session's single bidirectional byte channel. Consuming `self`
    /// is the contract: a session is one stream, opened once.
    ///
    /// The dialing side opens it and the listening side accepts it, which is
    /// the one place the two roles differ — implementors carry their role
    /// rather than exposing two methods.
    fn session_stream(self) -> impl Future<Output = Result<(Self::Send, Self::Recv)>> + Send;
}

/// Authenticate as the dialer over any transport and hand back the stream the
/// clipboard runs on.
///
/// This is the whole of what a new transport has to be plugged into on the
/// dialing side; the desktop runtime uses [`crate::key_auth`] directly only
/// because it also wraps the exchange in a timeout and translates iroh's close
/// codes into user-facing wording.
pub async fn authenticate_dialer<T: SessionTransport>(
    transport: T,
    identity: &crate::auth::Identity,
    expected_peer: nostr_sdk::PublicKey,
) -> Result<(T::Send, T::Recv)> {
    let (local_id, peer_id) = (transport.local_id(), transport.peer_id());
    let (mut send, mut recv) = transport.session_stream().await?;
    crate::key_auth::dialer_handshake(
        &mut send,
        &mut recv,
        identity,
        expected_peer,
        &local_id,
        &peer_id,
    )
    .await?;
    Ok((send, recv))
}

/// Authenticate as the listener over any transport, returning the stream and
/// the dialer's proven application key.
///
/// `admit` decides trust before this side signs anything — the caller's local
/// peer list is the only thing that can answer it. See
/// [`crate::key_auth::listener_handshake`] for the ordering guarantees.
///
/// It admits whoever `admit` allows: unlike the runtime, which also holds a
/// one-device-at-a-time claim across reconnects, this helper has no session
/// state to protect, so its commit step always succeeds.
pub async fn authenticate_listener<T, C>(
    transport: T,
    identity: &crate::auth::Identity,
    admit: C,
) -> Result<(T::Send, T::Recv, nostr_sdk::PublicKey)>
where
    T: SessionTransport,
    C: FnOnce(nostr_sdk::PublicKey) -> Result<()>,
{
    let (local_id, peer_id) = (transport.local_id(), transport.peer_id());
    let (mut send, mut recv) = transport.session_stream().await?;
    let (public_key, nonce) = crate::key_auth::read_key_request(&mut recv).await?;
    let peer = crate::key_auth::listener_handshake(
        &mut send,
        &mut recv,
        identity,
        &public_key,
        &nonce,
        &peer_id,
        &local_id,
        admit,
        |_| true,
    )
    .await?;
    Ok((send, recv, peer))
}
