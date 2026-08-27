//! A dummy transport over plain TCP — host and port, nothing else — for tests,
//! examples and porting work.
//!
//! Its purpose is to be the opposite of iroh in every respect that is supposed
//! not to matter: no discovery, no NAT traversal, no relays, no cryptography,
//! no node ids. What it keeps is exactly the contract in
//! [`super`](crate::transport): a reliable ordered byte channel in each
//! direction, and a label for each end that both ends agree on. Everything
//! above the transport — the mutual application-key handshake
//! ([`crate::key_auth`]), the framing and the clipboard messages
//! ([`crate::protocol`]) — then runs unchanged, which is the point.
//!
//! Two shapes, because the contract is a *pair of half-channels* and not a
//! socket:
//!
//! - [`TcpSession`] — one bidirectional connection: the host binds a port, the
//!   dialer connects to it, and the socket is split into its two halves.
//! - [`UniTcpSession`] — two one-way connections: each peer binds a port and
//!   dials the other's, then *writes only* to the socket it opened and *reads
//!   only* from the socket it accepted. The session layer cannot tell the
//!   difference.
//!
//! # Not a shipping transport
//!
//! TCP authenticates nothing and encrypts nothing:
//!
//! - **No confidentiality.** duocb leaves that to the transport, so clipboard
//!   text crosses this one in the clear. Loopback and test networks only.
//! - **Labels, not identities.** The ids are socket addresses, so they bind the
//!   handshake to an address pair rather than to a proven endpoint, and the
//!   binding is only as good as the network path. Anything that rewrites
//!   addresses — NAT, a proxy, a peer bound to `0.0.0.0` but reached on a
//!   specific interface — leaves the two ends signing different transcripts,
//!   and the handshake fails rather than proceeding on a mismatch. Use
//!   [`TcpSession::with_ids`]/[`UniTcpSession::with_ids`] when the address a
//!   peer knows you by is not the one you bound.
//!
//! Neither weakness reaches local trust: the application-key proofs are what
//! decide who is on the connection, so an untrusted key is refused over this
//! transport exactly as it is over iroh.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};

use super::SessionTransport;
use crate::protocol::{
    ClipMsg, MAX_CLIP_MESSAGE_SIZE, decode_clip_msg, encode_clip_msg, read_length_prefixed,
};

/// How long [`TcpSession::dial`] and [`UniTcpSession::connect`] keep retrying a
/// refused connection. Both peers of a demo are usually started at once, so the
/// dialing half may be ready first; a real transport waits for a rendezvous
/// record instead.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

async fn dial_with_retry(peer: SocketAddr) -> Result<TcpStream> {
    let deadline = tokio::time::Instant::now() + DIAL_TIMEOUT;
    loop {
        match TcpStream::connect(peer).await {
            Ok(stream) => return Ok(stream),
            Err(error) if tokio::time::Instant::now() < deadline => {
                log::debug!("dummy transport: {peer} not listening yet ({error}); retrying");
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => {
                return Err(anyhow::Error::new(error).context(format!("connecting to {peer}")));
            }
        }
    }
}

/// A session over one bidirectional TCP connection.
///
/// The ids default to the two socket addresses of that connection, which both
/// ends observe identically on a path that does not rewrite addresses.
pub struct TcpSession {
    stream: TcpStream,
    local_id: String,
    peer_id: String,
}

impl TcpSession {
    /// Dial a listening peer. This end takes the dialing half of the handshake.
    pub async fn dial(peer: SocketAddr) -> Result<Self> {
        Self::from_stream(dial_with_retry(peer).await?)
    }

    /// Accept one connection. This end takes the listening half.
    pub async fn accept(listener: &TcpListener) -> Result<Self> {
        let (stream, _) = listener.accept().await.context("accepting a TCP session")?;
        Self::from_stream(stream)
    }

    fn from_stream(stream: TcpStream) -> Result<Self> {
        let local_id = format!("tcp:{}", stream.local_addr().context("local address")?);
        let peer_id = format!("tcp:{}", stream.peer_addr().context("peer address")?);
        Ok(Self {
            stream,
            local_id,
            peer_id,
        })
    }

    /// Override the two transport ids. Needed whenever the addresses the two
    /// ends observe are not the same strings — the demo equivalent of a
    /// transport that names its endpoints by something more durable than the
    /// current socket.
    pub fn with_ids(mut self, local_id: impl Into<String>, peer_id: impl Into<String>) -> Self {
        self.local_id = local_id.into();
        self.peer_id = peer_id.into();
        self
    }
}

impl SessionTransport for TcpSession {
    type Send = OwnedWriteHalf;
    type Recv = OwnedReadHalf;

    fn local_id(&self) -> String {
        self.local_id.clone()
    }

    fn peer_id(&self) -> String {
        self.peer_id.clone()
    }

    async fn session_stream(self) -> Result<(OwnedWriteHalf, OwnedReadHalf)> {
        // TCP has one stream per connection, so there is nothing to open or
        // accept here: the connection *is* the session stream. Who dialed is
        // still what decides which half of the handshake this end runs, but
        // that is the caller's business, not the socket's.
        let (recv, send) = self.stream.into_split();
        Ok((send, recv))
    }
}

/// A session over two one-way TCP connections: this peer writes to the socket
/// it dialed and reads from the socket it accepted.
///
/// Each peer binds a listener and is told the other's listening address, so the
/// ids are those two listening addresses — stable, and identical on both sides,
/// unlike the ephemeral client ports the sockets themselves carry.
pub struct UniTcpSession {
    send: OwnedWriteHalf,
    recv: OwnedReadHalf,
    local_id: String,
    peer_id: String,
}

impl UniTcpSession {
    /// Bring up both directions: accept the peer's inbound connection on
    /// `listener` while dialing the peer's own listening address. Both peers
    /// call this symmetrically; which of them then takes the dialing half of
    /// the *handshake* is a separate question, answered by
    /// [`crate::net::session_role`] from the application keys.
    pub async fn connect(listener: TcpListener, peer_listen: SocketAddr) -> Result<Self> {
        let local_listen = listener.local_addr().context("local listen address")?;
        let (inbound, outbound) = tokio::try_join!(
            async {
                listener
                    .accept()
                    .await
                    .context("accepting the peer's inbound connection")
            },
            dial_with_retry(peer_listen),
        )?;

        // Each socket is used in one direction only. The unused write half of
        // the inbound socket is `forget()`-ten rather than dropped, because
        // dropping it would shut that direction down and hand the peer an
        // end-of-stream it never asked for.
        let (recv, unused_send) = inbound.0.into_split();
        unused_send.forget();
        let (_unused_recv, send) = outbound.into_split();

        Ok(Self {
            send,
            recv,
            local_id: format!("tcp:{local_listen}"),
            peer_id: format!("tcp:{peer_listen}"),
        })
    }

    /// Override the two transport ids — see [`TcpSession::with_ids`].
    pub fn with_ids(mut self, local_id: impl Into<String>, peer_id: impl Into<String>) -> Self {
        self.local_id = local_id.into();
        self.peer_id = peer_id.into();
        self
    }
}

impl SessionTransport for UniTcpSession {
    type Send = OwnedWriteHalf;
    type Recv = OwnedReadHalf;

    fn local_id(&self) -> String {
        self.local_id.clone()
    }

    fn peer_id(&self) -> String {
        self.peer_id.clone()
    }

    async fn session_stream(self) -> Result<(OwnedWriteHalf, OwnedReadHalf)> {
        Ok((self.send, self.recv))
    }
}

/// Push one clipboard item onto an authenticated session stream — the same
/// frame the runtime's clipboard pump writes, spelled out for demos.
pub async fn send_item<W: tokio::io::AsyncWrite + Unpin>(send: &mut W, text: &str) -> Result<()> {
    let frame = encode_clip_msg(&ClipMsg::item(text, 0))?;
    send.write_all(&frame).await?;
    send.flush().await?;
    Ok(())
}

/// Read one clipboard frame and return its text, for demos.
pub async fn recv_item<R: tokio::io::AsyncRead + Unpin>(recv: &mut R) -> Result<String> {
    let frame = read_length_prefixed(recv, MAX_CLIP_MESSAGE_SIZE).await?;
    match decode_clip_msg(&frame)?.body {
        crate::protocol::ClipBody::Item { text, .. }
        | crate::protocol::ClipBody::Latest { text, .. } => Ok(text),
        crate::protocol::ClipBody::PullLatest => {
            anyhow::bail!("expected a clipboard item, got a pull request")
        }
    }
}
