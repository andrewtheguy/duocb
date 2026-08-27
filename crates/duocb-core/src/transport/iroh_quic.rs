//! The transport duocb ships with: iroh's QUIC connections.
//!
//! This is the [`SessionTransport`] implementation the desktop and iOS apps
//! actually run on, and the reason the rest of the crate can stay
//! transport-free. It contributes the two things a shipping transport has to
//! contribute beyond a byte channel:
//!
//! - **Authenticated endpoint ids.** A node id is a public key that QUIC/TLS
//!   proves possession of during the handshake, so the ids
//!   [`crate::key_auth`] signs are identities rather than labels, and both ends
//!   necessarily agree on the pair. That survives NAT and relays, which is
//!   exactly where an address-shaped id (see [`super::dummy`]) would not.
//! - **Confidentiality.** Everything above this layer, handshake included, is
//!   inside QUIC/TLS.
//!
//! The endpoint plumbing around it — binding, discovery, relays, path
//! reporting — lives in [`crate::net::endpoint`]; this type is only the seam
//! where a session's stream comes from.

use anyhow::{Context, Result};
use iroh::endpoint::{Connection, RecvStream, SendStream};

use super::{Role, SessionTransport};

/// An established iroh connection, ready to give up its session stream.
///
/// `own_id` is passed in rather than read back off the connection: it is the
/// runtime's fixed transport id, the same for every endpoint it binds.
pub struct IrohSession {
    conn: Connection,
    own_id: iroh::EndpointId,
    role: Role,
}

impl IrohSession {
    pub fn dialer(conn: Connection, own_id: iroh::EndpointId) -> Self {
        Self {
            conn,
            own_id,
            role: Role::Dialer,
        }
    }

    pub fn listener(conn: Connection, own_id: iroh::EndpointId) -> Self {
        Self {
            conn,
            own_id,
            role: Role::Listener,
        }
    }
}

impl SessionTransport for IrohSession {
    type Send = SendStream;
    type Recv = RecvStream;

    fn local_id(&self) -> String {
        self.own_id.to_string()
    }

    /// The peer's node id as authenticated by QUIC/TLS — not a claim the peer
    /// made in-band.
    fn peer_id(&self) -> String {
        self.conn.remote_id().to_string()
    }

    async fn session_stream(self) -> Result<(SendStream, RecvStream)> {
        match self.role {
            Role::Dialer => self.conn.open_bi().await.context("opening session stream"),
            Role::Listener => self
                .conn
                .accept_bi()
                .await
                .context("Failed to accept session stream"),
        }
    }
}
