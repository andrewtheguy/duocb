//! A duocb clipboard session over a transport that is not iroh: plain TCP,
//! host and port, no discovery and no cryptography of its own.
//!
//! It exists to show where the transport boundary actually is. Everything the
//! two peers say to each other here — the mutual application-key handshake, the
//! length-prefixed framing, the clipboard messages — is the same code the
//! shipping app runs over iroh (`duocb_core::key_auth`, `duocb_core::protocol`).
//! The only thing swapped out is the thing under it, and the swap is one type
//! implementing `duocb_core::transport::SessionTransport`.
//!
//! Two shapes, both of them "host and port":
//!
//! - **bidirectional** — one TCP connection, split into a send half and a recv
//!   half.
//! - **unidirectional** (`--uni`) — two one-way connections: each peer binds a
//!   port, dials the other's, then writes only to the socket it opened and
//!   reads only from the socket it accepted.
//!
//! …and rendezvous on top of them (`lan`), where neither peer is told an
//! address at all: the hosting half publishes its `host:port` in the encrypted
//! pairwise hosting record over DNS-SD, exactly where the app publishes its
//! iroh node id, and the dialing half looks that record up by the pair of
//! application keys and dials what it says.
//!
//! ```sh
//! # both peers in one process, over loopback: bidirectional, then two one-way sockets
//! cargo run -p duocb-core --example dummy_transport
//!
//! # just the two one-way sockets
//! cargo run -p duocb-core --example dummy_transport -- --uni
//!
//! # two processes. Each prints its npub; give each the other's.
//! DUOCB_PEER_NPUB=<other npub> cargo run -p duocb-core --example dummy_transport -- \
//!     peer 127.0.0.1:7801 127.0.0.1:7802 [--uni]
//!
//! # two processes that find each other over mDNS — no addresses typed
//! DUOCB_PEER_NPUB=<other npub> cargo run -p duocb-core --example dummy_transport -- lan
//! ```
//!
//! Which peer listens and which dials is not a flag: `session_role` derives it
//! from the two application keys, exactly as the app does. In `peer` mode both
//! sides are given both addresses and only use the one their role calls for
//! (the unidirectional shape uses both).
//!
//! **Demo only.** TCP encrypts nothing, so the clipboard text below crosses in
//! the clear, and the transport ids are socket addresses rather than
//! authenticated node ids — see the `duocb_core::transport::dummy` docs.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use duocb_core::auth::Identity;
use duocb_core::net::{SessionRole, session_role};
use duocb_core::transport::dummy::{self, TcpSession, UniTcpSession, recv_item, send_item};
use duocb_core::transport::{SessionTransport, authenticate_dialer, authenticate_listener};
use tokio::net::TcpListener;

/// Run one side of a session over an already-connected transport: authenticate,
/// send one clipboard item, read the peer's.
async fn session<T: SessionTransport>(
    who: &str,
    identity: &Identity,
    transport: T,
    peer_key: nostr_sdk::PublicKey,
    text: &str,
) -> Result<String> {
    let role = session_role(identity.public_key(), peer_key);
    println!(
        "{who}: {role:?} — transport says local={} peer={}",
        transport.local_id(),
        transport.peer_id()
    );

    let (mut send, mut recv) = match role {
        // The listening half admits exactly the one key this session is for.
        // The app checks a stored signed card here; the demo checks the raw
        // key, which is the part the handshake actually proves.
        SessionRole::Host => {
            let (send, recv, proven) = authenticate_listener(transport, identity, |offered| {
                if offered == peer_key {
                    Ok(())
                } else {
                    anyhow::bail!("dialer application key is not locally trusted")
                }
            })
            .await
            .context("listener handshake")?;
            println!("{who}: authenticated {}", proven.to_hex());
            (send, recv)
        }
        SessionRole::Dial => authenticate_dialer(transport, identity, peer_key)
            .await
            .context("dialer handshake")?,
    };

    send_item(&mut send, text).await.context("sending")?;
    let received = recv_item(&mut recv).await.context("receiving")?;
    println!("{who}: received {received:?}");
    Ok(received)
}

/// Both peers in this process, over one bidirectional loopback connection.
async fn in_process_bidirectional() -> Result<()> {
    println!("\n== one bidirectional TCP connection ==");
    let (a, b) = (Identity::generate(), Identity::generate());
    let (a_key, b_key) = (a.public_key(), b.public_key());
    // The lower application key hosts, so that is the side that binds a port.
    let (host, joiner, host_key, joiner_key) = match session_role(a_key, b_key) {
        SessionRole::Host => (a, b, a_key, b_key),
        SessionRole::Dial => (b, a, b_key, a_key),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    println!("host listening on {addr}");

    let hosting = tokio::spawn(async move {
        let transport = TcpSession::accept(&listener).await?;
        session("host", &host, transport, joiner_key, "sent by the host").await
    });
    let transport = TcpSession::dial(addr).await?;
    session(
        "joiner",
        &joiner,
        transport,
        host_key,
        "sent by the joiner",
    )
    .await?;
    hosting.await.context("hosting task")??;
    Ok(())
}

/// Both peers in this process, each writing to a socket it dialed and reading
/// from one it accepted.
async fn in_process_unidirectional() -> Result<()> {
    println!("\n== two one-way TCP connections ==");
    let (a, b) = (Identity::generate(), Identity::generate());
    let (a_key, b_key) = (a.public_key(), b.public_key());
    let a_listener = TcpListener::bind("127.0.0.1:0").await?;
    let b_listener = TcpListener::bind("127.0.0.1:0").await?;
    let (a_addr, b_addr) = (a_listener.local_addr()?, b_listener.local_addr()?);
    println!("A listening on {a_addr}, B listening on {b_addr}");

    let peer_a = tokio::spawn(async move {
        let transport = UniTcpSession::connect(a_listener, b_addr).await?;
        session("A", &a, transport, b_key, "sent by A").await
    });
    let peer_b = tokio::spawn(async move {
        let transport = UniTcpSession::connect(b_listener, a_addr).await?;
        session("B", &b, transport, a_key, "sent by B").await
    });
    peer_a.await.context("peer A")??;
    peer_b.await.context("peer B")??;
    Ok(())
}

/// One side of a two-process run that uses no addresses at all: the peers are
/// found through the encrypted pairwise hosting record on the local network.
///
/// This is the same rendezvous the app runs — `lan::dnssd_advertise_hosting`
/// and `lan::dnssd_lookup_hosting`, one record per ordered pair of application
/// keys, NIP-44 encrypted to the one peer it is for. The only difference is
/// what the record says: `tcp:host:port` here, an iroh node id there. Neither
/// the DNS-SD carrier nor anything else on the network can read it.
async fn lan_peer(identity: Identity, peer_key: nostr_sdk::PublicKey) -> Result<()> {
    let text = format!("hello from {}", identity.to_npub());
    match session_role(identity.public_key(), peer_key) {
        SessionRole::Host => {
            let listener = TcpListener::bind("0.0.0.0:0").await.context("binding")?;
            let bound = listener.local_addr()?;
            // What the peer will dial. The advertised address has to be one the
            // peer can reach, so an ephemeral loopback/LAN port is resolved to
            // a concrete address here rather than advertised as 0.0.0.0.
            let reachable = SocketAddr::from(([127, 0, 0, 1], bound.port()));
            let addr = dummy::rendezvous_addr(reachable);
            println!("this key hosts — listening on {bound}, advertising {addr:?} over mDNS");
            // Dropping the advert withdraws the record, so it is held for the
            // whole session.
            let _advert = duocb_core::lan::dnssd_advertise_hosting(
                &identity,
                peer_key,
                &addr,
                &[reachable],
            )
            .await
            .context("advertising the hosting record")?;
            let transport = TcpSession::accept(&listener).await?;
            session("peer", &identity, transport, peer_key, &text).await?;
        }
        SessionRole::Dial => {
            println!("this key dials — looking for the peer's hosting record on mDNS");
            let found = duocb_core::lan::dnssd_lookup_hosting(&identity, peer_key)
                .await
                .context("looking up the hosting record")?
                .context("the peer is not hosting on this network")?;
            println!(
                "found {:?} (direct addrs {:?})",
                found.payload, found.addrs
            );
            let transport = TcpSession::dial_record(&found.payload).await?;
            session("peer", &identity, transport, peer_key, &text).await?;
        }
    }
    Ok(())
}

/// The identity and trusted peer both two-process modes run as: an `nsec` from
/// the environment or a fresh one, and the peer's `npub`.
fn peer_identity() -> Result<(Identity, nostr_sdk::PublicKey)> {
    let identity = match std::env::var("DUOCB_NSEC") {
        Ok(nsec) => Identity::parse_nsec(&nsec).context("invalid DUOCB_NSEC")?,
        Err(_) => Identity::generate(),
    };
    println!("nsec: {}", identity.to_nsec());
    println!("npub: {}", identity.to_npub());
    let peer_key = nostr_sdk::PublicKey::parse(
        &std::env::var("DUOCB_PEER_NPUB")
            .context("DUOCB_PEER_NPUB is required (the other process prints its npub)")?,
    )
    .context("invalid DUOCB_PEER_NPUB")?;
    Ok((identity, peer_key))
}

/// One side of a two-process run.
async fn one_peer(bind: SocketAddr, peer_addr: SocketAddr, uni: bool) -> Result<()> {
    let (identity, peer_key) = peer_identity()?;
    let text = format!("hello from {}", identity.to_npub());
    if uni {
        let listener = TcpListener::bind(bind).await.context("binding")?;
        let transport = UniTcpSession::connect(listener, peer_addr).await?;
        session("peer", &identity, transport, peer_key, &text).await?;
    } else {
        match session_role(identity.public_key(), peer_key) {
            SessionRole::Host => {
                let listener = TcpListener::bind(bind).await.context("binding")?;
                println!("this key hosts — listening on {bind}");
                let transport = TcpSession::accept(&listener).await?;
                session("peer", &identity, transport, peer_key, &text).await?;
            }
            SessionRole::Dial => {
                println!("this key dials — connecting to {peer_addr}");
                let transport = TcpSession::dial(peer_addr).await?;
                session("peer", &identity, transport, peer_key, &text).await?;
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let uni = args.iter().any(|arg| arg == "--uni");
    let positional: Vec<&String> = args.iter().filter(|arg| !arg.starts_with("--")).collect();

    match positional.as_slice() {
        [] if uni => in_process_unidirectional().await?,
        [] => {
            in_process_bidirectional().await?;
            in_process_unidirectional().await?;
        }
        [mode] if *mode == "lan" => {
            let (identity, peer_key) = peer_identity()?;
            lan_peer(identity, peer_key).await?;
        }
        [mode, bind, peer_addr] if *mode == "peer" => {
            one_peer(bind.parse()?, peer_addr.parse()?, uni).await?;
        }
        _ => anyhow::bail!(
            "usage: dummy_transport [--uni] | dummy_transport peer <bind-addr> <peer-addr> \
             [--uni] | dummy_transport lan"
        ),
    }
    Ok(())
}
