//! A complete clipboard session over a transport that is not iroh.
//!
//! These tests are the check on the claim in `duocb_core::transport`: the
//! session layer — mutual application-key authentication, framing, clipboard
//! messages — depends on nothing but a reliable ordered byte channel in each
//! direction and a pair of endpoint labels both sides agree on. Nothing here
//! binds an iroh endpoint, resolves a node id, or touches a relay; the code
//! being exercised is the same `key_auth`/`protocol` code the shipping runtime
//! runs.

use std::net::SocketAddr;

use anyhow::Result;
use duocb_core::auth::Identity;
use duocb_core::net::{SessionRole, session_role};
use duocb_core::transport::dummy::{TcpSession, UniTcpSession, recv_item, send_item};
use duocb_core::transport::{SessionTransport, authenticate_dialer, authenticate_listener};
use tokio::net::TcpListener;

async fn loopback_listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    (listener, addr)
}

/// Trust, spelled out: the listener admits exactly the one application key the
/// session is for, which is all `admit` ever decides in the real runtime too
/// (there it also checks the stored card's validity window).
fn only(expected: nostr_sdk::PublicKey) -> impl FnOnce(nostr_sdk::PublicKey) -> Result<()> {
    move |offered| {
        if offered == expected {
            Ok(())
        } else {
            anyhow::bail!("dialer application key is not locally trusted")
        }
    }
}

/// One bidirectional TCP connection carries a whole session: both sides prove
/// their application key to the other, then clipboard text crosses in both
/// directions.
#[tokio::test(flavor = "multi_thread")]
async fn a_clipboard_session_runs_over_one_bidirectional_tcp_connection() {
    let host = Identity::generate();
    let joiner = Identity::generate();
    let (host_key, joiner_key) = (host.public_key(), joiner.public_key());
    let (listener, addr) = loopback_listener().await;

    let hosting = tokio::spawn(async move {
        let transport = TcpSession::accept(&listener).await.expect("accept");
        let (mut send, mut recv, peer) = authenticate_listener(transport, &host, only(joiner_key))
            .await
            .expect("listener handshake");
        assert_eq!(peer, joiner_key, "the proven key is the dialer's");
        let text = recv_item(&mut recv).await.expect("receive");
        send_item(&mut send, &format!("echo: {text}"))
            .await
            .expect("send");
    });

    let transport = TcpSession::dial(addr).await.expect("dial");
    let (mut send, mut recv) = authenticate_dialer(transport, &joiner, host_key)
        .await
        .expect("dialer handshake");
    send_item(&mut send, "hello over TCP").await.expect("send");
    assert_eq!(
        recv_item(&mut recv).await.expect("receive"),
        "echo: hello over TCP"
    );
    hosting.await.expect("hosting task");
}

/// The contract is a send half and a recv half, not a socket: here each peer
/// binds its own port, writes only to the connection it opened and reads only
/// from the one it accepted. The session layer is unchanged, and so is the way
/// the halves are assigned — `session_role` picks the listening side from the
/// two application keys, exactly as the app does.
#[tokio::test(flavor = "multi_thread")]
async fn a_clipboard_session_runs_over_two_one_way_tcp_connections() {
    let a = Identity::generate();
    let b = Identity::generate();
    let (a_key, b_key) = (a.public_key(), b.public_key());
    let (a_listener, a_addr) = loopback_listener().await;
    let (b_listener, b_addr) = loopback_listener().await;

    async fn peer(
        identity: Identity,
        listener: TcpListener,
        peer_listen: SocketAddr,
        peer_key: nostr_sdk::PublicKey,
        text: &str,
    ) -> String {
        let transport = UniTcpSession::connect(listener, peer_listen)
            .await
            .expect("both directions up");
        let (mut send, mut recv) = match session_role(identity.public_key(), peer_key) {
            SessionRole::Host => {
                let (send, recv, proven) =
                    authenticate_listener(transport, &identity, only(peer_key))
                        .await
                        .expect("listener handshake");
                assert_eq!(proven, peer_key);
                (send, recv)
            }
            SessionRole::Dial => authenticate_dialer(transport, &identity, peer_key)
                .await
                .expect("dialer handshake"),
        };
        send_item(&mut send, text).await.expect("send");
        recv_item(&mut recv).await.expect("receive")
    }

    let (from_b, from_a) = tokio::join!(
        peer(a, a_listener, b_addr, b_key, "sent by A"),
        peer(b, b_listener, a_addr, a_key, "sent by B"),
    );
    assert_eq!(from_b, "sent by B");
    assert_eq!(from_a, "sent by A");
}

/// Local trust is decided above the transport, so it holds over a transport
/// with no cryptography of its own: an application key the listener does not
/// know is refused before the listener signs anything, and the dialer is told.
#[tokio::test(flavor = "multi_thread")]
async fn an_untrusted_application_key_is_refused_over_any_transport() {
    let host = Identity::generate();
    let stranger = Identity::generate();
    let expected = Identity::generate().public_key();
    let host_key = host.public_key();
    let (listener, addr) = loopback_listener().await;

    let hosting = tokio::spawn(async move {
        let transport = TcpSession::accept(&listener).await.expect("accept");
        authenticate_listener(transport, &host, only(expected))
            .await
            .expect_err("a key the host does not trust must not authenticate")
    });

    let transport = TcpSession::dial(addr).await.expect("dial");
    let error = authenticate_dialer(transport, &stranger, host_key)
        .await
        .expect_err("the listener refuses");
    let refusal = format!("{:#}", hosting.await.expect("hosting task"));
    assert!(
        refusal.contains("not locally trusted"),
        "the listener refuses on trust: {refusal}"
    );
    // The listener drops the connection instead of signing, so the dialer's
    // failure is the truncated stream rather than a rejection frame.
    assert!(
        !format!("{error:#}").is_empty(),
        "the dialer must fail too"
    );
}

/// The endpoint ids are signed, so both ends have to name the connection the
/// same way. Under iroh they are QUIC-authenticated node ids and cannot
/// disagree; over TCP they are addresses, so a rewritten one (NAT, a proxy)
/// fails the handshake rather than quietly authenticating a different path.
#[tokio::test(flavor = "multi_thread")]
async fn transport_ids_that_disagree_fail_the_handshake() {
    let host = Identity::generate();
    let joiner = Identity::generate();
    let (host_key, joiner_key) = (host.public_key(), joiner.public_key());
    let (listener, addr) = loopback_listener().await;

    let hosting = tokio::spawn(async move {
        let transport = TcpSession::accept(&listener).await.expect("accept");
        authenticate_listener(transport, &host, only(joiner_key))
            .await
            .map(|_| ())
    });

    let transport = TcpSession::dial(addr)
        .await
        .expect("dial")
        .with_ids("tcp:somewhere-else", format!("tcp:{addr}"));
    let error = format!(
        "{:#}",
        authenticate_dialer(transport, &joiner, host_key)
            .await
            .expect_err("the listener signed a different transcript")
    );
    assert!(
        error.contains("did not verify"),
        "a mismatched channel binding must fail the proof: {error}"
    );
    assert!(hosting.await.expect("hosting task").is_err());
}

/// The transport only reports labels; it never decides identity. Both dummy
/// shapes name their two ends, and the two ends name each other the same way —
/// which is the whole of what `key_auth` asks a transport for.
#[tokio::test(flavor = "multi_thread")]
async fn both_ends_label_the_connection_identically() {
    let (listener, addr) = loopback_listener().await;
    let accepting = tokio::spawn(async move { TcpSession::accept(&listener).await.expect("accept") });
    let dialing = TcpSession::dial(addr).await.expect("dial");
    let accepted = accepting.await.expect("accept task");

    assert_eq!(dialing.peer_id(), accepted.local_id());
    assert_eq!(dialing.local_id(), accepted.peer_id());
    assert_eq!(dialing.peer_id(), format!("tcp:{addr}"));
}
