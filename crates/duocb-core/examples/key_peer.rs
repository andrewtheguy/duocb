//! Headless application-key configure-mode peer for E2E tests.
//!
//! Environment:
//! - `DUOCB_ROLE=start|join`
//! - `DUOCB_NSEC` persistent identity private key (generated when omitted)
//! - `DUOCB_NAME` local name (default `headless`)
//! - `DUOCB_SUFFIX` persistent device suffix
//! - `DUOCB_PEER_CARD` the other side's signed card (required)
//! - `DUOCB_SEND` clipboard text sent after pairing (optional)
//! - `DUOCB_CHANNEL=lan|nostr` pins signaling to one transport, matching the
//!   desktop app's `--lan-only`/`--nostr-only`; the default tries the local
//!   network first and falls back to the relays

use std::time::Duration;

use duocb_core::auth::{Identity, IdentityCard};
use duocb_core::net::{
    DialSpec, KeyIdentity, NetEvent, ServerMode, SignalChannel, UiCommand, spawn_net_runtime,
};

fn main() {
    let identity = std::env::var("DUOCB_NSEC")
        .ok()
        .map(|value| Identity::parse_nsec(&value).expect("invalid DUOCB_NSEC"))
        .unwrap_or_else(Identity::generate);
    let name = std::env::var("DUOCB_NAME").unwrap_or_else(|_| "headless".into());
    let suffix = std::env::var("DUOCB_SUFFIX").expect("DUOCB_SUFFIX is required");
    let self_card = identity
        .card(&name, &suffix)
        .expect("invalid DUOCB_NAME or DUOCB_SUFFIX");
    let peer = IdentityCard::parse(
        &std::env::var("DUOCB_PEER_CARD").expect("DUOCB_PEER_CARD is required"),
    )
    .expect("invalid DUOCB_PEER_CARD");
    let configured = KeyIdentity {
        identity: identity.clone(),
        self_card: self_card.clone(),
        peers: vec![peer.clone()],
        relays: duocb_core::nostr::DEFAULT_NOSTR_RELAYS
            .iter()
            .map(|relay| relay.to_string())
            .collect(),
    };

    println!("nsec: {}", identity.to_nsec());
    println!("npub: {}", identity.to_npub());
    println!("card: {}", self_card.encode());

    let channel = match std::env::var("DUOCB_CHANNEL").as_deref() {
        Ok("lan") => SignalChannel::LanOnly,
        Ok("nostr") => SignalChannel::NostrOnly,
        Err(_) => SignalChannel::default(),
        Ok(other) => panic!("DUOCB_CHANNEL must be lan or nostr, got {other:?}"),
    };

    let net = spawn_net_runtime(None);
    match std::env::var("DUOCB_ROLE").as_deref() {
        Ok("start") => net.send(UiCommand::StartServer {
            mode: ServerMode::Key {
                identity: Box::new(configured),
                channel,
            },
        }),
        Ok("join") => net.send(UiCommand::Connect {
            spec: DialSpec::Key {
                identity: Box::new(configured),
                peer_public_key: peer.public_key(),
                channel,
            },
        }),
        _ => panic!("DUOCB_ROLE must be start or join"),
    }

    let mut pending_send = std::env::var("DUOCB_SEND").ok();
    loop {
        match net.events.recv_timeout(Duration::from_secs(60)) {
            Ok(event) => {
                println!("{event:?}");
                if matches!(
                    event,
                    NetEvent::Status(duocb_core::net::ConnStatus::Connected)
                ) && let Some(text) = pending_send.take()
                {
                    net.send(UiCommand::SendClipboard { text });
                }
            }
            Err(error) => panic!("network event timeout: {error}"),
        }
    }
}
