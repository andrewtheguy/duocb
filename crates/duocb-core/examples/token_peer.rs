//! Headless config-mode peer for same-machine E2E tests (e.g. pairing the iOS
//! Simulator app against this host). Drives the runtime exactly like a UI
//! would — commands in, events out — and prints every event.
//!
//! Environment:
//!   DUOCB_ROLE    start | join                 (default start)
//!   DUOCB_TOKEN   shared 47-char token         (default: generate + print, start only)
//!   DUOCB_NAME    this device's short name     (default mac-peer)
//!   DUOCB_SUFFIX  8-char device suffix         (default: generate + print)
//!   DUOCB_PEER    peer display identity to dial, e.g. mac_a7B2c3D4 (required for join)
//!   DUOCB_SEND    text to send once paired     (optional)
//!
//! Example:
//!   DUOCB_ROLE=start DUOCB_NAME=mac DUOCB_SEND='hello from mac' \
//!     cargo run -p duocb-core --example token_peer

use duocb_core::net::{DialSpec, NetEvent, ServerMode, TokenIdentity, UiCommand, spawn_net_runtime};

fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("duocb_core=info,token_peer=info"),
    )
    .init();

    let role = std::env::var("DUOCB_ROLE").unwrap_or_else(|_| "start".into());
    let name = std::env::var("DUOCB_NAME").unwrap_or_else(|_| "mac-peer".into());
    duocb_core::identity::validate_name(&name).expect("invalid DUOCB_NAME");
    let suffix = match std::env::var("DUOCB_SUFFIX") {
        Ok(suffix) if !suffix.is_empty() => {
            assert!(
                duocb_core::identity::is_valid_suffix(&suffix),
                "invalid DUOCB_SUFFIX"
            );
            suffix
        }
        _ => duocb_core::identity::generate_suffix(),
    };
    let token = match std::env::var("DUOCB_TOKEN") {
        Ok(token) if !token.is_empty() => token,
        _ => {
            assert_eq!(role, "start", "DUOCB_TOKEN is required for the join role");
            duocb_core::auth::generate_token()
        }
    };
    duocb_core::auth::validate_token(&token).expect("invalid DUOCB_TOKEN");
    let send_on_pair = std::env::var("DUOCB_SEND").ok();
    let relays: Vec<String> = duocb_core::nostr::DEFAULT_NOSTR_RELAYS
        .iter()
        .map(|s| s.to_string())
        .collect();

    let identity = TokenIdentity {
        token: token.clone(),
        name,
        suffix,
        relays,
    };
    println!("token: {token}");
    println!(
        "fingerprint: {}",
        duocb_core::auth::token_fingerprint(&token)
    );
    println!("identity: {}", identity.display());

    let mut net = spawn_net_runtime(None);
    net.send(UiCommand::SetPresence {
        identity: Some(identity.clone()),
    });
    let cmd = match role.as_str() {
        "start" => UiCommand::StartServer {
            mode: ServerMode::NostrToken { identity },
        },
        "join" => UiCommand::Connect {
            spec: DialSpec::NostrToken {
                identity,
                peer_display: std::env::var("DUOCB_PEER")
                    .expect("DUOCB_PEER (the peer's display identity) is required for join"),
            },
        },
        other => panic!("unknown DUOCB_ROLE '{other}' (use start or join)"),
    };
    net.send(cmd);

    let mut pending_send = send_on_pair;
    while let Ok(event) = net.events.recv() {
        println!("event: {event:?}");
        match event {
            NetEvent::Status(duocb_core::net::ConnStatus::Connected) => {
                if let Some(text) = pending_send.take() {
                    net.send(UiCommand::SendClipboard { text });
                }
            }
            NetEvent::ItemReceived { text, pulled } => {
                let tag = if pulled { "received-latest" } else { "received-text" };
                println!("{tag}: {text}");
            }
            _ => {}
        }
    }
    net.shutdown();
}
