//! Headless config-mode peer for same-machine E2E tests (e.g. pairing the iOS
//! Simulator app against this host). Drives the runtime exactly like a UI
//! would — commands in, events out — and prints every event.
//!
//! Environment:
//!   DUOCB_ROLE   start | join            (default start)
//!   DUOCB_TOKEN  shared 47-char token    (default: generate + print, start only)
//!   DUOCB_NAME   this device's name      (default mac-peer)
//!   DUOCB_SEND   text to send once paired (optional)
//!
//! Example:
//!   DUOCB_ROLE=start DUOCB_NAME=mac DUOCB_SEND='hello from mac' \
//!     cargo run -p duocb-core --example token_peer

use duocb_core::net::{DialSpec, NetEvent, ServerMode, UiCommand, spawn_net_runtime};

fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("duocb_core=info,token_peer=info"),
    )
    .init();

    let role = std::env::var("DUOCB_ROLE").unwrap_or_else(|_| "start".into());
    let name = std::env::var("DUOCB_NAME").unwrap_or_else(|_| "mac-peer".into());
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

    println!("token: {token}");
    println!(
        "fingerprint: {}",
        duocb_core::auth::token_fingerprint(&token)
    );

    let mut net = spawn_net_runtime(None);
    let cmd = match role.as_str() {
        "start" => UiCommand::StartServer {
            mode: ServerMode::NostrToken {
                token,
                name,
                relays,
            },
        },
        "join" => UiCommand::Connect {
            spec: DialSpec::NostrToken {
                token,
                own_name: name,
                relays,
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
