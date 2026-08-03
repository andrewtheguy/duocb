//! Spec-compliant DNS-SD backend for the LAN-only channel's PIN rendezvous —
//! see the module docs in `super`. The contract: advertise
//! `<instance>._duocb-pin._udp.local.` with the ciphertext in the `e` TXT
//! attribute and real SRV/A/AAAA data, and resolve a candidate instance back
//! into [`PinFound`] (node id + dialable direct addresses).
//!
//! The responder is the mdns-sd crate, an in-process RFC 6762/6763
//! implementation that interoperates with Bonjour.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow};
use iroh::EndpointId;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use nostr_sdk::prelude::Keys;

use super::{
    DNSSD_SERVICE_TYPE, LOOKUP_TIMEOUT, PinFound, TXT_KEY, TXT_KEY_PORT6, assemble_addrs,
    instance_name, split_ports,
};
use crate::pin_record;

/// The process-wide responder for *adverts*. Created on first use and
/// kept for the process lifetime: adverts register/unregister against it
/// (a rotation every period would otherwise spawn and tear down socket
/// threads). Lookups use their own short-lived daemon instead — a shared
/// browse would let one lookup's `stop_browse` kill a concurrent one's.
/// A failed first bind stays failed — the daemon binds 5353 with
/// SO_REUSEADDR/SO_REUSEPORT, so failure means something unusual that a
/// retry within this process won't fix.
fn daemon() -> Result<&'static ServiceDaemon> {
    static DAEMON: OnceLock<Option<ServiceDaemon>> = OnceLock::new();
    DAEMON
        .get_or_init(|| {
            ServiceDaemon::new()
                .inspect_err(|e| log::warn!("Failed to start the DNS-SD responder: {e}"))
                .ok()
        })
        .as_ref()
        .ok_or_else(|| anyhow!("the DNS-SD responder failed to start"))
}

/// A live registration; dropping it unregisters the instance (the daemon
/// sends the goodbye packets).
pub(super) struct Advert {
    fullname: String,
}

impl Drop for Advert {
    fn drop(&mut self) {
        if let Ok(daemon) = daemon() {
            let _ = daemon.unregister(&self.fullname);
        }
    }
}

/// Async for signature parity with the lookup side; the mdns-sd registration
/// itself is a non-blocking channel send.
pub(super) async fn advertise(
    keys: &Keys,
    node_id: &EndpointId,
    addrs: &[SocketAddr],
) -> Result<Advert> {
    let content = pin_record::encrypt_pin_payload(keys, node_id)?;
    let (srv_port, port6) =
        split_ports(addrs).context("endpoint has no direct addresses to advertise")?;
    let instance = instance_name(keys);

    let mut props = HashMap::from([(TXT_KEY.to_string(), content)]);
    if let Some(p6) = port6 {
        props.insert(TXT_KEY_PORT6.to_string(), p6.to_string());
    }
    let mut ips: Vec<IpAddr> = addrs.iter().map(SocketAddr::ip).collect();
    ips.sort_unstable();
    ips.dedup();

    // The hostname is only an SRV target label; deriving it from the
    // instance keeps two concurrent adverts (look-back window) distinct.
    let host = format!("{instance}.local.");
    let info = ServiceInfo::new(
        DNSSD_SERVICE_TYPE,
        &instance,
        &host,
        &ips[..],
        srv_port,
        props,
    )
    .map_err(|e| anyhow!("building DNS-SD service info: {e}"))?;
    let fullname = info.get_fullname().to_string();
    daemon()?
        .register(info)
        .map_err(|e| anyhow!("starting DNS-SD PIN advertisement: {e}"))?;
    Ok(Advert { fullname })
}

pub(super) async fn lookup(candidates: &[Keys]) -> Result<Option<PinFound>> {
    let by_instance: HashMap<String, &Keys> = candidates
        .iter()
        .map(|keys| (instance_name(keys), keys))
        .collect();

    // A lookup-private daemon (see `daemon` docs); shut down at the end.
    let daemon = ServiceDaemon::new().map_err(|e| anyhow!("starting the DNS-SD browser: {e}"))?;
    let receiver = daemon
        .browse(DNSSD_SERVICE_TYPE)
        .map_err(|e| anyhow!("starting DNS-SD PIN browse: {e}"))?;
    let deadline = tokio::time::Instant::now() + LOOKUP_TIMEOUT;
    let suffix = format!(".{DNSSD_SERVICE_TYPE}");

    let found = loop {
        let event = match tokio::time::timeout_at(deadline, receiver.recv_async()).await {
            Ok(Ok(event)) => event,
            // Browse window over, or the daemon went away mid-browse.
            Err(_) | Ok(Err(_)) => break None,
        };
        let ServiceEvent::ServiceResolved(info) = event else {
            continue;
        };
        // Instance labels are registered lowercase, but mDNS names are
        // case-insensitive and other stacks may echo them differently.
        let fullname = info.get_fullname().to_ascii_lowercase();
        let Some(instance) = fullname.strip_suffix(&suffix) else {
            continue;
        };
        let Some(keys) = by_instance.get(instance) else {
            continue;
        };
        let Some(content) = info.get_property_val_str(TXT_KEY) else {
            continue;
        };
        let Some(node_id) = pin_record::decrypt_pin_payload(keys, content) else {
            continue;
        };
        let port6 = info
            .get_property_val_str(TXT_KEY_PORT6)
            .and_then(|s| s.parse().ok());
        let ips: Vec<IpAddr> = info
            .get_addresses()
            .iter()
            .map(|scoped| scoped.to_ip_addr())
            .collect();
        break Some(PinFound {
            node_id,
            addrs: assemble_addrs(&ips, info.get_port(), port6),
        });
    };
    let _ = daemon.shutdown();
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Interop with the platform Bonjour daemon: `dns-sd -R` registers through
    /// macOS's mDNSResponder rather than our in-process responder, so a lookup
    /// that finds it proves we resolve records published by a foreign
    /// RFC 6762/6763 stack.
    #[cfg(target_os = "macos")]
    #[tokio::test(flavor = "multi_thread")]
    async fn lookup_finds_daemon_registered_advert() {
        let _ = env_logger::builder().is_test(true).try_init();
        let pin = "M3TDPWFA";
        let node_id = iroh::SecretKey::generate().public();

        let candidates = pin_record::candidate_keys(pin).await.unwrap();
        let content = pin_record::encrypt_pin_payload(&candidates[0], &node_id).unwrap();
        let instance = instance_name(&candidates[0]);
        let mut host = std::process::Command::new("dns-sd")
            .args([
                "-R",
                &instance,
                "_duocb-pin._udp",
                "local",
                "4433",
                &format!("{TXT_KEY}={content}"),
            ])
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("dns-sd CLI (ships with macOS)");
        // Give the daemon a beat to register before browsing.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let found = lookup(&candidates).await;
        let _ = host.kill();
        let _ = host.wait();
        let found = found.unwrap().expect("daemon-registered record on LAN");
        assert_eq!(found.node_id, node_id);
        assert!(
            found.addrs.iter().all(|a| a.port() == 4433),
            "addrs should carry the SRV port: {:?}",
            found.addrs
        );
        assert!(!found.addrs.is_empty(), "no dialable addresses resolved");
    }

    /// Debug probe: run the real lookup against a live host's PIN, passed
    /// via DUOCB_TEST_PIN. Run manually with `-- --ignored --nocapture`.
    #[ignore]
    #[tokio::test(flavor = "multi_thread")]
    async fn lookup_by_env_pin() {
        let _ = env_logger::builder().is_test(true).try_init();
        let pin = crate::pin::normalize_pin(&std::env::var("DUOCB_TEST_PIN").unwrap())
            .expect("valid PIN");
        let candidates = pin_record::candidate_keys(&pin).await.unwrap();
        let found = lookup(&candidates).await.unwrap();
        match found {
            Some(f) => println!("FOUND node_id={} addrs={:?}", f.node_id, f.addrs),
            None => println!("MISS"),
        }
    }

    /// Debug probe: raw-browse the PIN service type and dump every event.
    /// Run manually with `-- --ignored --nocapture` while a host is up.
    #[ignore]
    #[tokio::test(flavor = "multi_thread")]
    async fn raw_browse_probe() {
        let _ = env_logger::builder().is_test(true).try_init();
        let daemon = ServiceDaemon::new().unwrap();
        let receiver = daemon.browse(DNSSD_SERVICE_TYPE).unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
        while let Ok(Ok(event)) = tokio::time::timeout_at(deadline, receiver.recv_async()).await {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    println!(
                        "RESOLVED {} port={} addrs={:?} e={:?} p6={:?}",
                        info.get_fullname(),
                        info.get_port(),
                        info.get_addresses(),
                        info.get_property_val_str(TXT_KEY).map(|s| s.len()),
                        info.get_property_val_str(TXT_KEY_PORT6),
                    );
                }
                other => println!("EVENT {other:?}"),
            }
        }
        let _ = daemon.shutdown();
    }

    /// End-to-end rendezvous through the real DNS-SD responder: advertise
    /// a record for the current bucket, then look it up with the PIN's
    /// candidate keys and get the node id *and* dialable addresses back.
    #[tokio::test(flavor = "multi_thread")]
    async fn advertise_then_lookup_round_trips_with_addrs() {
        let _ = env_logger::builder().is_test(true).try_init();
        let pin = "K7P29QXM";
        let node_id = iroh::SecretKey::generate().public();
        let addr = SocketAddr::from(([127, 0, 0, 1], 4433));

        let candidates = pin_record::candidate_keys(pin).await.unwrap();
        // candidate_keys leads with the current bucket — the one to advertise.
        let _advert = advertise(&candidates[0], &node_id, &[addr]).await.unwrap();

        let found = lookup(&candidates).await.unwrap().expect("record on LAN");
        assert_eq!(found.node_id, node_id);
        assert!(
            found.addrs.contains(&addr),
            "resolved addrs {:?} missing {addr}",
            found.addrs
        );
    }
}
