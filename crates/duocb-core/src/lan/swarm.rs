//! swarm-discovery backend for the default (nostr+LAN) channel's PIN
//! rendezvous — see the module docs in `super` for how it relates to the
//! DNS-SD backend. Desktop-only: this responder opens its own multicast
//! sockets, which iOS gates behind the restricted multicast entitlement.
//!
//! The record appears as `<instance>._duocb-pin._udp.local.` with the
//! ciphertext in a TXT attribute. The advertised port/addresses are advisory:
//! the client dials the decrypted node id bare, and iroh's own mDNS address
//! lookup (the same swarm-discovery engine — same version, socket options
//! with SO_REUSEADDR/SO_REUSEPORT — which every desktop endpoint runs)
//! resolves the transport.

use std::collections::HashMap;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use iroh::EndpointId;
use nostr_sdk::prelude::Keys;
use swarm_discovery::{Discoverer, DropGuard};

use super::{LOOKUP_TIMEOUT, PIN_SERVICE_NAME, TXT_KEY, instance_name};
use crate::pin_record;

/// Advertise one bucket's PIN record; dropping the guard withdraws it.
/// Must be called within a tokio runtime.
pub(super) fn advertise(
    keys: &Keys,
    node_id: &EndpointId,
    addrs: &[SocketAddr],
) -> Result<DropGuard> {
    let content = pin_record::encrypt_pin_payload(keys, node_id)?;
    let mut discoverer =
        Discoverer::new_interactive(PIN_SERVICE_NAME.to_string(), instance_name(keys))
            .with_txt_attributes([(TXT_KEY.to_string(), Some(content))])
            .context("PIN record does not fit an mDNS TXT attribute")?;
    for addr in addrs {
        discoverer = discoverer.with_addrs(addr.port(), [addr.ip()]);
    }
    discoverer
        .spawn(&tokio::runtime::Handle::current())
        .context("starting mDNS PIN advertisement")
}

/// Browse for a record matching one of the candidate keypairs; `Ok(None)`
/// when nothing matching answered within the browse window.
pub(super) async fn lookup(candidates: &[Keys]) -> Result<Option<EndpointId>> {
    // Index by instance label so a browse hit picks the right bucket's secret
    // for decryption.
    let by_instance: HashMap<String, &Keys> = candidates
        .iter()
        .map(|keys| (instance_name(keys), keys))
        .collect();

    // Browse-only discoverer (no addrs registered → nothing announced). The
    // label only needs to be a valid DNS label distinct from the advertisers'.
    // The callback prefilters to our candidate instance labels so unrelated
    // `_duocb-pin._udp.local.` advertisers on the LAN never enter the channel,
    // which stays bounded (try_send drops on a full queue — one decryptable hit
    // is all the loop below needs).
    let accepted: std::collections::HashSet<String> = by_instance.keys().cloned().collect();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, String)>(16);
    let _guard = Discoverer::new_interactive(
        PIN_SERVICE_NAME.to_string(),
        format!("lookup-{:08x}", rand::random::<u32>()),
    )
    .with_callback(move |peer_id, peer| {
        let peer_id = peer_id.to_string();
        if !accepted.contains(&peer_id) {
            return;
        }
        if let Some(Some(content)) = peer.txt_attribute(TXT_KEY) {
            let _ = tx.try_send((peer_id, content.to_string()));
        }
    })
    .spawn(&tokio::runtime::Handle::current())
    .context("starting mDNS PIN lookup")?;

    let deadline = tokio::time::Instant::now() + LOOKUP_TIMEOUT;
    while let Ok(Some((peer_id, content))) = tokio::time::timeout_at(deadline, rx.recv()).await {
        let Some(keys) = by_instance.get(&peer_id) else {
            continue;
        };
        if let Some(node_id) = pin_record::decrypt_pin_payload(keys, &content) {
            return Ok(Some(node_id));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end rendezvous over real loopback multicast: advertise a record
    /// for the current bucket, then look it up with the PIN's candidate keys.
    #[tokio::test(flavor = "multi_thread")]
    async fn advertise_then_lookup_round_trips() {
        let _ = env_logger::builder().is_test(true).try_init();
        let pin = "K7P29QXM";
        let node_id = iroh::SecretKey::generate().public();

        let candidates = pin_record::candidate_keys(pin).await.unwrap();
        // candidate_keys leads with the current bucket — the one to advertise.
        let _advert = advertise(
            &candidates[0],
            &node_id,
            &[SocketAddr::from(([127, 0, 0, 1], 4433))],
        )
        .unwrap();

        let found = lookup(&candidates).await.unwrap();
        assert_eq!(found, Some(node_id));
    }
}
