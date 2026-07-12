//! mDNS transport for the encrypted PIN rendezvous record — the LAN-only
//! sibling of the nostr transport in `crate::nostr`. Used by the "PIN over
//! LAN" quick mode: no relays, no internet — the server advertises the record
//! as a DNS-SD service on the local network and a client holding the PIN
//! derives the same `(pin, bucket)` key to find and decrypt it.
//!
//! The record appears as `<instance>._duocb-pin._udp.local.` where the
//! instance label is derived from the `(pin, bucket)` public key — the same
//! lookup-by-derived-key model as the nostr record's author key — and a TXT
//! attribute carries the NIP-44 ciphertext (see `crate::pin_record`). The
//! advertised port/addresses are advisory: the client dials the decrypted node
//! id bare, and iroh's own mDNS address lookup resolves the transport.
//!
//! swarm-discovery is the same engine iroh's mDNS lookup runs on (same
//! version, socket options with SO_REUSEADDR/SO_REUSEPORT), so this responder
//! coexists with the one every duocb endpoint already runs.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::EndpointId;
use nostr_sdk::prelude::Keys;
use swarm_discovery::{Discoverer, DropGuard};

use crate::pin_record;

/// mDNS service name; records live under `_duocb-pin._udp.local.`.
const PIN_SERVICE_NAME: &str = "duocb-pin";
/// TXT attribute key carrying the encrypted record content.
const TXT_KEY: &str = "e";
/// How long a lookup browses before concluding no record is on this network.
/// Discovery cadence is sub-second (`new_interactive`), so a present record
/// answers well within this; a wrong/expired PIN should fail fast.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// The mDNS instance label for a `(pin, bucket)` keypair: the first 32 hex
/// chars of the derived public key. The full 64-hex key would exceed the
/// 63-byte DNS label limit; 128 bits keeps accidental collisions negligible,
/// and the payload decrypt is the real verification anyway.
fn instance_name(keys: &Keys) -> String {
    keys.public_key().to_hex()[..32].to_string()
}

/// A live mDNS advertisement of one bucket's PIN record; dropping it withdraws
/// the record from the network.
pub struct PinAdvert(#[expect(dead_code, reason = "held for Drop")] DropGuard);

/// Advertise the PIN rendezvous record for one bucket: the server's ephemeral
/// node id, encrypted under `keys` (the `(pin, bucket)`-derived keypair), as a
/// DNS-SD service instance on the local network. `addrs` should be the
/// endpoint's direct socket addresses (advisory — the dial resolves the node id
/// via iroh's own mDNS lookup). Must be called within a tokio runtime.
pub fn advertise_pin_record(
    keys: &Keys,
    node_id: &EndpointId,
    addrs: impl IntoIterator<Item = SocketAddr>,
) -> Result<PinAdvert> {
    let content = pin_record::encrypt_pin_payload(keys, node_id)?;
    let mut discoverer =
        Discoverer::new_interactive(PIN_SERVICE_NAME.to_string(), instance_name(keys))
            .with_txt_attributes([(TXT_KEY.to_string(), Some(content))])
            .context("PIN record does not fit an mDNS TXT attribute")?;
    for addr in addrs {
        discoverer = discoverer.with_addrs(addr.port(), [addr.ip()]);
    }
    let guard = discoverer
        .spawn(&tokio::runtime::Handle::current())
        .context("starting mDNS PIN advertisement")?;
    Ok(PinAdvert(guard))
}

/// Look up the PIN rendezvous record on the local network, trying each
/// candidate keypair (the caller derives one per adjacent bucket — see
/// `pin_record::candidate_keys`). Returns the decrypted node id, or `Ok(None)`
/// when no matching record answered within the browse window (wrong/expired
/// PIN, or the two devices are not on the same network). The connection is
/// then authenticated in-band with the same PIN (`crate::pin_auth`).
pub async fn lookup_pin_record(candidates: &[Keys]) -> Result<Option<EndpointId>> {
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

    #[test]
    fn instance_name_is_deterministic_and_a_valid_label() {
        let keys = Keys::generate();
        let a = instance_name(&keys);
        assert_eq!(a, instance_name(&keys));
        assert_eq!(a.len(), 32);
        assert!(a.len() <= 63, "must fit a DNS label");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        // Different keys, different label.
        assert_ne!(a, instance_name(&Keys::generate()));
    }

    #[test]
    fn record_fits_one_txt_attribute() {
        // swarm-discovery caps key + value at 254 bytes combined; the encrypted
        // payload length depends only on the (fixed-size) node id, so any
        // keypair stands in for a PIN-derived one here.
        let keys = Keys::generate();
        let node_id = iroh::SecretKey::generate().public();
        let content = pin_record::encrypt_pin_payload(&keys, &node_id).unwrap();
        assert!(
            TXT_KEY.len() + content.len() < 254,
            "TXT attribute too long: {}",
            TXT_KEY.len() + content.len()
        );
    }

    /// End-to-end rendezvous over real loopback multicast: advertise a record
    /// for the current bucket, then look it up with the PIN's candidate keys.
    #[tokio::test(flavor = "multi_thread")]
    async fn advertise_then_lookup_round_trips() {
        let _ = env_logger::builder().is_test(true).try_init();
        let pin = "K7P29QXM";
        let node_id = iroh::SecretKey::generate().public();

        let candidates = pin_record::candidate_keys(pin).await.unwrap();
        // candidate_keys leads with the current bucket — the one to advertise.
        let _advert = advertise_pin_record(
            &candidates[0],
            &node_id,
            [SocketAddr::from(([127, 0, 0, 1], 4433))],
        )
        .unwrap();

        let found = lookup_pin_record(&candidates).await.unwrap();
        assert_eq!(found, Some(node_id));
    }
}
