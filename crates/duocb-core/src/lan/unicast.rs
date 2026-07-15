//! Unicast side channel for the LAN-only PIN rendezvous — the multicast-free
//! sibling of the DNS-SD backend (`super::dnssd`).
//!
//! Where DNS-SD needs multicast to *discover* the host, this path has the joiner
//! type the host's LAN IPv4 directly, then fetch the very same PIN-encrypted
//! node-id record over a one-shot TCP request/response. The host — when hosting
//! on the LAN-only channel — runs a small listener on a port derived from the
//! record keypair (`super::side_channel_port`, the same Argon2-derived key the
//! DNS-SD instance label uses) that serves the record to anyone who connects; the
//! joiner derives the same port from its PIN-derived candidate keys, so no port is
//! ever typed. Because the key rotates per bucket, so does the port, and the
//! joiner probes each candidate bucket's port — mirroring the DNS-SD lookup's
//! candidate-label match. The served record carries the same NIP-44 ciphertext the
//! DNS-SD `e` TXT attribute holds, plus the host's direct socket addresses (which
//! DNS-SD instead conveys via SRV/A/AAAA), so the joiner ends up with the identical
//! [`PinFound`] and dials iroh exactly as the DNS-SD path does.
//!
//! Cross-platform (plain tokio TCP): on iOS the joiner's outbound connect to a
//! LAN IP is what raises the Local Network permission prompt.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use iroh::EndpointId;
use nostr_sdk::prelude::Keys;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use super::{PinFound, LOOKUP_TIMEOUT};
use crate::pin_record;

/// Cap on the record a joiner will read (and a host will serve): the JSON is a
/// short ciphertext plus a handful of socket addresses. Bounds a hostile or
/// wrong responder on the derived port.
const MAX_RECORD_BYTES: usize = 8 * 1024;

/// The record served over the side channel: the same NIP-44 ciphertext the
/// DNS-SD `e` TXT attribute carries (the encrypted node id), plus the host's
/// direct socket addresses. The field name `e` mirrors the TXT attribute for
/// wire familiarity; `SocketAddr` serializes as its string form.
#[derive(Serialize, Deserialize)]
struct UnicastRecord {
    e: String,
    addrs: Vec<SocketAddr>,
}

/// A live unicast side-channel listener. Dropping it aborts the accept loop and
/// frees the port — withdrawing the side channel, like dropping a `PinAdvert`.
pub struct UnicastListener {
    task: JoinHandle<()>,
}

impl Drop for UnicastListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Start serving the PIN rendezvous record on the side-channel port derived from
/// `keys` (the current bucket's record keypair, as for the DNS-SD advert); `addrs`
/// is the endpoint's direct socket addresses. Binds IPv4 on all interfaces (the
/// joiner types an IPv4).
pub async fn advertise(
    keys: &Keys,
    node_id: &EndpointId,
    addrs: &[SocketAddr],
) -> Result<UnicastListener> {
    let content =
        pin_record::encrypt_pin_payload(keys, node_id).context("encrypting the unicast PIN record")?;
    let record = UnicastRecord {
        e: content,
        addrs: addrs.to_vec(),
    };
    let body = serde_json::to_vec(&record).context("serializing the unicast PIN record")?;
    if body.len() > MAX_RECORD_BYTES {
        return Err(anyhow!(
            "unicast PIN record too large: {} bytes",
            body.len()
        ));
    }

    let port = super::side_channel_port(keys);
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
        .await
        .with_context(|| format!("binding the unicast side channel on port {port}"))?;

    let body = Arc::new(body);
    let task = tokio::spawn(async move {
        loop {
            let mut stream = match listener.accept().await {
                Ok((stream, _peer)) => stream,
                Err(e) => {
                    log::warn!("unicast side channel accept failed: {e}");
                    continue;
                }
            };
            let body = body.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_one(&mut stream, &body).await {
                    log::debug!("unicast side channel serve failed: {e}");
                }
            });
        }
    });
    log::info!("Serving the PIN over the unicast side channel on port {port}");
    Ok(UnicastListener { task })
}

/// Write the whole record and close the write half so the joiner reads to EOF.
async fn serve_one(stream: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    stream.write_all(body).await?;
    stream.shutdown().await
}

/// Fetch and decrypt the PIN record from the host's unicast side channel at `ip`.
/// Each candidate bucket key derives its own port; the host listens on the one for
/// the bucket it minted the PIN in, so the ports are probed concurrently and the
/// first that returns a decryptable record wins. Returns the decrypted node id plus
/// the host's direct socket addresses ([`PinFound`]), or `Ok(None)` when no reachable
/// port answered or none decrypted (wrong or expired PIN) — the same "no record"
/// outcome the DNS-SD browse window reports. Bounded overall by [`LOOKUP_TIMEOUT`].
pub async fn lookup(ip: IpAddr, candidates: &[Keys]) -> Result<Option<PinFound>> {
    if candidates.is_empty() {
        return Ok(None);
    }
    let mut probes: FuturesUnordered<_> = candidates
        .iter()
        .map(|keys| fetch_and_decrypt(SocketAddr::new(ip, super::side_channel_port(keys)), candidates))
        .collect();
    let race = async {
        while let Some(found) = probes.next().await {
            if found.is_some() {
                return found;
            }
        }
        None
    };
    match tokio::time::timeout(LOOKUP_TIMEOUT, race).await {
        Ok(found) => Ok(found),
        Err(_) => Ok(None),
    }
}

/// Connect to one candidate port, read the served record, and decrypt it with any
/// candidate key. `None` on any failure (unreachable/reset, oversize, unparseable,
/// or no candidate key decrypts) so a probe of a closed port simply drops out of
/// the race.
async fn fetch_and_decrypt(addr: SocketAddr, candidates: &[Keys]) -> Option<PinFound> {
    let buf = match fetch(addr).await {
        Ok(buf) => buf,
        Err(e) => {
            log::debug!("unicast side channel at {addr} unreachable: {e}");
            return None;
        }
    };
    if buf.len() > MAX_RECORD_BYTES {
        log::debug!("unicast side channel at {addr} returned an oversize record");
        return None;
    }
    let record: UnicastRecord = match serde_json::from_slice(&buf) {
        Ok(record) => record,
        // Something on the derived port that isn't our record — treat as a miss.
        Err(e) => {
            log::debug!("unicast side channel at {addr} returned an unparseable record: {e}");
            return None;
        }
    };
    candidates.iter().find_map(|keys| {
        pin_record::decrypt_pin_payload(keys, &record.e).map(|node_id| PinFound {
            node_id,
            addrs: record.addrs.clone(),
        })
    })
}

/// Connect and read the served record (up to one byte past the cap, so an oversize
/// responder is detectable).
async fn fetch(addr: SocketAddr) -> std::io::Result<Vec<u8>> {
    let stream = TcpStream::connect(addr).await?;
    let mut buf = Vec::new();
    stream
        .take(MAX_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn advertise_then_lookup_round_trips_node_id_and_addrs() {
        // Distinct per test so parallel runs bind distinct (key-derived) ports.
        let candidates = pin_record::candidate_keys("ROUNDTR1").await.unwrap();
        // The host advertises under the current bucket's key (candidates[0]); the
        // joiner probes every candidate's port and hits that one.
        let node_id = iroh::SecretKey::generate().public();
        let addrs: Vec<SocketAddr> =
            vec!["192.168.1.9:4433".parse().unwrap(), "[2001:db8::7]:4444".parse().unwrap()];

        let _listener = advertise(&candidates[0], &node_id, &addrs).await.unwrap();

        let found = lookup(IpAddr::V4(Ipv4Addr::LOCALHOST), &candidates)
            .await
            .unwrap()
            .expect("the just-advertised record must resolve");
        assert_eq!(found.node_id, node_id);
        assert_eq!(found.addrs, addrs);
    }

    #[tokio::test]
    async fn lookup_returns_none_when_nothing_is_listening() {
        // Candidate keys whose derived ports have no listener: every connect is refused.
        let candidates = pin_record::candidate_keys("NOLISTN2").await.unwrap();
        let found = lookup(IpAddr::V4(Ipv4Addr::LOCALHOST), &candidates)
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn lookup_returns_none_for_the_wrong_pin() {
        let host_candidates = pin_record::candidate_keys("WRONGHS3").await.unwrap();
        let node_id = iroh::SecretKey::generate().public();
        let _listener = advertise(&host_candidates[0], &node_id, &[]).await.unwrap();

        // A different PIN derives different keys, hence different ports, so nothing answers.
        let other_candidates = pin_record::candidate_keys("WRONGOT4").await.unwrap();
        let found = lookup(IpAddr::V4(Ipv4Addr::LOCALHOST), &other_candidates)
            .await
            .unwrap();
        assert!(found.is_none());
    }
}
