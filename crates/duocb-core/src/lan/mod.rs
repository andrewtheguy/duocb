//! LAN transports for the encrypted PIN rendezvous record — the local-network
//! siblings of the nostr transport in `crate::nostr`. Both backends carry the
//! same record (see `crate::pin_record`): a TXT attribute holding the NIP-44
//! ciphertext of the server's ephemeral node id, under a service instance
//! label derived from the `(pin, bucket)` public key — the same
//! lookup-by-derived-key model as the nostr record's author key.
//!
//! Two wire backends, selected by the PIN channel:
//!
//! - **swarm** ([`advertise_pin_record`] / [`lookup_pin_record`]) — the LAN
//!   half of the default nostr+LAN channel. swarm-discovery, the same engine
//!   iroh's mDNS address lookup runs on (same version, socket options with
//!   SO_REUSEADDR/SO_REUSEPORT), so this responder coexists with the one every
//!   desktop endpoint already runs. Its packets are mDNS-*like* but not DNS-SD
//!   conformant (no PTR records), so only swarm peers see each other. Desktop
//!   only: in-process multicast on iOS needs the restricted multicast
//!   entitlement, so there these calls are inert and the channel's nostr half
//!   carries the rendezvous.
//! - **dnssd** ([`dnssd_advertise_pin_record`] / [`dnssd_lookup_pin_record`])
//!   — the LAN-only channel. Spec-compliant DNS-SD (RFC 6762/6763): the
//!   mdns-sd responder on desktop, and on iOS the system mDNSResponder daemon
//!   via `dns_sd.h` (`DNSServiceRegister`/`DNSServiceResolve`), which is
//!   exempt from the multicast entitlement — the daemon performs the multicast;
//!   the app only needs the `NSBonjourServices` (`_duocb-pin._udp`) and
//!   `NSLocalNetworkUsageDescription` Info.plist keys and the user accepting
//!   the Local Network prompt. DNS-SD records carry real SRV/A/AAAA data, so
//!   the lookup returns the host's direct socket addresses ([`PinFound`]) and
//!   the joiner dials them explicitly — required because an iOS host runs no
//!   iroh mDNS responder for a bare node id to resolve against.
//!
//! The two backends do not see each other on the wire: a LAN-only host is
//! found by a LAN-only joiner, and the default channel's LAN race only finds
//! default-channel hosts (its nostr half covers everything else).
//!
//! Session traffic remains direct between devices either way, but there is no
//! packet-level on-link subnet filter.

mod dnssd;
#[cfg(not(target_os = "ios"))]
mod swarm;
mod unicast;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::Result;
use iroh::{EndpointAddr, EndpointId};
use nostr_sdk::prelude::Keys;
use sha2::{Digest, Sha256};

pub use unicast::UnicastListener;

/// mDNS service name; swarm records live under `_duocb-pin._udp.local.`.
#[cfg(not(target_os = "ios"))]
const PIN_SERVICE_NAME: &str = "duocb-pin";
/// The same service as a full DNS-SD type domain (desktop dnssd backend; the
/// iOS backend passes the regtype and domain separately — see `dnssd::ios`).
#[cfg(not(target_os = "ios"))]
const DNSSD_SERVICE_TYPE: &str = "_duocb-pin._udp.local.";
/// TXT attribute key carrying the encrypted record content.
const TXT_KEY: &str = "e";
/// TXT attribute key carrying the v6 port when it differs from the SRV port
/// (dnssd backend only — see [`split_ports`]).
const TXT_KEY_PORT6: &str = "p6";
/// How long a lookup browses before concluding no record is on this network.
/// Discovery cadence is sub-second on both backends, so a present record
/// answers well within this; a wrong/expired PIN should fail fast.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// The mDNS instance label for a `(pin, bucket)` keypair: the first 32 hex
/// chars of the derived public key. The full 64-hex key would exceed the
/// 63-byte DNS label limit; 128 bits keeps accidental collisions negligible,
/// and the payload decrypt is the real verification anyway.
fn instance_name(keys: &Keys) -> String {
    keys.public_key().to_hex()[..32].to_string()
}

/// Domain-separating salt for the unicast side-channel port derivation.
const PORT_SALT: &[u8] = b"duocb:pin-side-channel-port:v1";
/// First port of the IANA ephemeral/dynamic range (49152–65535).
const EPHEMERAL_START: u16 = 49152;
/// Size of the ephemeral range (65535 − 49152 + 1 = 16384).
const EPHEMERAL_LEN: u16 = u16::MAX - EPHEMERAL_START + 1;

/// The unicast side-channel port for a `(pin, bucket)` keypair, mapped into the ephemeral range
/// (49152–65535). Derived from the **same Argon2-derived rendezvous public key** the mDNS
/// [`instance_name`] label uses — not from the PIN string — so, exactly like the mDNS label,
/// mapping a candidate PIN to its port costs an Argon2 evaluation and the open port leaks no cheap
/// pre-filter of the PIN. The key already varies per rotation bucket, so the port does too; the
/// joiner tries each candidate bucket's port (see `unicast::lookup`), mirroring the mDNS
/// candidate-label match. Different PINs almost always map to different ports, so hosts on one LAN
/// normally coexist; the range is finite (16384 ports), so a collision is possible and would make
/// a second host's listener fail to bind on the shared port (the publisher only warns, and mDNS
/// still carries the rendezvous).
fn side_channel_port(keys: &Keys) -> u16 {
    let mut hasher = Sha256::new();
    hasher.update(PORT_SALT);
    hasher.update(keys.public_key().to_bytes());
    let digest = hasher.finalize();
    EPHEMERAL_START + (u16::from_be_bytes([digest[0], digest[1]]) % EPHEMERAL_LEN)
}

/// A resolved LAN rendezvous hit: the decrypted node id plus the direct socket
/// addresses reassembled from the DNS-SD records (A/AAAA + SRV port, `p6` TXT
/// override for the v6 socket). Empty `addrs` on the swarm path, which carries
/// no trusted address data — there the iroh mDNS lookup resolves the dial.
pub struct PinFound {
    pub node_id: EndpointId,
    pub addrs: Vec<SocketAddr>,
}

impl PinFound {
    /// The dial target: the node id with every resolved direct address
    /// attached, so the connect needs no LAN address lookup.
    pub fn endpoint_addr(&self) -> EndpointAddr {
        let mut addr = EndpointAddr::new(self.node_id);
        for a in &self.addrs {
            addr = addr.with_ip_addr(*a);
        }
        addr
    }
}

/// A live LAN advertisement of one bucket's PIN record; dropping it withdraws
/// the record from the network.
pub struct PinAdvert(#[expect(dead_code, reason = "held for Drop")] AdvertKind);

#[expect(dead_code, reason = "variants held for Drop")]
enum AdvertKind {
    /// swarm-discovery responder guard (default channel, desktop).
    #[cfg(not(target_os = "ios"))]
    Swarm(swarm_discovery::DropGuard),
    /// DNS-SD registration (LAN-only channel, both platforms).
    Dnssd(dnssd::Advert),
    /// iOS default channel: the LAN half is skipped (see module docs).
    #[cfg(target_os = "ios")]
    Inert,
}

/// Advertise the PIN rendezvous record on the default channel's swarm backend:
/// the server's ephemeral node id, encrypted under `keys` (the
/// `(pin, bucket)`-derived keypair). `addrs` should be the endpoint's direct
/// socket addresses (advisory on this backend — the dial resolves the node id
/// via iroh's own mDNS lookup). Must be called within a tokio runtime.
///
/// On iOS this is a no-op returning an inert guard: the in-process responder
/// would need the restricted multicast entitlement, and the default channel's
/// nostr half carries the rendezvous there.
pub fn advertise_pin_record(
    keys: &Keys,
    node_id: &EndpointId,
    addrs: &[SocketAddr],
) -> Result<PinAdvert> {
    #[cfg(not(target_os = "ios"))]
    {
        swarm::advertise(keys, node_id, addrs).map(|g| PinAdvert(AdvertKind::Swarm(g)))
    }
    #[cfg(target_os = "ios")]
    {
        let _ = (keys, node_id, addrs);
        log::debug!("iOS: skipping swarm mDNS PIN advertisement (nostr carries the rendezvous)");
        Ok(PinAdvert(AdvertKind::Inert))
    }
}

/// Look up the PIN rendezvous record on the default channel's swarm backend,
/// trying each candidate keypair (the caller derives one per adjacent bucket —
/// see `pin_record::candidate_keys`). Returns the decrypted node id, or
/// `Ok(None)` when no matching record answered within the browse window
/// (wrong/expired PIN, or the two devices are not on the same network). The
/// connection is then authenticated in-band with the same PIN
/// (`crate::pin_auth`).
///
/// On iOS this resolves to `Ok(None)` immediately (see module docs); the
/// racing nostr lookup decides the outcome there.
pub async fn lookup_pin_record(candidates: &[Keys]) -> Result<Option<EndpointId>> {
    #[cfg(not(target_os = "ios"))]
    {
        swarm::lookup(candidates).await
    }
    #[cfg(target_os = "ios")]
    {
        let _ = candidates;
        Ok(None)
    }
}

/// Advertise the PIN rendezvous record for the LAN-only channel as a
/// spec-compliant DNS-SD service instance. Unlike the swarm backend the
/// advertised SRV/A/AAAA data is load-bearing: the joiner dials the resolved
/// addresses directly. `addrs` must hold at least one direct socket address.
///
/// On iOS this waits for the system daemon's registration verdict: iOS gates
/// advertising behind the Local Network permission and only reports a denial
/// asynchronously. A denial fails the advertisement (after nudging the system
/// permission prompt, which registrations alone never trigger) — the caller
/// should surface the error, and the next PIN rotation retries.
pub async fn dnssd_advertise_pin_record(
    keys: &Keys,
    node_id: &EndpointId,
    addrs: &[SocketAddr],
) -> Result<PinAdvert> {
    dnssd::advertise(keys, node_id, addrs)
        .await
        .map(|a| PinAdvert(AdvertKind::Dnssd(a)))
}

/// Look up the PIN rendezvous record for the LAN-only channel over DNS-SD.
/// Returns the decrypted node id **and** the host's direct socket addresses;
/// `Ok(None)` when no matching record answered within the browse window.
pub async fn dnssd_lookup_pin_record(candidates: &[Keys]) -> Result<Option<PinFound>> {
    dnssd::lookup(candidates).await
}

/// Start the LAN-only channel's unicast side channel: a listener on the port
/// derived from the record keypair ([`side_channel_port`]) serving the same
/// PIN-encrypted node-id record, so a joiner who types the host's LAN IP can
/// pair where multicast is blocked. Dropping the returned [`UnicastListener`]
/// withdraws it. Runs alongside the DNS-SD advertisement (see `crate::lan::unicast`).
pub async fn unicast_advertise_pin_record(
    keys: &Keys,
    node_id: &EndpointId,
    addrs: &[SocketAddr],
) -> Result<UnicastListener> {
    unicast::advertise(keys, node_id, addrs).await
}

/// Fetch the LAN-only PIN record from the host's unicast side channel at `ip`,
/// trying the port each candidate keypair derives to (adjacent buckets, as for
/// the DNS-SD lookup). Returns the decrypted node id and the host's direct socket
/// addresses, or `Ok(None)` when nothing reachable answered or the record did not
/// decrypt (wrong/expired PIN).
pub async fn unicast_lookup_pin_record(
    ip: IpAddr,
    candidates: &[Keys],
) -> Result<Option<PinFound>> {
    unicast::lookup(ip, candidates).await
}

/// Pick the host's display-worthy LAN IPv4 from its direct socket addresses: the
/// first RFC1918 private address (10/8, 172.16/12, 192.168/16). Link-local
/// (169.254/16), loopback, and public addresses are skipped by `is_private`.
/// Used to show the joiner which IP to type for the unicast side channel;
/// `None` when no private IPv4 is present (e.g. only IPv6, or a loopback-only
/// endpoint in a same-machine test).
pub(crate) fn preferred_lan_ipv4(addrs: &[SocketAddr]) -> Option<Ipv4Addr> {
    addrs
        .iter()
        .filter_map(|a| match a.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .find(Ipv4Addr::is_private)
}

/// DNS-SD carries a single SRV port per service instance, but iroh binds its
/// v4 and v6 UDP sockets independently (their ports usually differ). The SRV
/// port is the v4 one (the v6 one when no v4 address exists); a differing v6
/// port rides in the [`TXT_KEY_PORT6`] attribute. `None` when `addrs` is
/// empty — nothing to advertise.
fn split_ports(addrs: &[SocketAddr]) -> Option<(u16, Option<u16>)> {
    let v4 = addrs.iter().find(|a| a.is_ipv4()).map(SocketAddr::port);
    let v6 = addrs.iter().find(|a| a.is_ipv6()).map(SocketAddr::port);
    let srv = v4.or(v6)?;
    Some((srv, v6.filter(|p| *p != srv)))
}

/// Rebuild dialable socket addresses from resolved IPs plus the advertised
/// ports (the [`split_ports`] inverse). v6 link-local addresses are dropped —
/// dialing them needs a scope id the record cannot carry.
fn assemble_addrs(ips: &[IpAddr], srv_port: u16, port6: Option<u16>) -> Vec<SocketAddr> {
    ips.iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(_) => Some(SocketAddr::new(*ip, srv_port)),
            IpAddr::V6(v6) => {
                if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                    return None;
                }
                Some(SocketAddr::new(*ip, port6.unwrap_or(srv_port)))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pin_record;

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
        // Both backends cap key + value at ~254 bytes combined; the encrypted
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

    #[test]
    fn ports_split_and_reassemble_per_family() {
        let v4: SocketAddr = "192.168.1.9:4433".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::7]:4444".parse().unwrap();

        assert_eq!(split_ports(&[]), None);
        assert_eq!(split_ports(&[v4]), Some((4433, None)));
        assert_eq!(split_ports(&[v6]), Some((4444, None)));
        assert_eq!(split_ports(&[v4, v6]), Some((4433, Some(4444))));
        // Equal ports need no override.
        let v6_same: SocketAddr = "[2001:db8::7]:4433".parse().unwrap();
        assert_eq!(split_ports(&[v4, v6_same]), Some((4433, None)));

        let ips = [
            "192.168.1.9".parse().unwrap(),
            "2001:db8::7".parse().unwrap(),
            // Link-local v6 is undialable without a scope id — dropped.
            "fe80::1".parse().unwrap(),
        ];
        assert_eq!(
            assemble_addrs(&ips, 4433, Some(4444)),
            vec![v4, v6],
        );
        assert_eq!(
            assemble_addrs(&ips[1..2], 4433, None),
            vec!["[2001:db8::7]:4433".parse::<SocketAddr>().unwrap()],
        );
    }
}
