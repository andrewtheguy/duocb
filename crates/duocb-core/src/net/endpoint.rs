//! iroh endpoint helpers: builders, connect, and the connection path watcher.
//!
//! The iroh identity is always ephemeral (a fresh node id every run); node-id
//! discovery is handled out-of-band (nostr or a node id embedded in a manual
//! pairing code), so no secret key is ever persisted or wired in here.

use anyhow::{Context, Result};
use futures::StreamExt;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, TransportAddr, Watcher,
    address_lookup::{DnsAddressLookup, PkarrPublisher},
    endpoint::{Builder as EndpointBuilder, PathList, QuicTransportConfig, presets},
};
use iroh_mdns_address_lookup::MdnsAddressLookup;
use log::{debug, info};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

/// Fixed ALPN protocol identifier for duocb connections.
///
/// Both peers advertise this; a mismatch fails at the QUIC handshake. Access
/// control is handled by the in-band auth (token or PIN), not the ALPN.
pub const ALPN: &[u8] = b"duocb/1";

/// Timeout for the endpoint to come online and for a connect attempt.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// QUIC keep-alive interval. Keeps NAT mappings alive (most NAT timeouts are
/// 30-120s) and detects dead connections reasonably quickly.
pub const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// QUIC idle timeout. Connections without activity (no data or keep-alive
/// pings) for this duration are considered dead and closed. With keep-alive
/// enabled, this only triggers for truly unresponsive connections — and it is
/// the detection time for an ungracefully dropped peer (crash, network loss):
/// the pump's stream read fails when it fires, letting the server reap the
/// dead session and accept the peer's reconnect, and the client start its
/// reconnect loop. Kept short (2× the keep-alive interval; lost keep-alives
/// retransmit at sub-second PTO, so transient loss won't trip it) because a
/// clipboard link, unlike a long-idle tunnel, wants prompt dead-peer reaping.
pub const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Create a base endpoint builder with common configuration: keep-alive/idle
/// transport tuning plus discovery, tuned to `readiness`.
///
/// Every mode enables mDNS (local-network discovery — the offline path). Modes
/// other than LAN-only additionally use the default relays and n0 DNS/pkarr, so
/// peers stay reachable across networks. **LAN-only touches no internet at all**:
/// the relay is disabled and the n0 DNS/pkarr publish+lookup are omitted, leaving
/// mDNS + direct paths only — so that mode genuinely uses no internet rather than
/// merely not requiring it.
fn create_endpoint_builder(readiness: EndpointReadiness) -> Result<EndpointBuilder> {
    let mut transport_config = QuicTransportConfig::builder();
    let idle_timeout = QUIC_IDLE_TIMEOUT
        .try_into()
        .context("converting QUIC_IDLE_TIMEOUT to IdleTimeout")?;
    transport_config = transport_config.max_idle_timeout(Some(idle_timeout));
    transport_config = transport_config.keep_alive_interval(QUIC_KEEP_ALIVE_INTERVAL);
    let transport_config = transport_config.build();

    // iroh 1.0 requires the crypto provider to be set explicitly on the builder
    // when starting from the `Empty` preset — the `tls-ring` feature only makes
    // the ring backend available, it does not wire it in, and rustls' global
    // `install_default()` is not consulted.
    let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = Endpoint::builder(presets::Empty)
        .transport_config(transport_config)
        .crypto_provider(crypto_provider);

    let builder = if readiness == EndpointReadiness::LanDirect {
        // LAN-only: no relay, no internet-backed discovery — mDNS + direct only.
        builder
            .relay_mode(RelayMode::Disabled)
            .address_lookup(MdnsAddressLookup::builder())
    } else {
        builder
            .relay_mode(RelayMode::Default)
            .address_lookup(PkarrPublisher::n0_dns())
            .address_lookup(DnsAddressLookup::n0_dns())
            .address_lookup(MdnsAddressLookup::builder())
    };

    Ok(builder)
}

/// What a freshly bound endpoint waits for before the session proceeds — and,
/// for [`LanDirect`](Self::LanDirect), which transport stack it is built with.
///
/// **Transport.** Every mode uses the default iroh stack — relays
/// (`RelayMode::Default`) plus n0 DNS/pkarr *and* mDNS discovery — so a
/// connection can always fall back to a relay or resolve across networks. The
/// **one exception is `LanDirect`** (quick mode's LAN-only PIN channel):
/// `create_endpoint_builder` strips the endpoint to `RelayMode::Disabled` with
/// mDNS as the *only* address lookup, so that mode touches no internet at all.
/// Note this is orthogonal to the *rendezvous* channel: e.g. `RelayOnline`
/// (internet-only PIN) still keeps mDNS + direct paths on the endpoint, so its
/// connection can be local even though its PIN discovery is nostr-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointReadiness {
    /// Wait for the home relay (`Endpoint::online`) and fail without it. The
    /// gate for internet-dependent modes — but `online()` **only** resolves
    /// once a relay connects, so it times out entirely offline. Full default
    /// transport stack.
    RelayOnline,
    /// Prefer the home relay but tolerate its absence: on timeout, log and
    /// continue with whatever direct addresses exist. The gate for modes that
    /// work both online and offline (the default nostr+LAN PIN channel, and
    /// manual mode). Full default transport stack.
    RelayPreferred,
    /// Wait only for a first direct (IP) address, and build the endpoint
    /// **relay-less, mDNS-only** (no n0 DNS/pkarr). The gate for the LAN-only
    /// PIN channel, which must come up promptly and use no internet at all.
    LanDirect,
}

/// Wait until the endpoint has discovered at least one direct (IP) address.
/// Resolves early if the endpoint is dropped (nothing to wait for then).
async fn wait_for_direct_address(endpoint: &Endpoint) {
    let mut watcher = endpoint.watch_addr();
    loop {
        if watcher.get().ip_addrs().next().is_some() {
            break;
        }
        if watcher.updated().await.is_err() {
            break;
        }
    }
}

/// Wait for an endpoint to be ready per `readiness`, with a timeout.
async fn wait_for_endpoint_ready(endpoint: &Endpoint, readiness: EndpointReadiness) -> Result<()> {
    info!(
        "Waiting for endpoint to be ready ({readiness:?}, timeout: {}s)...",
        CONNECT_TIMEOUT.as_secs()
    );
    let ready = async {
        match readiness {
            EndpointReadiness::RelayOnline | EndpointReadiness::RelayPreferred => {
                endpoint.online().await
            }
            EndpointReadiness::LanDirect => wait_for_direct_address(endpoint).await,
        }
    };
    match tokio::time::timeout(CONNECT_TIMEOUT, ready).await {
        Ok(()) => Ok(()),
        Err(_) if readiness == EndpointReadiness::RelayPreferred => {
            info!(
                "No relay came online after {}s — continuing offline (LAN pairing still works)",
                CONNECT_TIMEOUT.as_secs()
            );
            Ok(())
        }
        Err(_) => anyhow::bail!(
            "Endpoint failed to come online after {}s - check network connectivity",
            CONNECT_TIMEOUT.as_secs()
        ),
    }
}

/// Create a listening endpoint. The endpoint identity is ephemeral, so the node
/// id changes every run.
pub async fn create_server_endpoint(readiness: EndpointReadiness) -> Result<Endpoint> {
    let builder = create_endpoint_builder(readiness)?.alpns(vec![ALPN.to_vec()]);
    let endpoint = builder
        .bind()
        .await
        .context("Failed to create iroh endpoint")?;
    wait_for_endpoint_ready(&endpoint, readiness).await?;
    Ok(endpoint)
}

/// Create a dialing endpoint. The endpoint identity is ephemeral.
pub async fn create_client_endpoint(readiness: EndpointReadiness) -> Result<Endpoint> {
    let builder = create_endpoint_builder(readiness)?;
    let endpoint = builder
        .bind()
        .await
        .context("Failed to create iroh endpoint")?;
    wait_for_endpoint_ready(&endpoint, readiness).await?;
    Ok(endpoint)
}

/// Connect to a listening endpoint by bare node id. iroh resolves the actual
/// transport addresses via the endpoint's discovery services (n0 DNS/pkarr when
/// online, mDNS on the local network) and hole-punches, falling back to a relay.
pub async fn connect_to_server(
    endpoint: &Endpoint,
    server_id: EndpointId,
) -> Result<iroh::endpoint::Connection> {
    info!(
        "Connecting to server {} (timeout: {}s)...",
        server_id,
        CONNECT_TIMEOUT.as_secs()
    );
    let endpoint_addr = EndpointAddr::new(server_id);
    match tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(endpoint_addr, ALPN)).await {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(e)) => Err(anyhow::Error::from(e).context("Failed to connect to server")),
        Err(_) => anyhow::bail!(
            "Connection timed out after {}s",
            CONNECT_TIMEOUT.as_secs()
        ),
    }
}

/// Whether a connection path is a direct hole-punched route or via a relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnPathKind {
    Direct,
    Relay,
    Other,
}

/// A single connection path snapshot for status display, decoupled from iroh's
/// borrowed [`PathList`] so it can be handed to the UI and shown on demand (the
/// "connection path" button), needing no background watcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnPath {
    pub kind: ConnPathKind,
    /// Human line like `Direct 1.2.3.4:52186 (rtt 1ms)` or
    /// `Relay https://… (rtt 42ms)`.
    pub display: String,
    /// Whether iroh currently routes traffic over this path.
    pub selected: bool,
}

/// Snapshot the current path(s) of a live connection for a status UI, showing
/// *all* paths (not just the selected one) so a direct path iroh has discovered
/// but not yet selected is still visible. [`Connection::paths`] is itself a
/// point-in-time snapshot, so this needs no background watcher.
pub fn connection_paths(conn: &iroh::endpoint::Connection) -> Vec<ConnPath> {
    snapshot_paths(&conn.paths())
}

/// Classify a path's transport address and render its human display line
/// (`Direct 1.2.3.4:52186 (rtt 1ms)`, `Relay https://… (rtt 42ms)`). Shared by
/// the on-demand status snapshot and the debug path logger.
fn describe_path(remote: &TransportAddr, rtt: Duration) -> (ConnPathKind, String) {
    match remote {
        TransportAddr::Ip(addr) => (ConnPathKind::Direct, format!("Direct {addr} (rtt {rtt:.0?})")),
        TransportAddr::Relay(url) => (ConnPathKind::Relay, format!("Relay {url} (rtt {rtt:.0?})")),
        other => (ConnPathKind::Other, format!("{other:?} (rtt {rtt:.0?})")),
    }
}

/// Convert a borrowed [`PathList`] snapshot into owned [`ConnPath`]s.
fn snapshot_paths(paths: &PathList<'_>) -> Vec<ConnPath> {
    paths
        .iter()
        .map(|path| {
            let (kind, display) = describe_path(path.remote_addr(), path.rtt());
            ConnPath {
                kind,
                display,
                selected: path.is_selected(),
            }
        })
        .collect()
}

/// Format the selected path(s) of a connection for logging, e.g.
/// `Direct [2607:…]:52186 (rtt 1ms)` or `Relay https://… (rtt 42ms)`.
fn format_paths(paths: &PathList<'_>) -> String {
    if paths.is_empty() {
        return "establishing...".to_string();
    }
    let parts: Vec<String> = paths
        .iter()
        .filter(|p| p.is_selected())
        .map(|path| describe_path(path.remote_addr(), path.rtt()).1)
        .collect();
    if parts.is_empty() {
        "no selected path".to_string()
    } else {
        parts.join(", ")
    }
}

/// Key identifying the selected-path topology, excluding the volatile RTT, so
/// the watcher only logs when the path actually changes (not every RTT update).
fn paths_key(paths: &PathList<'_>) -> (bool, Vec<String>) {
    let selected = paths
        .iter()
        .filter(|p| p.is_selected())
        .map(|p| format!("{:?}", p.remote_addr()))
        .collect();
    (paths.is_empty(), selected)
}

/// RAII guard that aborts the background path-watcher task on drop.
pub struct PathWatcherGuard(Option<JoinHandle<()>>);

impl Drop for PathWatcherGuard {
    fn drop(&mut self) {
        if let Some(handle) = &self.0 {
            handle.abort();
        }
    }
}

/// Spawn a background task that logs the connection's selected path and any
/// changes to it (e.g. relay -> direct). Logging is its only purpose, so when
/// debug logging is disabled the task is not spawned and the returned guard is
/// inert. The guard aborts the task on drop; callers keep it alive for the
/// connection's life. On-demand status uses [`connection_paths`] instead.
pub fn watch_connection_paths(conn: &iroh::endpoint::Connection) -> PathWatcherGuard {
    if !log::log_enabled!(log::Level::Debug) {
        return PathWatcherGuard(None);
    }
    let conn = conn.clone();
    PathWatcherGuard(Some(tokio::spawn(async move {
        // The stream yields the current snapshot on the first poll, then a
        // fresh snapshot whenever the open or selected paths change; it ends
        // when the connection closes.
        let mut stream = conn.paths_stream();
        let mut last_key = None;
        while let Some(paths) = stream.next().await {
            let key = paths_key(&paths);
            if last_key.as_ref() != Some(&key) {
                debug!("Connection: {}", format_paths(&paths));
                last_key = Some(key);
            }
        }
    })))
}
