//! iroh endpoint helpers: builders, connect, and the connection path watcher.
//!
//! The iroh identity is always ephemeral (a fresh node id every run); node-id
//! discovery is handled out-of-band (nostr or a manually typed node id), so no
//! secret key is ever persisted or wired in here.

use anyhow::{Context, Result};
use futures::StreamExt;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, TransportAddr,
    address_lookup::{DnsAddressLookup, PkarrPublisher},
    endpoint::{Builder as EndpointBuilder, PathList, QuicTransportConfig, presets},
};
use iroh_mdns_address_lookup::MdnsAddressLookup;
use log::info;
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

/// Create a base endpoint builder with common configuration: default relays,
/// keep-alive/idle transport tuning, and discovery via n0 DNS/pkarr **plus mDNS**.
/// mDNS is what lets the manual/offline mode resolve a typed node id on the local
/// network with zero internet connectivity.
fn create_endpoint_builder() -> Result<EndpointBuilder> {
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
        .relay_mode(RelayMode::Default)
        .transport_config(transport_config)
        .crypto_provider(crypto_provider)
        .address_lookup(PkarrPublisher::n0_dns())
        .address_lookup(DnsAddressLookup::n0_dns())
        // mDNS always enabled for local network discovery (the offline path).
        .address_lookup(MdnsAddressLookup::builder());

    Ok(builder)
}

/// Wait for an endpoint to come online, with a timeout.
async fn wait_for_endpoint_online(endpoint: &Endpoint) -> Result<()> {
    info!(
        "Waiting for endpoint to come online (timeout: {}s)...",
        CONNECT_TIMEOUT.as_secs()
    );
    match tokio::time::timeout(CONNECT_TIMEOUT, endpoint.online()).await {
        Ok(()) => Ok(()),
        Err(_) => anyhow::bail!(
            "Endpoint failed to come online after {}s - check network connectivity",
            CONNECT_TIMEOUT.as_secs()
        ),
    }
}

/// Create a listening endpoint. The endpoint identity is ephemeral, so the node
/// id changes every run.
pub async fn create_server_endpoint() -> Result<Endpoint> {
    let builder = create_endpoint_builder()?.alpns(vec![ALPN.to_vec()]);
    let endpoint = builder
        .bind()
        .await
        .context("Failed to create iroh endpoint")?;
    wait_for_endpoint_online(&endpoint).await?;
    Ok(endpoint)
}

/// Create a dialing endpoint. The endpoint identity is ephemeral.
pub async fn create_client_endpoint() -> Result<Endpoint> {
    let builder = create_endpoint_builder()?;
    let endpoint = builder
        .bind()
        .await
        .context("Failed to create iroh endpoint")?;
    wait_for_endpoint_online(&endpoint).await?;
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

/// Format connection path info for display, showing selected paths with RTT.
fn format_paths(paths: &PathList<'_>) -> String {
    if paths.is_empty() {
        return "establishing...".to_string();
    }
    let parts: Vec<String> = paths
        .iter()
        .filter(|p| p.is_selected())
        .map(|path| {
            let rtt = path.rtt();
            match path.remote_addr() {
                TransportAddr::Ip(addr) => format!("Direct {} (rtt {:.0?})", addr, rtt),
                TransportAddr::Relay(url) => format!("Relay {} (rtt {:.0?})", url, rtt),
                other => format!("{:?} (rtt {:.0?})", other, rtt),
            }
        })
        .collect();
    if parts.is_empty() {
        "no selected path".to_string()
    } else {
        parts.join(", ")
    }
}

/// RAII guard that aborts the background path watcher task on drop.
pub struct PathWatcherGuard(JoinHandle<()>);

impl Drop for PathWatcherGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Spawn a background task that reports the connection's selected path (and
/// changes to it, e.g. relay -> direct) through `on_update`. The returned guard
/// aborts the task when dropped; callers keep it alive for the connection's life.
pub fn watch_connection_paths(
    conn: &iroh::endpoint::Connection,
    on_update: impl Fn(String) + Send + 'static,
) -> PathWatcherGuard {
    let conn = conn.clone();
    PathWatcherGuard(tokio::spawn(async move {
        // The stream yields the current snapshot on the first poll, then a
        // fresh snapshot whenever the open or selected paths change; it ends
        // when the connection closes.
        let mut stream = conn.paths_stream();
        let mut last: Option<String> = None;
        while let Some(paths) = stream.next().await {
            let display = format_paths(&paths);
            if last.as_deref() != Some(display.as_str()) {
                info!("Connection: {display}");
                on_update(display.clone());
                last = Some(display);
            }
        }
    }))
}
