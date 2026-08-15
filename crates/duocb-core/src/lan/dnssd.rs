//! Spec-compliant DNS-SD backend for the local-network half of both rendezvous
//! records — see the module docs in `super`. The contract is the same for
//! either: advertise `<instance>.<service type>` with the ciphertext in the `e`
//! TXT attribute and real SRV/A/AAAA data, and resolve an instance the caller
//! recognizes back into [`LanFound`] (node id + dialable direct addresses).
//!
//! Nothing here knows what an instance label means or how its content is keyed.
//! The caller supplies the label to advertise, and on lookup a `decode` closure
//! that maps `(instance, content)` to a node id — which is what lets the same
//! backend carry the PIN rendezvous (labels and keys derived from a PIN) and
//! pairwise hosting records (derived from a pair of application keys).
//!
//! Two platform halves implement that one contract:
//!
//! - **Desktop**: the mdns-sd crate, an in-process RFC 6762/6763 responder that
//!   interoperates with Bonjour.
//! - **iOS**: the system mDNSResponder daemon over `dns_sd.h` IPC. The daemon
//!   performs the multicast on the app's behalf, which is what exempts this
//!   path from Apple's restricted multicast entitlement — the app needs only
//!   the Local Network permission plus every service type it uses listed under
//!   `NSBonjourServices` (`_duocb-pin._udp` **and** `_duocb-host._udp`).
//!
//! iOS is also why this is the *only* mDNS in the iOS build: iroh's own
//! `MdnsAddressLookup` opens raw multicast sockets in-process and is compiled
//! out there (see `crate::net::endpoint`). Regular mDNS is not lost — it just
//! goes through the system daemon instead.

#[cfg(not(target_os = "ios"))]
pub(super) use desktop::{Advert, advertise, lookup};
#[cfg(target_os = "ios")]
pub(super) use ios::{Advert, advertise, lookup};

#[cfg(not(target_os = "ios"))]
mod desktop {
    use std::collections::HashMap;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::OnceLock;

    use anyhow::{Context, Result, anyhow};
    use iroh::EndpointId;
    use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

    use super::super::{
        LOOKUP_TIMEOUT, LanFound, TXT_KEY, TXT_KEY_PORT6, assemble_addrs, split_ports,
    };

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
    pub(in crate::lan) struct Advert {
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
    pub(in crate::lan) async fn advertise(
        service_type: &str,
        instance: &str,
        content: String,
        addrs: &[SocketAddr],
    ) -> Result<Advert> {
        let (srv_port, port6) =
            split_ports(addrs).context("endpoint has no direct addresses to advertise")?;

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
        let info = ServiceInfo::new(service_type, instance, &host, &ips[..], srv_port, props)
            .map_err(|e| anyhow!("building DNS-SD service info: {e}"))?;
        let fullname = info.get_fullname().to_string();
        daemon()?
            .register(info)
            .map_err(|e| anyhow!("starting DNS-SD advertisement: {e}"))?;
        Ok(Advert { fullname })
    }

    /// Browse `service_type` until `decode` accepts an instance or the window
    /// closes. `decode` receives the bare instance label and the `e` TXT content
    /// and returns the node id when it recognizes and can read the record; every
    /// other instance on the network is skipped.
    pub(in crate::lan) async fn lookup(
        service_type: &str,
        decode: impl Fn(&str, &str) -> Option<EndpointId>,
    ) -> Result<Option<LanFound>> {
        // A lookup-private daemon (see `daemon` docs); shut down at the end.
        let daemon =
            ServiceDaemon::new().map_err(|e| anyhow!("starting the DNS-SD browser: {e}"))?;
        let receiver = daemon
            .browse(service_type)
            .map_err(|e| anyhow!("starting DNS-SD browse: {e}"))?;
        let deadline = tokio::time::Instant::now() + LOOKUP_TIMEOUT;
        let suffix = format!(".{service_type}");

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
            let Some(content) = info.get_property_val_str(TXT_KEY) else {
                continue;
            };
            let Some(node_id) = decode(instance, content) else {
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
            break Some(LanFound {
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
        use crate::pin_record;

        /// Interop with the platform Bonjour daemon: `dns-sd -R` registers through
        /// macOS's mDNSResponder rather than our in-process responder, so a lookup
        /// that finds it proves we resolve records published by a foreign
        /// RFC 6762/6763 stack. This is the same daemon the iOS backend talks to,
        /// so it also stands in for iOS interop, which has no test runner.
        #[cfg(target_os = "macos")]
        #[tokio::test(flavor = "multi_thread")]
        async fn lookup_finds_daemon_registered_advert() {
            let _ = env_logger::builder().is_test(true).try_init();
            let pin = "M3TDPWFA";
            let node_id = iroh::SecretKey::generate().public();

            let candidates = pin_record::candidate_keys(pin).await.unwrap();
            let content = pin_record::encrypt_pin_payload(&candidates[0], &node_id).unwrap();
            let instance = crate::lan::pin_instance_name(&candidates[0]);
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

            let found = crate::lan::dnssd_lookup_pin_record(&candidates).await;
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
            let found = crate::lan::dnssd_lookup_pin_record(&candidates).await.unwrap();
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
            let receiver = daemon.browse(crate::lan::PIN_SERVICE_TYPE).unwrap();
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
            while let Ok(Ok(event)) = tokio::time::timeout_at(deadline, receiver.recv_async()).await
            {
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
            let _advert = crate::lan::dnssd_advertise_pin_record(&candidates[0], &node_id, &[addr])
                .await
                .unwrap();

            let found = crate::lan::dnssd_lookup_pin_record(&candidates)
                .await
                .unwrap()
                .expect("record on LAN");
            assert_eq!(found.node_id, node_id);
            assert!(
                found.addrs.contains(&addr),
                "resolved addrs {:?} missing {addr}",
                found.addrs
            );
        }

        /// The same round trip for a pairwise hosting record: a host advertises for
        /// one trusted peer, that peer resolves it, and a device the record was not
        /// addressed to finds nothing — the label it browses for is derived from a
        /// pair of keys it is not part of.
        #[tokio::test(flavor = "multi_thread")]
        async fn a_hosting_record_resolves_only_for_the_peer_it_names() {
            let _ = env_logger::builder().is_test(true).try_init();
            let host = crate::auth::Identity::generate();
            let peer = crate::auth::Identity::generate();
            let stranger = crate::auth::Identity::generate();
            let node_id = iroh::SecretKey::generate().public();
            let addr = SocketAddr::from(([127, 0, 0, 1], 4434));

            let _advert =
                crate::lan::dnssd_advertise_hosting(&host, peer.public_key(), &node_id, &[addr])
                    .await
                    .unwrap();

            let found = crate::lan::dnssd_lookup_hosting(&peer, host.public_key())
                .await
                .unwrap()
                .expect("the addressed peer resolves the record");
            assert_eq!(found.node_id, node_id);
            assert!(
                found.addrs.contains(&addr),
                "resolved addrs {:?} missing {addr}",
                found.addrs
            );

            assert!(
                crate::lan::dnssd_lookup_hosting(&stranger, host.public_key())
                    .await
                    .unwrap()
                    .is_none(),
                "a device the record does not name must not resolve it"
            );
        }
    }
}

/// The iOS half: the same advertise/lookup contract driven through the system
/// mDNSResponder daemon over `dns_sd.h` IPC.
///
/// Every call here is IPC to a system daemon that owns the multicast sockets,
/// which is the whole point — an in-process responder (the desktop half) needs
/// the `com.apple.developer.networking.multicast` entitlement Apple grants by
/// exception, while this path needs only the ordinary Local Network permission.
///
/// The trade is that the daemon's API is a set of blocking IPC sockets pumped
/// with `poll(2)`, so both entry points hop to `spawn_blocking`.
#[cfg(target_os = "ios")]
mod ios {
    use std::collections::HashMap;
    use std::ffi::{CStr, CString, c_char, c_void};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::ptr;
    use std::time::{Duration, Instant};

    use anyhow::{Context, Result, bail, ensure};
    use iroh::EndpointId;

    use super::super::{
        LOOKUP_TIMEOUT, LanFound, TXT_KEY, TXT_KEY_PORT6, assemble_addrs, split_ports,
    };

    /// kDNSServiceErr_PolicyDenied: the daemon refused the operation because
    /// the app lacks Local Network permission. iOS reports this only through
    /// the operation's callback — registrations never pop the permission
    /// prompt themselves (browses do).
    const ERR_POLICY_DENIED: DNSServiceErrorType = -65570;
    /// How long to pump a fresh registration for the daemon's verdict. The
    /// callback normally lands well within this (probing takes ~1s); with no
    /// verdict by then the registration is assumed live.
    const REGISTER_VERDICT_WAIT: Duration = Duration::from_secs(2);
    /// How long to keep collecting A/AAAA answers for the winning instance
    /// after the first arrives, so the second address family can land too.
    const ADDR_GRACE: Duration = Duration::from_millis(700);
    /// Slice of `LOOKUP_TIMEOUT` held back from browsing so the address lookup
    /// that follows always has time to run. A browse that hit at the very end
    /// of the window would otherwise resolve a record it can produce no address
    /// for, which reads as "nothing on this network" rather than "too slow".
    const ADDR_RESERVE: Duration = Duration::from_millis(1500);

    /// `super`'s service types are full DNS-SD names (`_duocb-pin._udp.local.`),
    /// but the dns_sd.h calls take the registration type and the domain as
    /// separate arguments. Split on the last two labels.
    fn split_service_type(service_type: &str) -> Result<(CString, CString)> {
        let trimmed = service_type.trim_end_matches('.');
        let (regtype, domain) = trimmed
            .rsplit_once('.')
            .context("service type has no domain label")?;
        Ok((CString::new(regtype)?, CString::new(format!("{domain}."))?))
    }

    // Hand-written bindings for the slice of dns_sd.h this module uses. The
    // symbols live in libSystem on Apple platforms; every call is IPC to the
    // system mDNSResponder daemon, which performs the multicast itself — that
    // is what exempts this path from the multicast entitlement.
    type DNSServiceRef = *mut c_void;
    type DNSServiceFlags = u32;
    type DNSServiceErrorType = i32;

    /// kDNSServiceFlagsMoreComing: more callbacks are already queued; only a
    /// callback *without* it marks the end of the currently-known answers.
    const MORE_COMING: DNSServiceFlags = 0x1;
    /// kDNSServiceFlagsAdd: the browse callback reports an instance appearing
    /// rather than going away.
    const FLAG_ADD: DNSServiceFlags = 0x2;
    /// kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6.
    const PROTOCOL_BOTH: u32 = 0x01 | 0x02;

    type ResolveReply = unsafe extern "C" fn(
        DNSServiceRef,
        DNSServiceFlags,
        u32,
        DNSServiceErrorType,
        *const c_char, // fullname
        *const c_char, // hosttarget
        u16,           // port, network byte order
        u16,           // txt_len
        *const u8,     // txt_record
        *mut c_void,
    );
    type GetAddrInfoReply = unsafe extern "C" fn(
        DNSServiceRef,
        DNSServiceFlags,
        u32,
        DNSServiceErrorType,
        *const c_char, // hostname
        *const libc::sockaddr,
        u32, // ttl
        *mut c_void,
    );
    type RegisterReply = unsafe extern "C" fn(
        DNSServiceRef,
        DNSServiceFlags,
        DNSServiceErrorType,
        *const c_char,
        *const c_char,
        *const c_char,
        *mut c_void,
    );
    type BrowseReply = unsafe extern "C" fn(
        DNSServiceRef,
        DNSServiceFlags,
        u32,
        DNSServiceErrorType,
        *const c_char, // service name (bare instance label)
        *const c_char, // regtype
        *const c_char, // domain
        *mut c_void,
    );

    unsafe extern "C" {
        fn DNSServiceRegister(
            sd_ref: *mut DNSServiceRef,
            flags: DNSServiceFlags,
            interface_index: u32,
            name: *const c_char,
            regtype: *const c_char,
            domain: *const c_char,
            host: *const c_char,
            port_network_order: u16,
            txt_len: u16,
            txt_record: *const c_void,
            callback: Option<RegisterReply>,
            context: *mut c_void,
        ) -> DNSServiceErrorType;
        fn DNSServiceResolve(
            sd_ref: *mut DNSServiceRef,
            flags: DNSServiceFlags,
            interface_index: u32,
            name: *const c_char,
            regtype: *const c_char,
            domain: *const c_char,
            callback: Option<ResolveReply>,
            context: *mut c_void,
        ) -> DNSServiceErrorType;
        fn DNSServiceBrowse(
            sd_ref: *mut DNSServiceRef,
            flags: DNSServiceFlags,
            interface_index: u32,
            regtype: *const c_char,
            domain: *const c_char,
            callback: Option<BrowseReply>,
            context: *mut c_void,
        ) -> DNSServiceErrorType;
        fn DNSServiceGetAddrInfo(
            sd_ref: *mut DNSServiceRef,
            flags: DNSServiceFlags,
            interface_index: u32,
            protocol: u32,
            hostname: *const c_char,
            callback: Option<GetAddrInfoReply>,
            context: *mut c_void,
        ) -> DNSServiceErrorType;
        fn DNSServiceRefSockFD(sd_ref: DNSServiceRef) -> i32;
        fn DNSServiceProcessResult(sd_ref: DNSServiceRef) -> DNSServiceErrorType;
        fn DNSServiceRefDeallocate(sd_ref: DNSServiceRef);
    }

    /// An owned dns_sd operation handle; deallocating cancels the operation
    /// (for a registration, the daemon withdraws the records with goodbye
    /// packets).
    struct Op(DNSServiceRef);

    // The raw ref is an opaque IPC handle. It is only ever driven from one
    // thread at a time (the registration never processes results at all), so
    // moving it across threads is sound.
    unsafe impl Send for Op {}

    impl Drop for Op {
        fn drop(&mut self) {
            unsafe { DNSServiceRefDeallocate(self.0) };
        }
    }

    /// A live registration with the system daemon. `outcome` is the
    /// registration callback's context; it must outlive the op even though
    /// the socket is no longer pumped once the verdict window closes
    /// (callbacks only ever run inside `DNSServiceProcessResult`).
    pub(in crate::lan) struct Advert {
        #[expect(dead_code, reason = "held for Drop")]
        op: Op,
        #[expect(dead_code, reason = "callback context, held for Drop")]
        outcome: Box<RegisterOutcome>,
    }

    /// The daemon's verdict on a registration, written by `register_cb`.
    #[derive(Default)]
    struct RegisterOutcome {
        err: Option<DNSServiceErrorType>,
    }

    unsafe extern "C" fn register_cb(
        _sd_ref: DNSServiceRef,
        _flags: DNSServiceFlags,
        err: DNSServiceErrorType,
        _name: *const c_char,
        _regtype: *const c_char,
        _domain: *const c_char,
        context: *mut c_void,
    ) {
        let outcome = unsafe { &mut *context.cast::<RegisterOutcome>() };
        outcome.err = Some(err);
    }

    unsafe extern "C" fn noop_browse_cb(
        _sd_ref: DNSServiceRef,
        _flags: DNSServiceFlags,
        _interface_index: u32,
        _err: DNSServiceErrorType,
        _service_name: *const c_char,
        _regtype: *const c_char,
        _domain: *const c_char,
        _context: *mut c_void,
    ) {
    }

    /// iOS never shows the Local Network prompt for a *registration* — it
    /// silently denies it — but a *browse* is a sanctioned prompt trigger
    /// (and our types are listed under NSBonjourServices). Browse briefly so
    /// the system can ask; the caller reports the denial and the publisher's
    /// next rotation re-registers once the user grants access.
    fn trigger_local_network_prompt(regtype: &CStr, domain: &CStr) {
        let mut sd_ref: DNSServiceRef = ptr::null_mut();
        let err = unsafe {
            DNSServiceBrowse(
                &mut sd_ref,
                0,
                0,
                regtype.as_ptr(),
                domain.as_ptr(),
                Some(noop_browse_cb),
                ptr::null_mut(),
            )
        };
        if err != 0 {
            log::warn!("DNSServiceBrowse (permission-prompt trigger) failed: {err}");
            return;
        }
        let op = Op(sd_ref);
        // The prompt fires on the daemon receiving the request; holding the
        // browse a moment is enough, and dropping it doesn't dismiss the
        // prompt. This runs on the blocking pool, so sleeping is fine.
        std::thread::sleep(Duration::from_millis(1500));
        drop(op);
    }

    /// One length-prefixed `key=value` string in TXT wire format.
    fn push_txt(buf: &mut Vec<u8>, key: &str, value: &str) -> Result<()> {
        let entry = format!("{key}={value}");
        let len: u8 = entry
            .len()
            .try_into()
            .ok()
            .filter(|len| *len > 0)
            .context("rendezvous record does not fit a TXT attribute")?;
        buf.push(len);
        buf.extend_from_slice(entry.as_bytes());
        Ok(())
    }

    pub(in crate::lan) async fn advertise(
        service_type: &str,
        instance: &str,
        content: String,
        addrs: &[SocketAddr],
    ) -> Result<Advert> {
        // The registration verdict is pumped with blocking poll(2), and the
        // permission-prompt fallback sleeps — keep it all off the executor.
        let service_type = service_type.to_string();
        let instance = instance.to_string();
        let addrs = addrs.to_vec();
        tokio::task::spawn_blocking(move || {
            blocking_advertise(&service_type, &instance, &content, &addrs)
        })
        .await
        .context("DNS-SD advertise task failed")?
    }

    fn blocking_advertise(
        service_type: &str,
        instance: &str,
        content: &str,
        addrs: &[SocketAddr],
    ) -> Result<Advert> {
        let (srv_port, port6) =
            split_ports(addrs).context("endpoint has no direct addresses to advertise")?;

        let mut txt = Vec::new();
        push_txt(&mut txt, TXT_KEY, content)?;
        if let Some(p6) = port6 {
            push_txt(&mut txt, TXT_KEY_PORT6, &p6.to_string())?;
        }
        let name = CString::new(instance)?;
        let (regtype, domain) = split_service_type(service_type)?;

        let mut outcome = Box::new(RegisterOutcome::default());
        let mut sd_ref: DNSServiceRef = ptr::null_mut();
        // host NULL → the daemon advertises this device's own hostname and
        // serves its A/AAAA records — exactly the addresses a joiner should
        // dial; only the SRV port comes from us.
        let err = unsafe {
            DNSServiceRegister(
                &mut sd_ref,
                0,
                0, // all interfaces
                name.as_ptr(),
                regtype.as_ptr(),
                domain.as_ptr(),
                ptr::null(),
                srv_port.to_be(),
                txt.len() as u16,
                txt.as_ptr().cast(),
                Some(register_cb),
                ptr::from_mut::<RegisterOutcome>(&mut outcome).cast(),
            )
        };
        ensure!(err == 0, "DNSServiceRegister failed: {err}");
        let op = Op(sd_ref);

        // Wait for the daemon's verdict: iOS gates advertising behind Local
        // Network permission and reports a denial *only* here — without this
        // pump a denied registration would look successful and the host would
        // be silently invisible to joiners.
        let deadline = Instant::now() + REGISTER_VERDICT_WAIT;
        while outcome.err.is_none() && poll_and_process(&[op.0], deadline)? {}
        match outcome.err {
            // A quiet window means no error so far; proceed optimistically.
            Some(0) | None => Ok(Advert { op, outcome }),
            Some(ERR_POLICY_DENIED) => {
                trigger_local_network_prompt(&regtype, &domain);
                anyhow::bail!(
                    "Local Network permission is not granted — allow it in the prompt (or in \
                     Settings > Privacy & Security > Local Network); the next attempt retries \
                     within a minute"
                )
            }
            Some(err) => anyhow::bail!("DNS-SD registration failed: {err}"),
        }
    }

    /// Browse for an instance `decode` recognizes, then resolve its addresses.
    ///
    /// The dns_sd socket pump is blocking (`poll(2)` + `DNSServiceProcessResult`),
    /// so it runs on `spawn_blocking` — but `decode` deliberately does **not**
    /// go with it. It is a caller-supplied closure that borrows local data (a
    /// candidate-key map, a trusted identity), so requiring the `Send + 'static`
    /// that `spawn_blocking` demands would force every call site to clone its
    /// world. Instead [`Browse`] carries the blocking state across successive
    /// `spawn_blocking` calls and hands resolved answers back, and `decode`
    /// judges them here on the async side.
    pub(in crate::lan) async fn lookup(
        service_type: &str,
        decode: impl Fn(&str, &str) -> Option<EndpointId>,
    ) -> Result<Option<LanFound>> {
        let deadline = Instant::now() + LOOKUP_TIMEOUT;
        // The browse stops early so `resolve_addresses` below still has a window
        // to work in; both phases share the one LOOKUP_TIMEOUT budget.
        let browse_deadline = deadline - ADDR_RESERVE;
        let owned_type = service_type.to_string();
        let mut browse = tokio::task::spawn_blocking(move || Browse::start(&owned_type))
            .await
            .context("DNS-SD browse task failed")??;

        let hit = loop {
            let (returned, answers) = tokio::task::spawn_blocking(move || {
                let answers = browse.pump(browse_deadline);
                (browse, answers)
            })
            .await
            .context("DNS-SD lookup task failed")?;
            browse = returned;
            let answers = answers?;
            // An empty round means the browse window closed with nothing new:
            // no record of ours is on this network.
            if answers.is_empty() {
                return Ok(None);
            }
            // Instances `decode` rejects are simply other duocb devices'
            // records on the same network — keep pumping.
            let recognized = answers.into_iter().find_map(|answer| {
                decode(&answer.instance, &answer.content).map(|node_id| (node_id, answer))
            });
            if let Some(hit) = recognized {
                break hit;
            }
        };
        // Cancels the browse and every outstanding resolve.
        drop(browse);
        let (
            node_id,
            Answer {
                host,
                srv_port,
                port6,
                ..
            },
        ) = hit;

        let ips = tokio::task::spawn_blocking(move || resolve_addresses(&host, deadline))
            .await
            .context("DNS-SD address task failed")??;

        let addrs = assemble_addrs(&ips, srv_port, port6);
        if addrs.is_empty() {
            // A record without a dialable address is useless here: iroh's own
            // mDNS lookup is compiled out on iOS, so there is nothing else to
            // resolve the bare node id against on a LAN-only channel.
            log::warn!("DNS-SD record resolved without dialable addresses");
            return Ok(None);
        }
        Ok(Some(LanFound { node_id, addrs }))
    }

    /// Instances the browse has reported as present, in arrival order.
    ///
    /// This is the structural difference from the desktop half. There, a
    /// resolved-service event carries the instance label, the TXT content and
    /// the addresses in one payload; here the daemon splits that across three
    /// operations, so a lookup browses to learn labels, resolves each label for
    /// its TXT and SRV target, and only then asks for the target's addresses.
    #[derive(Default)]
    struct BrowseOutcome {
        instances: Vec<(CString, CString, CString)>,
    }

    unsafe extern "C" fn browse_cb(
        _sd_ref: DNSServiceRef,
        flags: DNSServiceFlags,
        _interface_index: u32,
        err: DNSServiceErrorType,
        service_name: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
        context: *mut c_void,
    ) {
        // Only additions matter; a removal cannot produce a hit.
        if err != 0 || flags & FLAG_ADD == 0 {
            return;
        }
        if service_name.is_null() || regtype.is_null() || domain.is_null() {
            return;
        }
        let outcome = unsafe { &mut *context.cast::<BrowseOutcome>() };
        // The callback's own regtype/domain go straight back into the resolve:
        // they are the daemon's escaped forms, and re-deriving them from our
        // constants would drop any escaping it applied.
        outcome.instances.push((
            unsafe { CStr::from_ptr(service_name) }.to_owned(),
            unsafe { CStr::from_ptr(regtype) }.to_owned(),
            unsafe { CStr::from_ptr(domain) }.to_owned(),
        ));
    }

    /// What a resolve callback delivered for one browsed instance.
    #[derive(Default)]
    struct ResolveOutcome {
        /// `(SRV target host, SRV port, TXT attributes)`.
        answer: Option<(CString, u16, HashMap<String, String>)>,
    }

    unsafe extern "C" fn resolve_cb(
        _sd_ref: DNSServiceRef,
        _flags: DNSServiceFlags,
        _interface_index: u32,
        err: DNSServiceErrorType,
        _fullname: *const c_char,
        hosttarget: *const c_char,
        port_network_order: u16,
        txt_len: u16,
        txt_record: *const u8,
        context: *mut c_void,
    ) {
        if err != 0 || hosttarget.is_null() {
            return;
        }
        let outcome = unsafe { &mut *context.cast::<ResolveOutcome>() };
        let host = unsafe { CStr::from_ptr(hosttarget) }.to_owned();
        let txt = if txt_record.is_null() {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(txt_record, txt_len as usize) }
        };
        outcome.answer = Some((host, u16::from_be(port_network_order), parse_txt(txt)));
    }

    /// Decode TXT wire format: length-prefixed `key=value` strings.
    fn parse_txt(mut data: &[u8]) -> HashMap<String, String> {
        let mut map = HashMap::new();
        while let Some((&len, rest)) = data.split_first() {
            let len = len as usize;
            if len == 0 || rest.len() < len {
                break;
            }
            let (entry, tail) = rest.split_at(len);
            data = tail;
            let Ok(entry) = std::str::from_utf8(entry) else {
                continue;
            };
            if let Some((key, value)) = entry.split_once('=') {
                map.insert(key.to_string(), value.to_string());
            }
        }
        map
    }

    /// Addresses accumulated for the winning instance's SRV target.
    #[derive(Default)]
    struct AddrOutcome {
        ips: Vec<IpAddr>,
        /// Set once a callback arrives without `MORE_COMING` — all answers the
        /// daemon currently knows have been delivered.
        done: bool,
    }

    unsafe extern "C" fn addr_cb(
        _sd_ref: DNSServiceRef,
        flags: DNSServiceFlags,
        _interface_index: u32,
        err: DNSServiceErrorType,
        _hostname: *const c_char,
        address: *const libc::sockaddr,
        _ttl: u32,
        context: *mut c_void,
    ) {
        let outcome = unsafe { &mut *context.cast::<AddrOutcome>() };
        // Only additions are addresses to dial. GetAddrInfo reports expiry the
        // same way the browse reports a vanished instance — a callback with
        // FLAG_ADD clear — and collecting those would hand back an address the
        // daemon has just said is gone.
        if err == 0 && !address.is_null() && flags & FLAG_ADD != 0 {
            match unsafe { (*address).sa_family } as i32 {
                libc::AF_INET => {
                    let sa = unsafe { &*address.cast::<libc::sockaddr_in>() };
                    outcome
                        .ips
                        .push(IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr))));
                }
                libc::AF_INET6 => {
                    let sa = unsafe { &*address.cast::<libc::sockaddr_in6>() };
                    outcome
                        .ips
                        .push(IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr)));
                }
                _ => {}
            }
        }
        if flags & MORE_COMING == 0 {
            outcome.done = true;
        }
    }

    /// Wait for any of the operations' IPC sockets to become readable (up to
    /// `deadline`) and dispatch their pending callbacks. `Ok(false)` when the
    /// deadline passed or a socket died — time to stop pumping.
    fn poll_and_process(refs: &[DNSServiceRef], deadline: Instant) -> Result<bool> {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(false);
        };
        let mut fds: Vec<libc::pollfd> = refs
            .iter()
            .map(|&sd_ref| libc::pollfd {
                fd: unsafe { DNSServiceRefSockFD(sd_ref) },
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let timeout_ms = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                return Ok(true);
            }
            return Err(e).context("poll on dns_sd sockets");
        }
        if n == 0 {
            return Ok(false);
        }
        for (pfd, &sd_ref) in fds.iter().zip(refs) {
            if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Ok(false);
            }
            if pfd.revents & libc::POLLIN != 0 {
                let err = unsafe { DNSServiceProcessResult(sd_ref) };
                if err != 0 {
                    bail!("DNSServiceProcessResult failed: {err}");
                }
            }
        }
        Ok(true)
    }

    /// One in-flight resolve: its op, its callback context, and the bare
    /// instance label to hand `decode` when the answer lands.
    struct Resolve {
        op: Op,
        outcome: Box<ResolveOutcome>,
        instance: String,
    }

    /// One resolved instance, handed back to the async side for `decode` to
    /// judge. Everything the caller needs is owned, so nothing borrows the
    /// blocking state.
    struct Answer {
        instance: String,
        content: String,
        host: CString,
        srv_port: u16,
        port6: Option<u16>,
    }

    /// The blocking half of a lookup: a browse plus one resolve per instance it
    /// has reported.
    ///
    /// It exists as a struct rather than a straight-line function because it
    /// moves between `spawn_blocking` calls — pump a round, hand the answers to
    /// `decode` on the async side, come back and pump again. Every field is
    /// `Send`: the raw dns_sd handles are opaque IPC refs driven from one thread
    /// at a time (see [`Op`]), and the callback-context `Box`es keep their heap
    /// addresses across the move, which is what makes the registered pointers
    /// stay valid.
    struct Browse {
        browse_op: Op,
        outcome: Box<BrowseOutcome>,
        resolves: Vec<Resolve>,
        /// Instance labels already resolving, so a repeated browse callback
        /// (interface changes re-announce) does not start a second resolve.
        started: Vec<CString>,
    }

    impl Browse {
        /// Start browsing `service_type`.
        ///
        /// Browsing — rather than a targeted resolve per candidate label, which
        /// is what the PIN-only predecessor of this backend did — is what keeps
        /// it caller-agnostic: it does not know which labels the caller would
        /// accept, only that `decode` recognizes one when it sees it. It is also
        /// the operation iOS sanctions as a Local Network prompt trigger, so a
        /// first lookup asks for permission on its own.
        fn start(service_type: &str) -> Result<Self> {
            let (regtype, domain) = split_service_type(service_type)?;
            let mut outcome = Box::new(BrowseOutcome::default());
            let mut sd_ref: DNSServiceRef = ptr::null_mut();
            let err = unsafe {
                DNSServiceBrowse(
                    &mut sd_ref,
                    0,
                    0,
                    regtype.as_ptr(),
                    domain.as_ptr(),
                    Some(browse_cb),
                    ptr::from_mut::<BrowseOutcome>(&mut outcome).cast(),
                )
            };
            ensure!(err == 0, "DNSServiceBrowse failed: {err}");
            Ok(Self {
                browse_op: Op(sd_ref),
                outcome,
                resolves: Vec::new(),
                started: Vec::new(),
            })
        }

        /// Pump the browse and its resolves until at least one instance answers
        /// or `deadline` passes. An empty vec means the window closed with
        /// nothing new — the caller stops there.
        fn pump(&mut self, deadline: Instant) -> Result<Vec<Answer>> {
            loop {
                self.start_new_resolves();
                let answers: Vec<Answer> = self
                    .resolves
                    .iter_mut()
                    .filter_map(|resolve| {
                        let (host, srv_port, txt) = resolve.outcome.answer.take()?;
                        Some(Answer {
                            instance: resolve.instance.clone(),
                            content: txt.get(TXT_KEY)?.clone(),
                            host,
                            srv_port,
                            port6: txt.get(TXT_KEY_PORT6).and_then(|s| s.parse().ok()),
                        })
                    })
                    .collect();
                if !answers.is_empty() {
                    return Ok(answers);
                }

                let mut refs: Vec<DNSServiceRef> = vec![self.browse_op.0];
                refs.extend(self.resolves.iter().map(|r| r.op.0));
                if !poll_and_process(&refs, deadline)? {
                    return Ok(Vec::new());
                }
            }
        }

        /// Kick off a resolve for every instance the browse has newly reported.
        fn start_new_resolves(&mut self) {
            for (name, regtype, domain) in std::mem::take(&mut self.outcome.instances) {
                if self.started.contains(&name) {
                    continue;
                }
                let Ok(instance) = name.to_str() else { continue };
                // Our labels are lowercase hex, but mDNS names are
                // case-insensitive and another stack may echo them differently —
                // match the desktop half, which lowercases too.
                let instance = instance.to_ascii_lowercase();
                let mut outcome = Box::new(ResolveOutcome::default());
                let mut sd_ref: DNSServiceRef = ptr::null_mut();
                let err = unsafe {
                    DNSServiceResolve(
                        &mut sd_ref,
                        0,
                        0,
                        name.as_ptr(),
                        regtype.as_ptr(),
                        domain.as_ptr(),
                        Some(resolve_cb),
                        ptr::from_mut::<ResolveOutcome>(&mut outcome).cast(),
                    )
                };
                if err != 0 {
                    log::warn!("DNSServiceResolve failed: {err}");
                    continue;
                }
                self.started.push(name);
                self.resolves.push(Resolve {
                    op: Op(sd_ref),
                    outcome,
                    instance,
                });
            }
        }
    }

    /// Resolve an SRV target's A/AAAA records through the daemon. Answers arrive
    /// one record at a time, so a short grace after the first lets the second
    /// address family land too.
    ///
    /// The grace is measured from the *first address*, not from entry: the
    /// daemon may take longer than [`ADDR_GRACE`] to produce anything at all
    /// (a cold cache, a host still being probed), and starting the clock here
    /// would abandon the resolve before the first record ever landed and report
    /// a record with no dialable address. Until then the shared `deadline` is
    /// the only bound.
    fn resolve_addresses(host: &CStr, deadline: Instant) -> Result<Vec<IpAddr>> {
        let mut outcome = Box::new(AddrOutcome::default());
        let mut sd_ref: DNSServiceRef = ptr::null_mut();
        let err = unsafe {
            DNSServiceGetAddrInfo(
                &mut sd_ref,
                0,
                0,
                PROTOCOL_BOTH,
                host.as_ptr(),
                Some(addr_cb),
                ptr::from_mut::<AddrOutcome>(&mut outcome).cast(),
            )
        };
        ensure!(err == 0, "DNSServiceGetAddrInfo failed: {err}");
        let op = Op(sd_ref);
        let mut window = deadline;
        while !(outcome.done && !outcome.ips.is_empty()) && poll_and_process(&[op.0], window)? {
            if !outcome.ips.is_empty() {
                // Pinned by the first address: `min` keeps the earlier bound, so
                // later rounds cannot push the window out again.
                window = window.min(Instant::now() + ADDR_GRACE);
            }
        }
        drop(op);
        Ok(std::mem::take(&mut outcome.ips))
    }
}
