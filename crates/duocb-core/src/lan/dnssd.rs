//! Spec-compliant DNS-SD backend for the LAN-only channel's PIN rendezvous —
//! see the module docs in `super`. Two platform halves with one contract:
//! advertise `<instance>._duocb-pin._udp.local.` with the ciphertext in the
//! `e` TXT attribute and real SRV/A/AAAA data, and resolve a candidate
//! instance back into [`PinFound`] (node id + dialable direct addresses).
//!
//! - Desktop: the mdns-sd crate, an in-process RFC 6762/6763 responder that
//!   interoperates with Bonjour.
//! - iOS: the system mDNSResponder daemon over `dns_sd.h` IPC. The daemon
//!   performs the multicast, so the app needs no multicast entitlement —
//!   only the Local Network permission plus `NSBonjourServices` listing
//!   `_duocb-pin._udp`.

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
    use nostr_sdk::prelude::Keys;

    use super::super::{
        DNSSD_SERVICE_TYPE, LOOKUP_TIMEOUT, PinFound, TXT_KEY, TXT_KEY_PORT6, assemble_addrs,
        instance_name, split_ports,
    };
    use crate::pin_record;

    /// The process-wide responder. Created on first use and kept for the
    /// process lifetime: adverts register/unregister against it (a rotation
    /// every period would otherwise spawn and tear down socket threads), and
    /// lookups browse on it. A failed first bind stays failed — the daemon
    /// binds 5353 with SO_REUSEADDR/SO_REUSEPORT, so failure means something
    /// unusual that a retry within this process won't fix.
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

    pub(in crate::lan) fn advertise(
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

    pub(in crate::lan) async fn lookup(candidates: &[Keys]) -> Result<Option<PinFound>> {
        let by_instance: HashMap<String, &Keys> = candidates
            .iter()
            .map(|keys| (instance_name(keys), keys))
            .collect();

        let daemon = daemon()?;
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
        let _ = daemon.stop_browse(DNSSD_SERVICE_TYPE);
        Ok(found)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

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
            let _advert = advertise(&candidates[0], &node_id, &[addr]).unwrap();

            let found = lookup(&candidates).await.unwrap().expect("record on LAN");
            assert_eq!(found.node_id, node_id);
            assert!(
                found.addrs.contains(&addr),
                "resolved addrs {:?} missing {addr}",
                found.addrs
            );
        }
    }
}

#[cfg(target_os = "ios")]
mod ios {
    use std::collections::HashMap;
    use std::ffi::{CStr, CString, c_char, c_void};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::ptr;
    use std::time::{Duration, Instant};

    use anyhow::{Context, Result, bail, ensure};
    use iroh::EndpointId;
    use nostr_sdk::prelude::Keys;

    use super::super::{
        LOOKUP_TIMEOUT, PinFound, TXT_KEY, TXT_KEY_PORT6, assemble_addrs, instance_name,
        split_ports,
    };
    use crate::pin_record;

    /// `_duocb-pin._udp` — the dns_sd.h calls take the regtype and the domain
    /// (`local.`) as separate arguments.
    const REGTYPE: &str = "_duocb-pin._udp";

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

    /// A live registration with the system daemon.
    pub(in crate::lan) struct Advert(#[expect(dead_code, reason = "held for Drop")] Op);

    /// One length-prefixed `key=value` string in TXT wire format.
    fn push_txt(buf: &mut Vec<u8>, key: &str, value: &str) -> Result<()> {
        let entry = format!("{key}={value}");
        let len: u8 = entry
            .len()
            .try_into()
            .ok()
            .filter(|len| *len > 0)
            .context("PIN record does not fit a TXT attribute")?;
        buf.push(len);
        buf.extend_from_slice(entry.as_bytes());
        Ok(())
    }

    pub(in crate::lan) fn advertise(
        keys: &Keys,
        node_id: &EndpointId,
        addrs: &[SocketAddr],
    ) -> Result<Advert> {
        let content = pin_record::encrypt_pin_payload(keys, node_id)?;
        let (srv_port, port6) =
            split_ports(addrs).context("endpoint has no direct addresses to advertise")?;

        let mut txt = Vec::new();
        push_txt(&mut txt, TXT_KEY, &content)?;
        if let Some(p6) = port6 {
            push_txt(&mut txt, TXT_KEY_PORT6, &p6.to_string())?;
        }
        let name = CString::new(instance_name(keys))?;
        let regtype = CString::new(REGTYPE)?;

        let mut sd_ref: DNSServiceRef = ptr::null_mut();
        // host NULL → the daemon advertises this device's own hostname and
        // serves its A/AAAA records — exactly the addresses a joiner should
        // dial; only the SRV port comes from us. No callback: the instance
        // name is collision-free by construction (128-bit derived label), so
        // registration outcomes carry no actionable signal.
        let err = unsafe {
            DNSServiceRegister(
                &mut sd_ref,
                0,
                0, // all interfaces
                name.as_ptr(),
                regtype.as_ptr(),
                ptr::null(),
                ptr::null(),
                srv_port.to_be(),
                txt.len() as u16,
                txt.as_ptr().cast(),
                None,
                ptr::null_mut(),
            )
        };
        ensure!(err == 0, "DNSServiceRegister failed: {err}");
        Ok(Advert(Op(sd_ref)))
    }

    pub(in crate::lan) async fn lookup(candidates: &[Keys]) -> Result<Option<PinFound>> {
        // The dns_sd socket pump is blocking (poll(2) + ProcessResult), so the
        // whole lookup runs off the async executor.
        let candidates = candidates.to_vec();
        tokio::task::spawn_blocking(move || blocking_lookup(&candidates))
            .await
            .context("DNS-SD lookup task failed")?
    }

    /// What a resolve callback delivered for one candidate instance.
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
        if err == 0 && !address.is_null() {
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

    fn blocking_lookup(candidates: &[Keys]) -> Result<Option<PinFound>> {
        let deadline = Instant::now() + LOOKUP_TIMEOUT;
        let regtype = CString::new(REGTYPE)?;
        let domain = CString::new("local.")?;

        // One targeted resolve per candidate label — the instance names are
        // derived from the PIN, so no browse pass is needed. The outcome boxes
        // stay alive (and pinned by Box) for as long as the ops that write to
        // them; each tuple drops its Op (cancelling callbacks) before its box.
        let mut resolves: Vec<(Op, Box<ResolveOutcome>, &Keys)> = Vec::new();
        for keys in candidates {
            let name = CString::new(instance_name(keys))?;
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
            resolves.push((Op(sd_ref), outcome, keys));
        }
        ensure!(!resolves.is_empty(), "could not start any DNS-SD resolve");

        // Pump until one answer decrypts, or the window closes.
        let hit = loop {
            let decrypted = resolves.iter_mut().find_map(|(_, outcome, keys)| {
                let (host, srv_port, txt) = outcome.answer.take()?;
                let node_id = pin_record::decrypt_pin_payload(keys, txt.get(TXT_KEY)?)?;
                let port6 = txt.get(TXT_KEY_PORT6).and_then(|s| s.parse().ok());
                Some((node_id, host, srv_port, port6))
            });
            if let Some(hit) = decrypted {
                break hit;
            }
            let refs: Vec<DNSServiceRef> = resolves.iter().map(|(op, ..)| op.0).collect();
            if !poll_and_process(&refs, deadline)? {
                return Ok(None);
            }
        };
        drop(resolves);
        let (node_id, host, srv_port, port6) = hit;

        // Resolve the SRV target's A/AAAA through the daemon. Answers arrive
        // per record; a short grace after the first lets the second address
        // family land too.
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
        let grace = deadline.min(Instant::now() + Duration::from_millis(700));
        while !(outcome.done && !outcome.ips.is_empty()) && poll_and_process(&[op.0], grace)? {}
        drop(op);

        let addrs = assemble_addrs(&outcome.ips, srv_port, port6);
        if addrs.is_empty() {
            // A record without a dialable address is useless on this channel:
            // there is no other lookup to resolve the bare node id against.
            log::warn!("DNS-SD PIN record resolved without dialable addresses");
            return Ok(None);
        }
        Ok(Some(PinFound { node_id, addrs }))
    }
}
