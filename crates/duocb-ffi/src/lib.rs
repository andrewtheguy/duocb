//! C FFI surface for the iOS app (`aarch64-apple-ios`).
//!
//! The app links `libduocb.xcframework` (containing `libduocb.a` slices) and
//! drives the clipboard-pairing runtime with these calls:
//!
//! 1. [`duocb_start`] — parse the JSON config, spawn the networking runtime,
//!    and issue the role's initial command. Configure-mode roles ("hub",
//!    "start", "join") use this installation's application private key,
//!    signed self-card, and locally trusted signed peer cards. The selected
//!    peer is addressed by application public key. Quick-mode roles
//!    ("quick_host", "quick_join") remain identity-less:
//!    "quick_host" publishes a rotating PIN rendezvous and "quick_join" dials
//!    the `pin` typed by the user, both on the `channel` selected in the
//!    config (see [`QuickChannel`]). Returns an opaque handle. At most **one**
//!    instance may run at a time (a process-global guard rejects a second).
//! 2. [`duocb_next_event`] — drain one pending [`NetEvent`] as a JSON string.
//!    The runtime is event-driven; Swift polls this on a timer until it
//!    returns 0.
//! 3. [`duocb_refresh_directory`], [`duocb_check_backup`], and
//!    [`duocb_publish_backup`] perform explicit Nostr directory/backup work.
//!    A found backup is returned for preview and is never applied by the FFI.
//! 4. [`duocb_send_clipboard`] / [`duocb_query_conn_path`] — fire-and-forget
//!    commands; outcomes arrive as `item_sent`/`error` and `conn_path` events.
//! 5. [`duocb_stop`] — shut the runtime down and free the handle.
//!
//! Quick mode supports the default nostr+LAN channel (the desktop "P" preset)
//! and the LAN-only channel (the desktop "L" preset) via the `channel` config
//! key. LAN-only signaling goes through the system mDNSResponder daemon
//! (Bonjour), so it needs no multicast entitlement — but the app must list
//! `_duocb-pin._udp` under `NSBonjourServices` and set
//! `NSLocalNetworkUsageDescription`. For a LAN-only PIN the joiner may also
//! supply the host's IP (the `ip` config key) to pair over the unicast side
//! channel where multicast is blocked. The nostr-only preset remains
//! desktop-only. Application private-key, permanent name-suffix, and
//! signed-card persistence is the caller's job (Keychain on iOS). These keys
//! are deliberately separate from iroh's ephemeral transport identity.
//!
//! The intended app flow mirrors the desktop hub: run a "hub" instance while
//! the device list is on screen, and when the user picks an action stop it
//! and start a fresh instance with role "start" (host) or "join" plus the
//! selected peer's application public key.
//!
//! The workspace builds with `panic = "abort"` in release, so a Rust panic
//! terminates the process rather than unwinding across the C boundary.

use std::ffi::{CStr, c_char, c_int};
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::Deserialize;

use duocb_core::net::endpoint::ConnPathKind;
use duocb_core::net::{
    ConnStatus, DialSpec, EventSender, KeyIdentity, NetEvent, PinChannel, ServerMode, UiCommand,
};

/// Process-global guard: at most one running session per process.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Opaque handle owned by the Swift side. Freed by [`duocb_stop`].
pub struct DuocbHandle {
    runtime: tokio::runtime::Runtime,
    cmd_tx: tokio::sync::mpsc::UnboundedSender<UiCommand>,
    /// Drained by [`duocb_next_event`] (Mutex: FFI calls may race across threads).
    events: Mutex<std::sync::mpsc::Receiver<NetEvent>>,
    /// An event that didn't fit the caller's buffer, retained for retry.
    pending: Mutex<Option<String>>,
    task: tokio::task::JoinHandle<()>,
    /// The session command this handle was started with (`None` for the hub
    /// role), replayed by [`duocb_reconnect`] into the still-running runtime so
    /// its session identity/pairing memory is reused.
    session_cmd: Option<UiCommand>,
    directory_cmd: Option<UiCommand>,
    backup_check_cmd: Option<UiCommand>,
    backup_publish_cmd: Option<UiCommand>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FfiConfig {
    role: Role,
    /// Configure-mode roles: this installation's NIP-19 `nsec`.
    #[serde(default)]
    identity_secret: Option<String>,
    /// Configure-mode roles: this installation's persisted signed self-card.
    #[serde(default)]
    self_card: Option<String>,
    /// Configure-mode roles: locally trusted signed cards (max 128).
    #[serde(default)]
    peers: Vec<String>,
    /// Join role only: selected peer's hex or NIP-19 public key.
    #[serde(default)]
    peer_public_key: Option<String>,
    /// Optional standalone channel used only for encrypted Nostr peer backups.
    #[serde(default)]
    directory_channel: Option<String>,
    #[serde(default)]
    backup_generation: u64,
    /// QuickJoin role only: the PIN shown on the hosting device, in any
    /// user-typed form (dashes/spaces/lowercase ok).
    #[serde(default)]
    pin: Option<String>,
    /// QuickJoin role only, and only for a LAN-only PIN: the host's LAN IPv4 as
    /// shown on the hosting device (dotted-quad, no port). Present selects the
    /// unicast side channel (pairs where multicast is blocked); omitted/blank
    /// resolves via mDNS. Ignored for a non-LAN-only PIN.
    #[serde(default)]
    ip: Option<String>,
    /// QuickHost role only: which transport carries the rotating-PIN rendezvous.
    /// Omitted means `nostr_lan`. Ignored for QuickJoin — the join transport is
    /// read from the PIN's first character (see `duocb_core::pin`).
    ///
    /// Unrelated to `directory_channel`.
    #[serde(default)]
    channel: Option<QuickChannel>,
    /// Empty/omitted means the built-in default relays.
    #[serde(default)]
    relays: Vec<String>,
}

/// The quick-mode rendezvous transport (JSON `channel` config key). Quick mode
/// has no saved application identity.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum QuickChannel {
    /// Nostr relays + local network — the default; works across the internet
    /// and still pairs on the same network offline. On iOS the LAN half of
    /// the rendezvous is inert (nostr carries it); the connection itself can
    /// still be LAN-direct.
    NostrLan,
    /// LAN only (the desktop "L" preset): no third-party server at all. The
    /// rendezvous is a Bonjour/DNS-SD service registered through the system
    /// mDNSResponder daemon — no multicast entitlement needed — and the join
    /// dials the direct addresses it resolves. The app must declare the
    /// service under `NSBonjourServices` (`_duocb-pin._udp`) and set
    /// `NSLocalNetworkUsageDescription`; joining prompts for Local Network
    /// permission on first use.
    Lan,
}

impl QuickChannel {
    fn to_core(self) -> PinChannel {
        match self {
            QuickChannel::NostrLan => PinChannel::NostrAndLan,
            QuickChannel::Lan => PinChannel::LanOnly,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    /// Presence + peer discovery only; no session until restarted as
    /// `Start`/`Join`.
    Hub,
    Start,
    Join,
    /// Quick mode: host a rotating-PIN session (identity-less, no presence).
    QuickHost,
    /// Quick mode: dial the PIN shown on the hosting device.
    QuickJoin,
}

/// Route Rust `log` output to stderr (visible in Xcode's console and the
/// unified log). Idempotent; honors `RUST_LOG` when set.
#[unsafe(no_mangle)]
pub extern "C" fn duocb_init_logging() {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default()
            .default_filter_or("duocb=info,duocb_core=info,iroh=warn,nostr_sdk=warn"),
    )
    .try_init();
}

/// Generate a fresh persistent application private key as NIP-19 `nsec`.
/// Returns 1 on success, 0 if the buffer is too small, -1 on a NULL buffer.
/// # Safety
/// `out_buf` must be NULL or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_generate_identity(
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if out_buf.is_null() {
        return -1;
    }
    if write_cstr(out_buf, out_len, &duocb_core::auth::Identity::generate().to_nsec()) {
        1
    } else {
        0
    }
}

/// Generate this installation's permanent 8-character device-name suffix.
/// Persist it alongside the identity and reuse it when creating replacement
/// identity cards.
/// # Safety
/// `out_buf` must be NULL or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_generate_suffix(
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if out_buf.is_null() {
        return -1;
    }
    if write_cstr(out_buf, out_len, &duocb_core::identity::generate_suffix()) {
        1
    } else {
        0
    }
}

/// Validate an identity private key. Returns 1 if valid; 0 if invalid (the reason is
/// written to `err_buf` when provided); -1 on NULL/non-UTF-8 input.
/// # Safety
/// `private_key` must be NULL or a valid NUL-terminated C string; `err_buf` must be
/// NULL or point to at least `err_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_validate_identity(
    private_key: *const c_char,
    err_buf: *mut c_char,
    err_len: usize,
) -> c_int {
    let Some(private_key) = (unsafe { cstr_arg(private_key) }) else {
        return -1;
    };
    match duocb_core::auth::Identity::parse_nsec(private_key) {
        Ok(_) => 1,
        Err(err) => {
            write_cstr(err_buf, err_len, &format!("{err:#}"));
            0
        }
    }
}

/// Derive the NIP-19 public key (`npub`) from an identity private key.
/// Returns 1 on success, 0 if the buffer is too small, -1 for invalid input.
/// # Safety
/// Arguments must be NULL or valid pointers of the documented lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_identity_public_key(
    private_key: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    let Some(private_key) = (unsafe { cstr_arg(private_key) }) else {
        return -1;
    };
    let Ok(identity) = duocb_core::auth::Identity::parse_nsec(private_key) else {
        return -1;
    };
    if write_cstr(out_buf, out_len, &identity.to_npub()) {
        1
    } else {
        0
    }
}

/// Create a signed identity card. Call once after naming an identity and
/// persist the returned JSON with the private key.
/// # Safety
/// String inputs must be NUL-terminated UTF-8; `out_buf` must be NULL or point
/// to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_create_identity_card(
    private_key: *const c_char,
    name: *const c_char,
    suffix: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    let (Some(private_key), Some(name), Some(suffix)) = (
        unsafe { cstr_arg(private_key) },
        unsafe { cstr_arg(name) },
        unsafe { cstr_arg(suffix) },
    )
    else {
        return -1;
    };
    let Ok(identity) = duocb_core::auth::Identity::parse_nsec(private_key) else {
        return -1;
    };
    let Ok(card) = identity.card(name.trim(), suffix) else {
        return -1;
    };
    if write_cstr(out_buf, out_len, &card.encode()) {
        1
    } else {
        0
    }
}

/// Validate a signed identity card.
/// # Safety
/// `card` and `err_buf` follow the same pointer rules as
/// [`duocb_validate_identity`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_validate_identity_card(
    card: *const c_char,
    err_buf: *mut c_char,
    err_len: usize,
) -> c_int {
    let Some(card) = (unsafe { cstr_arg(card) }) else {
        return -1;
    };
    match duocb_core::auth::IdentityCard::parse(card) {
        Ok(_) => 1,
        Err(error) => {
            write_cstr(err_buf, err_len, &format!("{error:#}"));
            0
        }
    }
}

/// Write `{name,short_name,suffix,public_key,npub}` for a verified identity card.
/// # Safety
/// `card` must be NUL-terminated UTF-8; `out_buf` must be NULL or point
/// NULL or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_identity_card_info(
    card: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    let Some(card) = (unsafe { cstr_arg(card) }) else {
        return -1;
    };
    let Ok(card) = duocb_core::auth::IdentityCard::parse(card) else {
        return -1;
    };
    let json = serde_json::json!({
        "name": card.name(),
        "short_name": card.short_name(),
        "suffix": card.suffix(),
        "public_key": card.public_key().to_hex(),
        "npub": card.npub(),
    })
    .to_string();
    if write_cstr(out_buf, out_len, &json) {
        1
    } else {
        0
    }
}

/// Generate an optional Nostr backup channel.
/// # Safety
/// `out_buf` must be NULL or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_generate_directory_channel(
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if out_buf.is_null() {
        return -1;
    }
    let channel = duocb_core::auth::DirectoryChannel::generate().encode();
    if write_cstr(out_buf, out_len, &channel) {
        1
    } else {
        0
    }
}

/// Validate a Nostr backup channel.
/// # Safety
/// `channel` and `err_buf` follow the same pointer rules as
/// [`duocb_validate_identity`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_validate_directory_channel(
    channel: *const c_char,
    err_buf: *mut c_char,
    err_len: usize,
) -> c_int {
    let Some(channel) = (unsafe { cstr_arg(channel) }) else {
        return -1;
    };
    match duocb_core::auth::DirectoryChannel::parse(channel) {
        Ok(_) => 1,
        Err(error) => {
            write_cstr(err_buf, err_len, &format!("{error:#}"));
            0
        }
    }
}

/// Normalize a user-typed quick-pair PIN to canonical form (8 uppercase
/// Crockford characters): strips dashes/spaces, uppercases, maps the aliases
/// I/L→1 and O→0, and verifies the trailing check digit. Use for live
/// validation of the join field; `duocb_start` re-normalizes anyway.
/// Returns 1 = valid (canonical PIN written to `out_buf`), 0 = invalid PIN,
/// -1 = NULL/non-UTF-8 input or the buffer is too small (needs ≥ 9 bytes).
/// # Safety
/// `pin` must be NULL or a valid NUL-terminated C string; `out_buf` must be
/// NULL or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_normalize_pin(
    pin: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    let Some(pin) = (unsafe { cstr_arg(pin) }) else {
        return -1;
    };
    let Some(canonical) = duocb_core::pin::normalize_pin(pin) else {
        return 0;
    };
    if write_cstr(out_buf, out_len, &canonical) { 1 } else { -1 }
}

/// Whether a quick-pair PIN is a LAN-only PIN (its first character encodes the
/// channel — see `duocb_core::pin`). The Swift UI uses this to reveal the
/// optional host-IP field on join. `pin` is normalized first, so any user-typed
/// form is accepted. Returns 1 = LAN-only, 0 = not LAN-only (or the PIN is
/// invalid/incomplete), -1 = NULL/non-UTF-8 input.
/// # Safety
/// `pin` must be NULL or a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_pin_is_lan_only(pin: *const c_char) -> c_int {
    let Some(pin) = (unsafe { cstr_arg(pin) }) else {
        return -1;
    };
    match duocb_core::pin::normalize_pin(pin) {
        Some(canonical) if duocb_core::pin::pin_is_lan_only(&canonical) => 1,
        _ => 0,
    }
}

/// Describe how the LAN-only join screen should constrain the optional host-IP
/// entry to *this* device's own subnet. Writes a JSON object to `out_buf`:
///
///   {"prefix":"10.22.33.","placeholder":"last octet","hint":"","label":"10.22.33.0/24"}
///
/// `prefix` is the locked network part to show, non-editable, ahead of the
/// field (the user types only the host part; `duocb_resolve_join_ip` also
/// accepts a whole pasted address). `placeholder` describes the editable tail
/// ("last octet" / "last 2 octets") for the field's placeholder text. `hint` is
/// a range hint for a partial-octet subnet (a /20), else "". `label` is the CIDR
/// for the out-of-range message. All four are "" when no private subnet is
/// detected (free full-IP entry). Returns 1 = written, 0 = buffer too small,
/// -1 = NULL buffer.
/// # Safety
/// `out_buf` must be NULL or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_join_ip_context(out_buf: *mut c_char, out_len: usize) -> c_int {
    let constraint = duocb_core::subnet::JoinIpConstraint::detect();
    let json = serde_json::json!({
        "prefix": constraint.locked_prefix(),
        "placeholder": constraint.host_placeholder(),
        "hint": constraint.hint(),
        "label": constraint.label(),
    })
    .to_string();
    if out_buf.is_null() {
        return -1;
    }
    if write_cstr(out_buf, out_len, &json) { 1 } else { 0 }
}

/// Validate what the user typed into the host-IP entry against this device's
/// subnet, resolving the host part after the locked prefix (or a pasted whole
/// address) into a full IPv4. On success the full dotted-quad is written to
/// `out_buf` — pass exactly that as the config `ip` to `duocb_start`.
/// Returns 1 = in range (address written), 0 = out of range, 2 = empty entry
/// (resolve via mDNS; pass no `ip`), -1 = malformed / NULL input / buffer too
/// small.
/// # Safety
/// `entry` must be NULL or a valid NUL-terminated C string; `out_buf` must be
/// NULL or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_resolve_join_ip(
    entry: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    let Some(entry) = (unsafe { cstr_arg(entry) }) else {
        return -1;
    };
    use duocb_core::subnet::JoinIpOutcome;
    match duocb_core::subnet::JoinIpConstraint::detect().resolve(entry) {
        JoinIpOutcome::InRange(ip) => {
            if write_cstr(out_buf, out_len, &ip.to_string()) {
                1
            } else {
                -1
            }
        }
        JoinIpOutcome::OutOfRange => 0,
        JoinIpOutcome::Empty => 2,
        JoinIpOutcome::Malformed => -1,
    }
}

/// Start a session (configure or quick mode, per the config's `role`).
/// Returns a non-NULL handle, or NULL with the error message written to
/// `err_buf`.
/// # Safety
/// `config_json` must be NULL or a valid NUL-terminated C string; `err_buf`
/// must be NULL or point to at least `err_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_start(
    config_json: *const c_char,
    err_buf: *mut c_char,
    err_len: usize,
) -> *mut DuocbHandle {
    let Some(json) = (unsafe { cstr_arg(config_json) }) else {
        write_cstr(err_buf, err_len, "config_json is NULL or not UTF-8");
        return ptr::null_mut();
    };
    if RUNNING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        write_cstr(err_buf, err_len, "a duocb session is already running");
        return ptr::null_mut();
    }
    match start_inner(json) {
        Ok(handle) => Box::into_raw(Box::new(handle)),
        Err(msg) => {
            RUNNING.store(false, Ordering::Release);
            write_cstr(err_buf, err_len, &msg);
            ptr::null_mut()
        }
    }
}

fn start_inner(json: &str) -> Result<DuocbHandle, String> {
    let cfg: FfiConfig =
        serde_json::from_str(json).map_err(|e| format!("invalid config JSON: {e}"))?;
    let plan = build_start_plan(cfg)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to build tokio runtime: {e}"))?;
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, event_rx) = std::sync::mpsc::channel();
    // No waker: Swift polls duocb_next_event on a timer.
    let events = EventSender::new(event_tx, None);
    let task = runtime.spawn(duocb_core::net::runtime::net_main(cmd_rx, events));

    if let Some(cmd) = plan.initial.clone() {
        cmd_tx.send(cmd).map_err(|_| "runtime unavailable".to_string())?;
    }

    Ok(DuocbHandle {
        runtime,
        cmd_tx,
        events: Mutex::new(event_rx),
        pending: Mutex::new(None),
        task,
        session_cmd: plan.session_cmd,
        directory_cmd: plan.directory_cmd,
        backup_check_cmd: plan.backup_check_cmd,
        backup_publish_cmd: plan.backup_publish_cmd,
    })
}

struct StartPlan {
    initial: Option<UiCommand>,
    session_cmd: Option<UiCommand>,
    directory_cmd: Option<UiCommand>,
    backup_check_cmd: Option<UiCommand>,
    backup_publish_cmd: Option<UiCommand>,
}

impl StartPlan {
    fn session(cmd: UiCommand) -> Self {
        Self {
            initial: Some(cmd.clone()),
            session_cmd: Some(cmd),
            directory_cmd: None,
            backup_check_cmd: None,
            backup_publish_cmd: None,
        }
    }
}

/// Validate the strict key-identity config and resolve the role's commands.
fn build_start_plan(cfg: FfiConfig) -> Result<StartPlan, String> {
    let relays = if cfg.relays.is_empty() {
        duocb_core::nostr::DEFAULT_NOSTR_RELAYS
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        cfg.relays
    };

    // Quick roles first: identity-less, so none of the application identity
    // validation below applies.
    match cfg.role {
        Role::QuickHost => {
            if cfg.identity_secret.is_some()
                || cfg.self_card.is_some()
                || !cfg.peers.is_empty()
                || cfg.peer_public_key.is_some()
                || cfg.directory_channel.is_some()
                || cfg.backup_generation != 0
                || cfg.pin.is_some()
                || cfg.ip.is_some()
            {
                return Err(
                    "quick_host accepts only role, channel, and optional relays".into(),
                );
            }
            // The host picks the channel (the `channel` config key).
            let channel = cfg.channel.unwrap_or(QuickChannel::NostrLan).to_core();
            return Ok(StartPlan::session(UiCommand::StartServer {
                    mode: ServerMode::Pin { relays, channel },
                }));
        }
        Role::QuickJoin => {
            if cfg.identity_secret.is_some()
                || cfg.self_card.is_some()
                || !cfg.peers.is_empty()
                || cfg.peer_public_key.is_some()
                || cfg.directory_channel.is_some()
                || cfg.backup_generation != 0
                || cfg.channel.is_some()
            {
                return Err(
                    "quick_join accepts only role, pin, ip, and optional relays".into(),
                );
            }
            let canonical_pin =
                duocb_core::pin::normalize_pin(cfg.pin.as_deref().unwrap_or_default())
                    .ok_or("invalid PIN (enter the 8 characters shown on the other device)")?;
            // The join channel is not configured — it is read from the PIN's
            // first character (a LAN-only PIN uses the DNS-SD path, anything
            // else the nostr+LAN race). The `channel` config key is ignored here.
            let lan_only = duocb_core::pin::pin_is_lan_only(&canonical_pin);
            let channel = if lan_only {
                PinChannel::LanOnly
            } else {
                PinChannel::NostrAndLan
            };
            // An optional host IP selects the unicast side channel — only for a
            // LAN-only PIN, and only when a well-formed IPv4 is supplied.
            let target_ip = match cfg.ip.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                Some(ip) if lan_only => Some(std::net::IpAddr::V4(
                    ip.parse::<std::net::Ipv4Addr>()
                        .map_err(|_| "invalid host IP (enter the IPv4 address shown on the other device)")?,
                )),
                _ => None,
            };
            return Ok(StartPlan::session(UiCommand::Connect {
                    spec: DialSpec::Pin {
                        canonical_pin,
                        relays,
                        channel,
                        target_ip,
                    },
                }));
        }
        Role::Hub | Role::Start | Role::Join => {}
    }
    if cfg.pin.is_some() || cfg.ip.is_some() || cfg.channel.is_some() {
        return Err(
            "configure roles do not accept quick-mode pin, ip, or channel fields".into(),
        );
    }
    if !matches!(cfg.role, Role::Join) && cfg.peer_public_key.is_some() {
        return Err("peer_public_key is only valid for the join role".into());
    }

    let identity = duocb_core::auth::Identity::parse_nsec(
        cfg.identity_secret
            .as_deref()
            .ok_or("identity_secret is required")?,
    )
    .map_err(|error| format!("invalid identity_secret: {error:#}"))?;
    let self_card = duocb_core::auth::IdentityCard::parse(
        cfg.self_card.as_deref().ok_or("self_card is required")?,
    )
    .map_err(|error| format!("invalid self_card: {error:#}"))?;
    if self_card.public_key() != identity.public_key() {
        return Err("self_card is not signed by identity_secret".into());
    }
    if cfg.peers.len() > duocb_core::auth::MAX_TRUSTED_PEERS {
        return Err(format!(
            "peers exceeds the limit of {}",
            duocb_core::auth::MAX_TRUSTED_PEERS
        ));
    }
    let mut seen = std::collections::HashSet::new();
    let mut peers = Vec::with_capacity(cfg.peers.len());
    for encoded in &cfg.peers {
        let card = duocb_core::auth::IdentityCard::parse(encoded)
            .map_err(|error| format!("invalid peer identity card: {error:#}"))?;
        if card.public_key() == identity.public_key() {
            return Err("peers contains this installation's self_card".into());
        }
        if !seen.insert(card.public_key()) {
            return Err("peers contains a duplicate public key".into());
        }
        peers.push(card);
    }
    let channel = cfg
        .directory_channel
        .as_deref()
        .map(duocb_core::auth::DirectoryChannel::parse)
        .transpose()
        .map_err(|error| format!("invalid directory_channel: {error:#}"))?;
    let key_identity = KeyIdentity {
        identity: identity.clone(),
        self_card,
        peers,
        channel,
        backup_generation: cfg.backup_generation,
        relays: relays.clone(),
    };

    let initial = match cfg.role {
        Role::Hub => None,
        Role::Start => Some(UiCommand::StartServer {
            mode: ServerMode::NostrKey {
                identity: Box::new(key_identity.clone()),
            },
        }),
        Role::Join => {
            let selected = cfg
                .peer_public_key
                .as_deref()
                .map(str::trim)
                .filter(|key| !key.is_empty())
                .ok_or("peer_public_key is required for join")?;
            let peer_public_key = key_identity
                .peers
                .iter()
                .find(|peer| {
                    peer.public_key().to_hex() == selected || peer.npub() == selected
                })
                .map(duocb_core::auth::IdentityCard::public_key)
                .ok_or("peer_public_key is not in the local trusted peer list")?;
            Some(UiCommand::Connect {
                spec: DialSpec::NostrKey {
                    identity: Box::new(key_identity.clone()),
                    peer_public_key,
                },
            })
        }
        Role::QuickHost | Role::QuickJoin => unreachable!("handled above"),
    };
    let session_cmd = initial.clone();
    let directory_cmd = channel.map(|channel| UiCommand::RefreshDirectory {
        channel,
        relays: relays.clone(),
    });
    let backup_check_cmd = channel.map(|channel| UiCommand::CheckBackup {
        identity,
        channel,
        relays,
    });
    let backup_publish_cmd =
        channel.map(|_| UiCommand::PublishBackup {
            identity: Box::new(key_identity),
        });
    Ok(StartPlan {
        initial,
        session_cmd,
        directory_cmd,
        backup_check_cmd,
        backup_publish_cmd,
    })
}

/// Drain one pending event as a NUL-terminated JSON string.
/// Returns 1 = event written; 0 = none pending; -1 = NULL handle;
/// -2 = `out_buf` too small (the event is retained — retry with a larger buffer).
/// # Safety
/// `handle` must be NULL or a handle returned by [`duocb_start`] that has not
/// been passed to [`duocb_stop`]; `out_buf` must be NULL or point to at least
/// `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_next_event(
    handle: *const DuocbHandle,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &*handle };
    let mut pending = handle.pending.lock().unwrap();
    let json = match pending.take() {
        Some(json) => json,
        None => {
            let events = handle.events.lock().unwrap();
            match events.try_recv() {
                Ok(event) => event_json(&event),
                Err(_) => return 0,
            }
        }
    };
    if write_cstr(out_buf, out_len, &json) {
        1
    } else {
        *pending = Some(json);
        -2
    }
}

/// Queue a clipboard text for the peer. Returns 0 = queued (the outcome
/// arrives as an `item_sent` or `error` event), -1 = NULL/non-UTF-8 argument.
/// # Safety
/// `handle` must be NULL or a live handle from [`duocb_start`]; `text` must be
/// NULL or a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_send_clipboard(
    handle: *const DuocbHandle,
    text: *const c_char,
) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let Some(text) = (unsafe { cstr_arg(text) }) else {
        return -1;
    };
    let handle = unsafe { &*handle };
    let _ = handle.cmd_tx.send(UiCommand::SendClipboard {
        text: text.to_string(),
    });
    0
}

/// Fetch signed-card candidates from the configured directory channel.
/// Returns 0 = requested, -1 = NULL handle, -2 = no channel configured.
/// # Safety
/// `handle` must be NULL or a live handle from [`duocb_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_refresh_directory(handle: *const DuocbHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &*handle };
    let Some(cmd) = &handle.directory_cmd else {
        return -2;
    };
    let _ = handle.cmd_tx.send(cmd.clone());
    0
}

/// Check for this identity's encrypted peer-list backup. A `backup_found`
/// event contains a preview; the FFI never applies it.
/// Returns 0 = requested, -1 = NULL handle, -2 = no channel configured.
/// # Safety
/// `handle` must be NULL or a live handle from [`duocb_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_check_backup(handle: *const DuocbHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &*handle };
    let Some(cmd) = &handle.backup_check_cmd else {
        return -2;
    };
    let _ = handle.cmd_tx.send(cmd.clone());
    0
}

/// Publish the configured local peer list as an encrypted bounded backup.
/// Returns 0 = requested, -1 = NULL handle, -2 = no channel configured.
/// # Safety
/// `handle` must be NULL or a live handle from [`duocb_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_publish_backup(handle: *const DuocbHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &*handle };
    let Some(cmd) = &handle.backup_publish_cmd else {
        return -2;
    };
    let _ = handle.cmd_tx.send(cmd.clone());
    0
}

/// Quick-host only: mint and publish a fresh PIN immediately, invalidating
/// every previously shown PIN. The new code arrives as the next `pin_rotated`
/// event; an `error` event if no PIN is being published (wrong role, or a
/// peer already paired). Returns 0 = requested, -1 = NULL handle.
/// # Safety
/// `handle` must be NULL or a live handle from [`duocb_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_refresh_pin(handle: *const DuocbHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &*handle };
    let _ = handle.cmd_tx.send(UiCommand::RefreshPin);
    0
}

/// Request a point-in-time connection-path snapshot; the answer arrives as a
/// `conn_path` event. Returns 0 = requested, -1 = NULL handle.
/// # Safety
/// `handle` must be NULL or a live handle from [`duocb_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_query_conn_path(handle: *const DuocbHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &*handle };
    let _ = handle.cmd_tx.send(UiCommand::QueryConnPath);
    0
}

/// Liveness probe: 1 = runtime alive, 0 = runtime ended (fatal — restart via
/// a fresh [`duocb_start`] after [`duocb_stop`]), -1 = NULL handle.
/// # Safety
/// `handle` must be NULL or a live handle from [`duocb_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_is_running(handle: *const DuocbHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &*handle };
    if handle.task.is_finished() { 0 } else { 1 }
}

/// Re-issue the session command this handle was started with, on the handle's
/// still-running runtime. The runtime keeps the session identity and pairing
/// state (node id, the host's pair claim, the joiner's pinned dial target)
/// until the handle is stopped, so after the session ends on its own — e.g.
/// the joiner gave up reconnecting ("could not reach the peer…" + `status:
/// idle`) — this resumes the same pairing: the same node id dials the same
/// target and the peer recognizes it, no re-pairing and no fresh PIN needed.
/// A fresh [`duocb_start`] would instead mint a new identity, which an
/// already-paired peer refuses. Progress arrives as the usual status events.
/// Returns 0 = requested, -1 = NULL handle, -2 = the handle runs the hub role
/// (nothing to reconnect), -3 = runtime unavailable (it died — fall back to
/// [`duocb_stop`] + a fresh [`duocb_start`]).
/// # Safety
/// `handle` must be NULL or a live handle from [`duocb_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_reconnect(handle: *const DuocbHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &*handle };
    let Some(cmd) = &handle.session_cmd else {
        return -2;
    };
    if handle.task.is_finished() || handle.cmd_tx.send(cmd.clone()).is_err() {
        return -3;
    }
    0
}

/// Stop the session (graceful shutdown, bounded wait) and free the handle.
/// NULL is a safe no-op. The handle must not be used afterwards.
/// # Safety
/// `handle` must be NULL or a handle returned by [`duocb_start`]; it is freed
/// here and must not be used again afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_stop(handle: *mut DuocbHandle) {
    if handle.is_null() {
        return;
    }
    let DuocbHandle {
        runtime,
        cmd_tx,
        task,
        ..
    } = *unsafe { Box::from_raw(handle) };
    let _ = cmd_tx.send(UiCommand::Shutdown);
    let _ = runtime.block_on(async { tokio::time::timeout(Duration::from_secs(5), task).await });
    runtime.shutdown_background();
    RUNNING.store(false, Ordering::Release);
}

/// Serialize a [`NetEvent`] for the Swift side.
fn event_json(event: &NetEvent) -> String {
    use serde_json::json;
    let value = match event {
        NetEvent::ServerReady {
            node_id,
            identity_public_key,
        } => json!({
            "type": "server_ready",
            "node_id": node_id,
            "identity_public_key": identity_public_key,
        }),
        NetEvent::ClientReady {
            node_id,
            identity_public_key,
        } => json!({
            "type": "client_ready",
            "node_id": node_id,
            "identity_public_key": identity_public_key,
        }),
        NetEvent::PinRotated {
            pin_display,
            seconds_left,
            host_lan_ip,
        } => json!({
            "type": "pin_rotated",
            "pin_display": pin_display,
            "seconds_left": seconds_left,
            // The host's LAN IPv4 on the LAN-only channel (for the joiner's
            // manual-IP side channel); null on other channels.
            "host_lan_ip": host_lan_ip,
        }),
        // A peer paired (or the host stopped publishing) — hide the PIN.
        NetEvent::PinCleared => json!({ "type": "pin_cleared" }),
        NetEvent::Status(status) => {
            let state = match status {
                ConnStatus::Idle => "idle",
                ConnStatus::Starting => "starting",
                ConnStatus::Listening => "listening",
                ConnStatus::Resolving => "resolving",
                ConnStatus::Connecting => "connecting",
                ConnStatus::Authenticating => "authenticating",
                ConnStatus::Connected => "connected",
                ConnStatus::Reconnecting { .. } => "reconnecting",
            };
            let mut value = json!({ "type": "status", "state": state });
            if let ConnStatus::Reconnecting { attempt, max } = status {
                value["attempt"] = json!(attempt);
                value["max"] = json!(max);
            }
            value
        }
        NetEvent::PeerPaired {
            peer_node_id,
            peer_public_key,
        } => json!({
            "type": "peer_paired",
            "peer_node_id": peer_node_id,
            "peer_public_key": peer_public_key,
        }),
        NetEvent::PeerDisconnected => json!({ "type": "peer_disconnected" }),
        NetEvent::ConnPath(paths) => json!({
            "type": "conn_path",
            "paths": paths
                .iter()
                .map(|p| {
                    json!({
                        "kind": match p.kind {
                            ConnPathKind::Direct => "direct",
                            ConnPathKind::Relay => "relay",
                            ConnPathKind::Other => "other",
                        },
                        "display": p.display,
                        "selected": p.selected,
                    })
                })
                .collect::<Vec<_>>(),
        }),
        NetEvent::ItemReceived { text, pulled } => {
            json!({ "type": "item_received", "text": text, "pulled": pulled })
        }
        NetEvent::ItemSent => json!({ "type": "item_sent" }),
        NetEvent::DirectoryCards { cards } => json!({
            "type": "directory_cards",
            "cards": cards.iter().map(identity_card_json).collect::<Vec<_>>(),
        }),
        NetEvent::BackupFound { snapshot } => json!({
            "type": "backup_found",
            "backup": snapshot.as_ref().map(|snapshot| json!({
                "generation": snapshot.generation,
                "self_card": identity_card_json(&snapshot.self_card),
                "peers": snapshot.peers.iter().map(identity_card_json).collect::<Vec<_>>(),
            })),
        }),
        NetEvent::BackupPublished { generation } => json!({
            "type": "backup_published",
            "generation": generation,
        }),
        NetEvent::BackupCheckFailed { message } => json!({
            "type": "backup_check_failed",
            "message": message,
        }),
        NetEvent::BackupPublishFailed { message } => json!({
            "type": "backup_publish_failed",
            "message": message,
        }),
        NetEvent::Error(message) => json!({ "type": "error", "message": message }),
    };
    value.to_string()
}

fn identity_card_json(card: &duocb_core::auth::IdentityCard) -> serde_json::Value {
    serde_json::json!({
        "name": card.name(),
        "short_name": card.short_name(),
        "suffix": card.suffix(),
        "public_key": card.public_key().to_hex(),
        "npub": card.npub(),
        "card": card.encode(),
    })
}

/// Borrow a C string argument as `&str`; `None` for NULL or non-UTF-8.
unsafe fn cstr_arg<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

/// Copy `s` into `buf` as a NUL-terminated C string, truncating if needed.
/// Truncation lands on a UTF-8 character boundary so the written content is
/// always valid UTF-8. Returns true if the whole string (plus NUL) fit.
fn write_cstr(buf: *mut c_char, len: usize, s: &str) -> bool {
    if buf.is_null() || len == 0 {
        return false;
    }
    let bytes = s.as_bytes();
    // Reserve one byte for the trailing NUL, then back off to the nearest
    // char boundary so a multibyte character is never sliced in half.
    let mut copy = bytes.len().min(len - 1);
    while copy > 0 && !s.is_char_boundary(copy) {
        copy -= 1;
    }
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, copy);
        *buf.add(copy) = 0;
    }
    copy == bytes.len()
}

#[cfg(all(test, any()))]
mod tests {
    use super::*;

    #[test]
    fn config_parses_roles_and_defaults_relays() {
        let cfg: FfiConfig = serde_json::from_str(
            r#"{"role":"start","secret":"s","name":"mac","suffix":"a7B2c3D4"}"#,
        )
        .unwrap();
        assert!(matches!(cfg.role, Role::Start));
        assert!(cfg.relays.is_empty());
        assert!(cfg.peer.is_none());

        let cfg: FfiConfig = serde_json::from_str(
            r#"{"role":"join","secret":"s","name":"phone","suffix":"x9Y8z7W6","peer":"mac_a7B2c3D4","relays":["wss://r.example"]}"#,
        )
        .unwrap();
        assert!(matches!(cfg.role, Role::Join));
        assert_eq!(cfg.peer.as_deref(), Some("mac_a7B2c3D4"));
        assert_eq!(cfg.relays, ["wss://r.example"]);

        // The hub role browses the peer list before a role is chosen — no peer.
        let cfg: FfiConfig = serde_json::from_str(
            r#"{"role":"hub","secret":"s","name":"phone","suffix":"x9Y8z7W6"}"#,
        )
        .unwrap();
        assert!(matches!(cfg.role, Role::Hub));
        assert!(cfg.peer.is_none());
    }

    #[test]
    fn config_rejects_unknown_role() {
        assert!(
            serde_json::from_str::<FfiConfig>(
                r#"{"role":"quick","secret":"s","name":"x","suffix":"a7B2c3D4"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn config_parses_quick_roles_without_identity_fields() {
        let cfg: FfiConfig = serde_json::from_str(r#"{"role":"quick_host"}"#).unwrap();
        assert!(matches!(cfg.role, Role::QuickHost));
        assert!(cfg.secret.is_none());

        let cfg: FfiConfig =
            serde_json::from_str(r#"{"role":"quick_join","pin":"abcd-2345"}"#).unwrap();
        assert!(matches!(cfg.role, Role::QuickJoin));
        assert_eq!(cfg.pin.as_deref(), Some("abcd-2345"));
    }

    #[test]
    fn join_requires_a_peer_identity() {
        let secret = duocb_core::auth::Secret::generate().encode();
        let json = format!(
            r#"{{"role":"join","secret":"{secret}","name":"phone","suffix":"x9Y8z7W6"}}"#
        );
        let cfg: FfiConfig = serde_json::from_str(&json).unwrap();
        let err = build_initial_commands(cfg)
            .expect_err("join without peer fails");
        assert!(err.contains("peer"), "unexpected error: {err}");
    }

    #[test]
    fn identity_roles_require_a_valid_secret() {
        let cfg: FfiConfig =
            serde_json::from_str(r#"{"role":"hub","name":"phone","suffix":"x9Y8z7W6"}"#).unwrap();
        let err = build_initial_commands(cfg).expect_err("hub needs a secret");
        assert!(err.contains("secret is required"), "unexpected error: {err}");

        // A malformed secret is rejected with the parse reason, not silently
        // dropped: the old 47-char token format lands here.
        let cfg: FfiConfig = serde_json::from_str(
            r#"{"role":"hub","secret":"dAAAA","name":"phone","suffix":"x9Y8z7W6"}"#,
        )
        .unwrap();
        let err = build_initial_commands(cfg).expect_err("hub needs a valid secret");
        assert!(err.contains("invalid secret"), "unexpected error: {err}");
    }

    #[test]
    fn quick_host_builds_a_pin_server_without_presence() {
        let cfg: FfiConfig = serde_json::from_str(r#"{"role":"quick_host"}"#).unwrap();
        let (identity, cmd) = build_initial_commands(cfg).unwrap();
        assert!(identity.is_none());
        match cmd {
            UiCommand::StartServer {
                mode: ServerMode::Pin { relays, channel },
            } => {
                assert!(!relays.is_empty(), "default relays expected");
                assert_eq!(channel, PinChannel::NostrAndLan);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn quick_join_normalizes_the_pin_and_rejects_bad_ones() {
        let pin = duocb_core::pin::generate_pin(false);
        let typed = format!(
            "{}-{}",
            pin[..4].to_lowercase(),
            pin[4..].to_lowercase()
        );
        let json = format!(r#"{{"role":"quick_join","pin":"{typed}"}}"#);
        let cfg: FfiConfig = serde_json::from_str(&json).unwrap();
        let (identity, cmd) = build_initial_commands(cfg).unwrap();
        assert!(identity.is_none());
        match cmd {
            UiCommand::Connect {
                spec:
                    DialSpec::Pin {
                        canonical_pin,
                        channel,
                        ..
                    },
            } => {
                assert_eq!(canonical_pin, pin);
                // A lower-half PIN infers the nostr+LAN channel.
                assert_eq!(channel, PinChannel::NostrAndLan);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        // A wrong check digit (any other Crockford char in the last slot) and
        // a missing pin both fail.
        let check = pin.chars().last().unwrap();
        let corrupted = format!("{}{}", &pin[..7], if check == 'A' { 'B' } else { 'A' });
        for bad in [
            format!(r#"{{"role":"quick_join","pin":"{corrupted}"}}"#),
            r#"{"role":"quick_join"}"#.to_string(),
        ] {
            let cfg: FfiConfig = serde_json::from_str(&bad).unwrap();
            let err = build_initial_commands(cfg).expect_err("bad pin fails");
            assert!(err.contains("PIN"), "unexpected error: {err}");
        }
    }

    #[test]
    fn quick_join_infers_lan_only_from_the_pin_ignoring_config_channel() {
        // A LAN-only PIN (upper-half first char) resolves to the LAN-only
        // channel even when the config asks for the nostr+LAN channel — the
        // `channel` key is ignored on join.
        let pin = duocb_core::pin::generate_pin(true);
        let json = format!(r#"{{"role":"quick_join","pin":"{pin}","channel":"nostr_lan"}}"#);
        let cfg: FfiConfig = serde_json::from_str(&json).unwrap();
        let (_, cmd) = build_initial_commands(cfg).unwrap();
        match cmd {
            UiCommand::Connect {
                spec: DialSpec::Pin { channel, target_ip, .. },
            } => {
                assert_eq!(channel, PinChannel::LanOnly);
                // No `ip` key: resolve via mDNS.
                assert!(target_ip.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn quick_join_ip_selects_the_side_channel_only_for_a_lan_only_pin() {
        let lan_pin = duocb_core::pin::generate_pin(true);

        // A valid IPv4 with a LAN-only PIN selects the unicast side channel.
        let json = format!(r#"{{"role":"quick_join","pin":"{lan_pin}","ip":"192.168.1.42"}}"#);
        let cfg: FfiConfig = serde_json::from_str(&json).unwrap();
        match build_initial_commands(cfg).unwrap().1 {
            UiCommand::Connect {
                spec: DialSpec::Pin { target_ip: Some(ip), .. },
            } => assert_eq!(ip, "192.168.1.42".parse::<std::net::IpAddr>().unwrap()),
            other => panic!("unexpected command: {other:?}"),
        }

        // A malformed IP is rejected.
        let json = format!(r#"{{"role":"quick_join","pin":"{lan_pin}","ip":"not-an-ip"}}"#);
        let cfg: FfiConfig = serde_json::from_str(&json).unwrap();
        let err = build_initial_commands(cfg).expect_err("bad ip fails");
        assert!(err.contains("host IP"), "unexpected error: {err}");

        // The IP is ignored for a non-LAN-only PIN (the field is hidden there).
        let net_pin = duocb_core::pin::generate_pin(false);
        let json = format!(r#"{{"role":"quick_join","pin":"{net_pin}","ip":"192.168.1.42"}}"#);
        let cfg: FfiConfig = serde_json::from_str(&json).unwrap();
        match build_initial_commands(cfg).unwrap().1 {
            UiCommand::Connect {
                spec: DialSpec::Pin { channel, target_ip, .. },
            } => {
                assert_eq!(channel, PinChannel::NostrAndLan);
                assert!(target_ip.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn event_json_maps_peer_list_and_presence_conflict() {
        let json = event_json(&NetEvent::PeerList {
            peers: vec![duocb_core::nostr::PeerInfo {
                name: "mac".into(),
                suffix: "a7B2c3D4".into(),
                last_seen_unix: 42,
            }],
        });
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "peer_list");
        assert_eq!(v["peers"][0]["display"], "mac_a7B2c3D4");
        assert_eq!(v["peers"][0]["last_seen_unix"], 42);

        let json = event_json(&NetEvent::PresenceConflict {
            message: "another process".into(),
        });
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "presence_conflict");
        assert_eq!(v["message"], "another process");
    }

    #[test]
    fn event_json_maps_configure_mode_and_pin_events() {
        let json = event_json(&NetEvent::ServerReady {
            node_id: "abc".into(),
            secret_fingerprint: Some("aaaa-bbbb-cccc-dddd".into()),
        });
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "server_ready");
        assert_eq!(v["node_id"], "abc");
        assert_eq!(v["secret_fingerprint"], "aaaa-bbbb-cccc-dddd");

        let json = event_json(&NetEvent::Status(ConnStatus::Reconnecting {
            attempt: 4,
            max: 10,
        }));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["state"], "reconnecting");
        assert_eq!(v["attempt"], 4);
        assert_eq!(v["max"], 10);

        let json = event_json(&NetEvent::Status(ConnStatus::Connected));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["state"], "connected");
        assert!(v.get("attempt").is_none());

        let json = event_json(&NetEvent::ItemReceived {
            text: "resumed".into(),
            pulled: true,
        });
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "item_received");
        assert_eq!(v["pulled"], true);

        let json = event_json(&NetEvent::PinRotated {
            pin_display: "AAAA-BBBB".into(),
            seconds_left: 10,
            host_lan_ip: Some("192.168.1.42".into()),
        });
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "pin_rotated");
        assert_eq!(v["pin_display"], "AAAA-BBBB");
        assert_eq!(v["seconds_left"], 10);
        assert_eq!(v["host_lan_ip"], "192.168.1.42");

        let json = event_json(&NetEvent::PinCleared);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "pin_cleared");
    }

    #[test]
    fn normalize_pin_ffi_roundtrips_and_reports_errors() {
        let pin = duocb_core::pin::generate_pin(false);
        let typed = format!("{}-{}\0", pin[..4].to_lowercase(), pin[4..].to_lowercase());
        let mut out = [0 as c_char; 16];
        let rc = unsafe {
            duocb_normalize_pin(typed.as_ptr() as *const c_char, out.as_mut_ptr(), out.len())
        };
        assert_eq!(rc, 1);
        let written = unsafe { CStr::from_ptr(out.as_ptr()) };
        assert_eq!(written.to_str().unwrap(), pin);

        // Garbage input → 0.
        let rc = unsafe {
            duocb_normalize_pin(c"nope".as_ptr(), out.as_mut_ptr(), out.len())
        };
        assert_eq!(rc, 0);

        // NULL input and a too-small buffer → -1.
        assert_eq!(
            unsafe { duocb_normalize_pin(ptr::null(), out.as_mut_ptr(), out.len()) },
            -1
        );
        let rc = unsafe {
            duocb_normalize_pin(typed.as_ptr() as *const c_char, out.as_mut_ptr(), 8)
        };
        assert_eq!(rc, -1);
    }

    #[test]
    fn join_ip_context_returns_parseable_json() {
        // The concrete subnet depends on the host's interfaces, so assert only
        // the shape: a JSON object with the four string keys.
        let mut out = [0 as c_char; 256];
        let rc = unsafe { duocb_join_ip_context(out.as_mut_ptr(), out.len()) };
        assert_eq!(rc, 1);
        let json: serde_json::Value =
            serde_json::from_str(unsafe { CStr::from_ptr(out.as_ptr()) }.to_str().unwrap())
                .unwrap();
        assert!(json["prefix"].is_string());
        assert!(json["placeholder"].is_string());
        assert!(json["hint"].is_string());
        assert!(json["label"].is_string());
        // NULL buffer → -1.
        assert_eq!(unsafe { duocb_join_ip_context(ptr::null_mut(), 0) }, -1);
    }

    #[test]
    fn resolve_join_ip_reports_empty_loopback_and_malformed() {
        let mut out = [0 as c_char; 32];
        // Empty entry → 2 (resolve via mDNS).
        assert_eq!(
            unsafe { duocb_resolve_join_ip(c"".as_ptr(), out.as_mut_ptr(), out.len()) },
            2
        );
        // Loopback is always local, whatever the LAN subnet is → 1, address echoed.
        let rc =
            unsafe { duocb_resolve_join_ip(c"127.0.0.1".as_ptr(), out.as_mut_ptr(), out.len()) };
        assert_eq!(rc, 1);
        assert_eq!(
            unsafe { CStr::from_ptr(out.as_ptr()) }.to_str().unwrap(),
            "127.0.0.1"
        );
        // Malformed / NULL → -1.
        assert_eq!(
            unsafe { duocb_resolve_join_ip(c"nope".as_ptr(), out.as_mut_ptr(), out.len()) },
            -1
        );
        assert_eq!(
            unsafe { duocb_resolve_join_ip(ptr::null(), out.as_mut_ptr(), out.len()) },
            -1
        );
    }

    #[test]
    fn write_cstr_truncates_and_reports() {
        let mut buf = [0 as c_char; 4];
        assert!(write_cstr(buf.as_mut_ptr(), buf.len(), "abc"));
        assert!(!write_cstr(buf.as_mut_ptr(), buf.len(), "abcd"));
        // Truncated output is still NUL-terminated.
        assert_eq!(buf[3], 0);
    }

    #[test]
    fn write_cstr_truncates_on_utf8_boundaries() {
        // "é" is 2 bytes; a 4-byte buffer (3 usable) must not slice it in half.
        let mut buf = [0 as c_char; 4];
        assert!(!write_cstr(buf.as_mut_ptr(), buf.len(), "aéb"));
        let written = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(written.to_str().expect("valid UTF-8"), "aé");

        // Boundary right at the cut: only "a" fits (the é would straddle it).
        let mut buf = [0 as c_char; 3];
        assert!(!write_cstr(buf.as_mut_ptr(), buf.len(), "aé"));
        let written = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(written.to_str().expect("valid UTF-8"), "a");
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    #[test]
    fn ffi_generates_suffix_and_appends_it_to_card_name() {
        let mut suffix_buf = [0 as c_char; 16];
        assert_eq!(
            unsafe { duocb_generate_suffix(suffix_buf.as_mut_ptr(), suffix_buf.len()) },
            1
        );
        let suffix = unsafe { CStr::from_ptr(suffix_buf.as_ptr()) }
            .to_str()
            .unwrap();
        assert!(duocb_core::identity::is_valid_suffix(suffix));

        let identity = duocb_core::auth::Identity::generate();
        let private_key = std::ffi::CString::new(identity.to_nsec()).unwrap();
        let name = std::ffi::CString::new("phone").unwrap();
        let suffix = std::ffi::CString::new(suffix).unwrap();
        let mut card_buf = [0 as c_char; 4096];
        assert_eq!(
            unsafe {
                duocb_create_identity_card(
                    private_key.as_ptr(),
                    name.as_ptr(),
                    suffix.as_ptr(),
                    card_buf.as_mut_ptr(),
                    card_buf.len(),
                )
            },
            1
        );
        let encoded = unsafe { CStr::from_ptr(card_buf.as_ptr()) }
            .to_str()
            .unwrap();
        let card = duocb_core::auth::IdentityCard::parse(encoded).unwrap();
        assert_eq!(card.short_name(), "phone");
        assert_eq!(card.suffix(), suffix.to_str().unwrap());
    }

    fn configured_value(role: &str) -> serde_json::Value {
        let identity = duocb_core::auth::Identity::generate();
        let peer = duocb_core::auth::Identity::generate()
            .card("phone", "x9Y8z7W6")
            .unwrap();
        let peer_public_key = peer.public_key().to_hex();
        let mut value = serde_json::json!({
            "role": role,
            "identity_secret": identity.to_nsec(),
            "self_card": identity.card("desktop", "a7B2c3D4").unwrap().encode(),
            "peers": [peer.encode()],
            "directory_channel": duocb_core::auth::DirectoryChannel::generate().encode(),
            "backup_generation": 9,
        });
        if role == "join" {
            value["peer_public_key"] = serde_json::Value::String(peer_public_key);
        }
        value
    }

    #[test]
    fn legacy_shared_secret_config_is_rejected() {
        let error = serde_json::from_str::<FfiConfig>(
            r#"{"role":"hub","secret":"old","name":"mac","suffix":"a7B2c3D4"}"#,
        )
        .err()
        .expect("legacy fields must not be accepted");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn configure_plan_uses_application_keys_and_explicit_backup_commands() {
        let cfg: FfiConfig = serde_json::from_value(configured_value("hub")).unwrap();
        let plan = build_start_plan(cfg).unwrap();
        assert!(plan.initial.is_none());
        assert!(plan.directory_cmd.is_some());
        assert!(plan.backup_check_cmd.is_some());
        assert!(plan.backup_publish_cmd.is_some());

        let cfg: FfiConfig = serde_json::from_value(configured_value("start")).unwrap();
        let plan = build_start_plan(cfg).unwrap();
        assert!(matches!(
            plan.initial,
            Some(UiCommand::StartServer {
                mode: ServerMode::NostrKey { .. }
            })
        ));

        let cfg: FfiConfig = serde_json::from_value(configured_value("join")).unwrap();
        let plan = build_start_plan(cfg).unwrap();
        assert!(matches!(
            plan.initial,
            Some(UiCommand::Connect {
                spec: DialSpec::NostrKey { .. }
            })
        ));
    }

    #[test]
    fn self_card_must_match_the_private_key() {
        let mut value = configured_value("hub");
        value["self_card"] = serde_json::Value::String(
            duocb_core::auth::Identity::generate()
                .card("intruder", "p3Q4r5S6")
                .unwrap()
                .encode(),
        );
        let cfg: FfiConfig = serde_json::from_value(value).unwrap();
        let error = build_start_plan(cfg)
            .err()
            .expect("mismatched card must fail");
        assert!(error.contains("not signed"));
    }

    #[test]
    fn backup_event_is_a_preview_with_portable_cards() {
        let owner = duocb_core::auth::Identity::generate();
        let peer = duocb_core::auth::Identity::generate()
            .card("phone", "x9Y8z7W6")
            .unwrap();
        let snapshot = duocb_core::nostr::BackupSnapshot::new(
            3,
            owner.card("desktop", "a7B2c3D4").unwrap(),
            vec![peer.clone()],
        )
        .unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&event_json(&NetEvent::BackupFound {
                snapshot: Some(Box::new(snapshot)),
            }))
            .unwrap();
        assert_eq!(value["type"], "backup_found");
        assert_eq!(value["backup"]["generation"], 3);
        assert_eq!(
            value["backup"]["peers"][0]["name"],
            "phone_x9Y8z7W6"
        );
        assert_eq!(value["backup"]["peers"][0]["short_name"], "phone");
        assert_eq!(value["backup"]["peers"][0]["suffix"], "x9Y8z7W6");
        assert_eq!(
            value["backup"]["peers"][0]["public_key"],
            peer.public_key().to_hex()
        );
    }

    #[test]
    fn quick_mode_remains_identity_free() {
        let cfg: FfiConfig = serde_json::from_str(r#"{"role":"quick_host"}"#).unwrap();
        let plan = build_start_plan(cfg).unwrap();
        assert!(matches!(
            plan.initial,
            Some(UiCommand::StartServer {
                mode: ServerMode::Pin { .. }
            })
        ));
        assert!(plan.backup_check_cmd.is_none());
    }
}
