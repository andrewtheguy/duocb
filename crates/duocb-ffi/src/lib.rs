//! The mobile FFI: a C surface for the iOS app (`aarch64-apple-ios`, this
//! file) and a JNI surface for the Android app (`android.rs`, over the same
//! handle).
//!
//! A thin translation layer over [`duocb_core::net`] and nothing more: it
//! parses a JSON config into a [`UiCommand`], drains [`NetEvent`]s back out as
//! JSON, and wraps the pure helpers the setup screens need. **No policy lives
//! here.** In particular, a card that arrives over a card-setup session is
//! handed up verified-but-untrusted; whether to store it is the app's call, and
//! it must not be made without the user comparing the pairing code from
//! [`duocb_pairing_code`] across both screens (see `duocb_core::card_exchange`).
//!
//! The iOS app links `libduocb.xcframework` (containing `libduocb.a` slices)
//! and drives a session with:
//!
//! 1. [`duocb_start`] — parse the config, spawn the networking runtime, issue
//!    the role's initial command, and return an opaque handle. At most **one**
//!    may run at a time (a process-global guard rejects a second).
//! 2. [`duocb_next_event`] — drain one pending [`NetEvent`] as JSON. The
//!    runtime is event-driven; Swift polls this on a timer until it returns 0.
//! 3. [`duocb_send_clipboard`] / [`duocb_query_conn_path`] / [`duocb_refresh_pin`]
//!    — fire-and-forget commands whose outcomes arrive as events.
//! 4. [`duocb_stop`] — shut the runtime down and free the handle.
//!
//! # The three roles
//!
//! There is deliberately **no "hub" role**. The hub is pure local state — the
//! trusted-device list is read from the app's own storage, nothing is broadcast
//! and nothing is discovered — so no handle runs while it is on screen. A
//! handle exists only for one of:
//!
//! | role | core mapping | what it does |
//! | --- | --- | --- |
//! | `connect` | [`ServerMode::Key`] or [`DialSpec::Key`] | share the clipboard with one trusted peer |
//! | `card_host` | [`ServerMode::CardSetup`] | show a rotating PIN and trade cards |
//! | `card_join` | [`DialSpec::CardSetup`] | dial a typed PIN and trade cards |
//!
//! `connect` names a *device*, never a half of the connection: it takes the
//! chosen peer's public key, and [`duocb_core::net::session_role`] decides from
//! the two application keys whether this device hosts or dials. Both devices
//! send mirror-image configs and reach opposite answers, so nothing in the app
//! has to ask the user who goes first. [`duocb_session_role`] answers the same
//! question without starting anything, for a screen that wants to say which
//! device is setting the link up.
//!
//! The two `card_*` roles never carry clipboard traffic. They exist to bootstrap
//! trust between two devices that have no shared clipboard to paste a card
//! through, and they end as soon as the cards have crossed.
//!
//! # Persistence is the caller's job
//!
//! The application private key (`nsec`, for `connect`), signed self-card and
//! trusted peer cards are passed to [`duocb_start`] and never written anywhere
//! by this library. The permanent name suffix remains caller-owned and is used
//! only when minting a self-card through the pure helper. On iOS the secrets
//! belong in the Keychain and the cards in ordinary app storage. The
//! application key is deliberately unrelated to iroh's transport identity.
//!
//! # The iroh transport key
//!
//! Every [`duocb_start`] also takes `iroh_secret`, the key behind this
//! device's iroh node id. The desktop mints a fresh one per process because a
//! desktop config directory can be copied between machines, and two live
//! endpoints sharing a node id would shadow each other on the relays. An iOS
//! app's storage cannot be cloned by accident — the Keychain item is
//! this-device-only and the app binds it to `identifierForVendor` — so the app
//! mints one with [`duocb_generate_iroh_secret`], persists it, and passes the
//! same value on every start. Whatever the source, the node id is pinned for
//! the process's lifetime: the first `duocb_start` fixes it, and a later start
//! carrying a different `iroh_secret` is refused rather than letting one
//! running app present two node ids.
//!
//! # Local network on iOS
//!
//! The LAN half of both rendezvous records goes through the system
//! mDNSResponder daemon (`duocb_core::lan::dnssd`), so it needs no multicast
//! entitlement — but the app must list **both** service types under
//! `NSBonjourServices` (`_duocb-pin._udp` for card setup, `_duocb-host._udp`
//! for clipboard sessions) and set `NSLocalNetworkUsageDescription`. iroh's own
//! mDNS address lookup is compiled out on iOS; see
//! `duocb_core::net::endpoint::with_mdns_lookup`.
//!
//! # Local network on Android
//!
//! Android has no multicast entitlement, so it keeps the desktop core intact:
//! both the DNS-SD responder (mdns-sd) and iroh's own mDNS address lookup run
//! in-process. What Android does gate is *receiving* multicast on Wi-Fi — the
//! driver filters it unless the app holds a `WifiManager.MulticastLock` — so
//! the app acquires one for the life of every session. Everything about
//! persistence is the same as on iOS, with the Android Keystore in the
//! Keychain's place.
//!
//! The workspace builds with `panic = "abort"` in release, so a Rust panic
//! terminates the process rather than unwinding across the C boundary.

#[cfg(target_os = "android")]
mod android;

use std::ffi::{CStr, c_char, c_int};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde::Deserialize;

use duocb_core::auth::{CARD_RENEW_BEFORE_SECS, Identity, IdentityCard, MAX_TRUSTED_PEERS};
use duocb_core::iroh;
use duocb_core::net::endpoint::ConnPathKind;
use duocb_core::net::{
    ConnStatus, DialSpec, EventSender, KeyIdentity, NetEvent, ServerMode, SessionRole,
    SignalChannel, UiCommand, session_role,
};

/// Process-global guard: at most one running session per process.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// The iroh key this process presents, fixed by the first [`duocb_start`].
static IROH_SECRET: OnceLock<iroh::SecretKey> = OnceLock::new();

/// Opaque handle owned by the app side (a pointer in Swift, a `jlong` in
/// Kotlin). Freed by [`duocb_stop`] / `DuocbNative.stop`.
pub struct DuocbHandle {
    runtime: tokio::runtime::Runtime,
    cmd_tx: tokio::sync::mpsc::UnboundedSender<UiCommand>,
    /// Drained by [`duocb_next_event`] (Mutex: FFI calls may race across threads).
    events: Mutex<std::sync::mpsc::Receiver<NetEvent>>,
    /// An event that didn't fit the caller's buffer, retained for retry.
    pending: Mutex<Option<String>>,
    task: tokio::task::JoinHandle<()>,
    /// The session command this handle was started with, replayed by
    /// [`duocb_reconnect`] into the still-running runtime. Matching transient
    /// pairing memory is reused when it has not been explicitly cleared.
    session_cmd: UiCommand,
    /// What [`duocb_disconnect`] sends: hosts stop serving, joiners hang up.
    disconnect_cmd: UiCommand,
}

/// The session operations both FFI surfaces expose, so the C and JNI entry
/// points are each one argument conversion around the same body.
impl DuocbHandle {
    /// The next pending event as JSON: one retained by [`Self::retain_event`]
    /// first, then the queue. `None` when nothing is pending.
    fn take_event(&self) -> Option<String> {
        if let Some(json) = self.pending.lock().unwrap().take() {
            return Some(json);
        }
        let events = self.events.lock().unwrap();
        events.try_recv().ok().map(|event| event_json(&event))
    }

    /// Put an event back for the next [`Self::take_event`] — the C surface's
    /// remedy for a caller buffer it did not fit.
    fn retain_event(&self, json: String) {
        *self.pending.lock().unwrap() = Some(json);
    }

    fn send(&self, cmd: UiCommand) {
        let _ = self.cmd_tx.send(cmd);
    }

    fn send_clipboard(&self, text: String) {
        self.send(UiCommand::SendClipboard { text });
    }

    fn refresh_pin(&self) {
        self.send(UiCommand::RefreshPin);
    }

    fn query_conn_path(&self) {
        self.send(UiCommand::QueryConnPath);
    }

    /// End the logical session but keep the runtime: hosts stop serving,
    /// joiners hang up.
    fn disconnect(&self) {
        self.send(self.disconnect_cmd.clone());
    }

    fn is_running(&self) -> bool {
        !self.task.is_finished()
    }

    /// Re-issue the session command on the still-running runtime. `false` when
    /// the runtime is gone — stop and start afresh.
    fn reconnect(&self) -> bool {
        self.is_running() && self.cmd_tx.send(self.session_cmd.clone()).is_ok()
    }

    /// Graceful shutdown: **blocks** until the runtime task ends or 5 s pass,
    /// then releases the process-wide session slot.
    fn shutdown(self) {
        let DuocbHandle {
            runtime,
            cmd_tx,
            task,
            ..
        } = self;
        let _ = cmd_tx.send(UiCommand::Shutdown);
        let _ =
            runtime.block_on(async { tokio::time::timeout(Duration::from_secs(5), task).await });
        runtime.shutdown_background();
        RUNNING.store(false, Ordering::Release);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FfiConfig {
    role: Role,
    /// Every role: this device's persisted iroh transport key, 64 hex chars
    /// from [`duocb_generate_iroh_secret`]. Must be the same on every start
    /// within one process.
    #[serde(default)]
    iroh_secret: Option<String>,
    /// `connect`: this installation's NIP-19 `nsec`.
    #[serde(default)]
    identity_secret: Option<String>,
    /// Every role: this installation's persisted signed self-card.
    #[serde(default)]
    self_card: Option<String>,
    /// `connect`: locally trusted signed cards (max [`MAX_TRUSTED_PEERS`]).
    #[serde(default)]
    peers: Vec<String>,
    /// `connect` only: the chosen peer's hex or NIP-19 public key. Must name a
    /// card in `peers`. It says which *device* to share with, not which half of
    /// the connection to run.
    #[serde(default)]
    peer_public_key: Option<String>,
    /// `card_join` only: the PIN shown on the hosting device, in any user-typed
    /// form (dashes/spaces/lowercase ok).
    #[serde(default)]
    pin: Option<String>,
    /// `card_join` only: the host's LAN IPv4 as shown on the hosting device
    /// (dotted-quad, no port) — pass exactly what [`duocb_resolve_join_ip`]
    /// wrote. Present selects the unicast side channel, which pairs where
    /// multicast is blocked; omitted/blank browses DNS-SD instead.
    #[serde(default)]
    ip: Option<String>,
    /// Which transport(s) carry the rendezvous. Omitted means
    /// [`Channel::LanThenNostr`].
    #[serde(default)]
    channel: Option<Channel>,
    /// Empty/omitted means the built-in default relays.
    #[serde(default)]
    relays: Vec<String>,
}

/// Where the rendezvous records are put and looked for (JSON `channel` key).
///
/// The desktop fixes this at launch (`--lan-only` / `--nostr-only`) so both
/// flows always agree; iOS has no CLI, so the app picks it per session from a
/// setting. It governs card setup and clipboard sessions alike — read it as
/// "how the two devices find each other", not "how card setup works".
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Channel {
    /// The default: the host publishes on LAN and nostr relays; the dialer
    /// tries the local network first, then the relays. A local hit avoids the
    /// dialer's relay lookup, not the host's relay publication.
    LanThenNostr,
    /// Local network only — no third-party server at all, so a pair of devices
    /// with no internet still works. Needs the Local Network permission.
    LanOnly,
    /// Nostr relays only — no mDNS query and no side-channel listener.
    NostrOnly,
}

impl Channel {
    fn to_core(self) -> SignalChannel {
        match self {
            Channel::LanThenNostr => SignalChannel::LanThenNostr,
            Channel::LanOnly => SignalChannel::LanOnly,
            Channel::NostrOnly => SignalChannel::NostrOnly,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    /// Share the clipboard with one chosen trusted peer, hosting or dialing as
    /// [`session_role`] decides.
    Connect,
    /// Card setup: show a rotating PIN and trade identity cards.
    CardHost,
    /// Card setup: dial a typed PIN and trade identity cards.
    CardJoin,
}

/// What `log` shows unless `RUST_LOG` says otherwise.
const DEFAULT_LOG_FILTER: &str = "duocb=info,duocb_core=info,iroh=warn,nostr_sdk=warn";

/// Route Rust `log` output to stderr (visible in Xcode's console and the
/// unified log). Idempotent; honors `RUST_LOG` when set.
#[unsafe(no_mangle)]
pub extern "C" fn duocb_init_logging() {
    init_logging();
}

/// Route `log` to the platform's sink: stderr everywhere but Android, which
/// discards stderr and gets logcat (tag `duocb`) instead. Idempotent.
fn init_logging() {
    #[cfg(target_os = "android")]
    {
        let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| DEFAULT_LOG_FILTER.to_string());
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Trace)
                .with_tag("duocb")
                .with_filter(android_logger::FilterBuilder::new().parse(&filter).build()),
        );
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or(DEFAULT_LOG_FILTER),
        )
        .try_init();
    }
}

// ---------------------------------------------------------------------------
// Identity, card and name helpers
//
// All of these are pure: they touch no network and no storage, so the setup
// screens can call them freely for live validation.
// ---------------------------------------------------------------------------

/// Generate a fresh persistent application private key as NIP-19 `nsec`.
/// Returns 1 on success, 0 if the buffer is too small, -1 on a NULL buffer.
/// # Safety
/// `out_buf` must be NULL or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_generate_identity(out_buf: *mut c_char, out_len: usize) -> c_int {
    write_result(out_buf, out_len, &Identity::generate().to_nsec())
}

/// Generate this installation's permanent 8-character device-name suffix.
/// Mint it **once** and reuse it for every replacement self-card — it is what
/// keeps `<name>_<suffix>` stable across a rename, and it must survive an
/// identity reset.
/// Returns 1 on success, 0 if the buffer is too small, -1 on a NULL buffer.
/// # Safety
/// `out_buf` must be NULL or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_generate_suffix(out_buf: *mut c_char, out_len: usize) -> c_int {
    write_result(out_buf, out_len, &duocb_core::identity::generate_suffix())
}

/// Generate this device's iroh transport key as 64 hex characters. Mint it
/// **once**, persist it next to the application identity, and pass it as
/// `iroh_secret` on every [`duocb_start`] — see the crate docs for why iOS
/// persists it while the desktop does not.
/// Returns 1 on success, 0 if the buffer is too small, -1 on a NULL buffer.
/// # Safety
/// `out_buf` must be NULL or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_generate_iroh_secret(out_buf: *mut c_char, out_len: usize) -> c_int {
    write_result(
        out_buf,
        out_len,
        &hex::encode(iroh::SecretKey::generate().to_bytes()),
    )
}

/// Validate an identity private key. Returns 1 if valid; 0 if invalid (the
/// reason is written to `err_buf` when provided); -1 on NULL/non-UTF-8 input.
/// # Safety
/// `private_key` must be NULL or a valid NUL-terminated C string; `err_buf`
/// must be NULL or point to at least `err_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_validate_identity(
    private_key: *const c_char,
    err_buf: *mut c_char,
    err_len: usize,
) -> c_int {
    let Some(key) = (unsafe { cstr_arg(private_key) }) else {
        return -1;
    };
    match Identity::parse_nsec(key) {
        Ok(_) => 1,
        Err(error) => {
            write_cstr(err_buf, err_len, &format!("{error:#}"));
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
    let Some(key) = (unsafe { cstr_arg(private_key) }) else {
        return -1;
    };
    let Ok(identity) = Identity::parse_nsec(key) else {
        return -1;
    };
    write_result(out_buf, out_len, &identity.to_npub())
}

/// This identity's human-comparable key fingerprint — the value shown on the
/// hub, and this device's half of any card-setup pairing code.
///
/// Taken over the public key, not over a card, so it stays put when the card is
/// re-minted and can be re-checked out of band long after pairing.
/// Returns 1 on success, 0 if the buffer is too small, -1 for invalid input.
/// # Safety
/// Arguments must be NULL or valid pointers of the documented lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_identity_fingerprint(
    private_key: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    let Some(key) = (unsafe { cstr_arg(private_key) }) else {
        return -1;
    };
    let Ok(identity) = Identity::parse_nsec(key) else {
        return -1;
    };
    let fingerprint = duocb_core::auth::key_fingerprint(&identity.public_key());
    write_result(out_buf, out_len, &fingerprint)
}

/// Validate a user-typed short device name against the display-identity rules.
/// Returns 1 if valid; 0 if invalid (the reason is written to `err_buf` when
/// provided); -1 on NULL/non-UTF-8 input.
/// # Safety
/// `name` must be NULL or a valid NUL-terminated C string; `err_buf` must be
/// NULL or point to at least `err_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_validate_name(
    name: *const c_char,
    err_buf: *mut c_char,
    err_len: usize,
) -> c_int {
    let Some(name) = (unsafe { cstr_arg(name) }) else {
        return -1;
    };
    match duocb_core::identity::validate_name(name) {
        Ok(()) => 1,
        Err(error) => {
            write_cstr(err_buf, err_len, &format!("{error:#}"));
            0
        }
    }
}

/// Compose the broadcast identity `<name>_<suffix>` for the name field's live
/// preview. Does not validate — call [`duocb_validate_name`] first.
/// Returns 1 on success, 0 if the buffer is too small, -1 on NULL input.
/// # Safety
/// String inputs must be NUL-terminated UTF-8; `out_buf` must be NULL or point
/// to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_display_identity(
    name: *const c_char,
    suffix: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    let (Some(name), Some(suffix)) = (unsafe { cstr_arg(name) }, unsafe { cstr_arg(suffix) }) else {
        return -1;
    };
    write_result(
        out_buf,
        out_len,
        &duocb_core::identity::display_identity(name, suffix),
    )
}

/// Mint a signed identity card. Call after naming an identity, and again
/// whenever [`duocb_identity_card_info`] reports `needs_renewal`, so the card
/// the user hands out always has most of its life ahead of it.
/// Returns 1 on success, 0 if the buffer is too small, -1 for invalid input.
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
    let (Some(key), Some(name), Some(suffix)) = (
        unsafe { cstr_arg(private_key) },
        unsafe { cstr_arg(name) },
        unsafe { cstr_arg(suffix) },
    ) else {
        return -1;
    };
    let Ok(identity) = Identity::parse_nsec(key) else {
        return -1;
    };
    let Ok(card) = identity.card(name, suffix) else {
        return -1;
    };
    write_result(out_buf, out_len, &card.encode())
}

/// Validate a signed identity card — signature, schema, name rules and signed
/// validity-window shape. This is clock-free; use [`duocb_identity_card_info`]
/// to learn whether the local clock is currently inside that window.
/// Returns 1 if valid; 0 if invalid (the reason is written to `err_buf` when
/// provided); -1 on NULL/non-UTF-8 input.
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
    match IdentityCard::parse(card) {
        Ok(_) => 1,
        Err(error) => {
            write_cstr(err_buf, err_len, &format!("{error:#}"));
            0
        }
    }
}

/// Write a verified card's public detail as JSON:
///
/// ```jsonc
/// {"name":"mac-book_a7B2c3D4","short_name":"mac-book","suffix":"a7B2c3D4",
///  "public_key":"<64 hex>","npub":"npub1…","fingerprint":"A1B2 C3D4 …",
///  "not_before":1750000000,"not_after":1752592000,"remaining_secs":1209600,
///  "expired":false,"not_yet_valid":false,"needs_renewal":false}
/// ```
///
/// `not_before`/`not_after` are the signed validity window. `expired` is true
/// whenever the local clock is outside it, on either side; `not_yet_valid`
/// singles out the early side, where the fix is a clock and not a fresh card.
///
/// `fingerprint` is the card's half of a [`duocb_pairing_code`] and the value a
/// trusted-device row shows for out-of-band re-checks.
/// `expired` drives the warning colour on a trusted-device row — a
/// lapsed card can no longer pair, and the only way back is a fresh one from
/// its owner. `needs_renewal` is advisory and applies to the *self*-card: true
/// once less than [`CARD_RENEW_BEFORE_SECS`] remains.
///
/// Returns 1 on success, 0 if the buffer is too small, -1 for invalid input.
/// # Safety
/// `card` must be NUL-terminated UTF-8; `out_buf` must be NULL or point to at
/// least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_identity_card_info(
    card: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    let Some(card) = (unsafe { cstr_arg(card) }) else {
        return -1;
    };
    let Ok(card) = IdentityCard::parse(card) else {
        return -1;
    };
    write_result(out_buf, out_len, &identity_card_json(&card).to_string())
}

/// The single pairing code the card-setup confirmation screen shows: both
/// devices call this with their own card and the one they received (either
/// order — the code is order-normalized), render the identical value, and the
/// user checks the two screens match before importing. Each half of the code is
/// one card's key fingerprint, so an impostor still faces a fixed-target
/// second-preimage per key (see `duocb_core::auth::pairing_code`).
///
/// Returns 1 on success, 0 if the buffer is too small, -1 for invalid input
/// (either card fails verification, or both are the same key).
/// # Safety
/// `card_a` and `card_b` must be NUL-terminated UTF-8; `out_buf` must be NULL
/// or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_pairing_code(
    card_a: *const c_char,
    card_b: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    let (Some(card_a), Some(card_b)) = (unsafe { cstr_arg(card_a) }, unsafe { cstr_arg(card_b) })
    else {
        return -1;
    };
    let (Ok(card_a), Ok(card_b)) = (IdentityCard::parse(card_a), IdentityCard::parse(card_b))
    else {
        return -1;
    };
    // The core refuses one key in both slots — a comparison with nothing on
    // the other side; the caller passed the same card twice by mistake.
    let Ok(code) = duocb_core::auth::pairing_code(&card_a.public_key(), &card_b.public_key())
    else {
        return -1;
    };
    write_result(out_buf, out_len, &code)
}

/// Which half of a clipboard session this device runs with a given peer:
/// 1 = this device hosts (it listens and publishes the hosting record),
/// 0 = this device dials, -1 for invalid input (either card fails verification,
/// or both carry the same key).
///
/// Pure: it starts nothing and touches no network. [`duocb_start`] applies the
/// same rule to the config it is given, so this is only for telling the user
/// which device is setting the link up — never a switch the app has to set.
/// The peer's device runs the opposite half from the identical pair of cards.
/// # Safety
/// `self_card` and `peer_card` must be NUL-terminated UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_session_role(
    self_card: *const c_char,
    peer_card: *const c_char,
) -> c_int {
    let (Some(mine), Some(theirs)) =
        (unsafe { cstr_arg(self_card) }, unsafe { cstr_arg(peer_card) })
    else {
        return -1;
    };
    let (Ok(mine), Ok(theirs)) = (IdentityCard::parse(mine), IdentityCard::parse(theirs)) else {
        return -1;
    };
    // One key in both slots is a caller mistake, not a pairing: it would report
    // "hosting" for a session that can never have another end.
    if mine.public_key() == theirs.public_key() {
        return -1;
    }
    match session_role(mine.public_key(), theirs.public_key()) {
        SessionRole::Host => 1,
        SessionRole::Dial => 0,
    }
}

// ---------------------------------------------------------------------------
// Card-setup PIN helpers
// ---------------------------------------------------------------------------

/// Normalize a user-typed card-setup PIN to canonical form (8 uppercase
/// Crockford characters): strips dashes/spaces, uppercases, maps the aliases
/// I/L→1 and O→0, and verifies the trailing check digit. Use for live
/// validation of the join field; [`duocb_start`] re-normalizes anyway.
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

/// Render a canonical PIN in its display form (`XXXX-XXXX`).
/// Returns 1 on success, 0 if the buffer is too small, -1 on NULL input.
/// # Safety
/// `pin` must be NULL or a valid NUL-terminated C string; `out_buf` must be
/// NULL or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_format_pin(
    pin: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    let Some(pin) = (unsafe { cstr_arg(pin) }) else {
        return -1;
    };
    write_result(out_buf, out_len, &duocb_core::pin::format_pin(pin))
}

/// Keep only characters a PIN can contain, uppercasing and mapping the I/L→1
/// and O→0 aliases. Feed every keystroke of the PIN entry through this so the
/// field can never hold a character the code does not use.
/// Returns 1 on success, 0 if the buffer is too small, -1 on NULL input.
/// # Safety
/// `input` must be NULL or a valid NUL-terminated C string; `out_buf` must be
/// NULL or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_sanitize_pin_chars(
    input: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    let Some(input) = (unsafe { cstr_arg(input) }) else {
        return -1;
    };
    write_result(out_buf, out_len, &duocb_core::pin::sanitize_pin_chars(input))
}

/// Redistribute a two-group PIN entry across its fields, so typing past the end
/// of the first group spills into the second (Apple-style code entry). Writes
/// `{"first":"AB12","second":"CD34"}`.
/// Returns 1 on success, 0 if the buffer is too small, -1 on NULL input.
/// # Safety
/// String inputs must be NUL-terminated UTF-8; `out_buf` must be NULL or point
/// to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_split_pin_groups(
    first: *const c_char,
    second: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    let (Some(first), Some(second)) =
        (unsafe { cstr_arg(first) }, unsafe { cstr_arg(second) })
    else {
        return -1;
    };
    let (first, second) = duocb_core::pin::split_pin_groups(first, second);
    write_result(
        out_buf,
        out_len,
        &serde_json::json!({ "first": first, "second": second }).to_string(),
    )
}

/// The number of PIN characters entered so far, and the total a full PIN needs
/// — for the "keep typing — N of M characters" hint. Writes
/// `{"entered":3,"total":8,"group":4}`; `group` is the per-field length.
/// Returns 1 on success, 0 if the buffer is too small, -1 on NULL input.
/// # Safety
/// `input` must be NULL or a valid NUL-terminated C string; `out_buf` must be
/// NULL or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_pin_progress(
    input: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    let Some(input) = (unsafe { cstr_arg(input) }) else {
        return -1;
    };
    write_result(
        out_buf,
        out_len,
        &serde_json::json!({
            "entered": duocb_core::pin::pin_input_len(input),
            "total": duocb_core::pin::PIN_LEN,
            "group": duocb_core::pin::PIN_GROUP_LEN,
        })
        .to_string(),
    )
}

// ---------------------------------------------------------------------------
// Manual host-IP entry (card setup's multicast-blocked fallback)
// ---------------------------------------------------------------------------

/// Describe how the card-setup join screen should constrain the optional
/// host-IP entry to *this* device's own subnet. Writes a JSON object:
///
/// ```jsonc
/// {"prefix":"10.22.33.","placeholder":"last octet","hint":"","label":"10.22.33.0/24"}
/// ```
///
/// `prefix` is the locked network part to show, non-editable, ahead of the
/// field (the user types only the host part; [`duocb_resolve_join_ip`] also
/// accepts a whole pasted address). `placeholder` describes the editable tail
/// ("last octet" / "last 2 octets"). `hint` is a range hint for a
/// partial-octet subnet (a /20), else "". `label` is the CIDR for the
/// out-of-range message. All four are "" when no private subnet is detected
/// (free full-IP entry).
/// Returns 1 = written, 0 = buffer too small, -1 = NULL buffer.
/// # Safety
/// `out_buf` must be NULL or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_join_ip_context(out_buf: *mut c_char, out_len: usize) -> c_int {
    let constraint = duocb_core::subnet::JoinIpConstraint::detect();
    write_result(
        out_buf,
        out_len,
        &serde_json::json!({
            "prefix": constraint.locked_prefix(),
            "placeholder": constraint.host_placeholder(),
            "hint": constraint.hint(),
            "label": constraint.label(),
        })
        .to_string(),
    )
}

/// Validate what the user typed into the host-IP entry against this device's
/// subnet, resolving the host part after the locked prefix (or a pasted whole
/// address) into a full IPv4. On success the full dotted-quad is written to
/// `out_buf` — pass exactly that as the config `ip` to [`duocb_start`].
///
/// Returns 1 = in-range address written, 0 = a well-formed address outside
/// every allowed subnet, 2 = the entry is empty (browse DNS-SD instead of the
/// side channel — omit `ip`), -1 = malformed/NULL input or the buffer is too
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
    use duocb_core::subnet::JoinIpOutcome;
    let Some(entry) = (unsafe { cstr_arg(entry) }) else {
        return -1;
    };
    match duocb_core::subnet::JoinIpConstraint::detect().resolve(entry) {
        JoinIpOutcome::InRange(addr) => {
            if write_cstr(out_buf, out_len, &addr.to_string()) {
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

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

/// Start a session per the config's `role`. Returns a non-NULL handle, or NULL
/// with the error message written to `err_buf`.
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
    match start_session(json) {
        Ok(handle) => Box::into_raw(Box::new(handle)),
        Err(msg) => {
            write_cstr(err_buf, err_len, &msg);
            ptr::null_mut()
        }
    }
}

/// Claim the process's one session slot and start a session from the config
/// JSON; on failure the slot is released again. Shared by both FFI surfaces.
fn start_session(json: &str) -> Result<DuocbHandle, String> {
    if RUNNING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("a duocb session is already running".into());
    }
    start_inner(json).inspect_err(|_| RUNNING.store(false, Ordering::Release))
}

fn start_inner(json: &str) -> Result<DuocbHandle, String> {
    let cfg: FfiConfig =
        serde_json::from_str(json).map_err(|e| format!("invalid config JSON: {e}"))?;
    let plan = build_start_plan(cfg)?;
    let secret = pin_iroh_secret(&IROH_SECRET, plan.iroh_secret)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to build tokio runtime: {e}"))?;
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, event_rx) = std::sync::mpsc::channel();
    // No waker: the app polls duocb_next_event / DuocbNative.nextEvent on a timer.
    let events = EventSender::new(event_tx, None);
    let task = runtime.spawn(duocb_core::net::runtime::net_main(cmd_rx, events, secret));

    cmd_tx
        .send(plan.session_cmd.clone())
        .map_err(|_| "runtime unavailable".to_string())?;

    Ok(DuocbHandle {
        runtime,
        cmd_tx,
        events: Mutex::new(event_rx),
        pending: Mutex::new(None),
        task,
        session_cmd: plan.session_cmd,
        disconnect_cmd: plan.disconnect_cmd,
    })
}

#[derive(Debug)]
struct StartPlan {
    iroh_secret: iroh::SecretKey,
    session_cmd: UiCommand,
    disconnect_cmd: UiCommand,
}

impl StartPlan {
    fn host(iroh_secret: iroh::SecretKey, cmd: UiCommand) -> Self {
        Self {
            iroh_secret,
            session_cmd: cmd,
            disconnect_cmd: UiCommand::StopServer,
        }
    }

    fn dial(iroh_secret: iroh::SecretKey, cmd: UiCommand) -> Self {
        Self {
            iroh_secret,
            session_cmd: cmd,
            disconnect_cmd: UiCommand::Disconnect,
        }
    }
}

/// Parse the config's `iroh_secret`: exactly 32 bytes as hex.
fn parse_iroh_secret(value: Option<&str>) -> Result<iroh::SecretKey, String> {
    let hex = value.ok_or("iroh_secret is required")?.trim();
    let bytes: [u8; 32] = hex::decode(hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("invalid iroh_secret: expected 64 hex characters")?;
    Ok(iroh::SecretKey::from_bytes(&bytes))
}

/// Fix the process's iroh key on the first start and hold every later start to
/// it, so one running app never presents two node ids.
fn pin_iroh_secret(
    slot: &OnceLock<iroh::SecretKey>,
    secret: iroh::SecretKey,
) -> Result<iroh::SecretKey, String> {
    let pinned = slot.get_or_init(|| secret.clone());
    if pinned.to_bytes() != secret.to_bytes() {
        return Err("iroh_secret differs from the one this process already presents".into());
    }
    Ok(pinned.clone())
}

/// Validate the config for its role and resolve the commands it maps to.
///
/// Validation is strict — an unexpected field is an error rather than an
/// ignored key — because every one of them is a silent-misbehaviour trap: an
/// `ip` that is quietly dropped looks like a network problem, and a `peers`
/// list ignored by card setup looks like a trust bug.
fn build_start_plan(cfg: FfiConfig) -> Result<StartPlan, String> {
    let relays = if cfg.relays.is_empty() {
        duocb_core::nostr::DEFAULT_NOSTR_RELAYS
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        cfg.relays
    };
    let channel = cfg.channel.unwrap_or(Channel::LanThenNostr).to_core();
    let iroh_secret = parse_iroh_secret(cfg.iroh_secret.as_deref())?;

    // Every role needs a self-card; only the key roles need the private key.
    let self_card = IdentityCard::parse(cfg.self_card.as_deref().ok_or("self_card is required")?)
        .map_err(|error| format!("invalid self_card: {error:#}"))?;

    // One authoritative rule per field, each stated once: card setup is the
    // identity-less half of the protocol, and the PIN and its side-channel IP
    // belong to the one role that dials a PIN.
    let card_setup = matches!(cfg.role, Role::CardHost | Role::CardJoin);
    if card_setup && (cfg.identity_secret.is_some() || !cfg.peers.is_empty()) {
        return Err("card setup accepts only role, iroh_secret, self_card, pin, ip, channel and relays".into());
    }
    if cfg.role != Role::CardJoin && (cfg.pin.is_some() || cfg.ip.is_some()) {
        return Err("pin and ip are only valid for the card_join role".into());
    }
    if cfg.role != Role::Connect && cfg.peer_public_key.is_some() {
        return Err("peer_public_key is only valid for the connect role".into());
    }

    match cfg.role {
        Role::CardHost => {
            return Ok(StartPlan::host(iroh_secret, UiCommand::StartServer {
                mode: ServerMode::CardSetup {
                    self_card: Box::new(self_card),
                    channel,
                    relays,
                },
            }));
        }
        Role::CardJoin => {
            let canonical_pin =
                duocb_core::pin::normalize_pin(cfg.pin.as_deref().unwrap_or_default())
                    .ok_or("invalid PIN (enter the 8 characters shown on the other device)")?;
            // The typed host IP is the LAN half of the lookup, so it is
            // meaningless without the LAN channel. Rejecting rather than
            // ignoring it keeps a nostr-only pairing from looking like it
            // silently failed to use the address the user supplied.
            let target_ip = match cfg.ip.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                Some(_) if !channel.lan() => {
                    return Err("ip needs a channel that uses the local network".into());
                }
                Some(ip) => Some(std::net::IpAddr::V4(ip.parse::<std::net::Ipv4Addr>().map_err(
                    |_| "invalid host IP (enter the IPv4 address shown on the other device)",
                )?)),
                None => None,
            };
            return Ok(StartPlan::dial(iroh_secret, UiCommand::Connect {
                spec: DialSpec::CardSetup {
                    canonical_pin,
                    self_card: Box::new(self_card),
                    target_ip,
                    channel,
                    relays,
                },
            }));
        }
        Role::Connect => {}
    }

    let identity = Identity::parse_nsec(
        cfg.identity_secret
            .as_deref()
            .ok_or("identity_secret is required")?,
    )
    .map_err(|error| format!("invalid identity_secret: {error:#}"))?;
    if self_card.public_key() != identity.public_key() {
        return Err("self_card is not signed by identity_secret".into());
    }
    if cfg.peers.len() > MAX_TRUSTED_PEERS {
        return Err(format!("peers exceeds the limit of {MAX_TRUSTED_PEERS}"));
    }
    let mut seen = std::collections::HashSet::new();
    let mut peers = Vec::with_capacity(cfg.peers.len());
    for encoded in &cfg.peers {
        let card = IdentityCard::parse(encoded)
            .map_err(|error| format!("invalid peer identity card: {error:#}"))?;
        if card.public_key() == identity.public_key() {
            return Err("peers contains this installation's self_card".into());
        }
        if !seen.insert(card.public_key()) {
            return Err("peers contains a duplicate public key".into());
        }
        peers.push(card);
    }
    let key_identity = KeyIdentity {
        identity,
        self_card,
        peers,
        relays,
    };

    let selected = cfg
        .peer_public_key
        .as_deref()
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .ok_or("peer_public_key is required for connect")?;
    let peer_public_key = key_identity
        .peers
        .iter()
        .find(|peer| peer.public_key().to_hex() == selected || peer.npub() == selected)
        .map(IdentityCard::public_key)
        .ok_or("peer_public_key is not in the local trusted peer list")?;

    // The one place the halves part company. Both devices are given the same
    // kind of config — "share with that device" — and this rule, computed from
    // the two application keys, hands exactly one of them the listening half.
    Ok(
        match session_role(key_identity.identity.public_key(), peer_public_key) {
            SessionRole::Host => StartPlan::host(iroh_secret, UiCommand::StartServer {
                mode: ServerMode::Key {
                    identity: Box::new(key_identity),
                    peer_public_key,
                    channel,
                },
            }),
            SessionRole::Dial => StartPlan::dial(iroh_secret, UiCommand::Connect {
                spec: DialSpec::Key {
                    identity: Box::new(key_identity),
                    peer_public_key,
                    channel,
                },
            }),
        },
    )
}

/// Drain one pending event as a NUL-terminated JSON string.
/// Returns 1 = event written; 0 = none pending; -1 = NULL handle or `out_buf`;
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
    // Checked before anything is taken from the queue. A NULL buffer is a
    // caller bug, not a sizing problem, and reporting it as -2 would invite the
    // documented remedy — retry with a bigger buffer — which can never succeed.
    if handle.is_null() || out_buf.is_null() {
        return -1;
    }
    let handle = unsafe { &*handle };
    let Some(json) = handle.take_event() else {
        return 0;
    };
    if write_cstr(out_buf, out_len, &json) {
        1
    } else {
        handle.retain_event(json);
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
    unsafe { &*handle }.send_clipboard(text.to_string());
    0
}

/// Card-host only: mint and publish a fresh PIN immediately, invalidating every
/// previously shown PIN — their auth keys are dropped and their LAN
/// advertisements withdrawn, so a stale code can resolve at most an auth
/// rejection. The new code arrives as the next `pin_rotated` event; an `error`
/// event if no PIN is being published (wrong role, or a peer already paired).
/// Returns 0 = requested, -1 = NULL handle.
/// # Safety
/// `handle` must be NULL or a live handle from [`duocb_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_refresh_pin(handle: *const DuocbHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    unsafe { &*handle }.refresh_pin();
    0
}

/// Request a point-in-time connection-path snapshot; the answer arrives as a
/// `conn_path` event (empty if no connection is up). Returns 0 = requested,
/// -1 = NULL handle.
/// # Safety
/// `handle` must be NULL or a live handle from [`duocb_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_query_conn_path(handle: *const DuocbHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    unsafe { &*handle }.query_conn_path();
    0
}

/// End the session without tearing the handle down: a host stops serving, a
/// joiner hangs up. This clears the logical session's transient claim/PIN
/// memory but leaves the runtime and its iroh node id alive; a later
/// [`duocb_reconnect`] reissues the original command as a fresh logical
/// session. Returns 0 = requested, -1 = NULL handle.
/// # Safety
/// `handle` must be NULL or a live handle from [`duocb_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_disconnect(handle: *const DuocbHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    unsafe { &*handle }.disconnect();
    0
}

/// Liveness probe: 1 = runtime alive, 0 = runtime ended (fatal — restart via a
/// fresh [`duocb_start`] after [`duocb_stop`]), -1 = NULL handle.
/// # Safety
/// `handle` must be NULL or a live handle from [`duocb_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_is_running(handle: *const DuocbHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    if unsafe { &*handle }.is_running() { 1 } else { 0 }
}

/// Re-issue the session command this handle was started with on its
/// still-running runtime. If the session task ended on its own, this retains
/// the runtime's node id and any matching server-side claim/PIN memory; target
/// resolution runs again from the original command. An explicit
/// [`duocb_disconnect`] clears that transient session memory first. A fresh
/// [`duocb_start`] uses the caller's same `iroh_secret` but creates a new
/// runtime with empty session memory. Progress arrives as the usual status
/// events.
/// Returns 0 = requested, -1 = NULL handle, -2 = runtime unavailable (it died —
/// fall back to [`duocb_stop`] plus a fresh [`duocb_start`]).
/// # Safety
/// `handle` must be NULL or a live handle from [`duocb_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_reconnect(handle: *const DuocbHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    if unsafe { &*handle }.reconnect() { 0 } else { -2 }
}

/// Stop the session (graceful shutdown, bounded wait) and free the handle.
/// NULL is a safe no-op. The handle must not be used afterwards.
///
/// **Blocks** until the runtime task ends or a 5-second timeout expires —
/// normally immediate, but a live session takes as long as its peer needs to
/// wind down. Call it off the iOS main thread; on it, the UI freezes for the
/// duration and the watchdog can kill the app outright.
/// # Safety
/// `handle` must be NULL or a handle returned by [`duocb_start`]; it is freed
/// here and must not be used again afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_stop(handle: *mut DuocbHandle) {
    if handle.is_null() {
        return;
    }
    unsafe { Box::from_raw(handle) }.shutdown();
}

/// Serialize a [`NetEvent`] for the app side.
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
            // This host's LAN IPv4, for the joiner's manual-IP side channel;
            // null when none was detected or the LAN channel is off.
            "host_lan_ip": host_lan_ip,
        }),
        // A peer paired (or the host stopped publishing) — hide the PIN.
        NetEvent::PinCleared => json!({ "type": "pin_cleared" }),
        NetEvent::Status(status) => {
            let state = match status {
                ConnStatus::Idle => "idle",
                ConnStatus::Starting => "starting",
                ConnStatus::Waiting => "waiting",
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
            // Always null in card setup: nothing on that connection
            // authenticates an application identity.
            "peer_public_key": peer_public_key,
        }),
        // Verified as well-formed and correctly signed, and nothing more. The
        // app must not store this without the user comparing the pairing code
        // (duocb_pairing_code over the self-card and `card`) across both
        // devices' screens.
        NetEvent::PeerCardReceived(card) => json!({
            "type": "peer_card_received",
            "card": card.encode(),
            "info": identity_card_json(card),
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
        NetEvent::Error(message) => json!({ "type": "error", "message": message }),
    };
    value.to_string()
}

fn identity_card_json(card: &IdentityCard) -> serde_json::Value {
    let now = duocb_core::auth::unix_now();
    let remaining = card.remaining_secs_at(now);
    serde_json::json!({
        "name": card.name(),
        "short_name": card.short_name(),
        "suffix": card.suffix(),
        "public_key": card.public_key().to_hex(),
        "npub": card.npub(),
        "fingerprint": card.fingerprint(),
        "not_before": card.not_before(),
        "not_after": card.not_after(),
        "remaining_secs": remaining,
        "expired": !card.is_valid_at(now),
        "not_yet_valid": card.is_not_yet_valid_at(now),
        "needs_renewal": remaining < CARD_RENEW_BEFORE_SECS,
    })
}

/// Borrow a C string argument as `&str`; `None` for NULL or non-UTF-8.
unsafe fn cstr_arg<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

/// The common tail of every output helper: 1 = written, 0 = buffer too small,
/// -1 = NULL buffer.
fn write_result(buf: *mut c_char, len: usize, s: &str) -> c_int {
    if buf.is_null() {
        return -1;
    }
    if write_cstr(buf, len, s) { 1 } else { 0 }
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
        ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast::<u8>(), copy);
        *buf.add(copy) = 0;
    }
    copy == bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_with_card() -> (String, String) {
        let identity = Identity::generate();
        let card = identity.card("mac-book", "a7B2c3D4").unwrap();
        (identity.to_nsec(), card.encode())
    }

    fn iroh_secret() -> String {
        hex::encode(iroh::SecretKey::generate().to_bytes())
    }

    /// A trusted peer that puts `me` on the named half of the session. The
    /// halves fall out of the two keys, so a test that needs one picks a peer
    /// for it.
    fn peer_for_role(me: &Identity, role: SessionRole) -> Identity {
        std::iter::repeat_with(Identity::generate)
            .find(|peer| session_role(me.public_key(), peer.public_key()) == role)
            .expect("keys are random, so both halves come up quickly")
    }

    /// The config an app sends for "share the clipboard with that device" —
    /// identical on both devices bar their own keys.
    fn connect_config(nsec: &str, card: &str, peer: &Identity) -> serde_json::Value {
        let peer_card = peer.card("pixel", "9zKtm4Qp").unwrap();
        serde_json::json!({
            "role": "connect",
            "identity_secret": nsec,
            "self_card": card,
            "peers": [peer_card.encode()],
            "peer_public_key": peer.public_key().to_hex(),
        })
    }

    /// Parse and resolve a config, supplying an `iroh_secret` when the test
    /// did not set one so each test states only what it is about.
    fn build(json: &str) -> Result<StartPlan, String> {
        let mut cfg: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
        if cfg.get("iroh_secret").is_none() {
            cfg["iroh_secret"] = serde_json::json!(iroh_secret());
        }
        build_start_plan(serde_json::from_value(cfg).map_err(|e| e.to_string())?)
    }

    #[test]
    fn iroh_secret_is_required_and_must_be_32_hex_bytes() {
        let identity = Identity::generate();
        let (nsec, card) = (
            identity.to_nsec(),
            identity.card("mac-book", "a7B2c3D4").unwrap().encode(),
        );
        let base = connect_config(&nsec, &card, &Identity::generate());
        let without = build_start_plan(serde_json::from_value(base.clone()).unwrap());
        assert!(without.unwrap_err().contains("iroh_secret is required"));

        for bad in ["", "abc", &"0".repeat(63), &"zz".repeat(32)] {
            let mut cfg = base.clone();
            cfg["iroh_secret"] = serde_json::json!(bad);
            assert!(
                build(&cfg.to_string())
                    .unwrap_err()
                    .contains("invalid iroh_secret"),
                "{bad:?} must be rejected"
            );
        }

        // The same hex always yields the same node id — that is the whole
        // point of persisting it.
        let secret = iroh_secret();
        let mut cfg = base;
        cfg["iroh_secret"] = serde_json::json!(secret);
        let a = build(&cfg.to_string()).unwrap().iroh_secret;
        let b = build(&cfg.to_string()).unwrap().iroh_secret;
        assert_eq!(a.public(), b.public());
        assert_eq!(hex::encode(a.to_bytes()), secret);
    }

    #[test]
    fn a_process_presents_one_node_id() {
        let slot = OnceLock::new();
        let first = iroh::SecretKey::generate();
        let pinned = pin_iroh_secret(&slot, first.clone()).unwrap();
        assert_eq!(pinned.public(), first.public());
        // The same key again — a stop-and-restart with the persisted value.
        assert!(pin_iroh_secret(&slot, first.clone()).is_ok());
        // A different key is refused instead of silently changing node id.
        assert!(
            pin_iroh_secret(&slot, iroh::SecretKey::generate())
                .unwrap_err()
                .contains("already presents")
        );
        assert_eq!(slot.get().unwrap().public(), first.public());
    }

    /// The app sends one kind of config — "share with that device" — and this
    /// layer, not the app, works out which half it runs. Both halves must come
    /// out of the identical request shape, with the matching disconnect command:
    /// a hosting device that hung up like a dialer would leave its record
    /// published.
    #[test]
    fn connect_picks_the_half_from_the_two_keys() {
        let identity = Identity::generate();
        let (nsec, card) = (
            identity.to_nsec(),
            identity.card("mac-book", "a7B2c3D4").unwrap().encode(),
        );

        let host_peer = peer_for_role(&identity, SessionRole::Host);
        let resolved = build(&connect_config(&nsec, &card, &host_peer).to_string())
            .expect("valid connect config");
        match resolved.session_cmd {
            UiCommand::StartServer {
                mode:
                    ServerMode::Key {
                        peer_public_key,
                        channel,
                        ..
                    },
            } => {
                assert_eq!(peer_public_key, host_peer.public_key());
                assert_eq!(channel, SignalChannel::LanThenNostr);
            }
            other => panic!("expected the hosting half, got: {other:?}"),
        }
        assert!(matches!(resolved.disconnect_cmd, UiCommand::StopServer));

        let dial_peer = peer_for_role(&identity, SessionRole::Dial);
        let resolved = build(&connect_config(&nsec, &card, &dial_peer).to_string())
            .expect("valid connect config");
        match resolved.session_cmd {
            UiCommand::Connect {
                spec:
                    DialSpec::Key {
                        peer_public_key,
                        channel,
                        ..
                    },
            } => {
                assert_eq!(peer_public_key, dial_peer.public_key());
                assert_eq!(channel, SignalChannel::LanThenNostr);
            }
            other => panic!("expected the dialing half, got: {other:?}"),
        }
        assert!(matches!(resolved.disconnect_cmd, UiCommand::Disconnect));
    }

    #[test]
    fn connect_resolves_the_selected_peer_and_rejects_a_stranger() {
        let (nsec, card) = identity_with_card();
        let peer = Identity::generate();
        let peer_card = peer.card("pixel", "9zKtm4Qp").unwrap();
        let base = connect_config(&nsec, &card, &peer);

        assert!(
            build(&base.to_string()).is_ok(),
            "the hex public key selects the peer"
        );

        // The npub form of the same key is accepted too.
        let mut cfg = base.clone();
        cfg["peer_public_key"] = serde_json::json!(peer_card.npub());
        assert!(build(&cfg.to_string()).is_ok(), "npub selects the peer");

        // A key that is not in the local trusted list never starts a session.
        let mut cfg = base.clone();
        cfg["peer_public_key"] = serde_json::json!(Identity::generate().public_key().to_hex());
        assert!(
            build(&cfg.to_string())
                .unwrap_err()
                .contains("not in the local trusted peer list")
        );

        // And a session always names the device it is for: without a peer there
        // is no pairing, and so no half to compute.
        let mut cfg = base;
        cfg.as_object_mut().unwrap().remove("peer_public_key");
        assert!(
            build(&cfg.to_string())
                .unwrap_err()
                .contains("peer_public_key is required")
        );
    }

    #[test]
    fn a_self_card_signed_by_another_key_is_refused() {
        let (nsec, _) = identity_with_card();
        let other_card = Identity::generate().card("pixel", "9zKtm4Qp").unwrap();
        let mut cfg = connect_config(&nsec, &other_card.encode(), &Identity::generate());
        cfg["self_card"] = serde_json::json!(other_card.encode());
        assert!(
            build(&cfg.to_string())
                .unwrap_err()
                .contains("not signed by identity_secret")
        );
    }

    #[test]
    fn card_setup_roles_are_identity_less() {
        let (nsec, card) = identity_with_card();

        let json = serde_json::json!({ "role": "card_host", "self_card": card })
            .to_string();
        let resolved = build(&json).expect("valid card_host config");
        assert!(matches!(
            resolved.session_cmd,
            UiCommand::StartServer {
                mode: ServerMode::CardSetup { .. }
            }
        ));

        // Card setup still has an endpoint, so it presents the node id too.
        let json = serde_json::json!({ "role": "card_host", "self_card": card }).to_string();
        let without = build_start_plan(serde_json::from_str(&json).unwrap());
        assert!(without.unwrap_err().contains("iroh_secret is required"));

        // Passing the private key or a trust store to card setup is a mistake,
        // not something to silently ignore — neither is used there.
        let json = serde_json::json!({
            "role": "card_host",
            "self_card": card,
            "identity_secret": nsec,
        })
        .to_string();
        assert!(build(&json).unwrap_err().contains("card setup accepts only"));
    }

    #[test]
    fn card_join_normalizes_the_pin_and_rejects_a_typo() {
        let (_, card) = identity_with_card();
        let canonical = duocb_core::pin::generate_pin();
        // The user types what the other device displays — dashed, and here
        // lowercased for good measure. It must normalize back to the canonical
        // form the rendezvous keys are derived from.
        let typed = duocb_core::pin::format_pin(&canonical).to_lowercase();
        let json = serde_json::json!({
            "role": "card_join",
            "self_card": card,
            "pin": typed,
        })
        .to_string();
        match build(&json).expect("valid PIN").session_cmd {
            UiCommand::Connect {
                spec: DialSpec::CardSetup {
                    canonical_pin,
                    target_ip,
                    ..
                },
            } => {
                assert_eq!(canonical_pin, canonical);
                assert!(target_ip.is_none(), "no ip given → browse DNS-SD");
            }
            other => panic!("unexpected command: {other:?}"),
        }

        // Flip the last character: the trailing check digit no longer matches,
        // which is what catches a single-character typo before any network work.
        let mut typo: Vec<char> = canonical.chars().collect();
        let last = typo.len() - 1;
        typo[last] = if typo[last] == 'X' { 'Y' } else { 'X' };
        let json = serde_json::json!({
            "role": "card_join",
            "self_card": card,
            "pin": typo.into_iter().collect::<String>(),
        })
        .to_string();
        assert!(build(&json).unwrap_err().contains("invalid PIN"));
    }

    /// A typed host IP is the LAN half of the lookup; pairing it with a
    /// nostr-only channel is refused rather than silently dropped.
    #[test]
    fn a_host_ip_needs_a_lan_channel() {
        let (_, card) = identity_with_card();
        let pin = duocb_core::pin::generate_pin();
        let cfg = |channel: &str| {
            serde_json::json!({
                "role": "card_join",
                "self_card": card,
                "pin": pin,
                "ip": "192.168.1.42",
                "channel": channel,
            })
            .to_string()
        };
        match build(&cfg("lan_only")).expect("lan_only accepts an ip").session_cmd {
            UiCommand::Connect {
                spec: DialSpec::CardSetup { target_ip, .. },
            } => assert_eq!(target_ip, Some("192.168.1.42".parse().unwrap())),
            other => panic!("unexpected command: {other:?}"),
        }
        assert!(
            build(&cfg("nostr_only"))
                .unwrap_err()
                .contains("needs a channel that uses the local network")
        );
    }

    #[test]
    fn cross_role_fields_are_rejected_rather_than_ignored() {
        let (nsec, card) = identity_with_card();
        let mut cfg = connect_config(&nsec, &card, &Identity::generate());
        cfg["pin"] = serde_json::json!("K7P29QXM");
        assert!(
            build(&cfg.to_string())
                .unwrap_err()
                .contains("only valid for the card_join role")
        );

        // The same rule covers card_host, which has neither a PIN nor a
        // side-channel IP of its own: it *shows* a PIN rather than dialling one.
        let json = serde_json::json!({
            "role": "card_host",
            "self_card": card,
            "ip": "192.168.1.9",
        })
        .to_string();
        assert!(build(&json).unwrap_err().contains("only valid for the card_join role"));
    }

    #[test]
    fn card_info_reports_fingerprint_and_a_live_expiry() {
        let identity = Identity::generate();
        let card = identity.card("mac-book", "a7B2c3D4").unwrap();
        let info = identity_card_json(&card);
        assert_eq!(info["name"], "mac-book_a7B2c3D4");
        assert_eq!(info["fingerprint"], card.fingerprint());
        assert_eq!(info["expired"], false);
        assert_eq!(info["not_yet_valid"], false);
        assert_eq!(info["not_before"], card.not_before());
        assert_eq!(info["not_after"], card.not_after());
        assert_eq!(info["not_after"], card.not_before() + duocb_core::auth::CARD_TTL_SECS);
        // A card is minted with the full TTL, which is well past the renewal
        // window, so a fresh one never asks to be renewed.
        assert_eq!(info["needs_renewal"], false);

        // A card whose signed window has not opened — what a device with a slow
        // clock sees — is unusable, and the app is told it is the clock.
        let not_before = duocb_core::auth::unix_now() + 24 * 60 * 60;
        let future = identity.card_valid_from("mac-book", "a7B2c3D4", not_before).unwrap();
        let info = identity_card_json(&future);
        assert_eq!(info["not_before"], not_before);
        assert_eq!(info["not_after"], not_before + duocb_core::auth::CARD_TTL_SECS);
        assert_eq!(info["expired"], true);
        assert_eq!(info["not_yet_valid"], true);
        assert_eq!(info["remaining_secs"], 0);
    }

    /// Both devices ask this from the same two cards and must be told opposite
    /// things — that is the whole point of not asking the user.
    #[test]
    fn session_role_is_opposite_on_the_two_devices() {
        let a = Identity::generate().card("mac-book", "a7B2c3D4").unwrap();
        let b = Identity::generate().card("pixel", "9zKtm4Qp").unwrap();
        let card = |c: &IdentityCard| std::ffi::CString::new(c.encode()).unwrap();
        let (card_a, card_b) = (card(&a), card(&b));
        let role = |mine: &std::ffi::CString, theirs: &std::ffi::CString| unsafe {
            duocb_session_role(mine.as_ptr(), theirs.as_ptr())
        };

        let mine = role(&card_a, &card_b);
        assert!(mine == 0 || mine == 1);
        assert_eq!(role(&card_b, &card_a), 1 - mine, "exactly one device hosts");

        // The same card in both slots is not a pairing.
        assert_eq!(role(&card_a, &card_a), -1);
        let junk = std::ffi::CString::new("not a card").unwrap();
        assert_eq!(role(&card_a, &junk), -1);
    }

    /// The pairing code the confirmation screens render must be identical no
    /// matter which side computes it, must be the one duocb-core derives from
    /// the two keys, and must refuse a same-card call — that comparison would
    /// always "match" while checking nothing.
    #[test]
    fn pairing_code_is_order_free_and_refuses_a_self_pair() {
        let a = Identity::generate();
        let b = Identity::generate();
        let card_a = std::ffi::CString::new(
            a.card("mac-book", "a7B2c3D4").unwrap().encode(),
        )
        .unwrap();
        let card_b = std::ffi::CString::new(
            b.card("pixel", "9zKtm4Qp").unwrap().encode(),
        )
        .unwrap();

        let code = |x: &std::ffi::CString, y: &std::ffi::CString| {
            let mut buf = [0 as c_char; 128];
            let rc = unsafe {
                duocb_pairing_code(x.as_ptr(), y.as_ptr(), buf.as_mut_ptr(), buf.len())
            };
            assert_eq!(rc, 1);
            unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap().to_string()
        };
        let forward = code(&card_a, &card_b);
        assert_eq!(forward, code(&card_b, &card_a));
        assert_eq!(
            forward,
            duocb_core::auth::pairing_code(&a.public_key(), &b.public_key()).unwrap()
        );

        let mut buf = [0 as c_char; 128];
        let rc = unsafe {
            duocb_pairing_code(card_a.as_ptr(), card_a.as_ptr(), buf.as_mut_ptr(), buf.len())
        };
        assert_eq!(rc, -1, "one key on both sides compares nothing");
    }

    #[test]
    fn event_json_maps_the_card_setup_events() {
        let card = Identity::generate().card("pixel", "9zKtm4Qp").unwrap();
        let json: serde_json::Value = serde_json::from_str(&event_json(
            &NetEvent::PeerCardReceived(Box::new(card.clone())),
        ))
        .unwrap();
        assert_eq!(json["type"], "peer_card_received");
        assert_eq!(json["card"], card.encode());
        assert_eq!(json["info"]["fingerprint"], card.fingerprint());

        let json: serde_json::Value = serde_json::from_str(&event_json(&NetEvent::PinRotated {
            pin_display: "K7P2-9QXM".into(),
            seconds_left: 42,
            host_lan_ip: Some("192.168.1.9".into()),
        }))
        .unwrap();
        assert_eq!(json["type"], "pin_rotated");
        assert_eq!(json["seconds_left"], 42);
        assert_eq!(json["host_lan_ip"], "192.168.1.9");

        let json: serde_json::Value =
            serde_json::from_str(&event_json(&NetEvent::Status(ConnStatus::Reconnecting {
                attempt: 3,
                max: 10,
            })))
            .unwrap();
        assert_eq!(json["state"], "reconnecting");
        assert_eq!(json["attempt"], 3);
        assert_eq!(json["max"], 10);
    }

    #[test]
    fn write_cstr_truncates_on_utf8_boundaries() {
        let mut buf = [0 as c_char; 8];
        assert!(write_cstr(buf.as_mut_ptr(), buf.len(), "abc"));
        assert_eq!(
            unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap(),
            "abc"
        );

        // "é" is two bytes; a buffer that can hold only part of it must drop it
        // whole rather than write half a character.
        let mut buf = [0 as c_char; 3];
        assert!(!write_cstr(buf.as_mut_ptr(), buf.len(), "aéb"));
        assert_eq!(
            unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap(),
            "a"
        );
    }
}
