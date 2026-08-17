//! C FFI surface for the iOS app (`aarch64-apple-ios`).
//!
//! A thin translation layer over [`duocb_core::net`] and nothing more: it
//! parses a JSON config into a [`UiCommand`], drains [`NetEvent`]s back out as
//! JSON, and wraps the pure helpers the setup screens need. **No policy lives
//! here.** In particular, a card that arrives over a card-setup session is
//! handed up verified-but-untrusted; whether to store it is the app's call, and
//! it must not be made without the user comparing the pairing code from
//! [`duocb_pairing_code`] across both screens (see `duocb_core::card_exchange`).
//!
//! The app links `libduocb.xcframework` (containing `libduocb.a` slices) and
//! drives a session with:
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
//! # The four roles
//!
//! There is deliberately **no "hub" role**. The hub is pure local state — the
//! trusted-device list is read from the app's own storage, nothing is broadcast
//! and nothing is discovered — so no handle runs while it is on screen. A
//! handle exists only for one of:
//!
//! | role | core mapping | what it does |
//! | --- | --- | --- |
//! | `start` | [`ServerMode::Key`] | host a clipboard session for trusted peers |
//! | `join` | [`DialSpec::Key`] | dial exactly one trusted peer by public key |
//! | `card_host` | [`ServerMode::CardSetup`] | show a rotating PIN and trade cards |
//! | `card_join` | [`DialSpec::CardSetup`] | dial a typed PIN and trade cards |
//!
//! The two `card_*` roles never carry clipboard traffic. They exist to bootstrap
//! trust between two devices that have no shared clipboard to paste a card
//! through, and they end as soon as the cards have crossed.
//!
//! # Persistence is the caller's job
//!
//! The application private key (`nsec`), the permanent name suffix, the signed
//! self-card and the trusted peer cards are all passed in on every
//! [`duocb_start`] and never written anywhere by this library. On iOS the
//! secrets belong in the Keychain and the cards in ordinary app storage. These
//! application keys are deliberately unrelated to iroh's ephemeral transport
//! identity.
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
//! The workspace builds with `panic = "abort"` in release, so a Rust panic
//! terminates the process rather than unwinding across the C boundary.

use std::ffi::{CStr, c_char, c_int};
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::Deserialize;

use duocb_core::auth::{CARD_RENEW_BEFORE_SECS, Identity, IdentityCard, MAX_TRUSTED_PEERS};
use duocb_core::net::endpoint::ConnPathKind;
use duocb_core::net::{
    ConnStatus, DialSpec, EventSender, KeyIdentity, NetEvent, ServerMode, SignalChannel, UiCommand,
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
    /// The session command this handle was started with, replayed by
    /// [`duocb_reconnect`] into the still-running runtime so its session
    /// identity and pairing memory are reused.
    session_cmd: UiCommand,
    /// What [`duocb_disconnect`] sends: hosts stop serving, joiners hang up.
    disconnect_cmd: UiCommand,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FfiConfig {
    role: Role,
    /// `start`/`join`: this installation's NIP-19 `nsec`.
    #[serde(default)]
    identity_secret: Option<String>,
    /// Every role: this installation's persisted signed self-card.
    #[serde(default)]
    self_card: Option<String>,
    /// `start`/`join`: locally trusted signed cards (max [`MAX_TRUSTED_PEERS`]).
    #[serde(default)]
    peers: Vec<String>,
    /// `join` only: the selected peer's hex or NIP-19 public key. Must name a
    /// card in `peers`.
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
    /// The default: local network first, nostr relays as fallback. Resolves in
    /// well under a second for two devices in one room, and still reaches a
    /// device on another network.
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
    /// Host a clipboard session for locally trusted peers.
    Start,
    /// Dial one locally trusted peer.
    Join,
    /// Card setup: show a rotating PIN and trade identity cards.
    CardHost,
    /// Card setup: dial a typed PIN and trade identity cards.
    CardJoin,
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

/// Validate a signed identity card — signature, schema, name rules and expiry.
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
///  "created_at":1750000000,"expires_at":1752592000,"remaining_secs":1209600,
///  "expired":false,"needs_renewal":false}
/// ```
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
    session_cmd: UiCommand,
    disconnect_cmd: UiCommand,
}

impl StartPlan {
    fn host(cmd: UiCommand) -> Self {
        Self {
            session_cmd: cmd,
            disconnect_cmd: UiCommand::StopServer,
        }
    }

    fn dial(cmd: UiCommand) -> Self {
        Self {
            session_cmd: cmd,
            disconnect_cmd: UiCommand::Disconnect,
        }
    }
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

    // Every role needs a self-card; only the key roles need the private key.
    let self_card = IdentityCard::parse(cfg.self_card.as_deref().ok_or("self_card is required")?)
        .map_err(|error| format!("invalid self_card: {error:#}"))?;

    // One authoritative rule per field, each stated once: card setup is the
    // identity-less half of the protocol, and the PIN and its side-channel IP
    // belong to the one role that dials a PIN.
    let card_setup = matches!(cfg.role, Role::CardHost | Role::CardJoin);
    if card_setup && (cfg.identity_secret.is_some() || !cfg.peers.is_empty()) {
        return Err("card setup accepts only role, self_card, pin, ip, channel and relays".into());
    }
    if cfg.role != Role::CardJoin && (cfg.pin.is_some() || cfg.ip.is_some()) {
        return Err("pin and ip are only valid for the card_join role".into());
    }
    if cfg.role != Role::Join && cfg.peer_public_key.is_some() {
        return Err("peer_public_key is only valid for the join role".into());
    }

    match cfg.role {
        Role::CardHost => {
            return Ok(StartPlan::host(UiCommand::StartServer {
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
            return Ok(StartPlan::dial(UiCommand::Connect {
                spec: DialSpec::CardSetup {
                    canonical_pin,
                    self_card: Box::new(self_card),
                    target_ip,
                    channel,
                    relays,
                },
            }));
        }
        Role::Start | Role::Join => {}
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

    Ok(match cfg.role {
        Role::Start => StartPlan::host(UiCommand::StartServer {
            mode: ServerMode::Key {
                identity: Box::new(key_identity),
                channel,
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
                .find(|peer| peer.public_key().to_hex() == selected || peer.npub() == selected)
                .map(IdentityCard::public_key)
                .ok_or("peer_public_key is not in the local trusted peer list")?;
            StartPlan::dial(UiCommand::Connect {
                spec: DialSpec::Key {
                    identity: Box::new(key_identity),
                    peer_public_key,
                    channel,
                },
            })
        }
        Role::CardHost | Role::CardJoin => unreachable!("handled above"),
    })
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
    let handle = unsafe { &*handle };
    let _ = handle.cmd_tx.send(UiCommand::RefreshPin);
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
    let handle = unsafe { &*handle };
    let _ = handle.cmd_tx.send(UiCommand::QueryConnPath);
    0
}

/// End the session without tearing the handle down: a host stops serving, a
/// joiner hangs up. The runtime stays alive, so [`duocb_reconnect`] can resume
/// the same pairing afterwards. Returns 0 = requested, -1 = NULL handle.
/// # Safety
/// `handle` must be NULL or a live handle from [`duocb_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_disconnect(handle: *const DuocbHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &*handle };
    let _ = handle.cmd_tx.send(handle.disconnect_cmd.clone());
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
    let handle = unsafe { &*handle };
    if handle.task.is_finished() { 0 } else { 1 }
}

/// Re-issue the session command this handle was started with, on the handle's
/// still-running runtime. The runtime keeps the session identity and pairing
/// state (node id, the host's pair claim, the joiner's pinned dial target)
/// until the handle is stopped, so after a session ends on its own — e.g. the
/// joiner gave up reconnecting — this resumes the same pairing: the same node
/// id dials the same target and the peer recognizes it, with no re-pairing and
/// no fresh PIN. A fresh [`duocb_start`] would instead mint a new identity,
/// which an already-paired peer refuses. Progress arrives as the usual status
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
    let handle = unsafe { &*handle };
    if handle.task.is_finished() || handle.cmd_tx.send(handle.session_cmd.clone()).is_err() {
        return -2;
    }
    0
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
        "created_at": card.created_at(),
        "expires_at": card.expires_at(),
        "remaining_secs": remaining,
        "expired": !card.is_valid_at(now),
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

    fn build(json: &str) -> Result<StartPlan, String> {
        build_start_plan(serde_json::from_str(json).map_err(|e| e.to_string())?)
    }

    #[test]
    fn start_maps_to_a_key_server_on_the_default_channel() {
        let (nsec, card) = identity_with_card();
        let json = serde_json::json!({
            "role": "start",
            "identity_secret": nsec,
            "self_card": card,
        })
        .to_string();
        let resolved = build(&json).expect("valid start config");
        match resolved.session_cmd {
            UiCommand::StartServer {
                mode: ServerMode::Key { channel, .. },
            } => assert_eq!(channel, SignalChannel::LanThenNostr),
            other => panic!("unexpected command: {other:?}"),
        }
        assert!(matches!(resolved.disconnect_cmd, UiCommand::StopServer));
    }

    #[test]
    fn join_resolves_the_selected_peer_and_rejects_a_stranger() {
        let (nsec, card) = identity_with_card();
        let peer = Identity::generate();
        let peer_card = peer.card("pixel", "9zKtm4Qp").unwrap();
        let base = serde_json::json!({
            "role": "join",
            "identity_secret": nsec,
            "self_card": card,
            "peers": [peer_card.encode()],
        });

        let mut cfg = base.clone();
        cfg["peer_public_key"] = serde_json::json!(peer.public_key().to_hex());
        let resolved = build(&cfg.to_string()).expect("hex public key selects the peer");
        match resolved.session_cmd {
            UiCommand::Connect {
                spec: DialSpec::Key {
                    peer_public_key, ..
                },
            } => assert_eq!(peer_public_key, peer.public_key()),
            other => panic!("unexpected command: {other:?}"),
        }

        // The npub form of the same key is accepted too.
        let mut cfg = base.clone();
        cfg["peer_public_key"] = serde_json::json!(peer_card.npub());
        assert!(build(&cfg.to_string()).is_ok(), "npub selects the peer");

        // A key that is not in the local trusted list never dials.
        let mut cfg = base;
        cfg["peer_public_key"] = serde_json::json!(Identity::generate().public_key().to_hex());
        assert!(
            build(&cfg.to_string())
                .unwrap_err()
                .contains("not in the local trusted peer list")
        );
    }

    #[test]
    fn a_self_card_signed_by_another_key_is_refused() {
        let (nsec, _) = identity_with_card();
        let other_card = Identity::generate().card("pixel", "9zKtm4Qp").unwrap();
        let json = serde_json::json!({
            "role": "start",
            "identity_secret": nsec,
            "self_card": other_card.encode(),
        })
        .to_string();
        assert!(
            build(&json)
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
        let json = serde_json::json!({
            "role": "start",
            "identity_secret": nsec,
            "self_card": card.clone(),
            "pin": "K7P29QXM",
        })
        .to_string();
        assert!(build(&json).unwrap_err().contains("only valid for the card_join role"));

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
        // A card is minted with the full TTL, which is well past the renewal
        // window, so a fresh one never asks to be renewed.
        assert_eq!(info["needs_renewal"], false);
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
