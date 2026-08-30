//! JNI surface for the Android app (`../duocb-android`).
//!
//! Android has no C-callable app boundary: Kotlin reaches native code only
//! through JNI, so this module exposes the same session lifecycle and pure
//! helpers as the C surface in `lib.rs` as the `external fun`s of one Kotlin
//! object, `com.andrewtheguy.duocb.DuocbNative`. The JNI symbol names below
//! encode that class; renaming it on either side breaks the link at load time
//! (the `applicationId` may change, the class may not). It adds nothing of its
//! own: every entry point converts Java strings, delegates to the shared
//! [`DuocbHandle`] methods or the core's pure helpers, and converts the result
//! back. The JSON config, event and `card_info` shapes are exactly the ones
//! documented in `ios/duocb.h`.
//!
//! Conventions, chosen so the Kotlin side reads naturally:
//!
//! - Pure helpers return the value, or `null` where the C surface returns `-1`
//!   (invalid input). A JNI string has no "buffer too small", so that case is
//!   gone.
//! - `validate*` return `null` for valid and the reason as a `String` otherwise
//!   — the inverse of the C `1`/`0` + `err_buf` pair.
//! - Handles cross the boundary as `jlong` (the raw `*mut DuocbHandle`); `0`
//!   is null. `start` returns the handle and, on failure, `0` with the error
//!   message in `out[0]`. As with the C API, exactly one `stop` per successful
//!   `start`, never a use afterwards, and one session per process.
//! - `stop` **blocks** for up to five seconds like `duocb_stop`; call it off
//!   the main thread.
//!
//! Never unwinds into the JVM: the release profile is `panic = "abort"`, so a
//! panic terminates the app process instead.

use std::ffi::c_void;
use std::sync::OnceLock;

use jni::JNIEnv;
use jni::objects::{JClass, JObject, JObjectArray, JString};
use jni::sys::{jint, jlong, jstring};

use duocb_core::auth::{Identity, IdentityCard};
use duocb_core::net::{SessionRole, session_role};

use crate::{DuocbHandle, identity_card_json, init_logging, start_session};

/// Set once `DuocbNative.init` has registered the app context; later calls are
/// no-ops (ndk-context aborts on a second registration).
static ANDROID_CONTEXT: OnceLock<()> = OnceLock::new();

/// `DuocbNative.init(context: Context)`: one-time process setup, to be called
/// from `Application.onCreate` before anything else. Routes `log` output to
/// logcat (tag `duocb`) and registers the JVM + application context with
/// `ndk-context`, which iroh's dependencies (hickory-resolver's system DNS
/// lookup, netwatch's interface enumeration) use to reach
/// `ConnectivityManager` through JNI — without it the first session aborts the
/// process with "android context was not initialized". Idempotent.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_init<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    context: JObject<'local>,
) {
    init_logging();
    if ANDROID_CONTEXT.get().is_some() {
        return;
    }
    let (vm, context_ref) = match (env.get_java_vm(), env.new_global_ref(&context)) {
        (Ok(vm), Ok(context_ref)) => (vm, context_ref),
        (Err(e), _) | (_, Err(e)) => {
            log::error!("duocb init: cannot capture the JVM/context: {e}");
            return;
        }
    };
    let vm_ptr = vm.get_java_vm_pointer().cast::<c_void>();
    let context_ptr = context_ref.as_obj().as_raw().cast::<c_void>();
    // The global ref must outlive every later JNI call through ndk-context,
    // i.e. the process: leak it on purpose.
    std::mem::forget(context_ref);
    // SAFETY: both pointers are valid for the life of the process (the JVM
    // pointer by construction, the context through the leaked global ref), and
    // the OnceLock guarantees a single registration.
    unsafe { ndk_context::initialize_android_context(vm_ptr, context_ptr) };
    let _ = ANDROID_CONTEXT.set(());
}

// ---------------------------------------------------------------------------
// Identity, card and name helpers (pure: no network, no storage)

/// `DuocbNative.generateIdentity(): String` — a fresh application private key
/// as NIP-19 `nsec`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_generateIdentity<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    new_jstring(&mut env, &Identity::generate().to_nsec())
}

/// `DuocbNative.generateSuffix(): String` — the permanent 8-character
/// device-name suffix. Mint once, persist, reuse for every self-card.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_generateSuffix<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    new_jstring(&mut env, &duocb_core::identity::generate_suffix())
}

/// `DuocbNative.generateIrohSecret(): String` — this device's iroh transport
/// key, 64 hex characters. Mint once, persist, pass as `iroh_secret` on every
/// `start`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_generateIrohSecret<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    new_jstring(
        &mut env,
        &hex::encode(duocb_core::iroh::SecretKey::generate().to_bytes()),
    )
}

/// `DuocbNative.validateIdentity(nsec: String): String?` — `null` if valid,
/// else the reason.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_validateIdentity<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    nsec: JString<'local>,
) -> jstring {
    let Some(nsec) = get_string(&mut env, &nsec) else {
        return new_jstring(&mut env, "invalid private key");
    };
    match Identity::parse_nsec(&nsec) {
        Ok(_) => std::ptr::null_mut(),
        Err(error) => new_jstring(&mut env, &format!("{error:#}")),
    }
}

/// `DuocbNative.identityPublicKey(nsec: String): String?` — the `npub`, or
/// `null` for an invalid key.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_identityPublicKey<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    nsec: JString<'local>,
) -> jstring {
    match get_string(&mut env, &nsec).and_then(|nsec| Identity::parse_nsec(&nsec).ok()) {
        Some(identity) => new_jstring(&mut env, &identity.to_npub()),
        None => std::ptr::null_mut(),
    }
}

/// `DuocbNative.identityFingerprint(nsec: String): String?` — the key's
/// human-comparable fingerprint (this device's half of any pairing code), or
/// `null` for an invalid key.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_identityFingerprint<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    nsec: JString<'local>,
) -> jstring {
    match get_string(&mut env, &nsec).and_then(|nsec| Identity::parse_nsec(&nsec).ok()) {
        Some(identity) => new_jstring(
            &mut env,
            &duocb_core::auth::key_fingerprint(&identity.public_key()),
        ),
        None => std::ptr::null_mut(),
    }
}

/// `DuocbNative.validateName(name: String): String?` — `null` if the short
/// device name is valid, else the reason.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_validateName<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    name: JString<'local>,
) -> jstring {
    let Some(name) = get_string(&mut env, &name) else {
        return new_jstring(&mut env, "enter a name");
    };
    match duocb_core::identity::validate_name(&name) {
        Ok(()) => std::ptr::null_mut(),
        Err(error) => new_jstring(&mut env, &format!("{error:#}")),
    }
}

/// `DuocbNative.displayIdentity(name: String, suffix: String): String` —
/// `<name>_<suffix>` for the name field's live preview. Does not validate.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_displayIdentity<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    name: JString<'local>,
    suffix: JString<'local>,
) -> jstring {
    let name = get_string(&mut env, &name).unwrap_or_default();
    let suffix = get_string(&mut env, &suffix).unwrap_or_default();
    new_jstring(
        &mut env,
        &duocb_core::identity::display_identity(&name, &suffix),
    )
}

/// `DuocbNative.createIdentityCard(nsec, name, suffix): String?` — a signed
/// self-card, or `null` when the key or name is invalid.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_createIdentityCard<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    nsec: JString<'local>,
    name: JString<'local>,
    suffix: JString<'local>,
) -> jstring {
    let (Some(nsec), Some(name), Some(suffix)) = (
        get_string(&mut env, &nsec),
        get_string(&mut env, &name),
        get_string(&mut env, &suffix),
    ) else {
        return std::ptr::null_mut();
    };
    let Ok(identity) = Identity::parse_nsec(&nsec) else {
        return std::ptr::null_mut();
    };
    match identity.card(&name, &suffix) {
        Ok(card) => new_jstring(&mut env, &card.encode()),
        Err(_) => std::ptr::null_mut(),
    }
}

/// `DuocbNative.validateIdentityCard(card: String): String?` — `null` if the
/// card is well formed and correctly signed, else the reason. Clock-free; use
/// `identityCardInfo` for the validity window.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_validateIdentityCard<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    card: JString<'local>,
) -> jstring {
    let Some(card) = get_string(&mut env, &card) else {
        return new_jstring(&mut env, "invalid identity card");
    };
    match IdentityCard::parse(&card) {
        Ok(_) => std::ptr::null_mut(),
        Err(error) => new_jstring(&mut env, &format!("{error:#}")),
    }
}

/// `DuocbNative.identityCardInfo(card: String): String?` — the `card_info`
/// JSON object (see `duocb_identity_card_info`), or `null` for a card that does
/// not verify.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_identityCardInfo<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    card: JString<'local>,
) -> jstring {
    match get_string(&mut env, &card).and_then(|card| IdentityCard::parse(&card).ok()) {
        Some(card) => new_jstring(&mut env, &identity_card_json(&card).to_string()),
        None => std::ptr::null_mut(),
    }
}

/// `DuocbNative.pairingCode(cardA: String, cardB: String): String?` — the
/// order-normalized pairing code both devices render, or `null` when either
/// card fails verification or both carry the same key.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_pairingCode<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    card_a: JString<'local>,
    card_b: JString<'local>,
) -> jstring {
    let (Some(a), Some(b)) = (get_string(&mut env, &card_a), get_string(&mut env, &card_b)) else {
        return std::ptr::null_mut();
    };
    let (Ok(a), Ok(b)) = (IdentityCard::parse(&a), IdentityCard::parse(&b)) else {
        return std::ptr::null_mut();
    };
    match duocb_core::auth::pairing_code(&a.public_key(), &b.public_key()) {
        Ok(code) => new_jstring(&mut env, &code),
        Err(_) => std::ptr::null_mut(),
    }
}

/// `DuocbNative.sessionRole(selfCard: String, peerCard: String): Int` — which
/// half of a clipboard session this device runs with that peer: `1` hosts, `0`
/// dials, `-1` invalid input (a card fails verification, or both carry the
/// same key). Information for the session screen, never a switch.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_sessionRole<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    self_card: JString<'local>,
    peer_card: JString<'local>,
) -> jint {
    let (Some(mine), Some(theirs)) = (
        get_string(&mut env, &self_card),
        get_string(&mut env, &peer_card),
    ) else {
        return -1;
    };
    let (Ok(mine), Ok(theirs)) = (IdentityCard::parse(&mine), IdentityCard::parse(&theirs)) else {
        return -1;
    };
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

/// `DuocbNative.normalizePin(pin: String): String?` — the canonical 8-character
/// PIN, or `null` while the entry is not a valid PIN (check digit included).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_normalizePin<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    pin: JString<'local>,
) -> jstring {
    match get_string(&mut env, &pin).and_then(|pin| duocb_core::pin::normalize_pin(&pin)) {
        Some(canonical) => new_jstring(&mut env, &canonical),
        None => std::ptr::null_mut(),
    }
}

/// `DuocbNative.formatPin(pin: String): String` — a canonical PIN as
/// `XXXX-XXXX`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_formatPin<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    pin: JString<'local>,
) -> jstring {
    let pin = get_string(&mut env, &pin).unwrap_or_default();
    new_jstring(&mut env, &duocb_core::pin::format_pin(&pin))
}

/// `DuocbNative.sanitizePinChars(input: String): String` — only the characters
/// a PIN can contain, uppercased, I/L→1 and O→0. Feed every keystroke through.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_sanitizePinChars<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    input: JString<'local>,
) -> jstring {
    let input = get_string(&mut env, &input).unwrap_or_default();
    new_jstring(&mut env, &duocb_core::pin::sanitize_pin_chars(&input))
}

/// `DuocbNative.splitPinGroups(first: String, second: String): String` —
/// `{"first","second"}` redistributed so typing past one group spills into
/// the next.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_splitPinGroups<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    first: JString<'local>,
    second: JString<'local>,
) -> jstring {
    let first = get_string(&mut env, &first).unwrap_or_default();
    let second = get_string(&mut env, &second).unwrap_or_default();
    let (first, second) = duocb_core::pin::split_pin_groups(&first, &second);
    new_jstring(
        &mut env,
        &serde_json::json!({ "first": first, "second": second }).to_string(),
    )
}

/// `DuocbNative.pinProgress(input: String): String` —
/// `{"entered","total","group"}` for the "keep typing" hint.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_pinProgress<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    input: JString<'local>,
) -> jstring {
    let input = get_string(&mut env, &input).unwrap_or_default();
    new_jstring(
        &mut env,
        &serde_json::json!({
            "entered": duocb_core::pin::pin_input_len(&input),
            "total": duocb_core::pin::PIN_LEN,
            "group": duocb_core::pin::PIN_GROUP_LEN,
        })
        .to_string(),
    )
}

// ---------------------------------------------------------------------------
// Manual host-IP entry (card setup's multicast-blocked fallback)

/// `DuocbNative.joinIpContext(): String` —
/// `{"prefix","placeholder","hint","label"}` constraining the host-IP field to
/// this device's own subnet; all `""` when none is detected.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_joinIpContext<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let constraint = duocb_core::subnet::JoinIpConstraint::detect();
    new_jstring(
        &mut env,
        &serde_json::json!({
            "prefix": constraint.locked_prefix(),
            "placeholder": constraint.host_placeholder(),
            "hint": constraint.hint(),
            "label": constraint.label(),
        })
        .to_string(),
    )
}

/// `DuocbNative.resolveJoinIp(entry: String): String` — the entry checked
/// against this device's subnet, as
/// `{"outcome":"in_range","ip":"192.168.1.42"}` (pass `ip` as the config
/// `ip`), `{"outcome":"out_of_range"}`, `{"outcome":"empty"}` (omit `ip` and
/// browse DNS-SD) or `{"outcome":"malformed"}`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_resolveJoinIp<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    entry: JString<'local>,
) -> jstring {
    use duocb_core::subnet::JoinIpOutcome;
    let entry = get_string(&mut env, &entry).unwrap_or_default();
    let value = match duocb_core::subnet::JoinIpConstraint::detect().resolve(&entry) {
        JoinIpOutcome::InRange(addr) => {
            serde_json::json!({ "outcome": "in_range", "ip": addr.to_string() })
        }
        JoinIpOutcome::OutOfRange => serde_json::json!({ "outcome": "out_of_range" }),
        JoinIpOutcome::Empty => serde_json::json!({ "outcome": "empty" }),
        JoinIpOutcome::Malformed => serde_json::json!({ "outcome": "malformed" }),
    };
    new_jstring(&mut env, &value.to_string())
}

// ---------------------------------------------------------------------------
// Session lifecycle

/// `DuocbNative.start(configJson: String, out: Array<String?>): Long` — start
/// a session per the config's `role` (the JSON documented in `ios/duocb.h`).
/// Returns the handle, or `0` with the reason in `out[0]`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_start<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    config_json: JString<'local>,
    out: JObjectArray<'local>,
) -> jlong {
    let Some(json) = get_string(&mut env, &config_json) else {
        set_out(&mut env, &out, "configJson is not a valid string");
        return 0;
    };
    match start_session(&json) {
        Ok(handle) => Box::into_raw(Box::new(handle)) as jlong,
        Err(msg) => {
            set_out(&mut env, &out, &msg);
            0
        }
    }
}

/// `DuocbNative.nextEvent(handle: Long): String?` — the next pending event as
/// JSON, or `null` when none is pending (or the handle is `0`). Poll on a timer
/// until it returns `null`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_nextEvent<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jstring {
    match handle_ref(handle).and_then(DuocbHandle::take_event) {
        Some(json) => new_jstring(&mut env, &json),
        None => std::ptr::null_mut(),
    }
}

/// `DuocbNative.sendClipboard(handle: Long, text: String): Int` — queue a
/// clipboard text for the peer; the outcome arrives as `item_sent` or `error`.
/// `0` = queued, `-1` = null handle or text.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_sendClipboard<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    text: JString<'local>,
) -> jint {
    let (Some(handle), Some(text)) = (handle_ref(handle), get_string(&mut env, &text)) else {
        return -1;
    };
    handle.send_clipboard(text);
    0
}

/// `DuocbNative.queryConnPath(handle: Long): Int` — request a `conn_path`
/// event. `0` = requested, `-1` = null handle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_queryConnPath(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    match handle_ref(handle) {
        Some(handle) => {
            handle.query_conn_path();
            0
        }
        None => -1,
    }
}

/// `DuocbNative.refreshPin(handle: Long): Int` — card host only: mint a fresh
/// PIN now, invalidating every earlier one. `0` = requested, `-1` = null handle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_refreshPin(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    match handle_ref(handle) {
        Some(handle) => {
            handle.refresh_pin();
            0
        }
        None => -1,
    }
}

/// `DuocbNative.disconnect(handle: Long): Int` — end the session but keep the
/// runtime and its node id (see `duocb_disconnect`). `0` = requested, `-1` =
/// null handle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_disconnect(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    match handle_ref(handle) {
        Some(handle) => {
            handle.disconnect();
            0
        }
        None => -1,
    }
}

/// `DuocbNative.isRunning(handle: Long): Int` — `1` runtime alive, `0` runtime
/// ended (stop and start afresh), `-1` null handle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_isRunning(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    match handle_ref(handle) {
        Some(handle) if handle.is_running() => 1,
        Some(_) => 0,
        None => -1,
    }
}

/// `DuocbNative.reconnect(handle: Long): Int` — re-issue the session command on
/// the still-running runtime (see `duocb_reconnect`). `0` = requested, `-1` =
/// null handle, `-2` = runtime unavailable (stop, then a fresh `start`).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_reconnect(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    match handle_ref(handle) {
        Some(handle) if handle.reconnect() => 0,
        Some(_) => -2,
        None => -1,
    }
}

/// `DuocbNative.stop(handle: Long)` — graceful shutdown and free. `0` is a
/// no-op; the handle is invalid afterwards. **Blocks** up to five seconds.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_andrewtheguy_duocb_DuocbNative_stop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    // SAFETY: the Kotlin side passes back a value obtained from `start` and
    // never reuses it after `stop` (see the module docs for the contract).
    unsafe { Box::from_raw(handle as *mut DuocbHandle) }.shutdown();
}

// ---------------------------------------------------------------------------
// JNI helpers

/// Borrow the handle behind a `jlong`, or `None` for `0`.
fn handle_ref<'a>(handle: jlong) -> Option<&'a DuocbHandle> {
    if handle == 0 {
        return None;
    }
    // SAFETY: see `Java_…_stop`; a non-zero value is a live handle from `start`.
    Some(unsafe { &*(handle as *const DuocbHandle) })
}

/// Copy a Java string out, or `None` for null / non-UTF-8 input.
fn get_string(env: &mut JNIEnv, s: &JString) -> Option<String> {
    if s.is_null() {
        return None;
    }
    env.get_string(s).ok().map(|js| js.into())
}

/// Build a Java string, or null (with a pending `OutOfMemoryError`) when the
/// JVM could not allocate it.
fn new_jstring(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s)
        .map(|js| js.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Store `value` in `out[0]`. Failures (null array, zero length) are logged:
/// the caller already reports success/failure through its return value.
fn set_out(env: &mut JNIEnv, out: &JObjectArray, value: &str) {
    let Ok(js) = env.new_string(value) else {
        log::error!("cannot build JNI out string");
        return;
    };
    if let Err(e) = env.set_object_array_element(out, 0, &js) {
        log::error!("cannot store JNI out string: {e}");
        let _ = env.exception_clear();
    }
}
