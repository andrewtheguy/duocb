//! C FFI surface for the iOS app (`aarch64-apple-ios`).
//!
//! The app links `libduocb.xcframework` (containing `libduocb.a` slices) and
//! drives the clipboard-pairing runtime with these calls:
//!
//! 1. [`duocb_start`] — parse the JSON config, spawn the networking runtime
//!    ([`duocb_core::net::runtime::net_main`]) on an embedded tokio runtime,
//!    and issue the role's initial command. Configure-mode roles ("hub",
//!    "start", "join") take the shared `token`, this device's short `name`
//!    and permanent 8-char `suffix` (plus the `peer` display identity to dial
//!    for "join") and start the presence broadcast; the "hub" role runs
//!    presence + peer discovery only (an initial peer fetch is issued, its
//!    result arriving as a `peer_list` event) so the app can show the device
//!    list before the user commits to a role. Quick-mode roles ("quick_host",
//!    "quick_join") are identity-less — no token/name/suffix, no presence:
//!    "quick_host" publishes a rotating PIN rendezvous (nostr + LAN) and
//!    "quick_join" dials the `pin` typed by the user. Returns an opaque
//!    handle. At most **one** instance may run at a time (a process-global
//!    guard rejects a second).
//! 2. [`duocb_next_event`] — drain one pending [`NetEvent`] as a JSON string.
//!    The runtime is event-driven; Swift polls this on a timer until it
//!    returns 0.
//! 3. [`duocb_refresh_peers`] — re-fetch the presence records on demand; the
//!    result arrives as a `peer_list` event (valid in every role, though the
//!    hub is the natural place to poll it).
//! 4. [`duocb_send_clipboard`] / [`duocb_query_conn_path`] — fire-and-forget
//!    commands; outcomes arrive as `item_sent`/`error` and `conn_path` events.
//! 5. [`duocb_stop`] — shut the runtime down and free the handle.
//!
//! Quick mode is fixed to [`PinChannel::NostrAndLan`] (the desktop "P"
//! preset); the LAN-only / nostr-only presets and manual mode remain
//! desktop-only. Token/name/suffix persistence is the caller's job (Keychain
//! on iOS); mint the suffix once with [`duocb_generate_suffix`] and reuse it
//! forever.
//!
//! The intended app flow mirrors the desktop hub: run a "hub" instance while
//! the device list is on screen, and when the user picks an action stop it
//! and start a fresh instance with role "start" (host) or "join" plus the
//! selected peer's display identity from the last `peer_list` event.
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
    ConnStatus, DialSpec, EventSender, NetEvent, PinChannel, ServerMode, TokenIdentity, UiCommand,
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
}

#[derive(Deserialize)]
struct FfiConfig {
    role: Role,
    /// Configure-mode roles: 47-char duocb auth token (the standing secret)
    /// shared by all devices.
    #[serde(default)]
    token: Option<String>,
    /// Configure-mode roles: this device's short name (`A-Za-z0-9-`, ≤ 24 chars).
    #[serde(default)]
    name: Option<String>,
    /// Configure-mode roles: this device's permanent 8-char suffix (mint once
    /// with `duocb_generate_suffix`, persist forever).
    #[serde(default)]
    suffix: Option<String>,
    /// Join role only: the target device's full display identity as shown in
    /// the peer list, e.g. `"mac-book_a7B2c3D4"`.
    #[serde(default)]
    peer: Option<String>,
    /// QuickJoin role only: the PIN shown on the hosting device, in any
    /// user-typed form (dashes/spaces/lowercase ok).
    #[serde(default)]
    pin: Option<String>,
    /// Empty/omitted means the built-in default relays.
    #[serde(default)]
    relays: Vec<String>,
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

/// Generate a fresh 47-char auth token into `out_buf`.
/// Returns 1 on success, 0 if the buffer is too small, -1 on a NULL buffer.
/// # Safety
/// `out_buf` must be NULL or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_generate_token(out_buf: *mut c_char, out_len: usize) -> c_int {
    if out_buf.is_null() {
        return -1;
    }
    if write_cstr(out_buf, out_len, &duocb_core::auth::generate_token()) {
        1
    } else {
        0
    }
}

/// Generate this device's permanent 8-char identity suffix into `out_buf`.
/// Call once on first launch and persist the result forever (it must never
/// change, even when the secret is replaced).
/// Returns 1 on success, 0 if the buffer is too small, -1 on a NULL buffer.
/// # Safety
/// `out_buf` must be NULL or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_generate_suffix(out_buf: *mut c_char, out_len: usize) -> c_int {
    if out_buf.is_null() {
        return -1;
    }
    if write_cstr(out_buf, out_len, &duocb_core::identity::generate_suffix()) {
        1
    } else {
        0
    }
}

/// Validate a token's format. Returns 1 if valid; 0 if invalid (the reason is
/// written to `err_buf` when provided); -1 on NULL/non-UTF-8 input.
/// # Safety
/// `token` must be NULL or a valid NUL-terminated C string; `err_buf` must be
/// NULL or point to at least `err_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_validate_token(
    token: *const c_char,
    err_buf: *mut c_char,
    err_len: usize,
) -> c_int {
    let Some(token) = (unsafe { cstr_arg(token) }) else {
        return -1;
    };
    match duocb_core::auth::validate_token(token) {
        Ok(()) => 1,
        Err(err) => {
            write_cstr(err_buf, err_len, &format!("{err:#}"));
            0
        }
    }
}

/// Write the token's display fingerprint (`xxxx-xxxx-xxxx-xxxx`) to `out_buf`.
/// Returns 1 on success, 0 if the buffer is too small, -1 on NULL/non-UTF-8
/// input or an invalid token.
/// # Safety
/// `token` must be NULL or a valid NUL-terminated C string; `out_buf` must be
/// NULL or point to at least `out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_token_fingerprint(
    token: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    let Some(token) = (unsafe { cstr_arg(token) }) else {
        return -1;
    };
    if duocb_core::auth::validate_token(token).is_err() {
        return -1;
    }
    if write_cstr(out_buf, out_len, &duocb_core::auth::token_fingerprint(token)) {
        1
    } else {
        0
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
    let (identity, cmd) = build_initial_commands(cfg)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to build tokio runtime: {e}"))?;
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, event_rx) = std::sync::mpsc::channel();
    // No waker: Swift polls duocb_next_event on a timer.
    let events = EventSender::new(event_tx, None);
    let task = runtime.spawn(duocb_core::net::runtime::net_main(cmd_rx, events));

    // The presence broadcast makes this device visible in the other devices'
    // lists and, for the start role, carries the hosting node id to the
    // joiner. Quick mode is identity-less and runs no presence.
    if let Some(identity) = identity {
        cmd_tx
            .send(UiCommand::SetPresence {
                identity: Some(identity),
            })
            .map_err(|_| "runtime unavailable".to_string())?;
    }
    cmd_tx.send(cmd).map_err(|_| "runtime unavailable".to_string())?;

    Ok(DuocbHandle {
        runtime,
        cmd_tx,
        events: Mutex::new(event_rx),
        pending: Mutex::new(None),
        task,
    })
}

/// Validate the config and resolve it into the presence identity (configure
/// mode only) plus the role's initial runtime command.
fn build_initial_commands(cfg: FfiConfig) -> Result<(Option<TokenIdentity>, UiCommand), String> {
    let relays = if cfg.relays.is_empty() {
        duocb_core::nostr::DEFAULT_NOSTR_RELAYS
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        cfg.relays
    };

    // Quick roles first: identity-less, so none of the token/name/suffix
    // validation below applies.
    match cfg.role {
        Role::QuickHost => {
            return Ok((
                None,
                UiCommand::StartServer {
                    mode: ServerMode::Pin {
                        relays,
                        channel: PinChannel::NostrAndLan,
                    },
                },
            ));
        }
        Role::QuickJoin => {
            let canonical_pin =
                duocb_core::pin::normalize_pin(cfg.pin.as_deref().unwrap_or_default())
                    .ok_or("invalid PIN (enter the 8 characters shown on the other device)")?;
            return Ok((
                None,
                UiCommand::Connect {
                    spec: DialSpec::Pin {
                        canonical_pin,
                        relays,
                        channel: PinChannel::NostrAndLan,
                    },
                },
            ));
        }
        Role::Hub | Role::Start | Role::Join => {}
    }

    let token = cfg.token.ok_or("token is required")?;
    duocb_core::auth::validate_token(&token).map_err(|e| format!("invalid token: {e:#}"))?;
    let name = cfg.name.ok_or("name is required")?.trim().to_string();
    duocb_core::identity::validate_name(&name).map_err(|e| format!("invalid name: {e:#}"))?;
    let suffix = cfg.suffix.ok_or("suffix is required")?;
    if !duocb_core::identity::is_valid_suffix(&suffix) {
        return Err("invalid suffix (mint one with duocb_generate_suffix)".into());
    }
    let identity = TokenIdentity {
        token,
        name,
        suffix,
        relays,
    };

    let cmd = match cfg.role {
        // The hub browses: presence runs regardless (see start_inner), so just
        // kick off the initial peer fetch — its result arrives as a
        // `peer_list` event. duocb_refresh_peers re-runs it on demand.
        Role::Hub => UiCommand::RefreshPeers,
        Role::Start => UiCommand::StartServer {
            mode: ServerMode::NostrToken {
                identity: identity.clone(),
            },
        },
        Role::Join => UiCommand::Connect {
            spec: DialSpec::NostrToken {
                peer_display: cfg
                    .peer
                    .as_deref()
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .ok_or("peer (the target device's display identity) is required for join")?
                    .to_string(),
                identity: identity.clone(),
            },
        },
        Role::QuickHost | Role::QuickJoin => unreachable!("handled above"),
    };
    Ok((Some(identity), cmd))
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

/// Re-fetch the presence records of the other devices sharing the secret; the
/// result arrives as a `peer_list` event. At most one fetch runs at a time
/// (extra requests while one is in flight are dropped by the runtime).
/// Returns 0 = requested, -1 = NULL handle.
/// # Safety
/// `handle` must be NULL or a live handle from [`duocb_start`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duocb_refresh_peers(handle: *const DuocbHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &*handle };
    let _ = handle.cmd_tx.send(UiCommand::RefreshPeers);
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
            token_fingerprint,
            ..
        } => json!({
            "type": "server_ready",
            "node_id": node_id,
            "token_fingerprint": token_fingerprint,
        }),
        NetEvent::ClientReady {
            node_id,
            token_fingerprint,
        } => json!({
            "type": "client_ready",
            "node_id": node_id,
            "token_fingerprint": token_fingerprint,
        }),
        NetEvent::PinRotated {
            pin_display,
            seconds_left,
        } => json!({
            "type": "pin_rotated",
            "pin_display": pin_display,
            "seconds_left": seconds_left,
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
        NetEvent::PeerPaired { peer_node_id } => json!({
            "type": "peer_paired",
            "peer_node_id": peer_node_id,
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
        NetEvent::PeerList { peers } => json!({
            "type": "peer_list",
            "peers": peers
                .iter()
                .map(|p| {
                    json!({
                        "display": p.display(),
                        "name": p.name,
                        "suffix": p.suffix,
                        "last_seen_unix": p.last_seen_unix,
                    })
                })
                .collect::<Vec<_>>(),
        }),
        NetEvent::PresenceConflict { message } => {
            json!({ "type": "presence_conflict", "message": message })
        }
        NetEvent::Error(message) => json!({ "type": "error", "message": message }),
    };
    value.to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parses_roles_and_defaults_relays() {
        let cfg: FfiConfig = serde_json::from_str(
            r#"{"role":"start","token":"t","name":"mac","suffix":"a7B2c3D4"}"#,
        )
        .unwrap();
        assert!(matches!(cfg.role, Role::Start));
        assert!(cfg.relays.is_empty());
        assert!(cfg.peer.is_none());

        let cfg: FfiConfig = serde_json::from_str(
            r#"{"role":"join","token":"t","name":"phone","suffix":"x9Y8z7W6","peer":"mac_a7B2c3D4","relays":["wss://r.example"]}"#,
        )
        .unwrap();
        assert!(matches!(cfg.role, Role::Join));
        assert_eq!(cfg.peer.as_deref(), Some("mac_a7B2c3D4"));
        assert_eq!(cfg.relays, ["wss://r.example"]);

        // The hub role browses the peer list before a role is chosen — no peer.
        let cfg: FfiConfig = serde_json::from_str(
            r#"{"role":"hub","token":"t","name":"phone","suffix":"x9Y8z7W6"}"#,
        )
        .unwrap();
        assert!(matches!(cfg.role, Role::Hub));
        assert!(cfg.peer.is_none());
    }

    #[test]
    fn config_rejects_unknown_role() {
        assert!(
            serde_json::from_str::<FfiConfig>(
                r#"{"role":"quick","token":"t","name":"x","suffix":"a7B2c3D4"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn config_parses_quick_roles_without_identity_fields() {
        let cfg: FfiConfig = serde_json::from_str(r#"{"role":"quick_host"}"#).unwrap();
        assert!(matches!(cfg.role, Role::QuickHost));
        assert!(cfg.token.is_none());

        let cfg: FfiConfig =
            serde_json::from_str(r#"{"role":"quick_join","pin":"abcd-2345"}"#).unwrap();
        assert!(matches!(cfg.role, Role::QuickJoin));
        assert_eq!(cfg.pin.as_deref(), Some("abcd-2345"));
    }

    #[test]
    fn join_requires_a_peer_identity() {
        let token = duocb_core::auth::generate_token();
        let json = format!(
            r#"{{"role":"join","token":"{token}","name":"phone","suffix":"x9Y8z7W6"}}"#
        );
        let cfg: FfiConfig = serde_json::from_str(&json).unwrap();
        let err = build_initial_commands(cfg)
            .err()
            .expect("join without peer fails");
        assert!(err.contains("peer"), "unexpected error: {err}");
    }

    #[test]
    fn identity_roles_require_a_token() {
        let cfg: FfiConfig =
            serde_json::from_str(r#"{"role":"hub","name":"phone","suffix":"x9Y8z7W6"}"#).unwrap();
        let err = build_initial_commands(cfg).err().expect("hub needs token");
        assert!(err.contains("token"), "unexpected error: {err}");
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
        let pin = duocb_core::pin::generate_pin();
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
            let err = build_initial_commands(cfg).err().expect("bad pin fails");
            assert!(err.contains("PIN"), "unexpected error: {err}");
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
    fn event_json_maps_token_mode_and_pin_events() {
        let json = event_json(&NetEvent::ServerReady {
            node_id: "abc".into(),
            token_fingerprint: Some("aaaa-bbbb-cccc-dddd".into()),
            pairing_code: None,
        });
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "server_ready");
        assert_eq!(v["node_id"], "abc");
        assert_eq!(v["token_fingerprint"], "aaaa-bbbb-cccc-dddd");

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
        });
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "pin_rotated");
        assert_eq!(v["pin_display"], "AAAA-BBBB");
        assert_eq!(v["seconds_left"], 10);

        let json = event_json(&NetEvent::PinCleared);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "pin_cleared");
    }

    #[test]
    fn normalize_pin_ffi_roundtrips_and_reports_errors() {
        let pin = duocb_core::pin::generate_pin();
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
