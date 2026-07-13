/*
 * duocb.h — C interface to libduocb.xcframework for the iOS app.
 * Hand-maintained; keep in sync with crates/duocb-ffi/src/lib.rs.
 * Build with ./build-ios.sh (stages dist/ios/libduocb.xcframework + this header).
 *
 * Configure mode: every device shares one standing secret (the token) and
 * broadcasts a presence record under its unique display identity
 * "<name>_<suffix>" (e.g. "mac-book_a7B2c3D4"). Role "hub" broadcasts presence
 * and browses the peer list without a session (the screen where the user picks
 * what to do); role "start" hosts (its record carries the node id); role
 * "join" dials exactly the device named by "peer". To move from browsing to a
 * session, stop the hub instance and start a fresh one with the chosen role
 * (and, for join, the peer display picked from the last "peer_list" event).
 *
 * Quick mode: ephemeral device-to-device pairing with no standing state and no
 * identity. Role "quick_host" publishes a rotating 8-char PIN (a "pin_rotated"
 * event fires on every rotation until a peer pairs, then "pin_cleared"); role
 * "quick_join" dials the PIN typed by the user. The rendezvous channel is
 * fixed to nostr relays + LAN mDNS (the desktop "P" preset); the LAN-only /
 * nostr-only presets and manual mode remain desktop-only.
 *
 * Lifecycle:
 *   1. duocb_init_logging()                                   (once, optional)
 *   2. duocb_start(configJson, errBuf, errLen) -> handle      (NULL on error;
 *        errBuf holds the message). ONE instance per process at a time.
 *   3. duocb_next_event(handle, buf, len) in a loop on a timer:
 *        1 = one JSON event written, call again; 0 = none pending;
 *        -1 = NULL handle; -2 = buf too small (event retained, retry larger).
 *   -  duocb_refresh_peers(handle)             (re-fetch the device list; the
 *                                               result arrives as a "peer_list"
 *                                               event. The hub role fetches once
 *                                               on start by itself.)
 *   -  duocb_send_clipboard(handle, utf8Text)  (outcome arrives as an event)
 *   -  duocb_query_conn_path(handle)           (answer arrives as a "conn_path" event)
 *   4. duocb_stop(handle)                      (frees the handle)
 *
 * Config JSON (configure mode):
 *   {"role":"hub"|"start"|"join","token":"d…47 chars","name":"mac1",
 *    "suffix":"a7B2c3D4",                      permanent 8-char device id; mint
 *                                              once with duocb_generate_suffix
 *                                              and persist forever (Keychain)
 *    "peer":"mac2_x9Y8z7W6",                   join role only: the target
 *                                              device's display identity
 *    "relays":["wss://…"]}                     relays optional (built-in defaults)
 *
 * Config JSON (quick mode — no token/name/suffix/peer):
 *   {"role":"quick_host"}
 *   {"role":"quick_join","pin":"abcd-2345"}    pin: as typed by the user
 *                                              (dashes/spaces/lowercase ok;
 *                                              rejected with an error if the
 *                                              check digit doesn't match)
 *
 * Events (one JSON object per duocb_next_event call), by "type":
 *   server_ready      {node_id, token_fingerprint}
 *   client_ready      {node_id, token_fingerprint}
 *   status            {state: idle|starting|listening|resolving|connecting|
 *                             authenticating|connected|reconnecting,
 *                      attempt?, max?}          (attempt/max only when reconnecting)
 *   peer_paired       {peer_node_id}
 *   peer_disconnected {}
 *   conn_path         {paths: [{kind: direct|relay|other, display, selected}]}
 *   item_received     {text, pulled}           (text can be up to 1 MiB; a
 *                                               2 MiB buffer always fits.
 *                                               pulled=true marks a resume
 *                                               re-delivery of the peer's
 *                                               latest item — skip it if the
 *                                               inbox already holds that text)
 *   item_sent         {}
 *   pin_rotated       {pin_display, seconds_left} (quick_host: the current PIN
 *                                               as "XXXX-XXXX" and how long
 *                                               until it rotates; fires again
 *                                               on every rotation)
 *   pin_cleared       {}                        (quick_host: a peer paired or
 *                                               publishing stopped — hide the
 *                                               PIN)
 *   peer_list         {peers: [{display, name, suffix,
 *                               last_seen_unix}]}   (no online/offline or
 *                                               hosting flag: relay freshness is
 *                                               unreliable. Any listed peer is
 *                                               joinable — a join re-resolves and
 *                                               retries, and the iroh dial is the
 *                                               real liveness check)
 *   presence_conflict {message}                (another live process publishes
 *                                               as this device; broadcasting
 *                                               stopped)
 *   error             {message}
 *
 * All strings are NUL-terminated UTF-8. All functions are NULL-safe and never
 * unwind into Swift (the Rust workspace builds with panic=abort).
 */
#ifndef DUOCB_H
#define DUOCB_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DuocbHandle DuocbHandle;

/* Route Rust log output to stderr (Xcode console / unified log). Idempotent. */
void duocb_init_logging(void);

/* Token helpers for the setup UX. Tokens are 47 chars; fingerprints are
 * 19 chars ("xxxx-xxxx-xxxx-xxxx") — a 64-byte buffer is ample for both. */

/* Generate a fresh token. 1 = written, 0 = buffer too small, -1 = NULL buffer. */
int duocb_generate_token(char *out_buf, size_t out_len);

/* Generate this device's permanent 8-char identity suffix. Call once on first
 * launch and persist the result forever — it must never change, even when the
 * secret is replaced. 1 = written, 0 = buffer too small, -1 = NULL buffer. */
int duocb_generate_suffix(char *out_buf, size_t out_len);

/* 1 = valid, 0 = invalid (reason written to err_buf), -1 = NULL argument. */
int duocb_validate_token(const char *token, char *err_buf, size_t err_len);

/* Display fingerprint of a valid token. 1 = written, 0 = buffer too small,
 * -1 = NULL argument or invalid token. */
int duocb_token_fingerprint(const char *token, char *out_buf, size_t out_len);

/* Normalize a user-typed quick-pair PIN to canonical form (8 uppercase
 * Crockford characters): strips dashes/spaces, uppercases, maps I/L->1 and
 * O->0, and verifies the trailing check digit. Use for live validation of the
 * join field; duocb_start re-normalizes anyway. 1 = valid (canonical PIN
 * written), 0 = invalid PIN, -1 = NULL argument or buffer < 9 bytes. */
int duocb_normalize_pin(const char *pin, char *out_buf, size_t out_len);

/* Start a session (configure or quick mode, per the config's "role").
 * Returns a non-NULL handle, or NULL with the error message in err_buf. */
DuocbHandle *duocb_start(const char *config_json, char *err_buf, size_t err_len);

/* Drain one pending event as JSON (see header comment for return codes). */
int duocb_next_event(const DuocbHandle *handle, char *out_buf, size_t out_len);

/* Re-fetch the presence records of the other devices sharing the secret; the
 * result arrives as a {"type":"peer_list"} event. At most one fetch runs at a
 * time (extra requests while one is in flight are dropped).
 * 0 = requested, -1 = NULL handle. */
int duocb_refresh_peers(const DuocbHandle *handle);

/* Queue a clipboard text for the peer. 0 = queued (outcome arrives as an
 * "item_sent" or "error" event), -1 = NULL/invalid argument. */
int duocb_send_clipboard(const DuocbHandle *handle, const char *text);

/* Request a point-in-time connection-path snapshot; the reply arrives as a
 * {"type":"conn_path"} event. 0 = requested, -1 = NULL handle. */
int duocb_query_conn_path(const DuocbHandle *handle);

/* 1 = runtime alive, 0 = runtime ended (fatal — stop and start fresh),
 * -1 = NULL handle. */
int duocb_is_running(const DuocbHandle *handle);

/* Stop the session and free the handle. NULL is a safe no-op. */
void duocb_stop(DuocbHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* DUOCB_H */
