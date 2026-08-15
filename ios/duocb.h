/*
 * duocb.h — C interface to libduocb.xcframework for the iOS app.
 * Hand-maintained; keep in sync with crates/duocb-ffi/src/lib.rs.
 *
 * ── Trust model ──────────────────────────────────────────────────────────
 * Each installation holds one persistent application keypair. Its private key
 * authenticates duocb's wire protocol and signs a portable identity card
 * naming `<short-name>_<permanent-suffix>`. That key is unrelated to iroh's
 * ephemeral transport key. Pairing is mutual: each installation stores the
 * other's verified signed card in its local trusted-peer list.
 *
 * Cards expire 30 days after they are minted and both sides refuse to pair on
 * a lapsed one; the only way back is for the owner to hand over a fresh card.
 * Re-mint the local self-card whenever duocb_identity_card_info reports
 * "needs_renewal".
 *
 * Generate the permanent suffix once, persist it, and reuse it for every
 * renamed or replacement self-card — it must survive an identity reset.
 *
 * ── Roles ────────────────────────────────────────────────────────────────
 * There is no "hub" role: the hub is pure local state (the trusted-device list
 * comes from app storage; nothing is broadcast or discovered), so no handle
 * runs while it is on screen. One handle exists per session, for one of:
 *
 *   start      host a clipboard session for locally trusted peers
 *   join       dial exactly one trusted peer, by application public key
 *   card_host  card setup: show a rotating PIN and trade identity cards
 *   card_join  card setup: dial a typed PIN and trade identity cards
 *
 * The two card_* roles never carry clipboard traffic. They bootstrap trust
 * between devices that have no shared clipboard to paste a card through, and
 * end as soon as the cards have crossed. A card received that way is verified
 * as well-formed and correctly signed and NOTHING MORE — the user must compare
 * its fingerprint against the value the other device shows before it is
 * stored.
 *
 * ── Config JSON (duocb_start) ────────────────────────────────────────────
 * {
 *   "role": "start" | "join" | "card_host" | "card_join",
 *   "self_card": "{ signed card JSON }",         // every role
 *   "identity_secret": "nsec1…",                 // start/join only
 *   "peers": ["{ signed peer card JSON }"],      // start/join only, max 128
 *   "peer_public_key": "hex or npub1…",          // join only; must be in peers
 *   "pin": "abcd-2345",                          // card_join only
 *   "ip": "192.168.1.42",                        // card_join only, optional
 *   "channel": "lan_then_nostr",                 // optional, see below
 *   "relays": ["wss://…"]                        // optional
 * }
 *
 * Validation is strict: a field that does not belong to the role is an error,
 * not an ignored key.
 *
 * "channel" chooses where the rendezvous records are put and looked for, and
 * governs card setup and clipboard sessions alike:
 *   lan_then_nostr  (default) local network first, nostr relays as fallback
 *   lan_only        no third-party server at all — works fully offline
 *   nostr_only      relays only; no mDNS query, no side-channel listener
 * The desktop fixes this at launch (--lan-only / --nostr-only); iOS picks it
 * per session from a setting. Both devices must be reachable on a channel they
 * share.
 *
 * "ip" is the LAN half of the card-setup lookup: the host's LAN IPv4 as shown
 * on the hosting device, letting a joiner pair where multicast is blocked.
 * Pass exactly what duocb_resolve_join_ip wrote. It requires a channel that
 * uses the local network.
 *
 * ── Local network ────────────────────────────────────────────────────────
 * The LAN rendezvous goes through the system mDNSResponder daemon (Bonjour),
 * so no multicast entitlement is involved. The app MUST list BOTH service
 * types under NSBonjourServices — `_duocb-pin._udp` (card setup) and
 * `_duocb-host._udp` (clipboard sessions) — and set
 * NSLocalNetworkUsageDescription. A missing entry does not fail to build; the
 * LAN path just silently never resolves.
 *
 * ── Event JSON types (duocb_next_event) ──────────────────────────────────
 *   server_ready        {node_id, identity_public_key}
 *   client_ready        {node_id, identity_public_key}
 *   status              {state, attempt?, max?}
 *   pin_rotated         {pin_display, seconds_left, host_lan_ip}
 *   pin_cleared         {}
 *   peer_paired         {peer_node_id, peer_public_key}   // key null in card setup
 *   peer_card_received  {card, info}                      // info = card_info shape
 *   peer_disconnected   {}
 *   conn_path           {paths:[{kind, display, selected}]}
 *   item_received       {text, pulled}
 *   item_sent           {}
 *   error               {message}
 *
 * peer_card_received always arrives before the session's closing
 * `status: idle`, so the confirmation screen is guaranteed to see the card.
 *
 * All strings are NUL-terminated UTF-8. One DuocbHandle may run per process.
 */
#ifndef DUOCB_H
#define DUOCB_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DuocbHandle DuocbHandle;

#define DUOCB_IDENTITY_BUF_LEN 128
#define DUOCB_SUFFIX_BUF_LEN 16
#define DUOCB_NAME_BUF_LEN 64
#define DUOCB_PUBLIC_KEY_BUF_LEN 128
#define DUOCB_FINGERPRINT_BUF_LEN 64
#define DUOCB_PIN_BUF_LEN 16
#define DUOCB_IDENTITY_CARD_BUF_LEN 4096
#define DUOCB_IDENTITY_CARD_INFO_BUF_LEN 1024
#define DUOCB_JOIN_IP_BUF_LEN 256

void duocb_init_logging(void);

/* ── Pure helpers ─────────────────────────────────────────────────────────
 * None of these touch the network or storage, so the setup screens may call
 * them freely for live validation.
 *
 * Output functions: 1 = written, 0 = buffer too small, -1 = NULL or invalid
 * input. Validation functions: 1 = valid, 0 = invalid with a message written
 * to err_buf when supplied, -1 = NULL/non-UTF-8 input. */

int duocb_generate_identity(char *out_buf, size_t out_len);
/* Generate once and persist; reuse for every replacement self-card. */
int duocb_generate_suffix(char *out_buf, size_t out_len);
int duocb_validate_identity(const char *private_key,
                            char *err_buf,
                            size_t err_len);
int duocb_identity_public_key(const char *private_key,
                              char *out_buf,
                              size_t out_len);
/* The human-comparable fingerprint of this identity's public key — shown on
 * the hub, and compared by eye against the other device during card setup.
 * Taken over the key, not a card, so it survives a re-mint. */
int duocb_identity_fingerprint(const char *private_key,
                               char *out_buf,
                               size_t out_len);
int duocb_validate_name(const char *name, char *err_buf, size_t err_len);
/* Compose "<name>_<suffix>" for the name field's live preview. */
int duocb_display_identity(const char *name,
                           const char *suffix,
                           char *out_buf,
                           size_t out_len);
int duocb_create_identity_card(const char *private_key,
                               const char *name,
                               const char *suffix,
                               char *out_buf,
                               size_t out_len);
int duocb_validate_identity_card(const char *card,
                                 char *err_buf,
                                 size_t err_len);
/* Writes {name, short_name, suffix, public_key, npub, fingerprint, created_at,
 * expires_at, remaining_secs, expired, needs_renewal}. */
int duocb_identity_card_info(const char *card, char *out_buf, size_t out_len);

/* ── Card-setup PIN entry ─────────────────────────────────────────────── */

/* Normalize a typed PIN to canonical form and verify its check digit.
 * 1 = valid (canonical written), 0 = invalid PIN, -1 = NULL/buffer too small. */
int duocb_normalize_pin(const char *pin, char *out_buf, size_t out_len);
/* Render a canonical PIN as "XXXX-XXXX". */
int duocb_format_pin(const char *pin, char *out_buf, size_t out_len);
/* Drop characters a PIN cannot contain, uppercasing and mapping I/L->1, O->0.
 * Feed every keystroke through this. */
int duocb_sanitize_pin_chars(const char *input, char *out_buf, size_t out_len);
/* Redistribute a two-group entry so typing past the first group spills into
 * the second. Writes {"first","second"}. */
int duocb_split_pin_groups(const char *first,
                           const char *second,
                           char *out_buf,
                           size_t out_len);
/* Writes {"entered","total","group"} for the "keep typing" hint. */
int duocb_pin_progress(const char *input, char *out_buf, size_t out_len);

/* ── Manual host-IP entry (multicast-blocked fallback) ────────────────── */

/* Writes {"prefix","placeholder","hint","label"} constraining the host-IP
 * field to this device's own subnet; all "" when none is detected. */
int duocb_join_ip_context(char *out_buf, size_t out_len);
/* 1 = in-range address written, 0 = out of range, 2 = empty (omit "ip" and
 * browse DNS-SD instead), -1 = malformed/NULL/buffer too small. */
int duocb_resolve_join_ip(const char *entry, char *out_buf, size_t out_len);

/* ── Session lifecycle ────────────────────────────────────────────────── */

/* Returns a non-NULL handle, or NULL with the reason in err_buf. */
DuocbHandle *duocb_start(const char *config_json,
                         char *err_buf,
                         size_t err_len);
/* 1 = event written, 0 = none pending, -1 = NULL handle,
 * -2 = buffer too small (the event is retained; retry with a larger buffer). */
int duocb_next_event(const DuocbHandle *handle, char *out_buf, size_t out_len);

/* Fire-and-forget commands; outcomes arrive as events.
 * 0 = requested, -1 = NULL handle. */
int duocb_send_clipboard(const DuocbHandle *handle, const char *text);
int duocb_query_conn_path(const DuocbHandle *handle);
/* card_host only: mint a fresh PIN now, invalidating every earlier one. */
int duocb_refresh_pin(const DuocbHandle *handle);
/* End the session but keep the handle: a host stops serving, a joiner hangs
 * up. The runtime survives, so duocb_reconnect can resume the same pairing. */
int duocb_disconnect(const DuocbHandle *handle);

/* 1 = runtime alive, 0 = runtime ended, -1 = NULL handle. */
int duocb_is_running(const DuocbHandle *handle);
/* Re-issue the handle's session command on its still-running runtime, reusing
 * the session identity so an already-paired peer recognizes the reconnect. A
 * fresh duocb_start would mint a new identity, which such a peer refuses.
 * 0 = requested, -1 = NULL handle, -2 = runtime unavailable (stop and restart). */
int duocb_reconnect(const DuocbHandle *handle);
/* Graceful shutdown and free. NULL is a safe no-op; the handle must not be
 * used afterwards. */
void duocb_stop(DuocbHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* DUOCB_H */
