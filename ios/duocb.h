/*
 * duocb.h — C interface to libduocb.xcframework for the iOS app.
 * Hand-maintained; keep in sync with crates/duocb-ffi/src/lib.rs.
 *
 * Configure mode uses one persistent application keypair per installation.
 * The private key authenticates duocb's wire protocol and signs a portable
 * identity card containing the device name. It is unrelated to iroh's
 * ephemeral transport key. Pairing is mutual: each installation persists the
 * other installation's verified signed card in its local "peers" list.
 *
 * An optional directory_channel is a standalone 128-bit channel used only for
 * encrypted Nostr peer-list backups and signed-card discovery. The channel is
 * not an authentication credential. Backup restore is caller-controlled:
 * duocb_check_backup emits a preview and never modifies local state.
 *
 * Configure config JSON:
 * {
 *   "role": "hub" | "start" | "join",
 *   "identity_secret": "nsec1…",
 *   "self_card": "{ signed Nostr event JSON }",
 *   "peers": ["{ signed peer card JSON }"],       // max 128
 *   "peer_public_key": "hex or npub1…",           // join only; must be in peers
 *   "directory_channel": "dc1.…",                 // optional
 *   "backup_generation": 7,                       // persisted, monotonic
 *   "relays": ["wss://…"]                         // optional
 * }
 *
 * "hub" starts the runtime without a connection. Directory and backup work is
 * explicit through the functions below. "start" publishes pairwise encrypted
 * hosting records for locally trusted peers. "join" resolves exactly the
 * selected trusted application public key. Authentication uses the application
 * keys; Nostr and iroh only signal and establish the transport.
 *
 * Quick mode remains identity-free:
 *   {"role":"quick_host"}
 *   {"role":"quick_host","channel":"lan"}
 *   {"role":"quick_join","pin":"abcd-2345"}
 *   {"role":"quick_join","pin":"…","ip":"192.168.1.42"}
 *
 * quick_host channel is "nostr_lan" (default) or "lan". quick_join infers the
 * channel from the PIN. LAN mode uses Bonjour `_duocb-pin._udp`; the app must
 * declare NSBonjourServices and NSLocalNetworkUsageDescription.
 *
 * Event JSON types:
 *   server_ready      {node_id, identity_public_key}
 *   client_ready      {node_id, identity_public_key}
 *   status            {state, attempt?, max?}
 *   peer_paired       {peer_node_id, peer_public_key}
 *   peer_disconnected {}
 *   conn_path         {paths:[{kind,display,selected}]}
 *   item_received     {text,pulled}
 *   item_sent         {}
 *   pin_rotated       {pin_display,seconds_left,host_lan_ip}
 *   pin_cleared       {}
 *   directory_cards   {cards:[{name,public_key,npub,card}]}
 *   backup_found      {backup:null|{generation,self_card,peers:[...]}}
 *   backup_published  {generation}
 *   backup_check_failed   {message}
 *   backup_publish_failed {message}
 *   error             {message}
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
#define DUOCB_PUBLIC_KEY_BUF_LEN 128
#define DUOCB_IDENTITY_CARD_BUF_LEN 4096
#define DUOCB_IDENTITY_CARD_INFO_BUF_LEN 512
#define DUOCB_DIRECTORY_CHANNEL_BUF_LEN 64

void duocb_init_logging(void);

/* Identity/card/channel helpers.
 * Generation/output functions: 1 = written, 0 = buffer too small,
 * -1 = NULL or invalid input. Validation: 1 = valid, 0 = invalid with a
 * message written to err_buf when supplied, -1 = NULL/non-UTF-8 input. */
int duocb_generate_identity(char *out_buf, size_t out_len);
int duocb_validate_identity(const char *private_key,
                            char *err_buf,
                            size_t err_len);
int duocb_identity_public_key(const char *private_key,
                              char *out_buf,
                              size_t out_len);
int duocb_create_identity_card(const char *private_key,
                               const char *name,
                               char *out_buf,
                               size_t out_len);
int duocb_validate_identity_card(const char *card,
                                 char *err_buf,
                                 size_t err_len);
/* Writes JSON: {"name":"…","public_key":"hex","npub":"npub1…"}. */
int duocb_identity_card_info(const char *card,
                             char *out_buf,
                             size_t out_len);
int duocb_generate_directory_channel(char *out_buf, size_t out_len);
int duocb_validate_directory_channel(const char *channel,
                                     char *err_buf,
                                     size_t err_len);

/* Quick-pair helpers. */
int duocb_normalize_pin(const char *pin, char *out_buf, size_t out_len);
int duocb_pin_is_lan_only(const char *pin);
/* Writes {"prefix","placeholder","hint","label"} for the optional LAN IP UI. */
int duocb_join_ip_context(char *out_buf, size_t out_len);
/* 1 = in-range address written, 0 = out of range, 2 = empty/use mDNS,
 * -1 = malformed/NULL/buffer too small. */
int duocb_resolve_join_ip(const char *entry,
                          char *out_buf,
                          size_t out_len);

/* Start and event lifecycle. duocb_next_event returns 1 = event written,
 * 0 = none pending, -1 = NULL handle, -2 = buffer too small (event retained). */
DuocbHandle *duocb_start(const char *config_json,
                         char *err_buf,
                         size_t err_len);
int duocb_next_event(const DuocbHandle *handle,
                     char *out_buf,
                     size_t out_len);

/* Explicit Nostr operations: 0 = requested, -1 = NULL handle,
 * -2 = no directory_channel configured. */
int duocb_refresh_directory(const DuocbHandle *handle);
int duocb_check_backup(const DuocbHandle *handle);
int duocb_publish_backup(const DuocbHandle *handle);

/* Session operations. */
int duocb_refresh_pin(const DuocbHandle *handle);
int duocb_send_clipboard(const DuocbHandle *handle, const char *text);
int duocb_query_conn_path(const DuocbHandle *handle);
int duocb_is_running(const DuocbHandle *handle);
/* 0 = requested, -1 = NULL, -2 = hub, -3 = runtime unavailable. */
int duocb_reconnect(const DuocbHandle *handle);
void duocb_stop(DuocbHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* DUOCB_H */
