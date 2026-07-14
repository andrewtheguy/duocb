# Roadmap

Planned work with enough design detail to implement safely. Current behavior is
documented in [README.md](../README.md) and [ARCHITECTURE.md](./ARCHITECTURE.md).

## Follow-ups

### LAN manual-IP mode (replace manual mode; PIN+IP side channel for the node id)

Remove the current manual mode (the copy/paste JSON pairing code:
`crate::manual_code`, `ServerMode::Manual`, `DialSpec::Manual`, desktop
`PairMode::Manual` and its `quick.slint`/`server.slint` UI) and replace it with a
LAN mode that needs no mDNS: the host shows a PIN and its LAN IPv4, and the
joiner types the PIN and that IP. It sits alongside the LAN-only (mDNS/DNS-SD)
channel as the fallback for networks where multicast is blocked or the joiner
would rather name the address than discover it.

**The node-id problem.** iroh dials by *node id* (a 64-hex public key), not by
IP — `endpoint.connect(EndpointAddr, ALPN)` pins the QUIC/TLS handshake to that
key (`net/endpoint.rs`). An IP only says *where* to send packets. Today the
LAN-only channel gets the node id (and dialable addrs) from the DNS-SD record;
the PIN only carries the auth secret. With mDNS removed, the node id still has to
reach the joiner.

**Side channel keyed by PIN + IP.** The host runs a small unicast listener on
its LAN IP that serves the same PIN-encrypted node-id record the mDNS path
advertises. The joiner connects to the typed IP, decrypts with the PIN, and
learns the node id plus direct addrs — then dials iroh exactly as the DNS-SD
path does. This is unicast rendezvous standing in for multicast discovery.

**What the joiner types:** two fields, both shown on the host.

- **The PIN** — the same short Crockford PIN as the other quick modes (e.g.
  `M3TD-PWFA`), entered in the existing two-group PIN form. It keys the side
  channel (`candidate_keys`) *and* proves the in-band session auth; it is not
  typed twice.
- **The host's LAN IPv4** — a single dotted-quad (e.g. `192.168.1.42`), no port.
  The side-channel port is fixed, and the iroh port comes back inside the
  fetched record, so the joiner never types a port. Validated as a well-formed
  IPv4 as it is entered (the Join button stays disabled until both the PIN
  normalizes and the IP parses); a malformed or unreachable IP surfaces the same
  way a bad PIN does today. No node id, secret, or JSON blob is ever typed or
  pasted — the removed manual mode's 64-hex node id and full-strength token both
  move into the side channel.

Design notes, reusing existing machinery:

- **Payload/crypto:** reuse `crate::pin_record::{encrypt_pin_payload,
  decrypt_pin_payload, candidate_keys}` verbatim — the side-channel body is the
  same ciphertext as the DNS-SD `e` TXT attribute, binding the node id to the
  PIN's current bucket. Nothing new to encrypt.
- **Return shape:** the lookup yields `crate::lan::PinFound { node_id, addrs }`,
  so it plugs straight into `resolve_pin` in `net/runtime.rs` with no new client
  dial path. Model it as a third LAN backend beside `lan/swarm.rs` and
  `lan/dnssd.rs` (e.g. `lan/unicast.rs`): host-side `advertise` starts the
  listener; joiner-side `lookup(ip, candidates)` fetches and decrypts.
- **Transport/port:** the joiner types only the IP, so the side-channel port
  must be agreed without being typed. Derive it from the PIN
  (`port = f(PIN)` mapped into the ephemeral range) — both peers already share
  the PIN, so the joiner computes the host's listener port with nothing extra to
  enter, and different PINs land on different ports so hosts coexist. (A single
  fixed well-known port, the direct analog of the hardcoded `_duocb-pin._udp`
  DNS-SD service type, is the simpler fallback but can collide and squats one
  registered port.) Port-scanning the derived port gains nothing: the served
  record is PIN-encrypted and the iroh session is challenge-response
  authenticated regardless. The addrs the record returns are the host's real
  iroh direct addrs (including the correct dynamic iroh port) — the joiner dials
  those, never the side-channel port.
- **Auth unchanged / defense in depth:** the iroh session still proves the PIN
  in-band via the Argon2id challenge-response (`auth_as_dialer_pin`, the server
  `recent_pins` accept path). The side channel only bootstraps discovery — just
  like mDNS — so a spoofed or MITM'd node id still cannot pass auth. Because
  nothing is published (the record is only reachable by connecting to the host's
  IP), offline PIN brute force needs an on-LAN active connection per guess, and
  the PIN rotates.
- **IP scoping:** the host displays the IPv4 on the interface that owns the
  default route (the real LAN address) by default, listing other private IPv4s
  only when ambiguous, and hiding link-local/VPN/virtual adapters. std has no
  default-route API — resolve via a crate (`netdev`/`default-net`) or a
  private-range heuristic over `endpoint.addr().ip_addrs()`. The joiner's entry
  is validated as a well-formed IPv4 but not hard-rejected for being
  out-of-subnet.
- **Enum shape:** the joiner supplies the IP, which `DialSpec::Pin` does not
  carry today — either add a field or a dedicated variant/channel. Decide during
  implementation; the LAN-only `PinChannel::LanOnly` plumbing is the closest
  template.
- **PIN channel encoding.** Today the PIN's first character encodes *one bit* of
  channel so the joiner infers which discovery to run before resolving: `pin.rs`
  splits the 32-char Crockford `ALPHABET` in half at `HALF` (lower 16 =
  nostr-carrying, upper 16 = LAN-only-mDNS), minted by
  `generate_pin(lan_only: bool)` and recovered by `pin_is_lan_only`. This mode
  adds a *third* discovery dialect (unicast side channel); two ways to place it:
  - **Preferred: reuse the existing LAN-only range and distinguish by the typed
    IP.** Both mDNS and unicast-IP are LAN-only, no-relay channels (same
    `EndpointReadiness::LanDirect` endpoint, same upper-half first char) — they
    differ only in *discovery*: multicast browse vs. a unicast fetch from the
    typed IP. So mint manual-IP PINs from the same upper-half range as
    LAN-only-mDNS (no new segment, `generate_pin`/`pin_is_lan_only` stay a
    `bool`), and let the *presence of a typed IP* select the unicast path on the
    join side — the way `join_by_code` already distinguishes entries by what was
    entered. A LAN-only PIN with no IP resolves via mDNS; the same-shaped PIN
    with an IP resolves via the side channel. Keeps the first-char partition
    two-way and avoids re-segmenting the alphabet.
  - **Alternative: a self-describing three-way partition.** If host-minted PINs
    must encode the channel *without* relying on the typed IP as signal, split
    the first character three ways instead, which means:
    - generalize `generate_pin`/`pin_is_lan_only` from a `bool` to a 3-valued
      channel classifier (e.g. a `PinChannelTag` enum), and
    - re-segment the first char into thirds. 32 does not divide by 3, so pick a
      documented split (e.g. 11/11/10 or reserved ranges) and update the entropy
      note in the module docs — the first char already carries only ~4 bits (1 of
      16); a third region drops it to ~3.4 bits (1 of ~10), still inconsequential
      for a 60 s-rotated ephemeral secret but worth stating.

**iOS parity (`../duocb-ios`).** The FFI must gain a role/config to pass the
typed IP (`duocb-ffi/src/lib.rs` `build_initial_commands`, `FfiConfig`) with the
hand-maintained `ios/duocb.h` kept in sync, plus `event_json` forwarding the
host's LAN IPv4 so `SessionView` can display it. Swift adds host IP display
(model on `QuickPairView`/`SessionView`) and joiner IP entry. Note iOS Local
Network permission: a raw unicast dial to a LAN IP triggers the prompt, but with
no DNS-SD browse in this mode the prompt may need an explicit trigger (the
existing browse-based trigger in `lan/dnssd.rs` `trigger_local_network_prompt`,
or a `Network.framework` path); `NSLocalNetworkUsageDescription` is already
declared.

### Presence via relay subscriptions

The peer list is polled (fetch on entering the device picker behind the Join
action, manual refresh, 30 s auto-refresh while the picker is visible) over
one-shot relay connections, matching the existing connect–fetch–disconnect
nostr usage. A persistent relay subscription would
push presence changes instead of polling; it introduces a long-lived relay
connection lifecycle (reconnects, resubscribes) that the current design
deliberately avoids.
