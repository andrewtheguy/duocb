# duocb architecture

duocb is a wire protocol between two devices that hold each other's signed
identity card. **iroh is how the bytes get there — the transport duocb ships
with today, not something the protocol is built out of.** The layers above it
(identity, trust, authentication, framing, clipboard messages) name no
transport at all, and `crates/duocb-core/src/transport/` states what one has to
supply; see [the transport layer](#the-transport-layer).

It separates two concerns that deliberately use different keys:

| Layer | Key lifetime | Purpose |
|---|---|---|
| Application identity | Persistent per installation | Signed identity cards, local trust, configure-mode wire authentication, Nostr authorship |
| Session transport (iroh today) | Fixed for a runtime; device-persistent on iOS | QUIC/TLS endpoint identity, signaling target, connection establishment |

The application key is never used as an iroh secret key. The iroh key never
determines local trust. Every endpoint a runtime binds uses the same iroh key,
so its node id stays fixed across session tasks. The desktop creates that key
once per process; iOS stores a this-device-only key bound to
`identifierForVendor`, so its node id also survives relaunches.

## The transport layer

Sessions are carried, not defined, by their transport, so the transport is the
part most likely to change — and the split is enforced by where the code lives
rather than by intent:

- `duocb_core::transport` — the contract: what a transport must provide, as a
  `SessionTransport` trait plus the two generic entry points
  (`authenticate_dialer`, `authenticate_listener`) a transport is plugged into.
- `duocb_core::transport::iroh_quic` — the implementation the apps run on.
- `duocb_core::transport::dummy` — plain TCP, host and port, for tests and
  demos. It carries complete sessions, which is how the boundary stays honest:
  if something iroh-shaped leaked upward, the TCP tests would stop compiling or
  passing.

### What a transport must provide

| Requirement | Why | Under iroh |
|---|---|---|
| One reliable, ordered, bidirectional byte channel per session | The handshake runs on it first, then `ClipMsg` frames flow both ways for the life of the connection. Framing is length-prefixed and self-delimiting, so message boundaries need not survive — and the two directions need not even come from one socket | One QUIC bidirectional stream |
| A stable id for each end, labelled identically by both | Both ids are signed into the auth transcript, binding the application-key proofs to this connection | Node ids, authenticated by QUIC/TLS |
| Somewhere to point a dial | Finding the peer is rendezvous, not transport (see [below](#configure-mode-signaling)); the transport is handed the result | A `TransportAddr` of kind `iroh` — a node id — inside the encrypted hosting record |
| Confidentiality | duocb adds no encryption of its own above the transport — clipboard frames are plain JSON inside it | QUIC/TLS |

Optional, and what a transport loses by omitting it: connection close codes
(the runtime turns iroh's into precise "untrusted key" / "expired card" /
"already paired" wording, and without them a refusal reads as a dropped
connection), path introspection (the connection-path button), and NAT
traversal with relay fallback (reachability beyond one network). None of them
affect whether a session is correct or safe.

### What a transport does not decide

Identity and trust. A duocb installation *is* its application key; the
transport key is a separate, shorter-lived thing and its node id is never a
credential. The transport's endpoint ids only channel-bind a handshake that
authenticates the application keys on its own — which is why the TCP demo, with
no cryptography whatsoever, still refuses an untrusted application key, and why
a session over it still ends up bound to the two keys the user chose.

What the binding is *worth*, though, is the transport's contribution: iroh's
ids are proven public keys, so a peer cannot claim one it does not hold, and
both ends necessarily agree on the pair even across NAT and relays. The TCP
demo's ids are socket addresses, so they bind a session to an address pair and
no further — and anything that rewrites addresses leaves the two ends signing
different transcripts, which fails the handshake instead of quietly proceeding.

### Where the line falls in the code

- Transport-specific: `net/endpoint.rs` (binding, discovery, relays, path
  reporting), the session tasks in `net/runtime.rs` — which are what mint a
  `TransportAddr` for the record and read one back into a dial — and the
  card-setup `pin_record`, which still names an iroh node id (it is a LAN-only
  trade that bootstraps trust, not a session rendezvous).
- Transport-free: `protocol` (framing and messages), `key_auth` (the
  configure-mode mutual handshake), `auth` (identities and cards),
  `card_exchange`, `net::session_role`, the pairwise `hosting_record` and the
  two carriers that move it (`lan`, `nostr`), and everything in the apps above
  them.

### Adding a second transport

1. Implement `SessionTransport` for it: a `KIND` name, two half-channels and
   two ids.
2. Render its address into the rendezvous record and read it back —
   `hosting_record` encrypts a `TransportAddr`, which is the transport's `KIND`
   plus its own address text, so this is a pair of conversions
   (`iroh_quic::rendezvous_addr`/`endpoint_id`,
   `dummy::rendezvous_addr`/`socket_addr`) and no new record. Both carriers,
   DNS-SD and the nostr relays, move the payload without reading it, and a
   record naming a transport the looking device does not speak is a miss.
3. Decide the endpoint lifecycle — who binds, what "ready" means, how a session
   task is torn down — which is what `EndpointReadiness` answers for iroh.
4. Optionally map its close codes and path reporting into `NetEvent`s so the UI
   keeps its diagnostics.

The dummy transport does (1) and (2): it publishes a `tcp` address in the same
encrypted pairwise record the app publishes its node id in, so its `lan` mode
below finds a peer over mDNS with no address typed anywhere. What keeps it a
demo rather than something shippable is the transport itself — TCP encrypts
nothing, and its ids are addresses (see [above](#what-a-transport-does-not-decide)).
Steps (3) and (4) are the app's, not the contract's, and are the reason the
runtime still binds iroh endpoints specifically.

To see a session run on it:

```sh
cargo run -p duocb-core --example dummy_transport          # both peers, loopback
cargo run -p duocb-core --example dummy_transport -- --uni # two one-way sockets
cargo test -p duocb-core --test dummy_transport

# two processes that find each other through the encrypted hosting record over
# mDNS — no addresses typed. Each prints its npub; give each the other's.
DUOCB_PEER_NPUB=<other npub> cargo run -p duocb-core --example dummy_transport -- lan
```

## Workspace boundaries

- `duocb-core`: portable identity/card types, protocol framing, the transport
  contract and its iroh implementation, Nostr signaling, PIN support, and the
  headless tokio runtime.
- `duocb`: Slint desktop app, local config, and clipboard access.
- `duocb-ffi`: C ABI over the core runtime and setup helpers for the sibling
  iOS app; it owns no persistence or trust policy.

The Slint event loop and tokio runtime communicate only with `UiCommand` and
`NetEvent` channels.

## Persistent identity and local trust

`auth::Identity` wraps a secp256k1/Nostr keypair:

- private encoding: NIP-19 `nsec`;
- public display encoding: NIP-19 `npub`;
- wire/trust key: the 32-byte public key.

An identity card is a signed kind `30382` Nostr event with the identifier
`duocb:identity-card:v4` and a versioned JSON body containing the validated
final device name, `<short-name>_<permanent-random-suffix>`, and a mandatory
signed validity window, absolute `not_before` and `not_after` — the same shape
as an X.509 certificate's notBefore/notAfter. The suffix is persisted separately from the application
key so it remains stable across renames and identity resets; accepting a
recovered self-card restores its suffix. Parsing checks the event signature,
kind, identifier, schema, name and suffix rules, and 2 KiB size cap.

### Card validity window

Cards last 30 days; the application key has no expiry of its own, and a
renewal is the same key signing a new card with a new window. Four of the
parse checks concern the window, and all four compare only signed fields, so
parsing stays clock-free and deterministic:

- `not_after` is after `not_before`;
- the window does not exceed 30 days, so an issuer cannot self-assert
  unbounded trust;
- the event's `created_at` equals the body's `not_before`;
- the NIP-40 `expiration` tag equals the body's `not_after`.

Whether a card is *current* is a separate decision, made against the local
clock only where trust is acted on, and it checks **both** edges:
`not_before <= now + 300 seconds` and `now < not_after`. The five-minute skew
grace applies only to the opening edge. The end alone would not do: a device whose clock is set far in the
past never reaches any card's `not_after`, so it would honour every card ever
issued, including ones that lapsed years ago. The signed start makes such a
device reject the card as *not yet valid* — a state the UI reports separately
from *expired*, since the remedy is fixing a clock, not fetching a fresh card
that would fail the same way. The same check bounds how far a fast issuer
clock can stretch a real lifetime.

The clipboard handshake carries raw application public keys, never a card, so
each side enforces expiry against **its own stored copy** and there is no
renewal protocol. (A card does cross the wire during card setup, but that is the
hand-over itself — see below — and the receiving side still judges it locally.) The listener refuses a dialer whose stored card has
lapsed before signing anything, and closes with a dedicated code so the dialer
can say precisely what is wrong; the dialer refuses symmetrically before
dialing. A host also stops publishing hosting records to peers whose cards have
lapsed. Recovery is manual and identical to first-time pairing: the owner hands
over a fresh card. Both apps re-sign their own card at launch once it is within
seven days of expiry; the desktop also checks immediately before copying or
trading it.

Expired cards still parse. Config load runs through the same parser and may not
fail because trust aged out — an expired peer stays listed and marked expired
rather than vanishing. The desktop always shows the signed expiry date and adds
a countdown inside the last seven days. iOS shows the date while a card is
current and marks a lapsed row `expired`; both apps distinguish that state from
a not-yet-valid clock warning.

Each local peer entry is the full verified card, so the saved name is bound to
the public key. Trust is local, capped at 128 unique public keys, and only ever
added by explicitly importing a signed card.

## Who hosts

A clipboard session needs one device listening and one dialing, but neither
user is in a position to decide that: both know which device they want to share
with, neither knows who is supposed to press something first. So the two halves
are not offered. Each device picks the other from its trusted list, and
`net::session_role` answers the split from the two application keys — the lower
key hosts — identically on both sides, with no negotiation and no round trip.
Two users acting a minute apart still land on opposite halves, and the same
device hosts every time for a given pairing, so a log or a capture of one pair
reads the same way twice.

Everything downstream follows from that one call: the hosting half runs
`ServerMode::Key`, the dialing half `DialSpec::Key`, and the desktop, the FFI
and the headless example each make the call in exactly one place.

Because the device is chosen and not merely trusted, a session is *pairwise* on
both sides: the host publishes one record — the chosen peer's — and its listener
refuses another trusted device that dials in, which would otherwise take the
pairing slot the chosen device is coming for.

## Configure-mode signaling

Starting a configure-mode server binds an iroh endpoint with the runtime's
existing transport key. For the peer the session is with, the host publishes one
pairwise hosting record (`hosting_record`): NIP-44 ciphertext of
`{version, transport, address}` — the name of the transport that minted the
address and that transport's own address text, `iroh` and a node id today —
from the host's application key to exactly that peer's,
under a label that is a SHA-256 over a domain plus the **ordered** host/peer
public keys. Anyone who knows both public keys can derive the deterministic
label; it is an addressing mechanism, not a secret. Only the addressed peer can
read the content.

The record is carried on two transports, which differ only in how the label is
expressed and how long a copy survives:

| | Label | Payload | Lifetime |
|---|---|---|---|
| Nostr relays | `d` tag of a kind `30385` parameterized replaceable event, plus the public event author and `p` recipient keys | encrypted event content | NIP-40 expiry, five minutes; refreshed every 120 s while listening |
| Local network | DNS-SD instance under `_duocb-host._udp.local.` | `e` TXT attribute, with real SRV/A/AAAA data alongside | until withdrawn; re-registered only when the endpoint's direct addresses change |

The two labels use different domain separators, so their strings cannot be
matched directly. This is not an unlinkability boundary: anyone who knows both
application public keys can derive both labels, and a Nostr hosting event
exposes those keys as its author and public `p` tag. The LAN copy additionally
carries dialable addresses, so a local hit needs no further address lookup; the
relay copy is a bare node id the endpoint's own discovery resolves.

Neither carrier parses the payload — a record whose `transport` this build does
not speak decrypts, is logged, and counts as a miss, which is what lets the TCP
demo transport publish a `host:port` through the same record and the same two
carriers.

Which transports are in play is the session's `SignalChannel` choice — fixed at
desktop launch and read from Settings when an iOS session starts. Card setup
uses the same choice and the same table of channels and endpoint gates
([below](#rendezvous-channels)). The roles are asymmetric in the same way: the
host publishes on every enabled channel because it cannot know where the dialer
will look, and only the dialer falls back, sequentially, LAN first. A host also
stops publishing once the peer's card lapses, on both transports.

The dialing half waits as patiently as the hosting half: until it has connected
once it never gives up, because it is waiting for the other user to pick this
device, not recovering from a failure — it only slows its polling down after the
first half-minute. The bounded give-up (ten consecutive attempts, then a Retry
the user presses) applies to a session that *had* connected and dropped.

This signaling only answers “where is the selected application identity
hosting now?” The subsequent wire handshake proves who is on the connection.

## Configure-mode authentication

Wire protocol version 4 uses mutual application-key proofs in configure mode
and a SPAKE2 PAKE for card setup. Both live in transport-free modules
(`key_auth` and `pin_auth`): they take a byte stream in each direction and the
two endpoint ids the transport reports, and nothing else. The dialer opens the
session's one bidirectional stream:

```text
C → S  KeyRequest   {client application pubkey, nonce_c}
S → C  KeyChallenge {server application pubkey, nonce_s, signature_s}
C → S  KeyProof     {signature_c}
S → C  AuthResponse {accepted}
```

Before signing or accepting, both sides require the presented application key
to match a locally trusted card that has not expired. Both signatures cover a domain-separated
transcript containing:

```text
protocol version
role = dialer | listener
client application key
server application key
nonce_c
nonce_s
client transport endpoint id
server transport endpoint id
```

The endpoint ids are whatever the transport calls its two ends — iroh node ids
today, taken from the QUIC/TLS-authenticated connection. Signing them binds the
proof to this connection without treating the transport key as the persistent
identity; how much that binding is worth is the transport's contribution, not
the handshake's (see [the transport layer](#the-transport-layer)). Nonces and
roles prevent replay/reflection.

The server's one-peer claim stores the stable application public key in
configure mode. A reconnect may present a new iroh node id if it proves the same
trusted application key; the claim updates the transport id. Card setup has no
application identity to claim and claims the session's iroh id instead.

### Key fingerprints and the pairing code

`auth::key_fingerprint` is a domain-separated SHA-256 over a device's 32-byte
application public key, truncated to 80 bits and rendered as five groups of four
uppercase hex characters. It is taken over the **key**, not a card: a renewed
card is new bytes with a new timestamp and signature, while local trust is keyed
on the public key, so the value a user reads must not move when a card is
re-minted. It is shown for this device on the hub and beside every trusted peer.

`auth::pairing_code` is what the card-setup confirmation shows: the two keys'
fingerprints laid end to end, lower key first. Order-normalizing makes it a pure
function of the *pair*, so both devices render the identical ten groups and the
user compares one value across the two screens instead of cross-checking two
per-device fingerprints. It is deliberately a concatenation, never a hash over
both keys — see the security bullet below.

## Card setup

The trust-bootstrap path, for two devices that cannot copy and paste a card
between them. It is not a connection mode: it produces trusted peer cards, and
every subsequent connection is an ordinary configure-mode one.

A rotating Crockford PIN drives discovery via an Argon2id-derived rendezvous
key, then an in-band mutual PAKE — SPAKE2 over Ed25519, whose password is a
separate Argon2id stretch of the same PIN. A PAKE commits each side to one
password per instance, but the host still honors the previous rotation's PIN,
so the handshake runs two instances ("slots"): the dialer enters its typed PIN
in both, the host enters its current and previous PINs (a random password pads
an empty slot). Each side then proves it derived the same SPAKE2 key with an
HMAC per slot; the slot that verifies is the shared PIN. On the connection that
authenticates, both sides exchange cards:

```text
D→L  AuthRequest::Pin  {pakes:    [msg_a per slot]}
L→D  PinChallenge      {pakes:    [msg_b per slot]}
D→L  PinResponse       {confirms: [mac_d per slot]}
L→D  PinConfirm        {accepted, slot, confirm}
D→L  CardOffer         {card_d}     # concurrent, independent half-streams:
L→D  CardOffer         {card_l}     # the order shown here is illustrative only
```

No frame reveals anything offline-testable about the PIN: the dialer uses the
same guessed PIN in both slots, learns only whether that guess matched either
recent host PIN, and pays a full Argon2id derivation for it. The ~35-bit code
rotates every 60 seconds; the host honors the current and immediately previous
codes so setup can cross a rotation. The first successful claim ends the setup
session, but failed connections are not described as a rate limit.

Only the four PIN frames are turn-taking. Both offers are written immediately
once the PIN is accepted, so neither `CardOffer` waits on the other and their
relative arrival order is not defined.

Each side finishes its send stream only *after* reading the peer's card, so
seeing the peer's end-of-stream proves the peer already holds ours — without
that ordering, whichever side finished first would close the connection while
the other was still reading, and QUIC's connection close discards undelivered
stream data.

The runtime verifies each card's signature and schema and emits it as
`NetEvent::PeerCardReceived`; it decides nothing about trust. The host app shows
the pairing code over its own key and the received card's, and stores the card
only when the user confirms the other device shows the identical code.

The session is one-shot: it carries no clipboard traffic (the session task holds
no clipboard channel at all) and ends as soon as the cards have crossed. One PIN
admits one device — the pair claim refuses a second, and a device still dialing
when the exchange finishes is answered with a BUSY close rather than left
waiting. Card setup persists no PIN or session state. The iroh transport key has
an independent lifetime: one desktop process or, on iOS, the device-bound
Keychain item.

### Rendezvous channels

Both of duocb's rendezvous records — the card-setup PIN record (`pin_record`,
keyed by the `(pin, bucket)` public key) and the pairwise hosting record
(`hosting_record`, keyed by a pair of application keys) — carry a NIP-44-
encrypted payload whose only connection datum is the host's current node id.
Each transport encrypts its own copy, and the two record types use different
keys and envelopes. `SignalChannel` selects where each flow puts and looks for
its record. The desktop fixes the choice at launch; iOS reads its Settings
value when each session starts:

| Channel | Host publishes | Dialer looks | Endpoint gate |
|---|---|---|---|
| `LanThenNostr` (default) | DNS-SD (+ the PIN unicast side channel) **and** relays | local network, then relays if that missed | `DirectAddr` |
| `LanOnly` (`--lan-only`) | DNS-SD (+ the PIN unicast side channel) | local network only | `LanDirect` (relay-less) |
| `NostrOnly` (`--nostr-only`) | relays | relays only | `RelayOnline` |

The unicast side channel is PIN-only. It works by having the user type the
host's LAN IP, and card setup is the only flow with a screen that shows that IP
and a field to type it into; a clipboard session on a multicast-blocked network
falls back to the relays instead, or fails on `--lan-only`.

The two roles are deliberately asymmetric. The host publishes on *every* enabled
channel — it cannot know which one the dialer will reach it on, and a record
only helps if it is already in place. The dialer is the one that falls back, and
it does so sequentially rather than racing: the local lookup answers in well
under a second when the other device is there, so a local hit avoids a relay
lookup by the dialer. The default host has still published to the relays in
parallel. A LAN error is logged and treated like a miss; an error surfaces only
when nothing was found on any enabled channel.

Only the default channel needs both stacks, which is why it gates on
`DirectAddr` — waiting for a relay would stall a session that may never need
one, while the relay connects in the background for the fallback. `LanOnly`
builds a relay-less endpoint (no third-party server at all); `NostrOnly`
requires the relay before it can publish, and its record carries no direct
addresses, so the dialer's own discovery resolves the node id.

The channel is part of the runtime's logical session key. Changing it resets
the session's transient claim/PIN memory and binds a new endpoint with the
appropriate transport stack, while retaining the runtime's iroh node id.

Publishing to public relays widens who can *fetch* a record, so it rests
entirely on the PIN: the lookup key is Argon2id-derived, the payload is only a
current node id, dialing it still requires the in-band PAKE, and nothing
is trusted without the pairing-code check below. The record is the one
PIN-derived artifact that is offline-attackable by nature — its lookup key must
be derivable from the PIN alone, so an archived event lets an attacker test
guesses at Argon2id cost. The short TTL and rotation bound that exposure, and
a recovered PIN is useless once its window (and one claim) is gone.

### Why the pairing-code check is load-bearing

The PIN proves possession of a short code, not an identity. The PAKE stops a
stranger from grinding it out of the handshake, but anyone who reads,
shoulder-surfs, or offline-grinds it from the public rendezvous record while
the host still honors that PIN can complete the handshake and offer a card of
their choosing — PIN-keyed cryptography is transparent to a PIN holder. The human
pairing-code comparison is what catches that, because each device computes its
half of the code from its *own* key locally — that part never crossed the
network.

- **Concatenated, never hashed together.** The pairing code is the two per-key
  fingerprints verbatim, so each half commits to exactly one key. An interposer
  holds two separate PIN-authenticated connections and offers its own card each
  way; device A then renders `sort(fp(A), fp(X₁))` while device B renders
  `sort(fp(B), fp(X₂))`. Making those screens agree requires `fp(X₁) = fp(B)`
  and `fp(X₂) = fp(A)` — two second preimages against fixed 2^80 targets. The
  expected work remains on the order of 2^80, not 2^160. A combined 160-bit
  digest would let the interposer vary both of its keys in a collision-style
  search with a similar generic 2^80 work factor; an 80-bit combined digest
  would fall to roughly 2^40. Concatenation is chosen because each half remains
  attributable to one key and is the same fingerprint the apps show elsewhere,
  not because displaying 160 bits implies 160-bit attack work.
- **One comparison suffices.** The check is symmetric by construction: the two
  screens either render the identical code or they do not, and a mismatch
  anywhere in the ten groups exposes the interposer on both sides at once.
- **Auto-exchange leaks nothing.** A card is public material its owner hands out
  by copy-paste anyway, and carries no private key. Receiving one is not
  trusting it; only Import writes to the trusted list.
- **Bounded blast radius.** A card-setup connection carries no clipboard content,
  so a card slipped past an inattentive user grants only what any imported card
  grants: the ability to complete the mutual application-key handshake when the
  user later selects that device and presses Connect.

## Runtime commands and events

Key commands:

- `UiCommand::StartServer { mode: ServerMode::Key { identity, peer_public_key, channel } }`
- `UiCommand::Connect { spec: DialSpec::Key { identity, peer_public_key, channel } }`
- `UiCommand::StartServer { mode: ServerMode::CardSetup { self_card, channel, relays } }`
- `UiCommand::Connect { spec: DialSpec::CardSetup { canonical_pin, self_card, target_ip, channel, relays } }`

and the card-setup event `NetEvent::PeerCardReceived(IdentityCard)`.

The runtime never mutates caller-owned trust; the host app owns the peer list
and passes a snapshot of it in with each command. That still holds for card
setup: the runtime only *delivers* a verified card, and the host app decides
whether it is trusted.

## Persistence and bounds

Desktop config stores the application private key, permanent suffix, optional
short name and matching signed self-card, and signed peer cards. Loading is
strict: malformed or unsupported data is an error, not a migration or silent
drop. A sibling process-lifetime lock protects the config, and saves atomically
replace it through a flushed temporary file. Config-related files are
owner-only on Unix; Windows relies on the per-user configuration directory.

Clipboard content is never persisted. Inbox retention is five items in memory;
wire clipboard frames are capped at 1 MiB.

## Security assumptions

- Identity cards are transferred over a path the owner trusts: a clipboard the
  owner controls, or a card-setup connection whose pairing code the owner
  checked. Skipping that check reduces card setup's security to the PIN alone.
- A card's validity window bounds how long a leaked or abandoned card stays
  useful, but only against a peer whose clock is roughly correct: the window is
  enforced locally, so a device whose clock is wound back into a lapsed card's
  historical window honours it again. What the signed `not_before` rules out is
  the far cheaper mistake — a clock set before the window, which without it
  would accept every card ever issued, and with it accepts none.
- Possession of an application private key permits impersonating that
  installation and decrypting pairwise records addressed to it.
- Nostr relays may omit, retain, reorder, or replay events, and anything on the
  local network can answer an mDNS browse. A stale, replayed, or forged hosting
  record can only misdirect a dial; the wire handshake still has to prove the
  trusted application key, so a wrong target fails closed.
- A hosting record's label is stable for the life of a pairing, so an observer
  can link repeated sessions and their timing. A LAN observer sees a
  pseudonymous label and direct addresses. A Nostr relay additionally sees the
  host and intended peer application public keys as the event author and public
  `p` tag. The transport labels differ, but someone who knows both keys can
  derive and correlate them.
- iroh and relay infrastructure can observe connection/event metadata even
  though payloads are encrypted.
