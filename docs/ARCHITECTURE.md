# duocb architecture

duocb separates two concerns that deliberately use different keys:

| Layer | Key lifetime | Purpose |
|---|---|---|
| Application identity | Persistent per installation | Signed identity cards, local trust, configure-mode wire authentication, Nostr authorship |
| iroh endpoint | Ephemeral per logical session | QUIC/TLS endpoint identity, signaling target, connection establishment |

The application key is never used as an iroh secret key. The iroh key never
determines local trust.

## Workspace boundaries

- `duocb-core`: portable identity/card types, protocol framing, Nostr
  signaling, PIN support, and the headless tokio runtime.
- `duocb`: Slint desktop app, local config, and clipboard access.

The Slint event loop and tokio runtime communicate only with `UiCommand` and
`NetEvent` channels.

## Persistent identity and local trust

`auth::Identity` wraps a secp256k1/Nostr keypair:

- private encoding: NIP-19 `nsec`;
- public display encoding: NIP-19 `npub`;
- wire/trust key: the 32-byte public key.

An identity card is a signed kind `30382` Nostr event with the identifier
`duocb:identity-card:v3` and a versioned JSON body containing the validated
final device name, `<short-name>_<permanent-random-suffix>`, and a mandatory
absolute `expires_at`. The suffix is persisted separately from the application
key so it remains stable across renames and identity resets; accepting a
recovered self-card restores its suffix. Parsing checks the event signature,
kind, identifier, schema, name and suffix rules, and 2 KiB size cap.

### Card expiry

Cards last 30 days. Three of the parse checks concern expiry, and all three
compare only signed fields, so parsing stays clock-free and deterministic:

- `expires_at` is after the event's `created_at`;
- the claimed lifetime does not exceed 30 days, so an issuer cannot self-assert
  unbounded trust;
- the NIP-40 `expiration` tag equals the body's `expires_at`.

Whether a card is *current* is a separate decision, made against the local
clock only where trust is acted on. A card issued implausibly far in the future
(beyond a five-minute skew grace) is never current, which bounds how far a fast
clock can stretch a real lifetime.

The clipboard handshake carries raw application public keys, never a card, so
each side enforces expiry against **its own stored copy** and there is no
renewal protocol. (A card does cross the wire during card setup, but that is the
hand-over itself — see below — and the receiving side still judges it locally.) The listener refuses a dialer whose stored card has
lapsed before signing anything, and closes with a dedicated code so the dialer
can say precisely what is wrong; the dialer refuses symmetrically before
dialing. A host also stops publishing hosting records to peers whose cards have
lapsed. Recovery is manual and identical to first-time pairing: the owner hands
over a fresh card. A device re-signs its own card once it is within seven days
of expiry.

Expired cards still parse. Config load runs through the same parser and may not
fail because trust aged out — an expired peer stays listed and marked expired
rather than vanishing.
Every trusted-device row carries the expiry date read straight off the card, so
the deadline is visible before it bites; a countdown is added inside the last
seven days and the date is reported again in every refusal message.

Each local peer entry is the full verified card, so the saved name is bound to
the public key. Trust is local, capped at 128 unique public keys, and only ever
added by explicitly importing a signed card.

## Configure-mode signaling

Starting a configure-mode server creates an iroh endpoint with a fresh
session-scoped key. For each locally trusted card, the host publishes a kind
`30385` parameterized replaceable event:

- author: host application key;
- `p` recipient: exactly one trusted application key;
- `d`: SHA-256 over a domain plus ordered host/peer public keys;
- content: NIP-44 encrypted `{version, node_id}`;
- NIP-40 expiry: five minutes.

The host refreshes these pairwise records while listening. A joiner queries the
selected trusted author and pair-specific identifier, decrypts with its
application key, and obtains the ephemeral iroh node id. No shared group
presence key or broadcast list exists.

This signaling only answers “where is the selected application identity
hosting now?” The subsequent wire handshake proves who is on the connection.

## Configure-mode authentication

Wire protocol version 3 removes token authentication. The dialer opens one
bidirectional QUIC stream:

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
client iroh node id
server iroh node id
```

The iroh ids come from the QUIC/TLS-authenticated connection, binding the proof
to this transport without treating the transport key as the persistent
identity. Nonces and roles prevent replay/reflection.

The server's one-peer claim stores the stable application public key in
configure mode. A reconnect may present a new iroh node id if it proves the same
trusted application key; the claim updates the transport id. Card setup has no
application identity to claim and claims the session's iroh id instead.

### Key fingerprints

`auth::key_fingerprint` is a domain-separated SHA-256 over a device's 32-byte
application public key, truncated to 80 bits and rendered as five groups of four
uppercase hex characters. It is taken over the **key**, not a card: a renewed
card is new bytes with a new timestamp and signature, while local trust is keyed
on the public key, so the value a user reads must not move when a card is
re-minted. It is shown for this device on the hub, beside every trusted peer,
and on both sides of the card-setup confirmation.

## Card setup

The trust-bootstrap path, for two devices that cannot copy and paste a card
between them. It is not a connection mode: it produces trusted peer cards, and
every subsequent connection is an ordinary configure-mode one.

A rotating Crockford PIN drives discovery via an Argon2id-derived rendezvous
key, then a separate Argon2id-derived in-band mutual proof. On the connection
that authenticates, both sides exchange cards:

```text
D→L  AuthRequest::Pin  {nonce_d}
L→D  PinChallenge      {nonce_l}
D→L  PinResponse       {proof_d}
L→D  PinConfirm        {accepted, proof_l}
D→L  CardOffer         {card_d}     # concurrent, independent half-streams:
L→D  CardOffer         {card_l}     # the order shown here is illustrative only
```

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
both fingerprints and stores the card only when the user confirms.

The session is one-shot: it carries no clipboard traffic (the session task holds
no clipboard channel at all) and ends as soon as the cards have crossed. One PIN
admits one device — the pair claim refuses a second, and a device still dialing
when the exchange finishes is answered with a BUSY close rather than left
waiting. Nothing but the imported card is persisted: no PIN, iroh key, or
session survives.

### Rendezvous channels

The rendezvous record itself — NIP-44 ciphertext of the host's ephemeral node
id, keyed by the `(pin, bucket)` public key — is the same on every transport
(`pin_record`). What differs is where it is put and looked for, chosen at launch
by `SetupChannel`:

| Channel | Host publishes | Joiner looks | Endpoint gate |
|---|---|---|---|
| `LanThenNostr` (default) | DNS-SD + unicast side channel **and** relays | local network, then relays if that missed | `DirectAddr` |
| `LanOnly` (`--lan-only`) | DNS-SD + unicast side channel | local network only | `LanDirect` (relay-less) |
| `NostrOnly` (`--nostr-only`) | relays | relays only | `RelayOnline` |

The two roles are deliberately asymmetric. The host publishes on *every* enabled
channel — it cannot know which one the joiner will reach it on, and a record
only helps if it is already in place. The joiner is the one that falls back, and
it does so sequentially rather than racing: the local lookup answers in well
under a second when the other device is there, so the common case never touches
a relay. A LAN error is logged and treated like a miss; an error surfaces only
when nothing was found on any enabled channel.

Only the default channel needs both stacks, which is why it gates on
`DirectAddr` — waiting for a relay would stall a pairing that may never need
one, while the relay connects in the background for the fallback. `LanOnly`
builds a relay-less endpoint (no third-party server at all); `NostrOnly`
requires the relay before it can publish, and its record carries no direct
addresses, so the dialer's own discovery resolves the node id.

Publishing to public relays widens who can *fetch* a record, so it rests
entirely on the PIN: the lookup key is Argon2id-derived, the payload is only an
ephemeral node id, dialing it still requires the in-band PIN proof, and nothing
is trusted without the fingerprint check below.

### Why the fingerprint check is load-bearing

The PIN proves possession of a short code, not an identity. It is ~35 bits and
the construction is not a PAKE, so anyone who reads, shoulder-surfs, or guesses
it inside its 60-second window can complete the handshake and offer a card of
their choosing. The human fingerprint comparison is what catches that, because
the value compared never crossed the network.

- **Per-key, not combined.** The fingerprint commits to one public key, so an
  impostor must find a key whose fingerprint equals a *given* target — a
  second-preimage problem, 2^80 here. A "session code" hashing both devices'
  keys would instead let an interposer vary both of its own keys and hunt for a
  collision between two freely-grindable sets: a birthday problem at 2^40 for
  the same displayed length. Nothing here commits either side to a key before it
  learns the other's, so there is no commitment step to restore the full bound.
  That asymmetry is why the digest covers one key alone.
- **One direction suffices.** An interposer holds two separate PIN-authenticated
  connections and offers its own card each way, so both devices see its
  fingerprint. Comparing either device's incoming value against the other's own
  displayed value already fails for it.
- **Auto-exchange leaks nothing.** A card is public material its owner hands out
  by copy-paste anyway, and carries no private key. Receiving one is not
  trusting it; only Import writes to the trusted list.
- **Bounded blast radius.** A card-setup connection carries no clipboard content,
  so a card slipped past an inattentive user grants only what any imported card
  grants: the ability to be dialed as a trusted peer, which still requires the
  mutual application-key handshake and the victim choosing to Join.

## Runtime commands and events

Key commands:

- `StartServer::NostrKey { KeyIdentity }`
- `Connect::NostrKey { KeyIdentity, peer_public_key }`
- `StartServer::CardSetup { self_card, channel, relays }`
- `Connect::CardSetup { canonical_pin, self_card, target_ip, channel, relays }`

and the card-setup event `NetEvent::PeerCardReceived(IdentityCard)`.

The runtime never mutates caller-owned trust; the host app owns the peer list
and passes a snapshot of it in with each command. That still holds for card
setup: the runtime only *delivers* a verified card, and the host app decides
whether it is trusted.

## Persistence and bounds

Desktop config stores the application private key, optional signed self-card
short name and permanent suffix, and signed peer cards. Loading is strict:
invalid or legacy data is an error, not a migration or silent drop. Files are
owner-only, protected by a sibling process-lifetime lock, and atomically
replaced through a flushed temporary file.

Clipboard content is never persisted. Inbox retention is five items in memory;
wire clipboard frames are capped at 1 MiB.

## Security assumptions

- Identity cards are transferred over a path the owner trusts: a clipboard the
  owner controls, or a card-setup connection whose fingerprint the owner checked.
  Skipping that check reduces card setup's security to the PIN alone.
- Card expiry bounds how long a leaked or abandoned card stays useful, but only
  against a peer whose clock is roughly correct: expiry is enforced locally, so
  a device whose clock is set far back keeps honouring a lapsed card.
- Possession of an application private key permits impersonating that
  installation and decrypting pairwise records addressed to it.
- Nostr relays may omit, retain, reorder, or replay events. A stale or replayed
  hosting record can only misdirect a dial; the wire handshake still has to
  prove the trusted application key, so a wrong target fails closed.
- iroh and relay infrastructure can observe connection/event metadata even
  though payloads are encrypted.
