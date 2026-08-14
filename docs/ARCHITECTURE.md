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

Cards never travel over the wire — the handshake carries raw application public
keys — so each side enforces expiry against **its own stored copy** and there
is no renewal protocol. The listener refuses a dialer whose stored card has
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
trusted application key; the claim updates the transport id. Quick mode has no
application identity and continues to claim the session's iroh id.

## Quick mode

A rotating Crockford PIN drives:

- Argon2id-derived rendezvous keys for Nostr and/or LAN discovery;
- a separate Argon2id-derived in-band mutual proof;
- mDNS/DNS-SD or an optional typed-IP unicast lookup in LAN-only mode.

Quick mode persists no application key, peer card, iroh key, PIN, or session.

## Runtime commands and events

Key configure commands:

- `StartServer::NostrKey { KeyIdentity }`
- `Connect::NostrKey { KeyIdentity, peer_public_key }`

The runtime never mutates caller-owned trust; the host app owns the peer list
and passes a snapshot of it in with each command.

## Persistence and bounds

Desktop config stores the application private key, optional signed self-card
short name and permanent suffix, and signed peer cards. Loading is strict:
invalid or legacy data is an error, not a migration or silent drop. Files are
owner-only, protected by a sibling process-lifetime lock, and atomically
replaced through a flushed temporary file.

Clipboard content is never persisted. Inbox retention is five items in memory;
wire clipboard frames are capped at 1 MiB.

## Security assumptions

- Identity cards are transferred over a path the owner trusts.
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
