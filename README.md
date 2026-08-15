# duocb

End-to-end encrypted, peer-to-peer clipboard sharing between two devices you
own. Both sides can send and receive after one device starts a connection and
the other joins it. Received text stays in an in-memory inbox until you
explicitly copy it.

> [!WARNING]
> duocb is pre-1.0 and intentionally has no backward compatibility. This
> release rejects the former shared-secret config and wire protocol.

## How devices connect

Every connection is a configure-mode connection: two devices that already trust
each other's signed identity cards. **LAN setup** is not a second kind of
connection — it is a way to get those cards onto both devices when you cannot
copy and paste them.

| | Discovery/signaling | Authentication | Saved state |
|---|---|---|---|
| Configure connection | Pairwise encrypted Nostr hosting records | Mutual application-key signatures | One identity key and a local trusted-peer list per installation |
| LAN setup (trust bootstrap) | Local Bonjour/DNS-SD or a typed LAN IP | Rotating PIN challenge-response, then a human fingerprint check | The imported peer card |

### Configure mode

Every duocb installation generates its own permanent application keypair. This
key is separate from iroh's ephemeral transport key:

- The application private key signs the device's portable identity card and
  authenticates the duocb wire handshake.
- The signed identity card contains the final device name, application public
  key, and a mandatory expiry. The final name is
  `<short-name>_<permanent-random-suffix>`; the suffix is minted once per
  installation and stays stable across renames and identity resets.
- The iroh key creates the current QUIC endpoint and node id. It is used for
  signaling and transport establishment, never as the saved duocb identity.

Pairing is mutual. On each device:

1. Copy its signed identity card.
2. Paste and import the other device's card.

Import verifies the signature before saving `{name, public key, signed card}`.
A device only accepts application keys in its own local trusted list. The list
is capped at 128 entries.

Cards are valid for 30 days. There is no renewal over the wire: once a card
expires, both devices refuse to pair on it, and the pairing is restored by
copying a fresh card and importing it again — the same two steps as the first
time. An expired peer stays in the trusted list, marked expired, so it can be
renewed or removed deliberately. A device re-signs its own card automatically
as it nears expiry, so the card it offers always has most of its life left.

When a trusted device starts a connection, it publishes a separate NIP-44
encrypted hosting record for each trusted peer. The record carries only the
current ephemeral iroh node id. A joining device resolves the selected
application public key, establishes the iroh connection, and then both sides
sign a fresh transcript containing:

- both application public keys;
- two random nonces;
- the dialer/listener roles; and
- both QUIC-authenticated iroh node ids.

Clipboard traffic starts only after both signatures verify and both local
trust checks pass.

### LAN setup — importing a card without copy-paste

Two devices with no shared clipboard cannot hand each other a 2 KiB signed card,
and cards expire every 30 days, so this is not a one-time problem. LAN setup
carries the card over the local network instead:

1. Both devices open LAN setup. It requires a configured identity — there has to
   be a card to hand over — so it is offered only from the configured hub.
2. One device shows a rotating eight-character PIN; the other types it.
3. The PIN locates the host on the local network and drives a mutual
   Argon2id-backed challenge-response over the resulting direct connection.
4. Both devices send their signed identity card across that connection.
5. Both then show the card they received, next to their own identity.
6. **Check that the incoming fingerprint on each device matches the fingerprint
   the other device shows for itself.** If it does not match, press Cancel —
   something else answered the PIN.
7. Press Import on both. Each device is now a trusted peer of the other, and you
   share the clipboard from the home screen as usual.

A LAN-setup connection never carries clipboard content; it exists only to hand
over the cards, and ends as soon as they have crossed. Discovery is
Bonjour-compatible DNS-SD. Where multicast is blocked, enter the LAN IP shown by
the host to use the unicast side channel.

One PIN admits one device: once a device has answered, a second device offering
the same code is refused.

The fingerprint is derived from a device's application public key, so it is
stable across card renewals and is shown beside every trusted device — you can
re-check it out of band at any time.

## Build and run

```sh
cargo build --release
cargo run
```

On Linux, Slint needs the usual Wayland/X11, fontconfig, and OpenGL development
libraries. The release binary is `target/release/duocb`.

For two instances on one machine, use separate config paths:

```sh
cargo run -- --config /tmp/duocb-peer1.json
cargo run -- --config /tmp/duocb-peer2.json
```

Each process holds an exclusive sibling `<config>.lock`; `-c` aliases
`--config`, and the CLI overrides `DUOCB_CONFIG`.

## Configuration

The machine-managed config lives under the platform user config directory. Its
shape is:

```json
{
  "version": 4,
  "identity_secret": "nsec1…",
  "device_suffix": "a7B2c3D4",
  "my_name": "mac-book",
  "self_card": "{ signed Nostr event JSON }",
  "peers": ["{ signed peer card JSON }"]
}
```

Malformed keys, cards, duplicates, mismatched self-cards, legacy
fields, and oversized peer lists are startup errors. An *expired* card is not:
it loads and is shown as expired, so lapsed trust is visible rather than
silently dropped. Saves use an owner-only
temporary file and atomic rename. Clipboard text, inbox, and outbox are never
persisted.

## Security notes

- QUIC/TLS 1.3 encrypts the transport.
- The LAN-setup fingerprint check is what makes the PIN safe to build trust on.
  The PIN proves possession of a short code, not an identity: it is ~35 bits and
  its rendezvous record is offline-attackable, so anyone who reads or guesses it
  inside its 60-second window can complete the handshake and offer a card. The
  human comparison catches exactly that. The incoming fingerprint is computed
  from the card that just arrived, so it is network-delivered and proves
  nothing on its own; what is trustworthy is the *expected* value, which the
  other device shows for itself and which you read off its screen. Holding the
  two against each other is what carries the check out of band.
- The fingerprint commits to a single public key, so an impostor needs a second
  preimage against a fixed target. A combined "session code" mixing both devices'
  keys would instead let an interposer vary both of its own keys and hunt for a
  collision — far cheaper for the same number of displayed digits.
- Checking one direction is enough. An interposer must sit in both directions at
  once, so comparing one device's incoming fingerprint against the other's own
  already fails for it.
- Receiving a card is not trusting it: cards cross automatically once the PIN
  matches, but nothing is written to the trusted list until a person presses
  Import.
- The application-key handshake authenticates configured peers independently
  of the iroh transport key.
- Pairwise hosting records are encrypted to the intended trusted peer.
- Trust is local only: the trusted-peer list never leaves the device, so a lost
  config is re-paired by re-importing each peer's card.
- Nostr relays and iroh infrastructure may observe metadata and timing.
- Clipboard items are UTF-8 text capped at 1 MiB.
- A server links one peer at a time. Configure mode pins the stable application
  identity while allowing its later iroh transport id to change.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for protocol details.
