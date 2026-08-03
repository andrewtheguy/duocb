# duocb

End-to-end encrypted, peer-to-peer clipboard sharing between two devices you
own. Both sides can send and receive after one device starts a connection and
the other joins it. Received text stays in an in-memory inbox until you
explicitly copy it.

> [!WARNING]
> duocb is pre-1.0 and intentionally has no backward compatibility. This
> release rejects the former shared-secret config and wire protocol.

## Pairing modes

| Mode | Discovery/signaling | Authentication | Saved state |
|---|---|---|---|
| Configure | Pairwise encrypted Nostr hosting records | Mutual application-key signatures | One identity key and a local trusted-peer list per installation |
| Quick | Local Bonjour/DNS-SD or a typed LAN IP | Rotating PIN challenge-response | None |

### Configure mode

Every duocb installation generates its own permanent application keypair. This
key is separate from iroh's ephemeral transport key:

- The application private key signs the device's portable identity card and
  authenticates the duocb wire handshake.
- The signed identity card contains the final device name and application
  public key. The final name is `<short-name>_<permanent-random-suffix>`; the
  suffix is minted once per installation and stays stable across renames and
  identity resets.
- The iroh key creates the current QUIC endpoint and node id. It is used for
  signaling and transport establishment, never as the saved duocb identity.

Pairing is mutual. On each device:

1. Copy its signed identity card.
2. Paste and import the other device's card.

Import verifies the signature before saving `{name, public key, signed card}`.
A device only accepts application keys in its own local trusted list. The list
is capped at 128 entries.

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

### Optional Nostr peer-list backup

Configure mode can use a manually entered or generated `dc1.…` directory
channel. It is a standalone 128-bit backup/discovery channel, not an
authentication key.

Each installation publishes its own complete peer list as an NIP-44 encrypted,
signed, bounded snapshot. Backups:

- are selected by the owner's application public key;
- are capped at 128 peers and 128 KiB decoded;
- use 8 KiB chunks with hashes and a committed header; and
- alternate between two replaceable slots, retaining one fallback generation.

The channel can also reveal signed self-cards published by other owners on that
channel. They are candidates only: the UI never trusts them automatically.

#### Fresh-install recovery

Save both the private key (`nsec1…`) and the directory channel. On a fresh
installation:

1. Choose **Restore a private key** and enter the `nsec`.
2. Enter the saved `dc1.…` channel.
3. duocb looks up backups authored by the restored public key and decrypts them
   with the channel.
4. If a valid complete backup exists, duocb displays an offer with its signed
   name, generation, and peer list.
5. Select the peers to recover and explicitly choose **Restore selected**, or
   choose **Keep local state**.

Accepting the restore also recovers the signed short name and its permanent
suffix. Restore is never automatic. Entering an existing channel queries
before publishing, so a fresh empty install cannot overwrite the backup it is
trying to recover. The private key alone cannot recover the list because the
channel is intentionally separate and is required to locate/decrypt the
backup.

### Quick mode

Quick mode remains identity-free. The host displays a rotating eight-character
PIN; the joiner enters it. The PIN locates the host and drives a mutual
Argon2id-backed challenge-response.

The desktop quick flow is LAN-only and uses Bonjour-compatible DNS-SD. Where
multicast is blocked, enter the LAN IP shown by the host to use the unicast side
channel. No saved application key, trusted peer, or backup channel participates.

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
  "version": 1,
  "identity_secret": "nsec1…",
  "my_name": "mac-book",
  "self_card": "{ signed Nostr event JSON }",
  "directory_channel": "dc1.…",
  "peers": ["{ signed peer card JSON }"],
  "backup_generation": 4,
  "backup_dirty": false
}
```

Malformed keys, cards, channels, duplicates, mismatched self-cards, legacy
fields, and oversized peer lists are startup errors. Saves use an owner-only
temporary file and atomic rename. Clipboard text, inbox, and outbox are never
persisted.

## Security notes

- QUIC/TLS 1.3 encrypts the transport.
- The application-key handshake authenticates configured peers independently
  of the iroh transport key.
- Pairwise hosting records are encrypted to the intended trusted peer.
- Directory backups are encrypted with the optional channel and signed by
  their owning application key. Anyone holding the channel can read channel
  backups, so store it with the private key.
- Nostr relays and iroh infrastructure may observe metadata and timing.
- Clipboard items are UTF-8 text capped at 1 MiB.
- A server links one peer at a time. Configure mode pins the stable application
  identity while allowing its later iroh transport id to change.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for protocol details and
[ios/duocb.h](ios/duocb.h) for the strict iOS FFI.
