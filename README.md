# duocb

**P2P clipboard sharing between two devices you own — end-to-end encrypted over iroh, signaled over nostr, driven by a small egui desktop app.**

duocb links **two devices belonging to the same person** (desktop ↔ laptop, workstation ↔ homelab box) so they can share clipboard text directly, without accounts, servers that see your data, public IPs, or port forwarding. One device acts as the **server** (displays pairing credentials), the other as the **client** (enters them); once paired, **both** sides can push their clipboard to the other over a single encrypted QUIC connection.

Received content never touches the receiving machine's clipboard (or disk) by itself: it lands in an **in-memory inbox** where you can **peek** at the full text first, and only an explicit **Copy** click puts it into the system clipboard.

> [!IMPORTANT]
> **Project goal:** let a **single user link two of their own devices** for ad-hoc clipboard sharing. Both ends are expected to be machines you own (or fully trust) — it is not a public service, not multi-tenant, and one server session pairs with exactly **one** peer.

> [!WARNING]
> **No backward compatibility (pre-1.0):** during initial development no compatibility or migration path is provided between versions. Expect to regenerate tokens and update both devices together.

**Features:**

- **No account or registration** — download and run
- **No public IPs or port forwarding** — automatic NAT hole punching with relay fallback (iroh)
- **End-to-end encryption** via QUIC/TLS 1.3; the connection is bound to the peer's node id (its public key)
- **Every connection authenticates in-band** — a pre-shared token or a PIN challenge-response; knowing a node id is never enough to pair
- **Peek before copy** — received items are viewable in the app without entering your clipboard; nothing is ever auto-copied
- **Memory only** — clipboard content and the inbox are never written to disk
- **Works offline on a LAN** — the manual mode resolves the typed node id via mDNS with zero internet
- **Fully keyboard-operable** — every flow has a shortcut
- **Cross-platform** — Linux, macOS, Windows; no root required

## Pairing modes

Chosen on the home screen; the server displays credentials, the client types them.

| Mode | Signaling | What you transfer by hand | Auth | Internet |
|---|---|---|---|---|
| **PIN quick pair** | nostr relays | an 8-character PIN that rotates every 60 s | Argon2id PIN challenge-response (mutual, in-band) | required |
| **Token + name** | nostr relays | a shared 47-char token + device names (once; can be remembered) | pre-shared token | required |
| **Manual / offline** | none | the server's node id + a generated one-time token | one-time token | **not required** on the same LAN (mDNS) |

- **PIN quick pair** is the fastest ad-hoc pairing: the server shows a short code, you type it on the client. The PIN both locates the server (an encrypted rendezvous record on public nostr relays) and authenticates the connection in-band — no token ever exists, and nothing offline-crackable crosses the wire.
- **Token + name** is for a standing pairing: both devices share one auth token (generate it in the app), each has a name, and the client resolves the server's current ephemeral node id by name via nostr. A restarted server is re-resolved automatically. "Remember these settings" saves the token and names to `~/.config/duocb/config.toml` so you don't retype them.
- **Manual / offline** needs no signaling at all: the server displays its node id and a freshly generated one-time token; enter both on the client. On the same LAN the node id resolves via mDNS, so it works with the internet down.

The iroh identity is **ephemeral** — a fresh node id (and manual-mode token, and PIN sequence) is minted every time the server starts. Stopping and restarting the server invalidates the previous credentials.

## Install / build

Prebuilt binaries are published by the manual release workflow (Actions → *Release (Manual)*) for Linux (amd64/arm64), macOS (arm64), and Windows (amd64).

From source:

```sh
cargo build --release        # binary at target/release/duocb
```

On Linux CI/minimal systems, eframe needs: `libxkbcommon-dev libwayland-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev`.

## Usage

Run `duocb` on both devices.

1. **Both devices:** pick the same pairing mode on the home screen (`1`/`2`/`3`).
2. **Server device:** press `S`, fill the form if any (token mode), then `Ctrl+Enter` to start sharing. The screen shows the credentials to transfer.
3. **Client device:** press `C`, type the credentials, `Ctrl+Enter` to connect.
4. **Paired:** both sides now show the session panel — `Ctrl+S` (or the button) reads your clipboard and sends it; received items appear in the inbox where you can **Peek** (view without copying) and **Copy** (the only action that writes your clipboard).

The client reconnects automatically with backoff if the connection drops. A server stays listening after its peer disconnects, but only the **same** peer may reconnect — a *restarted* client has a new identity and is refused; stop and start the server to pair a fresh session.

### Keyboard shortcuts

| Key | Where | Action |
|---|---|---|
| `1` / `2` / `3` | home | select PIN / token+name / manual mode |
| `S` / `C` | home | open the server / client screen |
| `Ctrl+Enter` | server / client form | start sharing / connect |
| `Esc` | any screen (no field focused) | back to home, stopping the session |
| `Ctrl+I` / `Ctrl+T` | manual server screen | copy the node id / the one-time token |
| `Ctrl+S` | connected | send the current clipboard |
| `Ctrl+P` | connected | peek/hide the newest inbox item |
| `Ctrl+Y` | connected | copy the newest inbox item to the clipboard |
| `Ctrl+L` | connected | clear the inbox |

## Configuration

Optional, only for the token+name mode: `~/.config/duocb/config.toml` (written by the explicit **Remember these settings** button, never automatically):

```toml
auth_token = "d…"       # shared 47-char token
my_name = "desktop"     # this device's name (server side)
peer_name = "laptop"    # the other device's name (client side)
```

Clipboard content and the inbox are never persisted anywhere.

## Security model

- The transport is iroh QUIC (TLS 1.3); the server's node id **is** its public key, so the client always talks to the endpoint it typed/resolved, end to end.
- Signaling records on public nostr relays contain only the server's **ephemeral node id**, NIP-44-encrypted under keys derived from the shared secret (token or PIN+time-bucket via Argon2id). Relay operators see ciphertext under rotating keys.
- The node id is not a credential: every connection must pass in-band auth (token match or mutual PIN proof) before the clipboard channel opens, and the first authenticated peer claims the server for the whole session.
- Clipboard payloads are capped at 1 MiB per item, text only.

## Limitations

- **Two devices, one pairing per server session.** By design.
- **Text only** (UTF-8). No images or files.
- A **crashed** peer (vs. a clean disconnect) is only detected at the QUIC idle timeout (up to ~5 minutes); clean disconnects are instant.
- Very large X11 clipboards transferred via INCR (multi-megabyte) may fail to read; you get an error banner and the connection is unaffected.
- On X11 without a clipboard manager, text copied *from* duocb disappears when duocb exits (standard X11 selection semantics).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design: threading model, wire protocol, signaling schemes, and key derivations.

## Acknowledgements

duocb's transport, signaling, and authentication stack is ported from [duopipe](../duopipe), which tunnels SOCKS5 over the same iroh + nostr foundation.
