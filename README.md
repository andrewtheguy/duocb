# duocb

**P2P clipboard sharing between two devices you own — clipboard content is end-to-end encrypted over iroh; with optional nostr for signaling.**

duocb links **two devices belonging to the same person** (desktop ↔ laptop, workstation ↔ homelab box) so they can share clipboard text directly, without accounts, servers that see your data, public IPs, or port forwarding. The two roles are only about setup: one device **starts a connection** (displays pairing credentials), the other **joins** it (enters them). Once paired, **both** sides can send and receive — either can push its clipboard to the other over a single encrypted QUIC connection.

Received content never touches the receiving machine's clipboard (or disk) by itself: it lands in an **in-memory inbox** where you can **peek** at a truncated preview of the text first, and only an explicit **Copy** click puts the full content into the system clipboard.

> [!IMPORTANT]
> **Project goal:** let a **single user link two of their own devices** for ad-hoc clipboard sharing. Both ends are expected to be machines you own (or fully trust) — it is not a public service, not multi-tenant, and one connection pairs with exactly **one** peer.

> [!WARNING]
> **No backward compatibility (pre-1.0):** during initial development no compatibility or migration path is provided between versions. Expect to regenerate tokens and update both devices together.

**Features:**

- **No account or registration** — download and run
- **No public IPs or port forwarding** — automatic NAT hole punching with relay fallback (iroh)
- **End-to-end encryption** via QUIC/TLS 1.3; the connection is bound to the peer's node id (its public key)
- **Every connection authenticates in-band** — a pre-shared token or a PIN challenge-response; knowing a node id is never enough to pair
- **Peek before copy** — received items show size, a CRC-32 fingerprint, and arrival time; the content is only revealed on an explicit **Peek** (which auto-hides after a few seconds), and only **Copy** ever writes your clipboard
- **Compare what you sent** — the last item you sent is shown in an outbox with its size/CRC so the other device can confirm it matches what arrived
- **Memory only** — clipboard content, the inbox, and the outbox are never written to disk
- **Works offline on a LAN** — the manual mode resolves the typed node id via mDNS with zero internet
- **Fully keyboard-operable** — every flow has a shortcut
- **Cross-platform** — Linux, macOS, Windows; no root required

## Pairing modes

Chosen on the home screen; the **starting** device displays credentials, the **joining** device types them.

| Mode | Signaling | What you transfer by hand | Auth | Internet |
|---|---|---|---|---|
| **PIN quick pair** | nostr relays | an 8-character PIN that rotates every 60 s | Argon2id PIN challenge-response (mutual, in-band) | required |
| **Token + names** | nostr relays | a shared 47-char token + each device's own unique name (once; can be remembered) | pre-shared token | required |
| **Manual / offline** | none | the starting device's node id + a generated token | shared token | **not required** on the same LAN (mDNS) |

- **PIN quick pair** is the fastest ad-hoc pairing: the starting device shows a short code, you type it on the joining device. The PIN both locates the starting device (an encrypted rendezvous record on public nostr relays) and authenticates the connection in-band — no token ever exists, and nothing offline-crackable crosses the wire. Because it carries no shared standing state — just a fresh ephemeral identity and a rotating PIN — this mode is **conflict-free**: it works just as well for pairing two devices owned by two *different* people as for your own two. That's a supported side effect, not the project's primary focus (which remains linking your own devices).
- **Token + names** is for a standing pairing: both devices share one auth token (generate it in the app), and each enters its own distinct name. The joining device queries the shared token-derived nostr identity and automatically selects the newest record belonging to a different name; you never enter the other device's name. A restarted starting device is re-resolved automatically. The initiator always saves its valid token and name before starting; the connector saves them automatically only after a connection authenticates successfully.
- If two devices accidentally use the same name, the current join flow cannot distinguish that live collision from a stale self record. The planned actionable detection and resolution flow is documented in [docs/ROADMAP.md](docs/ROADMAP.md).
- **Manual / offline** needs no signaling at all: the starting device displays its node id and a freshly generated token (shown as a fingerprint, copied to the clipboard); enter both on the joining device. The token stays valid for the whole session, so the paired peer can reconnect after a drop. On the same LAN the node id resolves via mDNS, so it works with the internet down.

The iroh identity is **ephemeral** — a fresh node id (and manual-mode token, and PIN sequence) is minted every time a connection is started. Stopping and restarting invalidates the previous credentials.

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
2. **Starting device:** press `S`, fill the form if any (token mode), then `Ctrl+Enter` to start the connection. The screen shows the credentials to transfer.
3. **Joining device:** press `C`, type the credentials, `Ctrl+Enter` to connect.
4. **Paired:** both sides now show the same session panel — `Ctrl+S` (or the button) reads your clipboard and sends it; received items appear in the inbox where you can **Peek** (view without copying) and **Copy** (the only action that writes your clipboard). Either device can send at any time; the outbox above the inbox shows the last item you sent (size + CRC) so the other side can confirm it matches what arrived.

The joining device reconnects automatically with backoff if the connection drops. The starting device stays listening after its peer disconnects, but only the **same** peer may reconnect — a *restarted* joining device has a new identity and is refused; restart the connection to pair a fresh session.

### Keyboard shortcuts

| Key | Where | Action |
|---|---|---|
| `1` / `2` / `3` | home | select PIN / token+name / manual mode |
| `S` / `C` | home | start a connection / join a connection |
| `Ctrl+Enter` | start / join form | start the connection / connect |
| `Esc` | any screen (no field focused) | back to home, stopping the session |
| `Ctrl+I` / `Ctrl+T` | manual start screen | copy the node id / the token |
| `Ctrl+S` | connected | send the current clipboard |
| `Ctrl+P` | connected | peek/hide the newest inbox item |
| `Ctrl+Y` | connected | copy the newest inbox item to the clipboard |
| `Ctrl+L` | connected | clear the inbox |

## Configuration

Optional, only for the token+name mode: a `duocb/config.toml` under the platform's per-user config directory — `~/.config/duocb/config.toml` on Linux, `~/Library/Application Support/duocb/config.toml` on macOS, and `%APPDATA%\duocb\config.toml` on Windows. Starting a token-mode connection writes the valid initiator settings before launch. Joining writes the connector settings only after successful authentication, so failed attempts never replace the saved pairing:

```toml
auth_token = "d…"       # shared 47-char token
my_name = "desktop"     # this device's unique name, whether starting or joining
```

Only one duocb process may use a config path at a time. The process holds an
exclusive `config.toml.lock` sidecar for its lifetime, preventing two local
instances from accidentally claiming the same device identity. For same-machine
end-to-end testing, give each process its own config while keeping the token equal
and the names different:

```sh
duocb --config /tmp/duocb-mac1.toml
duocb --config /tmp/duocb-mac2.toml
```

`-c` is an alias for `--config`; `DUOCB_CONFIG=/path/to/config.toml` provides the
same override for test harnesses. A command-line path takes precedence over the
environment variable.

Clipboard content and the inbox are never persisted anywhere.

## Security model

- The transport is iroh QUIC (TLS 1.3); the starting device's node id **is** its public key, so the joining device always talks to the endpoint it typed/resolved, end to end.
- Signaling records on public nostr relays contain only the starting device's **ephemeral node id**, NIP-44-encrypted under keys derived from the shared secret (token or PIN+time-bucket via Argon2id). Relay operators see ciphertext under rotating keys.
- The node id is not a credential: every connection must pass in-band auth (token match or mutual PIN proof) before the clipboard channel opens, and the first authenticated peer claims the connection for the whole session.
- Clipboard payloads are capped at 1 MiB per item, text only.

## Limitations

- **Two devices, one pairing per connection.** By design.
- **Text only** (UTF-8). No images or files.
- A **crashed** peer (vs. a clean disconnect) is detected at the QUIC idle timeout (~30 s), after which the starting device accepts its reconnect and the joining device starts retrying; clean disconnects are instant.
- Very large X11 clipboards transferred via INCR (multi-megabyte) may fail to read; you get an error banner and the connection is unaffected.
- On X11 without a clipboard manager, text copied *from* duocb disappears when duocb exits (standard X11 selection semantics).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design: threading model, wire protocol, signaling schemes, and key derivations.

## Acknowledgements

duocb's transport, signaling, and authentication stack is ported from [duopipe](../duopipe), which tunnels SOCKS5 over the same iroh + nostr foundation.
