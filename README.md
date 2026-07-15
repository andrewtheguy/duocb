# duocb

**P2P clipboard sharing between two devices you own end-to-end encrypted..**

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
- **Works offline on a LAN** — LAN-only PIN pairing uses Bonjour-compatible DNS-SD (mDNS) discovery and direct device-to-device transport, so no third-party server participates in the session; "LAN-only" is a discovery policy, not a packet-level subnet boundary
- **Fully keyboard-operable** — every flow has a shortcut
- **Cross-platform** — Linux, macOS, Windows; no root required

## Pairing modes

**Configure** is the primary mode and the home screen itself; the quick options live behind the home's **Quick options** button (`Q`) for ad-hoc pairing.

| Mode | Signaling | What you transfer by hand | Auth | Internet |
|---|---|---|---|---|
| **Configure** (primary) | nostr relays | a shared 47-char secret (once per device, at setup) | pre-shared secret | required |
| **PIN quick pair** | nostr relays + LAN (mDNS, or a typed host IP when multicast is blocked); selectable | an 8-character PIN that rotates every 60 s (plus, optionally, the host's LAN IP) | Argon2id PIN challenge-response (mutual, in-band) | **not required** on the same LAN |

- **Configure** links all of your devices under one **standing secret**. A setup wizard generates the secret on the first device (shown as a masked hint plus fingerprint, with an explicit **Copy secret** action) or imports it on the next (masked paste, fingerprint confirmation); it stays in the config until you explicitly **Clear secret**. Each device gets a collision-resistant identity `<name>_<suffix>` — a short name you choose plus a permanent random 8-character suffix minted on first launch. The home screen is then the hub: your identity plus two actions — **Start** hosts a connection (nothing else needed on that device), **Join** opens the device picker. Nostr stays dormant until you pick one of those: only then does the device broadcast an encrypted presence record on public nostr relays under a keypair derived from the secret (authorship *is* the proof of secret possession); returning to the hub stops the broadcast, and the idle hub — or using only quick mode — touches no relays at all. The picker shows your other devices (with when each record was last broadcast — no online/offline guesswork: relay freshness is unreliable, so nothing is gated on it and the iroh dial itself is the liveness check), where you select the device to join. Any listed device can be joined — if it isn't hosting yet, the join retries every few seconds for up to 10 attempts, so starting the host shortly afterward works; if those attempts expire, press Join again. You never type the other device's name, and identical short names are distinguished by their high-entropy suffixes. A restarted host is re-resolved automatically.
- **PIN quick pair** is the fastest ad-hoc pairing: the starting device shows a short code (with a **Copy PIN** action), you type it on the joining device — into two four-character groups (uppercasing and mapping look-alikes as you go, with focus auto-advancing between groups) that tell you whether the code is still incomplete or fully typed but mistyped. The PIN both locates the starting device and authenticates the connection in-band — no token ever exists. The same encrypted rendezvous record travels over a **discovery** channel chosen on the hosting device: *internet + local network* (the default — the joiner races both), *internet only* (public nostr relays), or *local network only* (relayless direct transport with no built-in WAN discovery or fallback; the record is advertised as a spec-compliant Bonjour/DNS-SD service — `_duocb-pin._udp` — whose SRV/A records carry the host's direct addresses, which the joiner dials as resolved; on iOS the advertisement and lookup go through the system mDNSResponder daemon, so the iOS app needs no multicast entitlement). In local-network-only mode, **private** means that no third-party server participates in the session: discovery stays on the local network and all session traffic travels directly between the two devices, never through a middle server. It does not enforce an on-link IP boundary: direct addresses are not filtered and inbound connections are not rejected by source subnet, so reflected mDNS, a VPN or overlay, a globally routed interface, or a custom peer that already has the endpoint details and PIN can extend that direct path beyond a conventional LAN. A captured rendezvous record is an offline PIN-guessing target; Argon2id makes each guess expensive, and a guessed PIN is useful to an attacker only before the first peer claims the server. Once paired, the server stops publishing PINs and binds the session to that peer's QUIC-authenticated node id: a later PIN recovery alone cannot join, reconnect as a different identity, or decrypt the established QUIC session. The channel is picked only on the hosting device: the PIN it shows encodes the channel in its first character (a *local network only* PIN starts with one set of characters, the internet-carrying channels with another), so the joiner never chooses a channel — it reads the channel from the PIN it types, and the two sides can never mismatch. The *local network only* channel has a **manual-IP path** for networks that block multicast: a host on this channel also displays its LAN IPv4 and runs a small unicast listener that serves the same PIN-encrypted rendezvous record on a port derived from the PIN. Leaving the joiner's optional IP field blank resolves via mDNS as usual; typing the host's IP fetches the record straight from it (no multicast) and then dials the direct addresses it returns — same PIN either way, and the typed IP is the only thing that selects the path. Because this mode carries no shared standing state — just a fresh ephemeral identity and a rotating PIN — it works just as well for pairing two devices owned by two *different* people as for your own two. That's a supported side effect, not the project's primary focus (which remains linking your own devices).

The iroh identity is **ephemeral** — a fresh node id and PIN sequence are minted every time a connection is started. Stopping and restarting invalidates those ephemeral credentials. The configure mode's secret, device name, and suffix persist; its presence record is updated with each run's fresh node id.

## Install / build

Prebuilt packages are published by the manual release workflow (Actions → *Release (Manual)*) for Linux (amd64/arm64) and macOS (arm64). Stable releases also include Windows (amd64); prerelease runs skip the Windows build.

From source:

```sh
cargo build --release        # binary at target/release/duocb
```

On Linux CI/minimal systems, the Slint UI needs: `libxkbcommon-dev libwayland-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libfontconfig1-dev` plus OpenGL (mesa). The first build downloads the prebuilt Skia binaries for the text renderer, so expect it to take a while.

The UI renders in the platform's native fonts (San Francisco/Menlo on macOS, Segoe UI/Consolas on Windows, the fontconfig defaults on Linux); set `DUOCB_UI_FONT` to override the UI font family.

## Usage

Run `duocb` on both devices.

**Configure mode (primary):**

1. **First device:** the setup wizard opens on launch. Press `G` to generate the secret (copy it somewhere safe), then name the device. The home screen becomes the hub: your identity (e.g. `mac-book_a7B2c3D4`), the secret's fingerprint, and the Start/Join actions.
2. **Other device:** press `I`, paste the same secret (confirm the fingerprint matches), and name it.
3. **Pair:** press `S` (Start) on one device; on the other press `C` (Join) to open the device picker, select it (`R` refreshes the list), and press `Enter`. Joining first and starting shortly afterward also works: the join retries every few seconds for up to 10 attempts. If it gives up first, press Join again after the host starts.

**Quick options:** press `Q` on both devices. The two everyday choices are `P` PIN quick pair (internet + local network — the default) and `L` local network only (private session: Bonjour/DNS-SD discovery and direct device-to-device traffic, with no third-party server; this is also the channel the iOS app's "Local network only" option speaks — see the LAN-boundary caveat above). One advanced, mostly-for-testing option sits behind an "Advanced options" section: `I` internet only (the PIN is found through a nostr relay only, not advertised on the LAN — though the connection can still take a direct local path). **The channel is chosen only on the device showing the PIN**: `P` and `L` advertise the record differently on the LAN (`P` rides the iroh-style swarm responder, `L` a standard Bonjour service), and the PIN's first character encodes which, so the joiner just types the PIN and the app picks the matching discovery automatically — no channel to select on the joining side. Then press `S` on the starting device and `C` on the joining one, and type the displayed PIN. A device hosting on `L` also shows its LAN IP; if the joiner's network blocks multicast so the automatic lookup fails, type that IP into the join form's optional field to fetch the record over a direct unicast connection instead (same PIN either way).

**Paired:** both sides now show the same session panel — `Ctrl/⌘+S` (or the button) reads your clipboard and sends it, and a compose field sends typed text directly (Enter) without touching the clipboard; received items appear in the inbox where you can **Peek** (view without copying) and **Copy** (the only action that writes that received item to your clipboard). Either device can send at any time; the outbox above the inbox shows the last item you sent (size + CRC) so the other side can confirm it matches what arrived.

The joining device reconnects automatically if the connection drops — a fixed retry every few seconds, giving up after 10 consecutive failures (press Join again to resume). The starting device stays listening after its peer disconnects, but only the **same** peer may reconnect — any other device (a *restarted* joining device, which has a new identity, or a third device) is refused immediately with a busy signal rather than left hanging; restart the connection to pair a fresh session.

### Keyboard shortcuts

`Ctrl` is used on Windows and Linux; `⌘` (Command) is used on macOS.

| Key | Where | Action |
|---|---|---|
| `G` / `I` | home (configure setup) | generate a new secret / import an existing one |
| `S` | home / quick options | start (host) a connection |
| `C` | home (configure hub) | open the device picker |
| `C` / `Enter` | device picker | join the selected device |
| `R` / `↑` `↓` | device picker | refresh the device list / move the selection |
| `Esc` | device picker | back to the hub |
| `Q` | home | open the quick options |
| `P` / `L` | quick options | PIN quick pair (internet + local network) / local network only |
| `I` | quick options (uncommon) | internet only (PIN over a nostr relay) |
| `C` | quick options | go to the join form |
| `Ctrl/⌘+Enter` | quick-mode join forms | connect |
| `Esc` | any screen (no field focused) | back to home, stopping the session |
| `Ctrl/⌘+T` | when available | copy the PIN (PIN host) or the secret (hub) |
| `Ctrl/⌘+S` | connected | send the current clipboard |
| `Ctrl/⌘+P` | connected | peek/hide the newest inbox item |
| `Ctrl/⌘+Y` | connected | copy the newest inbox item to the clipboard |
| `Ctrl/⌘+L` | connected | clear the inbox |

## Configuration

On every launch, duocb creates (if needed) and locks `duocb/config.json` under the platform's per-user config directory — `~/.config/duocb/config.json` on Linux, `~/Library/Application Support/duocb/config.json` on macOS, and `%APPDATA%\duocb\config.json` on Windows. The file stores the configure mode's state and is written and read by duocb, not meant for hand editing. The setup wizard saves the secret and device name as soon as they are entered; `device_suffix` is generated on the very first launch and never changes — it survives **Clear secret** (which removes only `auth_token`):

```json
{
  "auth_token": "d…",
  "my_name": "mac-book",
  "device_suffix": "a7B2c3D4"
}
```

The config is **per-machine**: the permanent suffix is this device's identity, so
copying a config file to another machine is not supported — import the secret
through the wizard there instead. Configs from versions before the suffix
existed load with a fresh suffix; there is no other migration (pre-1.0, no
backward compatibility).

Only one duocb process may use a config path at a time. The process holds an
exclusive OS lock on the config file itself for its lifetime, preventing two local
instances from accidentally claiming the same device identity and guarding the
file against accidental external edits while duocb runs. For same-machine
end-to-end testing, give each process its own config (each mints its own suffix;
keep the secret equal):

```sh
duocb --config /tmp/duocb-mac1.json
duocb --config /tmp/duocb-mac2.json
```

`-c` is an alias for `--config`; `DUOCB_CONFIG=/path/to/config.json` provides the
same override for test harnesses. A command-line path takes precedence over the
environment variable.

Clipboard content and the inbox are never persisted anywhere.

## Security model

- The transport is iroh QUIC (TLS 1.3); the starting device's node id **is** its public key, so the joining device always talks to the endpoint it typed/resolved, end to end.
- Signaling records on public nostr relays are NIP-44-encrypted under keys derived from the shared secret (token or PIN+time-bucket via Argon2id). Configure-mode presence records carry each device's display name and, while hosting, its **ephemeral node id** — both inside the ciphertext; PIN records carry only the node id. Relay operators see ciphertext, author keys, and event timing.
- The node id is not a credential: every connection must pass in-band auth (token match or mutual PIN proof) before the clipboard channel opens, and the first authenticated peer claims the connection for the whole session.
- Clipboard payloads are capped at 1 MiB per item, text only.

## Limitations

- **Two devices, one pairing per server session.** By design.
- **Text only** (UTF-8). No images or files.
- A **crashed** peer (vs. a clean disconnect) is detected at the QUIC idle timeout (~30 s), after which the starting device accepts its reconnect and the joining device starts retrying; clean disconnects are instant.
- Very large X11 clipboards transferred via INCR (multi-megabyte) may fail to read; you get an error banner and the connection is unaffected.
- On X11 without a clipboard manager, text copied *from* duocb disappears when duocb exits (standard X11 selection semantics).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design: threading model, wire protocol, signaling schemes, and key derivations.

## Acknowledgements

duocb's transport, signaling, and authentication stack is ported from [duopipe](../duopipe), which tunnels SOCKS5 over the same iroh + nostr foundation.

The desktop UI is made with [Slint](https://slint.dev), used under the Slint Royalty-Free License.
