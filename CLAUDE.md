- strict no backward compatibility

- run `cargo clippy --workspace --all-targets` and `cargo test --workspace` after rust code changes
- no cargo fmt

## Workspace layout

- `crates/duocb-core` — portable core (persistent per-installation application identity and signed cards in `auth.rs`, mutual key wire authentication, pairwise Nostr signaling, encrypted directory backups, quick PIN support, and the headless tokio net runtime). Application identities, optional directory channels, and ephemeral iroh transport keys are separate. No GUI/clipboard/config-file deps.
- `crates/duocb` — desktop Slint app (binary `duocb`); owns config.rs, clipboard.rs, src/app/ (state + logic), and ui/*.slint (markup, compiled by build.rs; fluent style, Skia renderer, per-platform fonts set in main.rs).
- Version bumps: edit the single `[workspace.package] version` in the root Cargo.toml.
- Desktop-only. iOS support (the `duocb-ffi` staticlib, `ios/duocb.h`, `build-ios.sh`, and the release workflow's xcframework job) was removed while the core is being refactored; do not re-add it or reintroduce `target_os = "ios"` branches.

## Config-based E2E tests on the same device

Only one duocb process may use a config path at a time (it holds an exclusive OS lock on a sibling `<config>.lock` file for its lifetime, allowing JSON saves to use atomic temp-and-rename replacement). To run both peers of a configure-mode pairing on the same machine, give each process its own config location — otherwise the second fails to acquire the lock. Each config mints its own application identity and permanent device-name suffix. Pair the instances by copying each signed identity card into the other instance's trusted-peer list:

```sh
cargo run -- --config /tmp/duocb-peer1.json   # or DUOCB_CONFIG=/tmp/duocb-peer1.json
cargo run -- --config /tmp/duocb-peer2.json   # or DUOCB_CONFIG=/tmp/duocb-peer2.json
```

`-c` is an alias for `--config`; the CLI flag wins over `DUOCB_CONFIG`. Without an override, both processes resolve to the same default location (see README) and collide. Joining is by choosing Join on the home hub, which opens the local trusted-device picker, and selecting the peer there. The join retries at a fixed interval for up to 10 attempts, so press Join again if the host starts later. Configs are per-installation; recovery uses a saved private key plus optional directory channel and always requires explicit confirmation before applying a found peer backup.

## Running GUI apps for Linux

A TigerVNC server (XFCE desktop) runs on display `:1`, served on `127.0.0.1:5901` (localhost-only, 1280x800, 24-bit).

- The shell has no `DISPLAY` set by default. Launch GUI apps with `DISPLAY=:1`, e.g. `DISPLAY=:1 xclock &`.
- Screenshot the display to verify rendering: `DISPLAY=:1 import -window root screen.png` (ImageMagick), or `xwd -root -out screen.xwd`.
- List mapped windows: `DISPLAY=:1 xwininfo -root -children`.
- Port 5901 is localhost-only. To view remotely, tunnel it: `ssh -L 5901:localhost:5901 <host>`, then point a VNC viewer at `localhost:5901`.
