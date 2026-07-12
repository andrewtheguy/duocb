- strict no backward compatibility

- run `cargo clippy --workspace --all-targets` and `cargo test --workspace` after rust code changes
- no cargo fmt

## Workspace layout

- `crates/duocb-core` — portable core (token auth, wire protocol, nostr signaling, headless tokio net runtime). No GUI/clipboard/config-file deps.
- `crates/duocb` — desktop egui app (binary `duocb`); owns config.rs, clipboard.rs, ui/.
- `crates/duocb-ffi` — iOS staticlib (`libduocb.a`, config/token mode only), hand-written `extern "C"`; the C header is hand-maintained at `ios/duocb.h` and must stay in sync.
- Version bumps: edit the single `[workspace.package] version` in the root Cargo.toml.

## iOS

`./build-ios.sh [debug]` builds device + simulator slices of `duocb-ffi` and stages `dist/ios/libduocb.xcframework` + `duocb.h`. The sibling app repo `../duocb-ios` consumes the pinned GitHub release zip (`libduocb-ios.xcframework.zip`, produced by the release workflow) by default; for local FFI dev set `DUOCB_LOCAL_XCFRAMEWORK=1` there (both for `xcodegen generate` and `xcodebuild`) to use this repo's `dist/ios` build through a committed symlink.

## Config-based E2E tests on the same device

Only one duocb process may use a config path at a time (it holds an exclusive OS lock on the config file itself for its lifetime). To run both peers of a config/token pairing on the same machine, give each process its own config location — otherwise the second fails to acquire the lock. Keep the shared `auth_token` equal and the `my_name` values different:

```sh
cargo run -- --config /tmp/duocb-peer1.json   # or DUOCB_CONFIG=/tmp/duocb-peer1.json
cargo run -- --config /tmp/duocb-peer2.json   # or DUOCB_CONFIG=/tmp/duocb-peer2.json
```

`-c` is an alias for `--config`; the CLI flag wins over `DUOCB_CONFIG`. Without an override, both processes resolve to the same default location (see README) and collide.

## Running GUI apps for Linux

A TigerVNC server (XFCE desktop) runs on display `:1`, served on `127.0.0.1:5901` (localhost-only, 1280x800, 24-bit).

- The shell has no `DISPLAY` set by default. Launch GUI apps with `DISPLAY=:1`, e.g. `DISPLAY=:1 xclock &`.
- Screenshot the display to verify rendering: `DISPLAY=:1 import -window root screen.png` (ImageMagick), or `xwd -root -out screen.xwd`.
- List mapped windows: `DISPLAY=:1 xwininfo -root -children`.
- Port 5901 is localhost-only. To view remotely, tunnel it: `ssh -L 5901:localhost:5901 <host>`, then point a VNC viewer at `localhost:5901`.
