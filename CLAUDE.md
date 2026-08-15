- strict no backward compatibility, legacy codes, or changelogs at all

- run `cargo clippy --workspace --all-targets` and `cargo test --workspace` after rust code changes
- no cargo fmt

# Workspace layout

- `crates/duocb-core` — portable core (persistent per-installation application identity and signed cards in `auth.rs`, mutual key wire authentication, pairwise hosting signaling and the card-setup PIN rendezvous — both over LAN and/or Nostr — plus the card exchange itself, and the headless tokio net runtime). Application identities and ephemeral iroh transport keys are separate. No GUI/clipboard/config-file deps.
- `crates/duocb` — desktop Slint app (binary `duocb`); owns config.rs, clipboard.rs, src/app/ (state + logic), and ui/*.slint (markup, compiled by build.rs; fluent style, Skia renderer, per-platform fonts set in main.rs).
- Version bumps: edit the single `[workspace.package] version` in the root Cargo.toml.
- Desktop-only. iOS support (the `duocb-ffi` staticlib, `ios/duocb.h`, `build-ios.sh`, and the release workflow's xcframework job) was removed while the core is being refactored; do not re-add it or reintroduce `target_os = "ios"` branches.

# E2E tests

- Add keyboard shortcuts to ctas to facilitate e2e testing.

## Config-based E2E tests on the same device

Only one duocb process may use a config path at a time (it holds an exclusive OS lock on a sibling `<config>.lock` file for its lifetime, allowing JSON saves to use atomic temp-and-rename replacement). To run both peers of a configure-mode pairing on the same machine, give each process its own config location — otherwise the second fails to acquire the lock. Each config mints its own application identity and permanent device-name suffix. Pair the instances either by copying each signed identity card into the other instance's trusted-peer list, or by running card setup ("Trade cards") on both and confirming the fingerprints each window shows — by default they find each other over loopback/mDNS and fall back to Nostr relays. Cards expire 30 days after they are minted and both sides refuse to pair on a lapsed one, so a long-lived test config needs its cards re-copied:

```sh
cargo run -- --config /tmp/duocb-peer1.json   # or DUOCB_CONFIG=/tmp/duocb-peer1.json
cargo run -- --config /tmp/duocb-peer2.json   # or DUOCB_CONFIG=/tmp/duocb-peer2.json
```

`--lan-only` and `--nostr-only` pin all signaling to one transport for the life of the process — both the card-setup PIN rendezvous and the pairwise hosting records a clipboard session is found through (the default tries the local network first and falls back to Nostr relays). Both at once is an error, and the hub shows a banner naming whichever is in effect. Forcing them on the two instances *differently* — e.g. a `--nostr-only` host and a default joiner — is what exercises the fallback: the joiner misses on mDNS and then resolves through the relays. `--lan-only` on both is the way to run a fully offline pair.

`-c` is an alias for `--config`; the CLI flag wins over `DUOCB_CONFIG`. Without an override, both processes resolve to the same default location (see README) and collide. Joining is by choosing Join on the home hub, which opens the local trusted-device picker, and selecting the peer there. Card setup ("Trade cards") is a separate flow reached from the hub: it only trades identity cards and never carries clipboard traffic. The join retries at a fixed interval for up to 10 attempts, so press Join again if the host starts later. Configs are per-installation. There is no peer-list backup: a saved private key restores the identity only, and the trusted-peer list is rebuilt by re-importing each peer's card.
