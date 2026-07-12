# Roadmap

Planned work with enough design detail to implement safely. Current behavior is
documented in [README.md](../README.md) and [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Duplicate device names in token mode — SUPERSEDED

The duplicate-name problem this entry used to design around no longer exists.
The configure-mode redesign replaced free-form device names with unique-by-
construction display identities:

- Every device carries a **permanent random 8-character suffix** (unambiguous
  mixed-case alphabet), minted on the first launch with its config file and
  never regenerated. The broadcast identity is `<name>_<suffix>`
  (e.g. `mac-book_a7B2c3D4`), so two devices choosing the same short name can
  never collide on the presence-record `d` tag.
- The joiner no longer auto-picks "the newest record that isn't mine": it
  fetches the decrypted device list and the user selects the specific hosting
  device to dial. The ambiguous same-name lookup failure cannot occur.
- Configs are **per-machine** — copying a config file to another device is not
  a supported use case, so a cloned suffix is out of scope. The residual
  safety net is the per-publisher-run `run_id` in each presence record: a
  publisher that finds a record under its own identity written by another live
  publisher surfaces a conflict and stops broadcasting.

The phased `device_id` design that previously lived here (versioned payload,
pre-publish self-check, rename/take-over dialog) is superseded by the above and
was not implemented.

---

## Follow-ups

### Presence via relay subscriptions

The peer list is polled (fetch on hub entry, manual refresh, 30 s auto-refresh
while visible) over one-shot relay connections, matching the existing
connect–fetch–disconnect nostr usage. A persistent relay subscription would
push presence changes instead of polling; it introduces a long-lived relay
connection lifecycle (reconnects, resubscribes) that the current design
deliberately avoids.

### Graceful offline notice on shutdown

A device that exits could publish a final non-hosting record (or a shorter
freshness hint) so peers see it drop offline before the 300 s online window
lapses. Today it simply stops republishing and ages out.
