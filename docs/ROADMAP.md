# Roadmap

Planned work with enough design detail to implement safely. Current behavior is
documented in [README.md](../README.md) and [ARCHITECTURE.md](./ARCHITECTURE.md).

## Follow-ups

### Presence via relay subscriptions

The peer list is polled (fetch on entering the device picker behind the Join
action, manual refresh, 30 s auto-refresh while the picker is visible) over
one-shot relay connections, matching the existing connect–fetch–disconnect
nostr usage. A persistent relay subscription would
push presence changes instead of polling; it introduces a long-lived relay
connection lifecycle (reconnects, resubscribes) that the current design
deliberately avoids.
