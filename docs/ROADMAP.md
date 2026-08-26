# Roadmap

Planned work with enough design detail to implement safely. Current behavior is
documented in [README.md](../README.md) and [ARCHITECTURE.md](./ARCHITECTURE.md).

## Follow-ups

### Presence via relay subscriptions

The device picker currently reads only the local trusted-card list. It performs
no presence lookup; pairwise rendezvous starts after both users select each
other and press Connect. Adding presence would require either bounded polling
or a persistent relay subscription, plus a clear lifecycle for reconnecting,
resubscribing, expiry, and the metadata exposed by presence announcements.
