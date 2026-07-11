# Roadmap

Planned work with enough design detail to implement safely. Current behavior is
documented in [README.md](../README.md) and [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Duplicate device names in token mode

### Why this is still relevant

Token mode gives every device in a pairing the same nostr author key, derived
from the shared auth token. Each device's own name produces its parameterized
replaceable-event `d` tag:

```text
duocb:nodeid:<sha256("duocb:peer-id:v1" || auth_token || own_name)>
```

The joining device queries by author key alone and excludes its own `d` tag. This
is correct when the devices have distinct names: `mac2` excludes an old `mac2`
record and selects the active `mac1` record without needing to know that name.

If both devices are named `mac1`, however, the joining device also excludes the
starting device's record because both names derive the same `d` tag. The result is
a generic "no other-device record" failure even though the starter is online.

Two simultaneous starters with the same token and name have the related NIP-78
collision: both publish to the same `(author, d-tag)`, so newest wins. duocb
already detects a different node id during the publisher's post-publish checks,
stops the losing publisher, and surfaces an error. That covers the core of the
detect-and-warn recommendation in duopipe's roadmap, but it does not help the
normal starter/joiner same-name case.

The process-lifetime config lock prevents two local processes from using the
same config path. It deliberately does not reject distinct config paths, and it
cannot protect two different machines, so it is not a substitute for nostr-level
name collision handling.

### Current guarantees

- One local process per resolved config path.
- Distinct config paths can run together for same-machine E2E testing.
- A publisher that later observes a different node id under its own name stops
  publishing and reports the collision.
- Token-mode documentation and forms say that device names must differ.
- No stable device identity is persisted; iroh node ids remain ephemeral.

### Remaining gaps

- A joiner cannot distinguish "the online starter has my name" from "only my
  stale record exists and the other device is offline."
- The joiner reports a generic discovery failure instead of an actionable name
  warning.
- Publisher conflict detection compares ephemeral node ids. A pre-publish check
  would therefore mistake this device's own previous-run record for another
  device, which is why startup currently publishes before checking.
- There is no rename/take-over/decline flow; the publisher only stops.

### Recommended implementation

#### Phase 1: actionable ambiguous-name detection

Keep the current wire format and author-only query. Classify lookup results before
discarding the joining device's own `d` tag:

1. If at least one valid other-name record exists, select the newest as today.
2. If no other-name record exists but a valid record with our `d` tag does, return
   a dedicated discovery error rather than the generic no-peer error.
3. Surface wording that preserves the real ambiguity, for example:
   "No differently named device was found. If the other device is running, both
   devices may have the same name; choose a unique name on this device."
4. Show the active config path beside the error so local E2E users know which
   config to edit.

This phase fixes the confusing failure without claiming that a stale self record
proves a live collision.

#### Phase 2: robust device ownership and conflict UI

Introduce a stable, random local device identifier that is not derived from the
auth token, device name, or ephemeral iroh key. Store it in config-scoped local
state rather than in the portable config body, so copying a config to another
machine does not copy the device identity.

Change the encrypted token-mode payload from a bare node id to a versioned record:

```text
{ version, node_id, device_id }
```

Then:

1. A starter can check its own `d` tag before publishing. The same `device_id`
   means its own stale record and is safe to replace; a different `device_id`
   means another device owns the name.
2. A joiner that finds only its own-name `d` tag can compare `device_id` values and
   distinguish a stale self record from another device using the same name.
3. Present an explicit conflict dialog:
   - **Rename this device** — return to the form with the name focused.
   - **Take over** — explicitly replace the remote record.
   - **Cancel** — remain idle without publishing or dialing.
4. Never silently overwrite a record known to belong to another device.

This changes the token-mode record format. Per the project's no-backward-
compatibility policy, old bare-node-id records can be rejected rather than adding
a compatibility decoder.

#### Phase 3: tests

Add coverage for:

- Distinct names under one token still resolve by author and exclude self.
- Same name plus different `device_id` produces a definite collision.
- Same name plus the local `device_id` is treated as a stale self record.
- A publisher restart replaces its own stale record without a false conflict.
- Two config paths with the same token and name reach the conflict UI in a
  same-machine E2E test.
- Choosing rename succeeds after republishing under the new `d` tag.
- Choosing take-over requires an explicit action and leaves only the new owner
  publishing.

### Acceptance criteria

- Same-name starter/joiner pairing never fails as an unexplained missing peer.
- Normal restarts do not produce false name conflicts.
- A live record owned by another device is never overwritten without an explicit
  take-over decision.
- Distinct-name discovery and reconnect behavior remain unchanged.
- Config-path locking continues to block only the same local config path.

