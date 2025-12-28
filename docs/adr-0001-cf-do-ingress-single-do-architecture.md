# ADR-0001: Single Global Durable Object for Sequencing Queue

## Status
Accepted

## Context
The Forestrie ingress pipeline requires a sequencing queue to hold pending
log entries between canopy-api (Cloudflare Worker) and ranger (GCP service).
Two architectural options were considered:

1. **Single global DO**: One Durable Object instance handles all logs, with
   `log_id` as a column in the schema.
2. **Per-log DOs**: Each log gets its own Durable Object instance, keyed by
   `logId`.

## Decision
We will use a **single global Durable Object** for the sequencing queue.

If throughput eventually saturates the single DO, we will shard by `logId`
prefix (e.g., first 2 hex characters → 256 shards), not by individual log.
This maintains the coordination benefits while distributing load.

## Rationale

### Benefits of single DO

- **Centralised coordination**: The DO has a global view of all logs and all
  active ranger pollers, enabling fair work distribution and horizontal
  scaling logic in one place.
- **Simpler discovery**: Rangers ask "give me work" and the DO decides which
  logs to serve. No need for a separate coordinator or discovery mechanism.
- **Operational simplicity**: One DO class, one logical instance, easier
  monitoring and debugging.
- **Fairness**: Round-robin or weighted fair queuing across logs is trivial
  when all entries are in one place.

### Why not per-log DOs

- **Discovery overhead**: Rangers would need to learn which logs have work,
  requiring a coordinator DO or polling all known logs.
- **Fairness complexity**: Fair distribution across logs must be implemented
  in ranger or a coordinator, duplicating logic.
- **More moving parts**: N DOs instead of one, harder to reason about.

### Why prefix sharding over per-log sharding

If we need to scale beyond a single DO:

- Prefix sharding (e.g., 256 shards by first byte of logId) maintains
  coordination benefits within each shard.
- Each shard still handles multiple logs, enabling fair distribution among
  them.
- Avoids the discovery problem of per-log DOs.
- Ranger can poll all shards or be assigned shards via consistent hashing.

### Expected capacity

Transparency log ingress is expected to be well within a single DO's capacity
(thousands of operations per second). Sharding is a contingency, not an
immediate need.

## Consequences

- The sequencing queue schema includes `log_id` as a column.
- All queue operations (enqueue, pull, ack) go through one DO instance.
- Monitoring should track DO operation latency and SQLite size.
- If metrics indicate saturation, implement prefix-based sharding.

## Worker Deployment Pattern

The SequencingQueue DO is owned by a **separate worker** (`forestrie-ingress`)
rather than being co-located in `canopy-api`. The `canopy-api` worker accesses
it via a cross-worker DO binding using `script_name`:

```jsonc
// canopy-api/wrangler.jsonc
{
  "durable_objects": {
    "bindings": [{
      "name": "SEQUENCING_QUEUE",
      "class_name": "SequencingQueue",
      "script_name": "forestrie-ingress"
    }]
  }
}
```

### Why cross-worker DO RPC, not co-location or service bindings

1. **Native DO RPC efficiency**: Cross-worker DO bindings use the same RPC
   mechanism as local bindings. There is no HTTP overhead or serialization
   penalty compared to co-location. The DO runs in the owning worker's
   isolate, and callers invoke methods directly via the stub.

2. **Clear ownership**: The `forestrie-ingress` worker owns the DO class,
   migrations, and SQLite schema. This matches the `ranger-cache` pattern
   where `canopy-api` consumes `SequencedContent` from `ranger-cache`.

3. **Independent deployment**: Each worker can be deployed, scaled, and
   versioned independently.

4. **Not service bindings**: Service bindings add HTTP overhead for each call.
   DO bindings with `script_name` avoid this.

### Bootstrap requirement

The `forestrie-ingress` worker must be deployed at least once before
`canopy-api` can successfully start with the binding. On first deployment:

1. Deploy `forestrie-ingress` first: `pnpm --filter @canopy/forestrie-ingress deploy`
2. Then deploy `canopy-api`: `pnpm --filter @canopy/api deploy`

Subsequent deployments can happen in any order. This is the same bootstrap
requirement that exists for `ranger-cache` / `canopy-api`.

## References
- [arc-cloudflare-do-ingress.md](arc-cloudflare-do-ingress.md): Full
  architecture document
