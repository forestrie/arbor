# ADR-0007: Poller Scaling Limits

## Status
Accepted

## Context
The SequencingQueue DO tracks active pollers in memory to support consistent
hashing for log assignment. Each pull request registers/updates the poller in
an in-memory `Map<pollerId, { lastSeen }>`.

The design assumes a small number of pollers (10s to 100s), which is
appropriate for normal operation. However, cluster misconfiguration could
cause this to grow unexpectedly:

- Container orchestration issues spawning excessive ranger instances
- Stuck/zombie processes not being cleaned up
- Misconfigured autoscaling with aggressive scale-out

With 1000s of pollers:
1. Memory usage grows (though modest: ~100 bytes per poller)
2. Sorting pollers on every pull becomes slower (O(n log n))
3. Frequent poller churn causes excessive log reassignment, undermining the
   "sticky assignment" benefit of consistent hashing

## Decision
Implement a hard cap of **500 active pollers** with graceful degradation:

1. When a new poller attempts to register and the cap is reached, the DO
   returns an empty `PullResponse` (no entries) rather than failing with
   an error.

2. The poller is not added to the active set, so it doesn't participate in
   log assignment.

3. Existing pollers continue operating normally.

4. The `stats()` response includes a `pollerLimitReached: boolean` field to
   aid monitoring and alerting.

This approach:
- Prevents runaway memory/CPU usage
- Doesn't break existing pollers
- Provides visibility into the condition
- Allows the system to self-heal as excess pollers time out or are terminated

## Rationale

### Why 500?
This is a conservative limit that's:
- 5-50x larger than expected normal operation (10-100 pollers)
- Small enough that sorting and iteration remain fast (<1ms)
- Large enough to handle reasonable scale-out scenarios

The limit can be adjusted via constant if operational experience suggests
a different value.

### Why not reject with an error?
Returning an error (e.g., HTTP 503) could cause pollers to retry aggressively,
potentially worsening the situation. An empty response is semantically valid
("no work for you") and causes pollers to back off naturally via their normal
polling interval.

### Why not random assignment fallback?
Random assignment would allow excess pollers to participate but would:
- Create a two-tier system (hashed vs random) that's harder to reason about
- Potentially cause contention if random pollers overlap with hashed ones
- Still not address the root cause (too many pollers)

The simpler approach of "you don't get work" is easier to understand and debug.

### Why not evict oldest pollers?
Evicting pollers to make room for new ones would cause churn in log
assignments, potentially causing duplicate processing if an evicted poller
was mid-batch. The current approach preserves assignment stability.

## Consequences

### Positive
- System remains stable under misconfiguration
- Monitoring can detect the condition via `pollerLimitReached`
- Self-healing as excess pollers time out (60s)

### Negative
- Excess pollers get no work, which may not be immediately obvious to operators
- Hard-coded limit may need tuning for different deployment scales

### Future considerations
If real-world usage approaches the limit in normal operation, we could:
1. Increase the limit (memory/CPU impact is modest)
2. Implement hierarchical consistent hashing (hash to a shard, then to a
   poller within the shard)
3. Shard the DO itself by log prefix (see ADR-0001)

For now, the simple cap is sufficient given expected scale.

## Implementation

```typescript
const MAX_POLLERS = 500;

private updatePollers(pollerId: string): string[] | null {
  const now = Date.now();

  // Expire stale pollers first
  const cutoff = now - POLLER_TIMEOUT_MS;
  for (const [id, state] of this.pollers) {
    if (state.lastSeen < cutoff) {
      this.pollers.delete(id);
    }
  }

  // Check if this is a new poller and we're at capacity
  if (!this.pollers.has(pollerId) && this.pollers.size >= MAX_POLLERS) {
    return null; // Signal to return empty response
  }

  // Update/add the poller
  this.pollers.set(pollerId, { lastSeen: now });
  return Array.from(this.pollers.keys());
}
```

## References
- ADR-0001: Single DO architecture (discusses future sharding)
- ADR-0002: Consistent hashing for ranger assignment
- ADR-0006: Hash function choice
