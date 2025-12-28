# ADR-0002: Consistent Hashing for Ranger Log Assignment

## Status
Accepted

## Context
With multiple ranger instances polling the sequencing queue DO, we need a
strategy to assign logs to rangers. Goals:

1. **Avoid concurrent writes**: At any moment, it should be unlikely that two
   ranger instances receive entries for the same log. This maximises
   throughput by avoiding optimistic concurrency conflicts on massif writes.
2. **No strong guarantee required**: Ranger's optimistic concurrency model
   (ETag/If-Match on R2 writes) naturally reconciles conflicts. Occasional
   overlap is acceptable; we just want it to be uncommon.
3. **Stateless rangers**: Rangers should not need to coordinate with each
   other or maintain persistent state about log assignments.
4. **Graceful scaling**: Adding or removing ranger instances should not cause
   widespread reassignment.

Three assignment strategies were considered:

1. **Consistent hashing**: Hash `logId` to determine which poller receives it.
2. **Round-robin with sticky preference**: Assign logs round-robin, but
   remember assignments and prefer to keep a log with its current poller.
3. **Weighted by backlog**: Assign more logs to pollers processing faster.

## Decision
We will use **consistent hashing** on `logId` modulo active pollers.

## Rationale

### Why consistent hashing

- **Simple and stateless**: The DO computes assignments from `logId` and the
  current set of active pollers. No persistent assignment state needed.
- **Minimal churn on scaling**: When a ranger joins or leaves, only a subset
  of logs move (roughly 1/N logs per scaling event). This is better than
  round-robin which may reassign many logs.
- **Natural affinity**: The same log tends to go to the same ranger while the
  poller set is stable. This reduces (but doesn't eliminate) concurrent
  writes to the same massif.
- **No ranger coordination**: Rangers don't need to know about each other.
  Each ranger just sends its `pollerId`; the DO handles assignment.

### Why not round-robin with sticky preference

- Requires the DO to persist assignment state.
- More complex to implement correctly, especially when pollers die and
  assignments need redistribution.
- The "stickiness" benefit is marginal compared to consistent hashing's
  natural stability.

### Why not weighted by backlog

- Adds significant complexity (tracking ack rates per poller).
- Optimises for throughput, but our primary concern is avoiding conflicts,
  not maximising throughput beyond what consistent hashing provides.
- Can be added later if metrics show load imbalance.

### Conflict tolerance

Forestrie rangers use optimistic concurrency when writing massifs:

1. Ranger reads current massif state (or expects empty).
2. Ranger writes with `If-Match` (ETag) or `If-None-Match` (for new massifs).
3. If another ranger wrote first, the write fails with 412 Precondition
   Failed.
4. The "losing" ranger's entries redeliver after visibility timeout.

This means occasional assignment overlap is safe—just inefficient. Consistent
hashing makes overlap uncommon without requiring strong guarantees.

## Implementation

```typescript
function assignLog(logId: string, pollerIds: string[]): string {
  const sorted = [...pollerIds].sort();
  const hash = simpleHash(logId);
  return sorted[hash % sorted.length];
}
```

The DO:
1. Tracks recently active pollers (those that polled within timeout).
2. On each pull, computes which logs are assigned to the requesting poller.
3. Returns only entries for assigned logs.

## Consequences

- Rangers are fully stateless; all assignment logic is in the DO.
- Log-to-ranger affinity is stable while the poller set is stable.
- Scaling events cause minimal reassignment (~1/N logs move).
- Occasional conflicts are handled by ranger's optimistic concurrency.

## References
- [ADR-0001](adr-0001-cf-do-ingress-single-do-architecture.md): Single DO
  architecture (prerequisite for centralised assignment)
- [arc-cloudflare-do-ingress.md](arc-cloudflare-do-ingress.md): Full
  architecture document
