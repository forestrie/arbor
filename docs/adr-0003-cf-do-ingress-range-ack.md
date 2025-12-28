# ADR-0003: Limit-Based Acknowledgement for Batch Commits

## Status
Accepted (evolved from range-based to limit-based)

## Context
Ranger processes log entries in batches, committing a contiguous sequence of
entries to a massif in a single write. After a successful commit, it must
acknowledge (delete) those entries from the queue.

Three acknowledgement patterns were considered:

1. **Per-entry ack**: `ack([seq1, seq2, seq3, ...])` — explicitly list each
   sequence number to delete.
2. **Range ack**: `ackRange(logId, fromSeq, toSeq)` — delete all entries for
   a log within a sequence range.
3. **Limit-based ack**: `ackFirst(logId, seqLo, limit)` — delete the first N
   entries for a log starting from a sequence number.

## Decision
We will use **limit-based acknowledgement** parameterised on `logId`.

The method signature:

```typescript
ackFirst(logId: ArrayBuffer, seqLo: number, limit: number): Promise<{ deleted: number }>
```

The SQL:

```sql
-- Find first N entries for this log starting from seqLo
SELECT seq FROM queue_entries
WHERE log_id = ? AND seq >= ?
ORDER BY seq ASC
LIMIT ?

-- Delete those specific entries
DELETE FROM queue_entries WHERE seq IN (...)
```

## Rationale

### Evolution from range-based to limit-based ack

The original design assumed per-entry seq values would be contiguous within
a log. However, **seq is allocated globally across all logs**, so entries for
a single log have non-contiguous seq values:

```
Global sequence:  1   2   3   4   5   6   7   8   9  10
Log A entries:    *           *       *               *
Log B entries:        *   *       *       *   *   *
```

If ranger pulls entries for Log A with `seqLo=1, seqHi=10`, the actual
entries have seq values [1, 4, 6, 10], not [1, 2, 3, 4].

**Why range ack fails**: If ranger commits 2 entries and tries to ack with
`fromSeq=1, toSeq=seqLo+2-1=2`, it would try to delete seq 1-2, but seq 2
belongs to Log B. The correct toSeq is 4, but ranger doesn't know this
because the pull response doesn't include per-entry seq values.

**Why limit-based ack works**: Ranger knows it committed N entries. The DO
can select and delete the first N entries (by seq order) for that log
starting from seqLo. This matches exactly what was pulled and committed.

### Why include logId in the ack

With a single global DO (see ADR-0001), entries for multiple logs share one
table. Including `logId` ensures:

- **Correctness**: Only entries for the specified log are deleted.
- **Defence in depth**: The logId constraint prevents cross-log deletion.
- **Future compatibility**: If we shard by logId prefix, the query remains
  valid.

### Why not per-entry ack

- **Larger payloads**: Listing 100 sequence numbers is more bytes than
  `{logId, seqLo, limit}`.
- **Multiple round trips**: If batching is limited, more HTTP calls.
- **Requires per-entry seq in wire format**: Would increase pull response
  size and complexity.

### Partial commit handling

If ranger commits only part of a batch (e.g., entries 0-2 succeed but 3+
fail due to massif size limits):

```go
committed := 3  // entries 0, 1, 2 of the batch
err := r.ackFirst(ctx, group.LogId, group.SeqLo, committed)
```

Entries 3+ remain in the queue and redeliver after visibility timeout.

## Consequences

- Ranger commits batches and acks with one `ackFirst` call per log group.
- The DO schema includes `log_id` for efficient queries.
- The `idx_log_visible` index supports both pull and ack operations.
- Sparse acknowledgement is not supported. This is acceptable because ranger
  processes entries in order.
- The ack operation requires a SELECT before DELETE (two queries), slightly
  more expensive than a pure range delete. This is acceptable given the
  correctness guarantee.

## References
- [ADR-0001](adr-0001-cf-do-ingress-single-do-architecture.md): Single DO
  architecture (explains why `log_id` is in the schema)
- [arc-cloudflare-do-ingress.md](arc-cloudflare-do-ingress.md): Full
  architecture document (see section 2.3 for detailed limit-based ack design)
