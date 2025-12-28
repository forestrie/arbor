# ADR-0003: Range-Based Acknowledgement for Batch Commits

## Status
Accepted

## Context
Ranger processes log entries in batches, committing a contiguous sequence of
entries to a massif in a single write. After a successful commit, it must
acknowledge (delete) those entries from the queue.

Two acknowledgement patterns were considered:

1. **Per-entry ack**: `ack([seq1, seq2, seq3, ...])` — explicitly list each
   sequence number to delete.
2. **Range ack**: `ackRange(logId, fromSeq, toSeq)` — delete all entries for
   a log within a sequence range.

## Decision
We will use **range-based acknowledgement** parameterised on `logId`.

The method signature:

```typescript
ackRange(logId: ArrayBuffer, fromSeq: number, toSeq: number): Promise<{ deleted: number }>
```

The SQL:

```sql
DELETE FROM queue_entries WHERE log_id = ? AND seq >= ? AND seq <= ?
```

## Rationale

### Why range ack

- **Single HTTP call**: Acknowledging 100 entries requires one request, not
  100 entry IDs in a payload.
- **Natural fit for batch commits**: Ranger commits entries `[5, 6, 7, 8, 9]`
  to a massif and calls `ackRange(logId, 5, 9)`.
- **Atomic from ranger's perspective**: Either the batch is committed and
  acked, or neither. No partial acknowledgement.
- **Efficient SQL**: A range delete with indexed columns is fast.

### Why include logId in the ack

With a single global DO (see ADR-0001), entries for multiple logs share one
table. Including `logId` ensures:

- **Correctness**: Only entries for the specified log are deleted.
- **Defence in depth**: Even if sequence numbers somehow overlapped (they
  shouldn't), the logId constraint prevents cross-log deletion.
- **Future compatibility**: If we shard by logId prefix, the query remains
  valid.

### Why not per-entry ack

- **Larger payloads**: Listing 100 sequence numbers is more bytes than
  `{logId, from, to}`.
- **Multiple round trips**: If batching is limited, more HTTP calls.
- **No benefit**: Ranger always commits contiguous ranges; there's no need
  for sparse acknowledgement.

### Partial commit handling

If ranger commits only part of a batch (e.g., entries 5-7 succeed but 8-9
fail due to massif size limits):

```go
committed := 3  // entries 0, 1, 2 of the batch (seq 5, 6, 7)
ackTo := entries[committed-1].Seq  // seq 7
ackRange(logIdBytes, firstSeq, ackTo)
```

Entries 8-9 remain in the queue and redeliver after visibility timeout.

## Consequences

- Ranger commits batches and acks with one `ackRange` call per log.
- The DO schema includes `log_id` for efficient range queries.
- The `idx_log_visible` index supports both pull and ack operations.
- Sparse acknowledgement (e.g., ack entries 5, 7, 9 but not 6, 8) is not
  supported. This is acceptable because ranger processes entries in order.

## References
- [ADR-0001](adr-0001-cf-do-ingress-single-do-architecture.md): Single DO
  architecture (explains why `log_id` is in the schema)
- [arc-cloudflare-do-ingress.md](arc-cloudflare-do-ingress.md): Full
  architecture document
