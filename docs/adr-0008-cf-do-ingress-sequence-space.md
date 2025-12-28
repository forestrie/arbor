# ADR-0008: Sequence Number Space and Rollover

## Status
Accepted

## Context
The SequencingQueue DO assigns monotonically increasing sequence numbers to
each enqueued entry. These sequence numbers are used for:

1. Total ordering of entries within the queue
2. Limit-based acknowledgement (`ackFirst(logId, seqLo, limit)`)
3. Identifying entries in the `LogGroup.seqLo` / `seqHi` response fields

The sequence counter (`nextSeq`) is a JavaScript `number` incremented on each
enqueue. This raises questions about:

- Maximum sequence number before rollover
- Behavior when the limit is reached
- Whether mitigation is needed

## Decision
Accept the theoretical rollover limit without mitigation, documenting it as a
known constraint that will not be reached in practice.

## Analysis

### JavaScript number limits
JavaScript `number` is a 64-bit IEEE 754 float. For integers:

- Safe integer range: -(2^53 - 1) to (2^53 - 1)
- `Number.MAX_SAFE_INTEGER` = 9,007,199,254,740,991 (~9 quadrillion)

Beyond this range, integer precision is lost (e.g., `2^53 + 1 === 2^53`).

### Time to exhaustion
At various sustained throughput rates:

| Rate | Time to exhaust 2^53 |
|------|---------------------|
| 1/sec | 285 million years |
| 1,000/sec | 285,000 years |
| 1,000,000/sec | 285 years |
| 10,000,000/sec | 28.5 years |

The DO cannot sustain 10M ops/sec (Cloudflare limits are ~1000 RPS per DO),
so exhaustion is not a practical concern.

### SQLite storage
SQLite `INTEGER` is signed 64-bit, supporting values up to 2^63-1. This
exceeds JavaScript's safe integer range, so SQLite is not the limiting factor.

### CBOR encoding
The cbor-x library handles large integers transparently, encoding them as
CBOR bignums when necessary. The ranger (Go) side uses `fxamacker/cbor/v2`
which also handles bignums. No special handling is needed.

### Limit-based ack behavior
The `ackFirst` implementation selects entries by limit then deletes:
```sql
SELECT seq FROM queue_entries WHERE log_id = ? AND seq >= ? ORDER BY seq LIMIT ?
DELETE FROM queue_entries WHERE seq IN (...)
```

If seq wrapped to negative values, this could behave unexpectedly. However:
1. JavaScript numbers don't wrap—they lose precision at 2^53
2. We'd see incorrect behavior (duplicate seqs) long before any "wrap"
3. The time to reach this point is measured in centuries

### DO reset scenarios
If the DO is recreated (migration, reset):
- `nextSeq` is initialized from `MAX(seq) + 1` in storage
- If storage is preserved, seq continues correctly
- If storage is lost, seq restarts from 1 (but this is a data loss scenario)

## Consequences

### Positive
- No complexity added for an impractical scenario
- Seq remains a simple incrementing number

### Negative
- Theoretical limit exists (documented here)
- No warning if approaching limit (not worth implementing)

### Monitoring recommendation
If operational longevity becomes a concern (multi-decade deployment), add
monitoring for `nextSeq > 2^50` (~1% of safe range remaining). This provides
years of warning before any issue.

### Future mitigation (if ever needed)
If this somehow becomes a concern:
1. Use BigInt for seq (requires code changes, CBOR handling)
2. Reset seq when queue is empty (safe, seq is only meaningful within queue)
3. Shard by time epoch (each epoch has its own seq space)

None of these are worth implementing now.

## References
- [Number.MAX_SAFE_INTEGER](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/MAX_SAFE_INTEGER)
- [SQLite INTEGER](https://www.sqlite.org/datatype3.html)
- [CBOR bignums](https://www.rfc-editor.org/rfc/rfc8949.html#section-3.4.3)
