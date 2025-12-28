# ADR-0005: CBOR Encoding for HTTP Pull Interface

## Status
Accepted

## Context
The HTTP pull interface returns queue entries containing binary fields
(`logId`, `contentHash`, `extra0`–`extra3`). Ranger (Go) consumes these
entries and works naturally with binary bytes. Three encoding options:

1. **JSON with hex/base64**: Standard, but requires encode/decode of every
   binary field. Verbose.
2. **Bespoke binary**: Compact and fast, but requires custom serialisation
   code on both ends. Fragile to schema changes.
3. **CBOR**: Binary-native, compact, standardised. Supports raw byte strings
   without encoding overhead.

Error responses should use RFC 9457 Problem Details regardless of payload
encoding.

## Decision
We will use **CBOR** for pull request/response bodies with **bespoke
encoding/decoding** that exploits known schema.

Error responses will use `application/problem+json` (RFC 9457).

## Rationale

### Why CBOR over JSON

- **No base64/hex overhead**: Binary fields are transmitted as CBOR byte
  strings (major type 2), not encoded text.
- **Compact**: CBOR is typically 30-50% smaller than JSON for binary-heavy
  payloads.
- **Decode performance**: No hex/base64 parsing on the consumer side.
- **Standardised**: RFC 8949. Libraries available for TypeScript and Go.

### Why CBOR over bespoke binary

- **Schema evolution**: CBOR maps allow adding fields without breaking
  existing consumers.
- **Debuggability**: CBOR can be inspected with standard tools (`cbor-diag`).
- **Less code**: Leverage existing CBOR libraries rather than writing custom
  serialisation.

### Why bespoke CBOR encoding

Both producer (DO) and consumer (ranger) know the exact schema. We can:

- Encode fields in a fixed order without field names (CBOR array).
- Skip the generic CBOR library's reflection/introspection overhead.
- Decode directly into typed structs.

This gives CBOR's wire efficiency with near-bespoke decode performance.

### Wire format

Pull response as CBOR array, grouped by logId:

```
[
  version,               // uint (1 for this format)
  leaseExpiry,           // uint64 (Unix ms)
  [                      // array of log groups
    [logId, seqLo, seqHi, [[contentHash, extra0, extra1, extra2, extra3], ...]],
    [logId, seqLo, seqHi, [[contentHash, extra0, extra1, extra2, extra3], ...]],
    ...
  ]
]
```

Each log group:
- `logId`: byte string (16 bytes)
- `seqLo`: uint64 (first seq in range, for ack)
- `seqHi`: uint64 (last seq in range, for ack)
- entries array: each entry is `[contentHash, extra0, extra1, extra2, extra3]`

Each entry field:
- `contentHash`: byte string (32 bytes)
- `extra0`–`extra3`: byte string or null

### Design rationale

**Why group by logId**: Ranger processes entries per-log (commits to massifs
per-log). Grouping in the wire format eliminates client-side grouping and
reduces repeated logId transmission.

**Why seqLo/seqHi instead of per-entry seq**: Ranger uses seqLo as the
starting point for limit-based ack (`ackFirst(logId, seqLo, limit)`). Since
entries are pulled ordered by seq ASC per-log, the count of committed entries
is sufficient to ack. seqHi is informational. This saves 8 bytes per entry.
See ADR-0003 and arc-cloudflare-do-ingress.md section 2.3 for the evolution
from range-based to limit-based ack.

**Why no `attempts` field**: The DO uses `attempts` internally for poison
message detection, but ranger doesn't need it. Ranger's job is to commit
entries; if processing fails, entries redeliver automatically.

**Why no `assignedLogs` field**: Redundant—the log groups in the payload
implicitly enumerate the assigned logs.

**Why version field**: Allows future format evolution without breaking
existing consumers.

**SQL efficiency**: The current query pattern already supports this:

```sql
SELECT seq, content_hash, extra0, extra1, extra2, extra3
FROM queue_entries
WHERE log_id = ? AND (visible_after IS NULL OR visible_after <= ?)
ORDER BY seq ASC
LIMIT ?
```

The `idx_log_visible` index on `(log_id, visible_after)` makes this efficient.
Results are naturally contiguous and sorted.

### Error responses

Errors use `application/problem+json` (RFC 9457):

```json
{
  "type": "https://forestrie.io/problems/queue-full",
  "title": "Queue capacity exceeded",
  "status": 503,
  "detail": "Pending count 100000 exceeds limit"
}
```

This keeps errors human-readable while payloads are binary-efficient.

## Consequences

- Pull endpoint returns `Content-Type: application/cbor`.
- Response is pre-grouped by logId; ranger doesn't need to group.
- seqLo per log group enables limit-based `ackFirst` calls (see ADR-0003).
- Ack endpoint accepts `application/cbor` or `application/json`.
- Ranger decodes CBOR responses; existing Go CBOR libraries (e.g.,
  `fxamacker/cbor`) support this efficiently.
- DO encodes using bespoke CBOR array construction for performance.
- Error responses are JSON Problem Details regardless of `Accept` header.
- Version field (currently 1) allows future format changes.

## Alternatives considered

### JSON with base64
- Pro: Universal tooling.
- Con: ~33% size overhead for binary fields; encode/decode cost.

### Bespoke TLV or length-prefixed binary
- Pro: Maximum compactness and speed.
- Con: Fragile; no schema evolution; hard to debug.

### Protocol Buffers
- Pro: Efficient, schema-driven.
- Con: Requires .proto files, code generation; overkill for this use case.

## References
- RFC 8949: Concise Binary Object Representation (CBOR)
- RFC 9457: Problem Details for HTTP APIs
- [arc-cloudflare-do-ingress.md](arc-cloudflare-do-ingress.md): Full
  architecture document (section 2.10)
