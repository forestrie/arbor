# Plan 0001: Cloudflare DO Ingress Queue Implementation

## Status
Draft

## Overview

This plan covers implementation of a Durable Object-based sequencing queue
that replaces the current `R2_LEAVES` ingress buffer and Cloudflare Queue
with a single, domain-aware component.

### Motivation

The current ingress path has unnecessary latency and complexity:

1. `canopy-api` writes to `R2_LEAVES` (~50ms)
2. R2 notification triggers Cloudflare Queue (~100-500ms)
3. Ranger polls queue (0-5000ms depending on interval)

The DO queue eliminates the R2 write and queue notification, reducing p50
latency by 100-500ms and simplifying the architecture.

### Related Documents

- [arc-cloudflare-do-ingress.md](./arc-cloudflare-do-ingress.md): Full
  architecture document
- [adr-0001-cf-do-ingress-single-do-architecture.md](adr-0001-cf-do-ingress-single-do-architecture.md):
  Single global DO decision
- [adr-0002-cf-do-ingress-consistent-hashing.md](adr-0002-cf-do-ingress-consistent-hashing.md):
  Consistent hashing for ranger assignment
- [adr-0003-cf-do-ingress-range-ack.md](adr-0003-cf-do-ingress-range-ack.md):
  Range-based acknowledgement
- [adr-0004-cf-do-ingress-fixed-visibility-timeout.md](adr-0004-cf-do-ingress-fixed-visibility-timeout.md):
  Fixed visibility timeout
- [adr-0005-cf-do-ingress-pull-encoding.md](adr-0005-cf-do-ingress-pull-encoding.md):
  CBOR encoding for pull interface

---

## Phase 1: Project Scaffold

### 1.1 Create shared types package

Create `canopy/packages/shared/forestrie-ingress/` following the pattern
established by `@canopy/ranger-sequence-types`. Package name:
`@canopy/forestrie-ingress-types`.

**Files to create:**

Follow the file-per-type pattern (see canopy/WARP.md "Type and Interface
Organization"). Each type or closely related group gets its own file;
`types.ts` serves as the aggregating re-export point.

```
canopy/packages/shared/forestrie-ingress/
├── package.json
├── tsconfig.json
└── src/
    ├── index.ts              # Package entry point, re-exports from types.ts
    ├── types.ts              # Aggregates re-exports from individual files
    ├── pullrequest.ts        # PullRequest interface
    ├── pullresponse.ts       # PullResponse, LogGroup, Entry interfaces
    ├── ack.ts                # AckRequest, AckResponse interfaces
    ├── queuestats.ts         # QueueStats interface
    ├── sequencingqueuestub.ts # SequencingQueueStub, EnqueueExtras interfaces
    └── problemdetails.ts     # ProblemDetails, PROBLEM_TYPES, PROBLEM_CONTENT_TYPE
```

**package.json:**

```json
{
  "name": "@canopy/forestrie-ingress-types",
  "private": true,
  "version": "0.0.1",
  "type": "module",
  "main": "./src/index.ts",
  "types": "./src/index.ts",
  "exports": {
    ".": {
      "types": "./src/index.ts",
      "default": "./src/index.ts"
    }
  },
  "scripts": {
    "typecheck": "tsc --noEmit"
  },
  "devDependencies": {
    "typescript": "^5.9.2"
  }
}
```

**Key types to export:**

- `PullRequest`: `{ pollerId, batchSize, visibilityMs }`
- `PullResponse`: `{ version, leaseExpiry, logGroups }`
- `LogGroup`: `{ logId, seqLo, seqHi, entries }`
- `Entry`: `{ contentHash, extra0, extra1, extra2, extra3 }`
- `AckRequest`: `{ logId, fromSeq, toSeq }`
- `AckResponse`: `{ deleted }`
- `QueueStats`: `{ pending, deadLetters, oldestEntryAge, ... }`
- `ProblemDetails`: RFC 9457 structure

### 1.2 Create forestrie-ingress worker package

Create a **separate worker** at `canopy/packages/apps/forestrie-ingress/`
following the pattern established by `@canopy/ranger-cache`. The DO is owned
by this worker and consumed by canopy-api via cross-worker DO RPC binding
(using `script_name` in the binding config).

This pattern:
- Uses native DO RPC (not service bindings) — same efficiency as co-location
- Keeps DO ownership clear (forestrie-ingress owns SequencingQueue)
- Allows independent deployment and scaling
- Requires initial deployment of forestrie-ingress before canopy-api can
  reference it (bootstrap requirement)

**Files to create:**

```
canopy/packages/apps/forestrie-ingress/
├── package.json
├── tsconfig.json
├── vitest.config.ts
├── wrangler.jsonc
├── src/
│   ├── index.ts              # Worker entrypoint, exports DO class
│   ├── env.ts                # Environment bindings type
│   └── durableobjects/
│       ├── index.ts          # Re-export SequencingQueue
│       └── sequencingqueue.ts # Main DO implementation
└── test/
    ├── tsconfig.json
    ├── unit/
    │   └── sequencingqueue.test.ts
    └── integration/
        └── handlers.test.ts
```

**wrangler.jsonc (key sections):**

```jsonc
{
  "name": "forestrie-ingress",
  "durable_objects": {
    "bindings": [{
      "name": "SEQUENCING_QUEUE",
      "class_name": "SequencingQueue"
    }]
  },
  "migrations": [{
    "tag": "v1",
    "new_sqlite_classes": ["SequencingQueue"]
  }]
}
```

### 1.3 Update canopy-api to reference forestrie-ingress

Add DO binding with `script_name` to reference the external worker:

**Update canopy-api/wrangler.jsonc:**

```jsonc
{
  "durable_objects": {
    "bindings": [
      {
        "name": "SEQUENCING_QUEUE",
        "class_name": "SequencingQueue",
        "script_name": "forestrie-ingress"
      }
    ]
  }
}
```

**Add shared types dependency to canopy-api/package.json:**

```json
"dependencies": {
  "@canopy/forestrie-ingress-types": "workspace:*",
  ...
}
```

### 1.4 Create test scaffolds in forestrie-ingress

Create `test/unit/sequencingqueue.test.ts` with basic DO instantiation test:

- DO can be created via `idFromName("global")`

Create `test/integration/handlers.test.ts` with stub endpoint test:

- Worker responds to `GET /_forestrie-ingress/health` with 200

### 1.5 Verify scaffold builds and tests pass

Run from `canopy/packages/apps/forestrie-ingress/`:

```bash
pnpm install
pnpm typecheck
pnpm test
```

Both stub tests should pass, confirming vitest and pool-workers are
correctly configured.

---

## Phase 2: Core DO Implementation

### 2.1 Implement SQLite schema

In `SequencingQueue.ensureSchema()`:

```sql
CREATE TABLE IF NOT EXISTS queue_entries (
  seq INTEGER PRIMARY KEY,
  log_id BLOB NOT NULL,
  content_hash BLOB NOT NULL,
  extra0 BLOB CHECK (extra0 IS NULL OR length(extra0) <= 32),
  extra1 BLOB CHECK (extra1 IS NULL OR length(extra1) <= 32),
  extra2 BLOB CHECK (extra2 IS NULL OR length(extra2) <= 32),
  extra3 BLOB CHECK (extra3 IS NULL OR length(extra3) <= 32),
  visible_after INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0,
  enqueued_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_log_visible
  ON queue_entries (log_id, visible_after);

CREATE INDEX IF NOT EXISTS idx_visible
  ON queue_entries (visible_after);

CREATE INDEX IF NOT EXISTS idx_attempts
  ON queue_entries (attempts);

CREATE TABLE IF NOT EXISTS dead_letters (
  seq INTEGER PRIMARY KEY,
  log_id BLOB NOT NULL,
  content_hash BLOB NOT NULL,
  extra0 BLOB,
  extra1 BLOB,
  extra2 BLOB,
  extra3 BLOB,
  attempts INTEGER NOT NULL,
  enqueued_at INTEGER NOT NULL,
  dead_at INTEGER NOT NULL,
  reason TEXT
);
```

**Happy path test:** `ensureSchema()` creates tables without error; calling
it twice is idempotent.

### 2.2 Implement enqueue()

RPC method called by canopy-api:

```typescript
async enqueue(
  logId: ArrayBuffer,
  contentHash: ArrayBuffer,
  extras?: { extra0?: ArrayBuffer; ... }
): Promise<{ seq: number }>
```

- Validate extras (each ≤32 bytes)
- Check backpressure (`pendingCount < MAX_PENDING`)
- Insert row with `visible_after = NULL`
- Update in-memory `pendingCount` and `nextSeq`
- Return assigned `seq`

**Happy path test:** `enqueue()` returns incrementing seq; entry persists
in SQLite.

### 2.3 Implement ackRange()

RPC/HTTP method called by ranger:

```typescript
async ackRange(
  logId: ArrayBuffer,
  fromSeq: number,
  toSeq: number
): Promise<{ deleted: number }>
```

- Delete rows matching `log_id = ? AND seq >= ? AND seq <= ?`
- Update in-memory `pendingCount`
- Return count of deleted rows

**Happy path test:** `ackRange()` deletes enqueued entries; returns correct
count.

### 2.4 Implement stats()

HTTP method for monitoring:

```typescript
async stats(): Promise<QueueStats>
```

- Return `pendingCount`, dead letter count, oldest entry age
- Return attempt distribution, active poller count

**Happy path test:** `stats()` returns zero counts on empty queue; reflects
counts after enqueue.

### 2.5 Phase 2 integration test

Add to `test/integration/handlers.test.ts`:

- Basic enqueue → ack round-trip via DO RPC (no HTTP yet)

---

## Phase 3: Pull Implementation with Poller Coordination

### 3.1 Implement poller tracking

In-memory state:

```typescript
private pollers: Map<string, { lastSeen: number }> = new Map();
private readonly POLLER_TIMEOUT_MS = 60_000;
```

On each pull:
1. Update `lastSeen` for requesting `pollerId`
2. Expire pollers not seen within timeout
3. Compute active poller list

### 3.2 Implement consistent hashing assignment

```typescript
function assignLog(logId: string, pollerIds: string[]): string {
  const sorted = [...pollerIds].sort();
  const hash = simpleHash(logId);
  return sorted[hash % sorted.length];
}
```

Use a simple hash function (e.g., djb2 or FNV-1a) on logId hex.

**Happy path test:** Given sorted poller list, `assignLog()` returns
consistent assignment for same logId; different logIds distribute across
pollers.

### 3.3 Implement pull() with grouped response

```typescript
async pull(req: PullRequest): Promise<PullResponse>
```

1. Update poller state
2. Find logs with available entries (`SELECT DISTINCT log_id ...`)
3. Filter to logs assigned to this poller
4. For each assigned log:
   - Query entries `ORDER BY seq ASC LIMIT ?`
   - Update `visible_after` and `attempts`
   - Build `LogGroup` with `seqLo`, `seqHi`, entries
5. Move poison messages to dead_letters (attempts ≥ MAX_ATTEMPTS)
6. Return grouped response

**Happy path test:** Single poller pulls all entries; entries grouped by
logId with correct seqLo/seqHi; pulled entries become invisible.

### 3.4 Implement CBOR encoding

Use `cbor-x` library with bespoke positional array encoding:

```typescript
function encodePullResponse(resp: PullResponse): ArrayBuffer {
  const logGroups = resp.logGroups.map(g => [
    g.logId,
    g.seqLo,
    g.seqHi,
    g.entries.map(e => [e.contentHash, e.extra0, e.extra1, e.extra2, e.extra3])
  ]);
  return encode([resp.version, resp.leaseExpiry, logGroups]);
}
```

**Happy path test:** Encode known response, decode with cbor-x, verify
structure matches expected positional array format.

### 3.5 Phase 3 integration test

Add to `test/integration/handlers.test.ts`:

- Enqueue multiple entries across two logIds; pull returns grouped response
  with correct structure

---

## Phase 4: HTTP Interface

### 4.1 Implement fetch handler routing

In worker `fetch()`:

```typescript
if (url.pathname === "/queue/pull" && method === "POST") {
  return handlePull(request, env);
}
if (url.pathname === "/queue/ack" && method === "POST") {
  return handleAck(request, env);
}
if (url.pathname === "/queue/stats" && method === "GET") {
  return handleStats(request, env);
}
```

### 4.2 Implement pull handler

- Parse CBOR or JSON request body
- Get DO stub via `env.SEQUENCING_QUEUE.idFromName("global")`
- Call `stub.pull(request)`
- Return CBOR response with `Content-Type: application/cbor`

### 4.3 Implement ack handler

- Parse CBOR or JSON request body
- Call `stub.ackRange(logId, fromSeq, toSeq)`
- Return JSON response

### 4.4 Implement stats handler

- Call `stub.stats()`
- Return JSON response

### 4.5 Implement error handling

All errors return RFC 9457 Problem Details:

```typescript
function problemResponse(
  status: number,
  type: string,
  title: string,
  detail?: string
): Response {
  return new Response(JSON.stringify({
    type: `https://forestrie.io/problems/${type}`,
    title,
    status,
    detail
  }), {
    status,
    headers: { "Content-Type": "application/problem+json" }
  });
}
```

---

## Phase 5: Test Coverage Review

This phase reviews the implementation for gaps and deepens test coverage
beyond the happy path tests established in earlier phases.

### 5.1 Review and expand unit tests

Review existing unit tests and add coverage for:

**enqueue() edge cases:**
- Rejects entry when queue at MAX_PENDING (backpressure)
- Rejects extra fields exceeding 32 bytes
- Handles concurrent enqueue calls correctly

**pull() edge cases:**
- Returns empty response when no entries visible
- Respects visibility timeout (re-pulls after expiry)
- With multiple pollers, each sees only assigned logs
- Increments attempts counter on each pull
- Moves entry to dead_letters after MAX_ATTEMPTS

**ackRange() edge cases:**
- No-op when range doesn't match any entries
- Only deletes entries for specified logId (not others)
- Handles ack of already-deleted entries gracefully

**stats() edge cases:**
- Correct counts after mixed enqueue/ack/pull operations
- Oldest entry age calculation accuracy

### 5.2 Review and expand integration tests

Review existing integration tests and add coverage for:

- Full cycle: enqueue → pull → ack with verification
- Visibility timeout redelivery via HTTP
- Problem Details format for all error conditions
- CBOR response round-trip (encode in TS, decode, verify)
- Multiple pollers with log assignment verification

### 5.3 Performance tests (optional)

- Throughput: enqueue rate under sustained load
- Latency: pull response time distribution
- Memory: usage growth with large pending count

---

## Phase 6: Integration with canopy-api

Since the DO is co-located within canopy-api, no additional bindings are
needed. The DO is already available via `env.SEQUENCING_QUEUE`.

### 6.1 Update statement registration handler

Replace R2_LEAVES write with DO enqueue:

```typescript
// Before:
await env.R2_LEAVES.put(key, payload, { customMetadata: { ... } });

// After:
const id = env.SEQUENCING_QUEUE.idFromName("global");
const queue = env.SEQUENCING_QUEUE.get(id);
await queue.enqueue(logIdBytes, contentHashBytes, { extra0, ... });
```

### 6.2 Feature flag for gradual rollout

Add environment variable to toggle between old and new paths:

```typescript
if (env.USE_DO_INGRESS === "true") {
  await queue.enqueue(...);
} else {
  await env.R2_LEAVES.put(...);
}
```

---

## Phase 7: Ranger Integration

Note: Ranger is a Go service. This phase involves changes outside the
canopy monorepo.

### 7.1 Add CBOR decoding to ranger

Use `github.com/fxamacker/cbor/v2` for CBOR decoding.

### 7.2 Update ranger poll loop

Replace Cloudflare Queue consumer with HTTP poll to DO:

```go
func (r *Ranger) pollFromDO(ctx context.Context) (*PullResponse, error) {
    req := PullRequest{
        PollerId:     r.pollerId,
        BatchSize:    r.batchSize,
        VisibilityMs: r.visibilityMs,
    }
    // POST to /queue/pull with CBOR body
    // Decode CBOR response
}
```

### 7.3 Update ranger ack logic

Call HTTP ack endpoint after successful massif commit:

```go
func (r *Ranger) ackRange(ctx context.Context, logId []byte, seqLo, seqHi uint64) error {
    // POST to /queue/ack with JSON body
}
```

---

## Phase 8: Cleanup and Migration

### 8.1 Disable R2_LEAVES notifications

Remove R2 event notification configuration that triggers the ranger queue.

### 8.2 Delete R2_LEAVES bucket

After confirming no traffic to old path.

### 8.3 Delete Cloudflare Queue

Remove `{CANOPY_ID}-ranger` queue and DLQ.

### 8.4 Remove feature flag

Set `USE_DO_INGRESS=true` permanently, then remove flag handling code.

---

## Implementation Notes

### File Organization

Follow the file-per-type pattern established in canopy/WARP.md:

- Each type or closely related group of types gets its own file
- Use `types.ts` as an aggregating re-export point, not a monolithic file
- Keep related code together (interface + its constants in one file)
- Avoid circular dependencies by structuring imports carefully

This applies to shared type packages (e.g., `@canopy/forestrie-ingress-types`)
and to implementation code within forestrie-ingress.

### Authentication

The pull/ack endpoints should require the same bearer token currently used
for queue authentication. This is configured via environment variable and
validated in the HTTP handlers.

### Monitoring

Add Cloudflare Analytics Engine events for:
- Enqueue rate per log
- Pull latency
- Ack rate
- Dead letter count

### Rate Limiting

Per-log rate limiting in `enqueue()` uses in-memory sliding window:

```typescript
private logEnqueueCounts: Map<string, number[]> = new Map();
private readonly MAX_RATE_PER_LOG = 1000; // per second
```

### Backpressure

Global backpressure via `MAX_PENDING` constant (e.g., 100,000). Returns
HTTP 503 with Problem Details when exceeded.

---

## Resolved Design Choices

1. **MAX_PENDING**: 100,000 entries. Tune based on metrics if needed.

2. **Poller timeout**: 60 seconds.

3. **CBOR library**: `cbor-x` — already used by canopy-api (^1.5.9).
   Maintains consistency across canopy packages.

4. **Separate worker with cross-worker DO RPC**: SequencingQueue DO is owned
   by a separate `forestrie-ingress` worker at
   `canopy/packages/apps/forestrie-ingress/`. The canopy-api worker references
   it via `script_name: "forestrie-ingress"` in the DO binding. This uses
   native DO RPC (not service bindings) with the same efficiency as
   co-location. The pattern matches `ranger-cache` / `canopy-api` and requires
   initial deployment of forestrie-ingress before canopy-api can reference it.
