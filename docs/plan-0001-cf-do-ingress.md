# Plan 0001: Cloudflare DO Ingress Queue Implementation

## Status
Draft

## Rollout Strategy

This is a **flag-day rollout**. The system is pre-production so service
downtime is immaterial. Delivery efficiency is the key concern—no backwards
compatibility or gradual migration is required. The cutover will:

1. Deploy forestrie-ingress worker (creates DO and SQLite storage)
2. Update canopy-api to use DO ingress instead of R2_LEAVES
3. Update ranger to poll DO instead of Cloudflare Queue
4. Delete obsolete resources (R2_LEAVES bucket, Cloudflare Queue)

Deploying forestrie-ingress early (after Phase 4) is recommended to establish
the worker and DO resources before the integration phases.

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
- [adr-0006-cf-do-ingress-hash-function.md](adr-0006-cf-do-ingress-hash-function.md):
  Non-cryptographic hash function for poller assignment
- [adr-0007-cf-do-ingress-poller-limits.md](adr-0007-cf-do-ingress-poller-limits.md):
  Poller scaling limits
- [adr-0008-cf-do-ingress-sequence-space.md](adr-0008-cf-do-ingress-sequence-space.md):
  Sequence number space and rollover

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

### 2.3 Implement ackFirst()

RPC/HTTP method called by ranger. Uses limit-based ack because seq values
are non-contiguous per-log (see arc-cloudflare-do-ingress.md section 2.3):

```typescript
async ackFirst(
  logId: ArrayBuffer,
  seqLo: number,
  limit: number
): Promise<{ deleted: number }>
```

- Select first N entries for logId where `seq >= seqLo ORDER BY seq ASC LIMIT N`
- Delete those specific entries by seq
- Update in-memory `pendingCount`
- Return count of deleted rows

**Happy path test:** `ackFirst()` deletes first N enqueued entries for log;
returns correct count.

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

- Require `Content-Type: application/cbor` (return 415 if not)
- Parse CBOR request body
- Get DO stub via `env.SEQUENCING_QUEUE.idFromName("global")`
- Call `stub.pull(request)`
- Return CBOR response with `Content-Type: application/cbor`

### 4.3 Implement ack handler

- Require `Content-Type: application/cbor` (return 415 if not)
- Parse CBOR request body: `[logId, seqLo, limit]` (see section 2.3)
- Call `stub.ackFirst(logId, seqLo, limit)`
- Return CBOR response with `Content-Type: application/cbor`

### 4.4 Implement stats handler (observability endpoint)

- Call `stub.stats()`
- Return JSON response (observability endpoints use JSON for easy tooling)

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

### 4.6 Deploy forestrie-ingress (checkpoint)

After Phase 4 is complete and tests pass, deploy forestrie-ingress to
establish the worker and DO resources:

```bash
pnpm --filter @canopy/forestrie-ingress deploy
```

This creates:
- The `forestrie-ingress` worker in Cloudflare
- The `SequencingQueue` Durable Object class and SQLite storage
- The HTTP endpoints at `/queue/pull`, `/queue/ack`, `/queue/stats`

Deploying early allows verification of the worker in isolation before
integrating with canopy-api and ranger.

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

**ackFirst() edge cases:**
- No-op when no entries match logId and seqLo
- Only deletes entries for specified logId (not others)
- Deletes exactly N entries even with non-contiguous seq values
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

The DO is accessed via cross-worker RPC binding (`script_name: "forestrie-ingress"`).

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

### 6.2 Remove R2_LEAVES binding

Remove the `R2_LEAVES` binding from canopy-api's wrangler.jsonc since it is
no longer used.

---

## Phase 7: Ranger Integration

Note: Ranger is a Go service. This phase involves changes outside the
canopy monorepo.

### 7.1 Add CBOR decoding to ranger

Use `github.com/fxamacker/cbor/v2` for CBOR decoding.

Define types matching the pull response wire format:

```go
type PullResponse struct {
    Version     uint
    LeaseExpiry uint64
    LogGroups   []LogGroup
}

type LogGroup struct {
    LogId   []byte
    SeqLo   uint64
    SeqHi   uint64
    Entries []Entry
}

type Entry struct {
    ContentHash []byte
    Extra0      []byte // may be nil
    Extra1      []byte
    Extra2      []byte
    Extra3      []byte
}
```

### 7.2 Update ranger poll loop

Replace Cloudflare Queue consumer with HTTP poll to DO.

**Architecture change**: The pull response is pre-grouped by logId. Each
LogGroup contains `seqLo`, `seqHi`, and a contiguous list of entries. Ranger
spawns a goroutine per LogGroup to commit and ack independently.

**Key design point**: Entries within a LogGroup are ordered by seq ASC but
have **non-contiguous** seq values because seq is allocated globally across
all logs (see arc-cloudflare-do-ingress.md section 2.3).

This requires limit-based ack: ranger acks N entries starting from seqLo,
without needing to know the actual seq values.

```go
func (r *Ranger) pollCycle(ctx context.Context) error {
    resp, err := r.pullFromDO(ctx)
    if err != nil {
        return err
    }
    if len(resp.LogGroups) == 0 {
        return nil // Nothing to process
    }

    var wg sync.WaitGroup
    for _, group := range resp.LogGroups {
        wg.Add(1)
        go func(g LogGroup) {
            defer wg.Done()
            r.processLogGroup(ctx, g)
        }(group)
    }
    wg.Wait()
    return nil
}

func (r *Ranger) processLogGroup(ctx context.Context, group LogGroup) {
    // Commit entries to massif. Returns count of successfully committed.
    committed, err := r.commitBatch(ctx, group.LogId, group.Entries)
    if err != nil {
        r.logger.Warn("batch commit failed",
            "logId", hex.EncodeToString(group.LogId),
            "error", err)
        // Don't ack; entries will redeliver after visibility timeout.
        return
    }

    if committed == 0 {
        return
    }

    // Limit-based ack: delete the first N entries for this log starting from seqLo.
    // See arc-cloudflare-do-ingress.md section 2.3 for why limit-based ack is required.
    if err := r.ackFirst(ctx, group.LogId, group.SeqLo, committed); err != nil {
        // IMPORTANT: Entries were committed but ack failed.
        // They will redeliver and may cause duplicate commits.
        // See arc-cloudflare-do-ingress.md section 3.8 and 3.10 for
        // accepted risk analysis and future mitigation options.
        r.logger.Warn("ack failed after commit",
            "logId", hex.EncodeToString(group.LogId),
            "seqLo", group.SeqLo,
            "committed", committed,
            "error", err)
    }
}
```

**Duplicate commit risk**: If `ackFirst` fails after `commitBatch` succeeds,
the committed entries will redeliver and be re-committed. This is an accepted
risk for the initial implementation. See `arc-cloudflare-do-ingress.md`:
- Section 3.8 for reliability analysis
- Section 3.10 for future mitigation options (bloom filter deduplication,
  attempt-aware checks, DO-allocated pre-sequence IDs)

Add a code comment in the commit path referencing future directions:

```go
// commitBatch commits entries to the massif for this log.
//
// DUPLICATE COMMIT NOTE: If ack fails after this returns successfully,
// entries will redeliver and be re-committed. This is currently accepted.
// Future options to mitigate:
// - Bloom filter check before commit (arc-cloudflare-do-ingress.md 3.10.1)
// - Attempt-aware deduplication (3.10.2)
// - DO-allocated pre-sequence IDs (3.10.4)
func (r *Ranger) commitBatch(ctx context.Context, logId []byte, entries []Entry) (int, error) {
    // ... existing commit logic ...
}
```

### 7.3 Implement HTTP pull client

```go
func (r *Ranger) pullFromDO(ctx context.Context) (*PullResponse, error) {
    req := PullRequest{
        PollerId:     r.pollerId,
        BatchSize:    r.batchSize,
        VisibilityMs: r.visibilityMs,
    }

    body, err := cbor.Marshal(req)
    if err != nil {
        return nil, fmt.Errorf("marshal pull request: %w", err)
    }

    url := fmt.Sprintf("%s/queue/pull", r.cfg.IngressBaseURL)
    httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
    if err != nil {
        return nil, err
    }
    httpReq.Header.Set("Authorization", "Bearer "+r.cfg.IngressToken)
    httpReq.Header.Set("Content-Type", "application/cbor")

    httpResp, err := r.httpClient.Do(httpReq)
    if err != nil {
        return nil, fmt.Errorf("pull request failed: %w", err)
    }
    defer httpResp.Body.Close()

    if httpResp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("pull returned status %d", httpResp.StatusCode)
    }

    respBody, err := io.ReadAll(httpResp.Body)
    if err != nil {
        return nil, fmt.Errorf("read pull response: %w", err)
    }

    return decodePullResponse(respBody)
}
```

### 7.4 Implement HTTP ack client

Use limit-based ack (see arc-cloudflare-do-ingress.md section 2.3):

```go
// AckRequest wire format: [logId (bytes), seqLo (uint64), limit (uint64)]
type AckRequest struct {
    LogId []byte
    SeqLo uint64
    Limit uint64
}

func (r *Ranger) ackFirst(ctx context.Context, logId []byte, seqLo uint64, limit int) error {
    req := AckRequest{
        LogId: logId,
        SeqLo: seqLo,
        Limit: uint64(limit),
    }

    body, err := cbor.Marshal(req)
    if err != nil {
        return fmt.Errorf("marshal ack request: %w", err)
    }

    url := fmt.Sprintf("%s/queue/ack", r.cfg.IngressBaseURL)
    httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
    if err != nil {
        return err
    }
    httpReq.Header.Set("Authorization", "Bearer "+r.cfg.IngressToken)
    httpReq.Header.Set("Content-Type", "application/cbor")

    httpResp, err := r.httpClient.Do(httpReq)
    if err != nil {
        return fmt.Errorf("ack request failed: %w", err)
    }
    defer httpResp.Body.Close()

    if httpResp.StatusCode != http.StatusOK {
        return fmt.Errorf("ack returned status %d", httpResp.StatusCode)
    }

    return nil
}
```

### 7.5 Configuration changes

Add new configuration for DO ingress endpoint:

```go
type Config struct {
    // ... existing fields ...

    // IngressBaseURL is the forestrie-ingress worker URL.
    // e.g., "https://forestrie-ingress.{account}.workers.dev"
    IngressBaseURL string `env:"INGRESS_BASE_URL,required"`

    // IngressToken is the bearer token for pull/ack endpoints.
    IngressToken string `env:"INGRESS_TOKEN,required"`
}
```

Remove Cloudflare Queue consumer configuration.

### 7.6 Remove Cloudflare Queue consumer

- Delete queue consumer code and related handlers
- Remove queue-related configuration
- Update main.go to use new poll loop

---

## Phase 8: Resource Cleanup

This phase deletes obsolete infrastructure. Since this is a flag-day rollout,
cleanup can happen immediately after verifying the new path works.

### 8.1 Delete R2_LEAVES bucket

Remove the R2 bucket and any associated event notifications:

```bash
# List bucket contents (should be empty or stale)
wrangler r2 object list {CANOPY_ID}-leaves

# Delete bucket
wrangler r2 bucket delete {CANOPY_ID}-leaves
```

### 8.2 Delete Cloudflare Queue

Remove the ranger queue and its dead-letter queue:

```bash
# Delete main queue
wrangler queues delete {CANOPY_ID}-ranger

# Delete DLQ if it exists
wrangler queues delete {CANOPY_ID}-ranger-dlq
```

### 8.3 Remove obsolete code

- Remove R2_LEAVES references from canopy-api
- Remove Cloudflare Queue consumer code from ranger
- Remove any queue-related taskfile entries

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

### Test Organization

Tests are organized by discrete logical area using a common grouping prefix:

```
test/unit/
├── sequencingqueue.test.ts        # Basic DO instantiation and schema tests
├── sequencingqueue-enqueue.test.ts
├── sequencingqueue-pull.test.ts
├── sequencingqueue-ack.test.ts
├── sequencingqueue-stats.test.ts
└── sequencingqueue-fixture.ts     # Shared testEnv, getStub helpers

test/integration/handlers/
├── fixture.ts
├── pull.test.ts
├── ack.test.ts
├── stats.test.ts
└── roundtrip.test.ts
```

This structure keeps test files focused and easier to navigate. See
`canopy/WARP.md` for the full test organization guidelines.

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
