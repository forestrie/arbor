# Cloudflare DO ingress queue design

This document describes a Durable Object based queue that replaces the
current `R2_LEAVES` ingress buffer and `{CANOPY_ID}-ranger` Cloudflare
Queue with a single, domain-aware component.

## Related ADRs

Key architectural decisions are documented separately:

- [ADR-0001](adr-0001-cf-do-ingress-single-do-architecture.md): Single
  global DO architecture (with future prefix-based sharding path)
- [ADR-0002](adr-0002-cf-do-ingress-consistent-hashing.md): Consistent
  hashing for ranger log assignment
- [ADR-0003](adr-0003-cf-do-ingress-range-ack.md): Range-based
  acknowledgement for batch commits
- [ADR-0004](adr-0004-cf-do-ingress-fixed-visibility-timeout.md): Fixed
  visibility timeout per pull
- [ADR-0005](adr-0005-cf-do-ingress-pull-encoding.md): CBOR encoding for
  HTTP pull interface
- [ADR-0006](adr-0006-cf-do-ingress-hash-function.md): Non-cryptographic
  hash function (djb2) for poller assignment
- [ADR-0007](adr-0007-cf-do-ingress-poller-limits.md): Poller scaling
  limits (500 max with graceful degradation)
- [ADR-0008](adr-0008-cf-do-ingress-sequence-space.md): Sequence number
  space and rollover (theoretical limit, no mitigation needed)

## Document structure

1. **Fundamentals** — general patterns for building reliable queues on
   Cloudflare Durable Objects, applicable to any similar system.
2. **Forestrie specifics** — optimisations and semantics tailored to
   how ranger processes and commits log entries, using a single global
   DO with consistent hashing for ranger assignment.
3. **Integrated design** — the complete design synthesising all parts.

---

# Part 1: Fundamentals

This section covers the core building blocks of a DO-based queue:
storage schema, write-through operation, at-least-once delivery,
visibility and redelivery, poison message handling, backpressure,
operational tooling, and local integration testing.

## 1.1 Storage schema

Durable Objects provide transactional SQLite storage via
`ctx.storage.sql`. For a queue, the minimal schema tracks entries and
their delivery state.

```sql path=null start=null
CREATE TABLE IF NOT EXISTS queue_entries (
  -- Monotonic sequence number assigned at enqueue time.
  seq INTEGER PRIMARY KEY,

  -- Application payload columns.
  log_id BLOB NOT NULL,
  content_hash BLOB NOT NULL,
  extra0 BLOB,
  extra1 BLOB,
  extra2 BLOB,
  extra3 BLOB,

  -- Delivery state.
  -- NULL means available; non-NULL means leased until this timestamp.
  visible_after INTEGER,

  -- Number of delivery attempts.
  attempts INTEGER NOT NULL DEFAULT 0,

  -- Enqueue timestamp (Unix millis).
  enqueued_at INTEGER NOT NULL
);

-- Index for efficient pull queries: find available entries.
CREATE INDEX IF NOT EXISTS idx_visible
  ON queue_entries (visible_after);

-- Index for poison message identification.
CREATE INDEX IF NOT EXISTS idx_attempts
  ON queue_entries (attempts);
```

Key points:

- `seq` is an auto-increment primary key providing total order.
- `visible_after` encodes visibility: `NULL` or past timestamp means
  available; future timestamp means leased.
- `attempts` supports poison message detection.
- `extra0..extra3` are opaque application bytes, each max 32 bytes.

## 1.2 Write-through operation

Durable Objects execute JavaScript in a single-threaded isolate with
durable storage. A common pattern is to keep a small in-memory index
that mirrors or summarises persistent state, updated transactionally.

For a queue:

- **On enqueue**: insert row, increment in-memory `pendingCount`.
- **On ack**: delete rows, decrement `pendingCount`.
- **On visibility expiry**: `pendingCount` doesn't change (entry was
  already counted), but it becomes available again.

This avoids a `SELECT COUNT(*)` on every pull.

```typescript path=null start=null
export class SequencingQueue extends DurableObject<Env> {
  private pendingCount: number | null = null;
  private nextSeq: number | null = null;

  private ensureSchema(): void {
    // Run CREATE TABLE IF NOT EXISTS statements once per instance.
  }

  private async loadState(): Promise<void> {
    if (this.pendingCount !== null) return;

    const countRow = this.ctx.storage.sql
      .exec<{ cnt: number }>(
        "SELECT COUNT(*) as cnt FROM queue_entries",
      )
      .one();
    this.pendingCount = countRow?.cnt ?? 0;

    const maxRow = this.ctx.storage.sql
      .exec<{ m: number | null }>(
        "SELECT MAX(seq) as m FROM queue_entries",
      )
      .one();
    this.nextSeq = (maxRow?.m ?? 0) + 1;
  }

  async enqueue(
    logId: ArrayBuffer,
    contentHash: ArrayBuffer,
    extras?: {
      extra0?: ArrayBuffer;
      extra1?: ArrayBuffer;
      extra2?: ArrayBuffer;
      extra3?: ArrayBuffer;
    },
  ): Promise<{ seq: number }> {
    this.ensureSchema();
    await this.loadState();

    const seq = this.nextSeq!;
    const now = Date.now();

    this.ctx.storage.sql.exec(
      `INSERT INTO queue_entries
         (seq, log_id, content_hash, extra0, extra1, extra2, extra3,
          visible_after, attempts, enqueued_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0, ?)`,
      seq,
      logId,
      contentHash,
      extras?.extra0 ?? null,
      extras?.extra1 ?? null,
      extras?.extra2 ?? null,
      extras?.extra3 ?? null,
      now,
    );

    this.nextSeq = seq + 1;
    this.pendingCount!++;

    return { seq };
  }
}
```

The in-memory state is reconstructed on DO wake-up via `loadState()`.
All mutations go through SQLite first, then update in-memory counters.

## 1.3 At-least-once delivery

At-least-once semantics require:

1. Messages are not deleted until explicitly acknowledged.
2. Unacknowledged messages become available again after a visibility
   timeout.

The `pull` operation selects available entries (where `visible_after`
is `NULL` or in the past), sets `visible_after` to `now + timeout`, and
returns the entries. If the consumer crashes, the entries automatically
become available again.

```typescript path=null start=null
interface QueueEntry {
  seq: number;
  logId: ArrayBuffer;
  contentHash: ArrayBuffer;
  extra0: ArrayBuffer | null;
  extra1: ArrayBuffer | null;
  extra2: ArrayBuffer | null;
  extra3: ArrayBuffer | null;
  attempts: number;
}

async pull(
  batchSize: number,
  visibilityMs: number,
): Promise<{ entries: QueueEntry[]; leaseExpiry: number }> {
  this.ensureSchema();
  await this.loadState();

  const now = Date.now();
  const leaseExpiry = now + visibilityMs;

  // Select available entries.
  const rows = this.ctx.storage.sql
    .exec<QueueEntryRow>(
      `SELECT seq, log_id, content_hash, extra0, extra1, extra2, extra3,
              attempts
       FROM queue_entries
       WHERE visible_after IS NULL OR visible_after <= ?
       ORDER BY seq ASC
       LIMIT ?`,
      now,
      batchSize,
    )
    .toArray();

  if (rows.length === 0) {
    return { entries: [], leaseExpiry };
  }

  // Mark them as leased.
  const seqs = rows.map((r) => r.seq);
  this.ctx.storage.sql.exec(
    `UPDATE queue_entries
     SET visible_after = ?, attempts = attempts + 1
     WHERE seq IN (${seqs.map(() => "?").join(",")})`,
    leaseExpiry,
    ...seqs,
  );

  const entries: QueueEntry[] = rows.map((r) => ({
    seq: r.seq,
    logId: r.log_id,
    contentHash: r.content_hash,
    extra0: r.extra0,
    extra1: r.extra1,
    extra2: r.extra2,
    extra3: r.extra3,
    attempts: r.attempts + 1,
  }));

  return { entries, leaseExpiry };
}
```

The `attempts` column is incremented on every pull. This supports
poison message detection (see below).

## 1.4 Visibility and redelivery

Visibility timeout controls how long a consumer has to process and
acknowledge entries before they become available to another consumer
(or the same consumer on retry).

We use **fixed timeout per pull**: the consumer specifies `visibilityMs`
in the pull request and all returned entries share that timeout. See
[ADR-0004](adr-0004-cf-do-ingress-fixed-visibility-timeout.md) for the
rationale.

The consumer requests a visibility window (e.g. 30 seconds), and if it
doesn't ack within that window, entries reappear.

Redelivery happens automatically: the next `pull` query's
`WHERE visible_after IS NULL OR visible_after <= ?` picks up expired
leases.

No background process is needed. Visibility expiry is evaluated
lazily on each pull.

## 1.5 Poison message handling (DLQ equivalent)

A poison message is one that repeatedly fails processing. Without
handling, it blocks the queue or causes infinite retry loops.

Pattern: after N attempts, move the entry to a dead-letter table or
mark it as "dead" so it's excluded from normal pulls.

```sql path=null start=null
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

On pull, if `attempts >= MAX_ATTEMPTS`, move to dead letters instead
of returning:

```typescript path=null start=null
const MAX_ATTEMPTS = 5;

// Inside pull(), after selecting rows:
const deadRows = rows.filter((r) => r.attempts >= MAX_ATTEMPTS);
const liveRows = rows.filter((r) => r.attempts < MAX_ATTEMPTS);

if (deadRows.length > 0) {
  const now = Date.now();
  for (const r of deadRows) {
    this.ctx.storage.sql.exec(
      `INSERT INTO dead_letters
         (seq, log_id, content_hash, extra0, extra1, extra2, extra3,
          attempts, enqueued_at, dead_at, reason)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      r.seq,
      r.log_id,
      r.content_hash,
      r.extra0,
      r.extra1,
      r.extra2,
      r.extra3,
      r.attempts,
      r.enqueued_at,
      now,
      "max attempts exceeded",
    );
    this.ctx.storage.sql.exec(
      "DELETE FROM queue_entries WHERE seq = ?",
      r.seq,
    );
    this.pendingCount!--;
  }
}

// Continue with liveRows...
```

Dead letters can be inspected, retried manually, or purged after a
retention period.

## 1.6 Backpressure

If producers enqueue faster than consumers can process, the queue
grows unboundedly. Backpressure mechanisms:

1. **Reject on capacity**: `enqueue` returns an error if
   `pendingCount > MAX_PENDING`.
2. **Slow acknowledgement**: don't ack the HTTP response to the
   producer until the entry is persisted (already implicit in DO
   request handling).
3. **Rate limiting**: enforce enqueue rate per caller or globally.

Simple capacity-based backpressure:

```typescript path=null start=null
const MAX_PENDING = 100_000;

async enqueue(...): Promise<{ seq: number }> {
  // ...
  await this.loadState();

  if (this.pendingCount! >= MAX_PENDING) {
    throw new Error("queue full");
  }

  // ... insert ...
}
```

The caller (canopy-api) can convert this into an HTTP 503 with
`Retry-After`.

## 1.7 Acknowledgement

Acknowledgement deletes entries from the queue, signalling successful
processing.

Simple per-entry ack:

```typescript path=null start=null
async ack(seqs: number[]): Promise<{ deleted: number }> {
  this.ensureSchema();
  await this.loadState();

  if (seqs.length === 0) return { deleted: 0 };

  const result = this.ctx.storage.sql.exec(
    `DELETE FROM queue_entries
     WHERE seq IN (${seqs.map(() => "?").join(",")})`,
    ...seqs,
  );

  const deleted = result.rowsWritten;
  this.pendingCount! -= deleted;

  return { deleted };
}
```

Range-based ack (for ordered processing):

```typescript path=null start=null
async ackRange(
  logId: ArrayBuffer,
  fromSeq: number,
  toSeq: number,
): Promise<{ deleted: number }> {
  this.ensureSchema();
  await this.loadState();

  const result = this.ctx.storage.sql.exec(
    `DELETE FROM queue_entries
     WHERE log_id = ? AND seq >= ? AND seq <= ?`,
    logId,
    fromSeq,
    toSeq,
  );

  const deleted = result.rowsWritten;
  this.pendingCount! -= deleted;

  return { deleted };
}
```

The `logId` parameter ensures that only entries for the specified log
are deleted. This is critical when using a single DO for multiple logs
(see [ADR-0001](adr-0001-cf-do-ingress-single-do-architecture.md)).

The deleted rows are exactly those that ranger committed to verifiable
storage for that log. If ranger commits entries with seq 5, 6, 7 for
logId X, it calls `ackRange(X, 5, 7)` and only those three rows are
removed.

Range ack is efficient when the consumer processes entries in order
and commits a contiguous batch.

## 1.8 Operational tooling

A production queue needs visibility into:

- Current backlog size.
- Oldest entry age.
- Delivery attempt distribution.
- Dead letter count.
- Throughput (enqueue/ack rates).

Expose a `stats` RPC method:

```typescript path=null start=null
interface QueueStats {
  pending: number;
  deadLetters: number;
  oldestEntryAge: number | null;
  attemptDistribution: Record<number, number>;
}

async stats(): Promise<QueueStats> {
  this.ensureSchema();
  await this.loadState();

  const deadCount = this.ctx.storage.sql
    .exec<{ cnt: number }>("SELECT COUNT(*) as cnt FROM dead_letters")
    .one()?.cnt ?? 0;

  const oldestRow = this.ctx.storage.sql
    .exec<{ enqueued_at: number }>(
      `SELECT enqueued_at FROM queue_entries
       ORDER BY seq ASC LIMIT 1`,
    )
    .one();
  const oldestAge = oldestRow
    ? Date.now() - oldestRow.enqueued_at
    : null;

  const distRows = this.ctx.storage.sql
    .exec<{ attempts: number; cnt: number }>(
      `SELECT attempts, COUNT(*) as cnt FROM queue_entries
       GROUP BY attempts`,
    )
    .toArray();
  const attemptDistribution: Record<number, number> = {};
  for (const r of distRows) {
    attemptDistribution[r.attempts] = r.cnt;
  }

  return {
    pending: this.pendingCount!,
    deadLetters: deadCount,
    oldestEntryAge: oldestAge,
    attemptDistribution,
  };
}
```

Expose via HTTP endpoint for monitoring systems:

```typescript path=null start=null
// In the DO's fetch handler:
if (url.pathname === "/stats") {
  const stats = await this.stats();
  return Response.json(stats);
}
```

For throughput metrics, maintain in-memory counters reset on a timer
or use Cloudflare Analytics Engine.

## 1.9 Local integration testing

Cloudflare provides `wrangler dev` with local DO support and the
`@cloudflare/vitest-pool-workers` package for unit and integration
tests.

### 1.9.1 Unit tests with vitest

Configure `vitest.config.ts` to use the Workers pool:

```typescript path=null start=null
import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: "./wrangler.jsonc" },
      },
    },
  },
});
```

Test file:

```typescript path=null start=null
import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";

describe("SequencingQueue", () => {
  function getQueue(name: string) {
    const id = env.SEQUENCING_QUEUE.idFromName(name);
    return env.SEQUENCING_QUEUE.get(id);
  }

  it("enqueue and pull returns entry", async () => {
    const q = getQueue("test-enqueue-pull");

    const logId = new Uint8Array(16).fill(0x01).buffer;
    const hash = new Uint8Array(32).fill(0xab).buffer;

    const { seq } = await q.enqueue(logId, hash);
    expect(seq).toBe(1);

    const { entries } = await q.pull(10, 30_000);
    expect(entries).toHaveLength(1);
    expect(entries[0].seq).toBe(1);
  });

  it("ack removes entry", async () => {
    const q = getQueue("test-ack");

    const logId = new Uint8Array(16).fill(0x02).buffer;
    const hash = new Uint8Array(32).fill(0xcd).buffer;

    const { seq } = await q.enqueue(logId, hash);
    const { entries } = await q.pull(10, 30_000);
    expect(entries).toHaveLength(1);

    await q.ack([seq]);

    const stats = await q.stats();
    expect(stats.pending).toBe(0);
  });

  it("visibility timeout causes redelivery", async () => {
    const q = getQueue("test-visibility");

    const logId = new Uint8Array(16).fill(0x03).buffer;
    const hash = new Uint8Array(32).fill(0xef).buffer;

    await q.enqueue(logId, hash);

    // Pull with 1ms visibility.
    const first = await q.pull(10, 1);
    expect(first.entries).toHaveLength(1);

    // Wait for expiry.
    await new Promise((r) => setTimeout(r, 10));

    // Should redeliver.
    const second = await q.pull(10, 30_000);
    expect(second.entries).toHaveLength(1);
    expect(second.entries[0].attempts).toBe(2);
  });
});
```

### 1.9.2 Integration tests with wrangler dev

For end-to-end tests that exercise the HTTP interface:

1. Start the worker locally:

   ```bash
   wrangler dev --local --persist-to .wrangler/state
   ```

2. Run tests against `http://localhost:8787`:

   ```typescript path=null start=null
   // integration/queue.spec.ts
   import { test, expect } from "@playwright/test";

   const BASE = "http://localhost:8787";

   test("enqueue via HTTP", async ({ request }) => {
     const res = await request.post(`${BASE}/queue/test-log/enqueue`, {
       data: {
         contentHash: "ab".repeat(32),
       },
     });
     expect(res.ok()).toBe(true);
     const body = await res.json();
     expect(body.seq).toBeGreaterThan(0);
   });
   ```

3. For CI, use `wrangler dev` in the background or the
   `unstable_dev` API:

   ```typescript path=null start=null
   import { unstable_dev } from "wrangler";

   let worker: Awaited<ReturnType<typeof unstable_dev>>;

   beforeAll(async () => {
     worker = await unstable_dev("src/index.ts", {
       experimental: { disableExperimentalWarning: true },
     });
   });

   afterAll(async () => {
     await worker.stop();
   });

   it("stats endpoint", async () => {
     const res = await worker.fetch("/queue/test-log/stats");
     expect(res.status).toBe(200);
   });
   ```

### 1.9.3 Miniflare for isolated tests

Miniflare (used internally by wrangler) can be configured directly
for more control:

```typescript path=null start=null
import { Miniflare } from "miniflare";

const mf = new Miniflare({
  modules: true,
  scriptPath: "dist/index.js",
  durableObjects: {
    SEQUENCING_QUEUE: "SequencingQueue",
  },
});

const queue = await mf.getDurableObjectNamespace("SEQUENCING_QUEUE");
const id = queue.idFromName("test");
const stub = queue.get(id);

// Call RPC methods directly.
const { seq } = await stub.enqueue(...);
```

This is useful for fast, isolated unit tests without starting a full
dev server.

---

# Part 2: Forestrie specifics

This section covers optimisations and semantics specific to how
Forestrie's ranger service processes log entries.

## 2.1 Single global DO architecture

This design uses a single global Durable Object for all logs, with
`log_id` as a column in the schema. See
[ADR-0001](adr-0001-cf-do-ingress-single-do-architecture.md) for the
full rationale.

Key benefits:

- **Centralised coordination**: the DO has a global view of all logs
  and active pollers, enabling fair work distribution.
- **No discovery problem**: ranger asks "give me work" and the DO
  decides which logs to serve.
- **Simpler deployment**: one DO class, one logical instance.

If throughput eventually saturates the single DO, we will shard by
`logId` prefix (e.g., first 2 hex characters → 256 shards), not by
individual log. This maintains coordination benefits within each shard.

DO stub access:

```typescript path=null start=null
// In canopy-api:
function getQueueStub(env: Env) {
  const id = env.SEQUENCING_QUEUE.idFromName("global");
  return env.SEQUENCING_QUEUE.get(id);
}
```

## 2.2 Fairness and rate limiting

With a single DO, fairness is centralised. The DO's pull method
implements fair distribution across logs.

## 2.3 Batch commit and range ack

ranger's natural processing unit is a contiguous batch of entries for
a single log, committed together to a massif. See
[ADR-0003](adr-0003-cf-do-ingress-range-ack.md) for the full rationale.

With the single DO design, ranger:

1. Pulls a batch of entries (may include multiple logs).
2. Groups entries by `logId`.
3. For each log: commits entries to massif, acks the committed range.

The DO's `ackRange(logId, fromSeq, toSeq)` method deletes exactly the
committed entries:

```typescript path=null start=null
async ackRange(
  logId: ArrayBuffer,
  fromSeq: number,
  toSeq: number,
): Promise<{ deleted: number }> {
  // ... as shown in Part 1 ...
}
```

ranger call:

```go path=null start=null
func (r *Ranger) processLog(ctx context.Context, logID string) error {
    entries, err := r.pullFromDO(ctx, logID, r.batchSize, r.visibility)
    if err != nil {
        return err
    }
    if len(entries) == 0 {
        return nil
    }

    // entries are ordered by seq.
    firstSeq := entries[0].Seq
    lastSeq := entries[len(entries)-1].Seq

    committed, err := r.commitBatch(ctx, logID, entries)
    if err != nil {
        // Don't ack; entries will redeliver after visibility timeout.
        return err
    }

    // Ack the committed range for this specific log.
    // If committed < len(entries), only ack up to the last committed.
    ackTo := entries[committed-1].Seq
    logIdBytes, _ := hex.DecodeString(logID)
    return r.ackRange(ctx, logIdBytes, firstSeq, ackTo)
}
```

Benefits:

- Single HTTP call to ack an entire batch.
- Atomic from ranger's perspective: either the batch is committed and
  acked, or neither.
- If ranger crashes mid-batch, unacked entries redeliver.

## 2.4 Extra bytes fields

The schema includes four opaque extra fields, each max 32 bytes:

```sql path=null start=null
extra0 BLOB CHECK (extra0 IS NULL OR length(extra0) <= 32),
extra1 BLOB CHECK (extra1 IS NULL OR length(extra1) <= 32),
extra2 BLOB CHECK (extra2 IS NULL OR length(extra2) <= 32),
extra3 BLOB CHECK (extra3 IS NULL OR length(extra3) <= 32),
```

These can carry application-specific metadata without changing the
queue schema. Potential uses:

- `extra0`: client-provided idempotency key.
- `extra1`: priority or deadline hint.
- `extra2`: routing tag for multi-region processing.
- `extra3`: reserved for future use.

Validation on enqueue:

```typescript path=null start=null
function validateExtra(buf: ArrayBuffer | null, name: string): void {
  if (buf !== null && buf.byteLength > 32) {
    throw new Error(`${name} exceeds 32 bytes`);
  }
}

async enqueue(
  logId: ArrayBuffer,
  contentHash: ArrayBuffer,
  extras?: {
    extra0?: ArrayBuffer;
    extra1?: ArrayBuffer;
    extra2?: ArrayBuffer;
    extra3?: ArrayBuffer;
  },
): Promise<{ seq: number }> {
  validateExtra(extras?.extra0 ?? null, "extra0");
  validateExtra(extras?.extra1 ?? null, "extra1");
  validateExtra(extras?.extra2 ?? null, "extra2");
  validateExtra(extras?.extra3 ?? null, "extra3");
  // ...
}
```

## 2.5 HTTP interface for ranger

ranger consumes the DO queue via HTTP (since it runs in GCP, not as a
Cloudflare Worker).

Endpoints exposed by `canopy-api` or a dedicated worker:

- `POST /queue/pull`
  - Body: `{ pollerId: string, batchSize: number, visibilityMs: number }`
  - Response: `{ entries: [...], leaseExpiry: number, assignedLogs: [...] }`

- `POST /queue/ack`
  - Body: `{ logId: string, fromSeq: number, toSeq: number }`
  - Response: `{ deleted: number }`

- `GET /queue/stats`
  - Response: `{ pending, deadLetters, oldestEntryAge, activePollers, ... }`

Authentication: bearer token (same as current queue token) or mTLS.

Example pull request from ranger:

```go path=null start=null
func (r *Ranger) pullFromDO(
    ctx context.Context,
    pollerId string,
    batchSize int,
    visibilityMs int,
) (*PullResponse, error) {
    url := fmt.Sprintf("%s/queue/pull", r.cfg.QueueBaseURL)
    body, _ := json.Marshal(map[string]any{
        "pollerId":     pollerId,
        "batchSize":    batchSize,
        "visibilityMs": visibilityMs,
    })

    req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
    req.Header.Set("Authorization", "Bearer "+r.cfg.QueueToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := r.httpClient.Do(req)
    // ... handle response ...
}
```

## 2.6 Eliminating R2_LEAVES

With the DO queue, `R2_LEAVES` is no longer needed:

- Ingress writes go directly to the DO.
- ranger reads entries from the DO, not from R2.
- The COSE payload is not stored at all (ranger only needs
  `contentHash`).

Migration path:

1. Deploy the DO queue and new `canopy-api` endpoints.
2. Update ranger to poll the DO instead of Cloudflare Queues.
3. Disable R2 event notifications for `R2_LEAVES`.
4. Remove `R2_LEAVES` bucket and related cleanup cron.

The `{CANOPY_ID}-ranger` Cloudflare Queue can also be deleted once
migration is complete.

## 2.7 Latency improvement summary

Current path:

```
POST -> R2_LEAVES write -> R2 notification -> Queue -> ranger poll
```

Latencies: ~50ms + ~100-500ms + 0-5000ms (poll interval)

New path:

```
POST -> DO write -> ranger poll
```

Latencies: ~20ms + 0-Xms (poll interval)

Fixed savings: ~100-500ms from removing R2 + notification.

Variable savings: depends on poll interval tuning. With adaptive
polling (immediate re-poll when entries exist, backoff when empty),
the effective poll latency under load approaches zero.

Combined with the simpler ack semantics and per-log sharding, the
DO queue should provide a measurable improvement in p50 and p95
registration-to-sequenced latency.

## 2.8 Robustness summary

| Property | Current (R2+Queue) | DO Queue |
|----------|-------------------|----------|
| Durability of pending entries | R2 (designed for objects) | DO SQLite (designed for transactions) |
| At-least-once delivery | Cloudflare Queue guarantees | Custom implementation |
| Poison message handling | DLQ | Custom DLQ table |
| Backpressure | Queue limits | Custom capacity check |
| Sharding | None (single queue) | Natural per-log |
| Operational visibility | Queue dashboard | Custom stats endpoint |

Both approaches provide adequate robustness. The DO queue requires
implementing well-understood patterns, but in return offers better
domain alignment and more control over semantics.

## 2.9 Horizontal scaling of ranger instances

Ranger scales horizontally using standard Kubernetes scaling. The DO
acts as coordinator, assigning logs to pollers using consistent
hashing. See [ADR-0002](adr-0002-cf-do-ingress-consistent-hashing.md)
for the full rationale.

Key points:

- Rangers are stateless; each instance generates a `pollerId` at
  startup.
- Rangers poll a single endpoint; the DO decides which logs to serve.
- Consistent hashing on `logId` assigns logs to pollers.
- At any moment, it's unlikely two rangers receive entries for the
  same log (maximises throughput by avoiding optimistic concurrency
  conflicts).
- If rangers do conflict, ranger's ETag-based writes ensure
  correctness; the "losing" entries redeliver after visibility
  timeout.

### Poller-aware pull

The `pull` endpoint accepts a `pollerId` and returns entries for logs
assigned to that poller:

```typescript path=null start=null
interface PullRequest {
  pollerId: string;
  batchSize: number;
  visibilityMs: number;
}

// Response is CBOR-encoded; see section 2.10 for wire format.
interface PullResponse {
  version: number;
  leaseExpiry: number;
  logGroups: LogGroup[];
}

interface LogGroup {
  logId: ArrayBuffer;
  seqLo: number;
  seqHi: number;
  entries: Entry[];
}
```

On each pull:

1. Record `pollerId` with current timestamp.
2. Expire pollers not seen within timeout (e.g., 60s).
3. Compute log assignments via consistent hashing.
4. Return entries only for logs assigned to this poller.

### Log assignment via consistent hashing

```typescript path=null start=null
function assignLog(logId: string, pollerIds: string[]): string {
  const sorted = [...pollerIds].sort();
  const hash = simpleHash(logId);
  return sorted[hash % sorted.length];
}
```

This provides:

- Minimal log movement when pollers scale up/down (~1/N logs move).
- Natural affinity (same log tends to go to same ranger).
- Stateless assignment (no persistent state needed).

### Example pull implementation

```typescript path=null start=null
async pull(req: PullRequest): Promise<PullResponse> {
  this.ensureSchema();
  await this.loadState();

  const now = Date.now();

  // Update poller state.
  this.pollers.set(req.pollerId, {
    lastSeen: now,
    assignedLogs: new Set(),
  });

  // Expire stale pollers.
  for (const [id, state] of this.pollers) {
    if (now - state.lastSeen > this.POLLER_TIMEOUT_MS) {
      this.pollers.delete(id);
    }
  }

  const activePollerIds = [...this.pollers.keys()];

  // Find logs with available entries.
  const logsWithWork = this.ctx.storage.sql
    .exec<{ log_id: ArrayBuffer }>(
      `SELECT DISTINCT log_id FROM queue_entries
       WHERE visible_after IS NULL OR visible_after <= ?`,
      now,
    )
    .toArray()
    .map((r) => bufferToHex(r.log_id));

  // Assign logs to this poller via consistent hashing.
  const myLogs = logsWithWork.filter(
    (logId) => assignLog(logId, activePollerIds) === req.pollerId,
  );

  const leaseExpiry = now + req.visibilityMs;

  if (myLogs.length === 0) {
    return { version: 1, leaseExpiry, logGroups: [] };
  }

  // Pull entries for assigned logs, respecting batchSize.
  // For fairness, pull a few from each log rather than all from one.
  const entriesPerLog = Math.max(
    1,
    Math.floor(req.batchSize / myLogs.length),
  );

  const logGroups: LogGroup[] = [];
  let totalEntries = 0;

  for (const logIdHex of myLogs) {
    if (totalEntries >= req.batchSize) break;

    const logIdBlob = hexToBuffer(logIdHex);
    const remaining = req.batchSize - totalEntries;
    const limit = Math.min(entriesPerLog, remaining);

    // Query returns entries sorted by seq ASC (contiguous range).
    const rows = this.ctx.storage.sql
      .exec<QueueEntryRow>(
        `SELECT seq, content_hash, extra0, extra1, extra2, extra3
         FROM queue_entries
         WHERE log_id = ?
           AND (visible_after IS NULL OR visible_after <= ?)
         ORDER BY seq ASC
         LIMIT ?`,
        logIdBlob,
        now,
        limit,
      )
      .toArray();

    if (rows.length > 0) {
      const seqs = rows.map((r) => r.seq);
      this.ctx.storage.sql.exec(
        `UPDATE queue_entries
         SET visible_after = ?, attempts = attempts + 1
         WHERE seq IN (${seqs.map(() => "?").join(",")})`,
        leaseExpiry,
        ...seqs,
      );

      // Build grouped response: seqLo and seqHi from contiguous range.
      logGroups.push({
        logId: logIdBlob,
        seqLo: seqs[0],
        seqHi: seqs[seqs.length - 1],
        entries: rows.map((r) => ({
          contentHash: r.content_hash,
          extra0: r.extra0,
          extra1: r.extra1,
          extra2: r.extra2,
          extra3: r.extra3,
        })),
      });

      totalEntries += rows.length;
    }
  }

  return { version: 1, leaseExpiry, logGroups };
}
```

### Ranger side

Ranger instances generate a `pollerId` at startup and include it in
every pull request. The response is pre-grouped by logId (see section
2.10 for wire format), so ranger processes each group directly.

See section 2.10 "Ranger processing with grouped response" for the
implementation example.

## 2.10 HTTP pull interface encoding

The pull interface exchanges binary-heavy payloads (`logId`, `contentHash`,
`extra0`–`extra3`). Three encoding options were considered:

1. **JSON with hex/base64**: Universal but verbose; encode/decode overhead.
2. **Bespoke binary**: Maximum efficiency but fragile; no schema evolution.
3. **CBOR**: Binary-native, compact, standardised (RFC 8949).

See [ADR-0005](adr-0005-cf-do-ingress-pull-encoding.md) for the full
analysis.

### Decision: CBOR with bespoke grouped encoding

We use CBOR for pull request/response bodies. The response is pre-grouped
by logId with entries sorted by seq. Since both producer (DO) and consumer
(ranger) know the exact schema, we use positional arrays for performance.

**Pull response wire format:**

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
- entries: array of `[contentHash, extra0, extra1, extra2, extra3]`

Each entry:
- `contentHash`: byte string (32 bytes)
- `extra0`–`extra3`: byte string or null

**Design rationale:**

- **Grouped by logId**: Ranger processes per-log; eliminates client-side
  grouping.
- **seqLo/seqHi**: Ranger only needs these for `ackRange(logId, from, to)`.
  Individual seq values are redundant since entries are contiguous.
- **No `attempts`**: Internal to DO for poison detection; ranger doesn't
  need it.
- **Version field**: Enables future format evolution.

**Content types:**

Non-observability endpoints (pull, ack) use CBOR exclusively. This simplifies
implementation by avoiding base64/hex encoding of binary fields and provides
a consistent wire format for both request and response bodies.

- Pull request: `application/cbor` (required)
- Pull response: `application/cbor`
- Ack request: `application/cbor` (required)
- Ack response: `application/cbor`
- Stats request: no body
- Stats response: `application/json`
- Error responses: `application/problem+json` (RFC 9457)

Requests with incorrect `Content-Type` receive 415 Unsupported Media Type.

### Error responses

All errors use RFC 9457 Problem Details in JSON:

```json path=null start=null
{
  "type": "https://forestrie.io/problems/queue-full",
  "title": "Queue capacity exceeded",
  "status": 503,
  "detail": "Pending count 100000 exceeds limit"
}
```

### Example DO encoder (TypeScript)

```typescript path=null start=null
import { encode } from "cbor-x";

interface LogGroup {
  logId: ArrayBuffer;
  seqLo: number;
  seqHi: number;
  entries: Array<{
    contentHash: ArrayBuffer;
    extra0: ArrayBuffer | null;
    extra1: ArrayBuffer | null;
    extra2: ArrayBuffer | null;
    extra3: ArrayBuffer | null;
  }>;
}

function encodePullResponse(
  version: number,
  leaseExpiry: number,
  groups: LogGroup[],
): ArrayBuffer {
  const logGroups = groups.map((g) => [
    g.logId,
    g.seqLo,
    g.seqHi,
    g.entries.map((e) => [
      e.contentHash,
      e.extra0,
      e.extra1,
      e.extra2,
      e.extra3,
    ]),
  ]);
  return encode([version, leaseExpiry, logGroups]);
}
```

### Example ranger decoder (Go)

```go path=null start=null
import "github.com/fxamacker/cbor/v2"

const PullResponseVersion = 1

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
    Extra0      []byte
    Extra1      []byte
    Extra2      []byte
    Extra3      []byte
}

func decodePullResponse(data []byte) (*PullResponse, error) {
    var raw []any
    if err := cbor.Unmarshal(data, &raw); err != nil {
        return nil, err
    }

    resp := &PullResponse{
        Version:     toUint(raw[0]),
        LeaseExpiry: raw[1].(uint64),
    }

    groupsRaw := raw[2].([]any)
    resp.LogGroups = make([]LogGroup, len(groupsRaw))
    for i, g := range groupsRaw {
        arr := g.([]any)
        group := LogGroup{
            LogId: arr[0].([]byte),
            SeqLo: arr[1].(uint64),
            SeqHi: arr[2].(uint64),
        }

        entriesRaw := arr[3].([]any)
        group.Entries = make([]Entry, len(entriesRaw))
        for j, e := range entriesRaw {
            ea := e.([]any)
            group.Entries[j] = Entry{
                ContentHash: ea[0].([]byte),
                Extra0:      toByteOrNil(ea[1]),
                Extra1:      toByteOrNil(ea[2]),
                Extra2:      toByteOrNil(ea[3]),
                Extra3:      toByteOrNil(ea[4]),
            }
        }
        resp.LogGroups[i] = group
    }
    return resp, nil
}
```

### Ranger processing with grouped response

```go path=null start=null
func (r *Ranger) pollCycle(ctx context.Context) error {
    resp, err := r.pullFromDO(ctx, r.pollerId, r.batchSize, r.visibility)
    if err != nil {
        return err
    }
    if len(resp.LogGroups) == 0 {
        return nil
    }

    // Process each log group directly (no client-side grouping needed).
    for _, group := range resp.LogGroups {
        committed, err := r.commitBatch(ctx, group.LogId, group.Entries)
        if err != nil {
            r.logger.Warn("batch commit failed",
                "logId", hex.EncodeToString(group.LogId), "error", err)
            continue
        }

        // Ack the committed range using seqLo/seqHi from response.
        if committed == len(group.Entries) {
            // Full batch committed.
            if err := r.ackRange(ctx, group.LogId, group.SeqLo, group.SeqHi); err != nil {
                r.logger.Warn("ack failed", "error", err)
            }
        } else if committed > 0 {
            // Partial commit: ack seqLo to seqLo + committed - 1.
            ackHi := group.SeqLo + uint64(committed) - 1
            if err := r.ackRange(ctx, group.LogId, group.SeqLo, ackHi); err != nil {
                r.logger.Warn("ack failed", "error", err)
            }
        }
    }

    return nil
}
```

---

# Part 3: Integrated final design

This section presents the complete design based on the decisions in
the related ADRs:

- Single global DO ([ADR-0001](adr-0001-cf-do-ingress-single-do-architecture.md))
- Consistent hashing for log assignment ([ADR-0002](adr-0002-cf-do-ingress-consistent-hashing.md))
- Range-based acknowledgement ([ADR-0003](adr-0003-cf-do-ingress-range-ack.md))
- Fixed visibility timeout ([ADR-0004](adr-0004-cf-do-ingress-fixed-visibility-timeout.md))
- CBOR encoding for pull interface ([ADR-0005](adr-0005-cf-do-ingress-pull-encoding.md))

## 3.1 Architecture overview

```
┌─────────────┐      POST /logs/{logId}/entries
│   Client    │ ─────────────────────────────────────────────┐
└─────────────┘                                          │
                                                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                        canopy-api worker                        │
│                                                                 │
│  • Validates COSE payload                                       │
│  • Computes contentHash = SHA256(payload)                       │
│  • Calls SequencingQueue.enqueue(logId, contentHash, extras)   │
│  • Returns 303 See Other to /logs/{logId}/entries/{contentHash} │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 │ RPC / fetch
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                   SequencingQueue Durable Object                │
│                                                                 │
│  • Single global DO (ADR-0001)                                  │
│  • SQLite: queue_entries, dead_letters                          │
│  • Methods: enqueue, pull, ackRange, stats                      │
│  • Tracks active pollers for horizontal scaling                 │
│  • Assigns logs via consistent hashing (ADR-0002)               │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 │ HTTP pull (from GCP)
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ranger service (GCP / K8s)                   │
│                                                                 │
│  • Stateless; each instance has a pollerId                      │
│  • Polls SequencingQueue with pollerId, batchSize, visibilityMs │
│  • Receives entries for assigned logs                          │
│  • For each log batch: commit to massif, ackRange (ADR-0003)    │
│  • Scales horizontally via K8s HPA                              │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 │ Write massifs
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                        R2_MMRS bucket                           │
│                                                                 │
│  • v2/merklelog/massifs/{height}/{logId}/{index}.log            │
│  • v2/merklelog/checkpoints/{height}/{logId}/{index}.sth        │
│  • R2 notifications → sealer, ranger-cache, forester queues     │
└─────────────────────────────────────────────────────────────────┘
```

## 3.2 Schema

```sql path=null start=null
-- Main queue table.
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

-- Dead letter table.
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

## 3.3 HTTP API

### Ingress (canopy-api internal, not exposed to ranger)

Not an HTTP endpoint; canopy-api calls the DO via RPC:

```typescript path=null start=null
await queueStub.enqueue(logId, contentHash, { extra0, extra1, ... });
```

### Consumer (exposed to ranger)

**POST /queue/pull**

Request:

```json path=null start=null
{
  "pollerId": "ranger-abc123",
  "batchSize": 100,
  "visibilityMs": 30000
}
```

Response:

```json path=null start=null
{
  "entries": [
    {
      "seq": 42,
      "logId": "<hex>",
      "contentHash": "<hex>",
      "extra0": "<hex or null>",
      "extra1": "<hex or null>",
      "extra2": "<hex or null>",
      "extra3": "<hex or null>",
      "attempts": 1
    }
  ],
  "leaseExpiry": 1703779200000,
  "assignedLogs": ["<logId hex>", ...]
}
```

**POST /queue/ack**

Request:

```json path=null start=null
{
  "logId": "<hex>",
  "fromSeq": 42,
  "toSeq": 50
}
```

Response:

```json path=null start=null
{
  "deleted": 9
}
```

**GET /queue/stats**

Response:

```json path=null start=null
{
  "pending": 1234,
  "deadLetters": 5,
  "oldestEntryAge": 45000,
  "attemptDistribution": { "0": 1000, "1": 200, "2": 34 },
  "activePollers": 3,
  "logsWithWork": 17
}
```

## 3.4 Ranger flow

1. On startup, generate `pollerId = uuid.New()`.
2. Poll loop:
   a. POST `/queue/pull` with `pollerId`, `batchSize`, `visibilityMs`.
   b. If empty, back off exponentially (up to 5s).
   c. If non-empty, reset backoff.
   d. Group entries by `logId`.
   e. For each log:
      - Call `commitBatch(logId, entries)` → writes to R2_MMRS.
      - On success, POST `/queue/ack` with `logId`, `fromSeq`, `toSeq`.
      - On failure, log error; entries will redeliver.
3. On shutdown, stop polling; leased entries redeliver after timeout.

## 3.5 Fairness

The DO's pull implementation ensures fairness:

- Identifies all logs with available entries.
- Assigns logs to the requesting poller via consistent hashing.
- Pulls a limited number of entries from each assigned log
  (round-robin within the batch).

This prevents a single hot log from monopolising a ranger instance.

## 3.6 Rate limiting

Per-log rate limiting in the DO:

```typescript path=null start=null
private logEnqueueCounts: Map<string, number[]> = new Map();
private readonly MAX_RATE_PER_LOG = 1000;
private readonly RATE_WINDOW_MS = 1000;

async enqueue(logId: ArrayBuffer, ...): Promise<{ seq: number }> {
  const logIdHex = bufferToHex(logId);
  const now = Date.now();

  let timestamps = this.logEnqueueCounts.get(logIdHex) ?? [];
  timestamps = timestamps.filter((t) => t > now - this.RATE_WINDOW_MS);

  if (timestamps.length >= this.MAX_RATE_PER_LOG) {
    throw new Error("rate limit exceeded for log");
  }

  timestamps.push(now);
  this.logEnqueueCounts.set(logIdHex, timestamps);

  // ... rest of enqueue ...
}
```

## 3.7 Migration path

1. Implement and deploy `SequencingQueue` DO.
2. Update `canopy-api` to enqueue to the DO instead of writing to
   `R2_LEAVES`.
3. Deploy new ranger version that polls the DO instead of Cloudflare
   Queues.
4. Disable R2 event notifications for `R2_LEAVES`.
5. Delete `R2_LEAVES` bucket and `{CANOPY_ID}-ranger` queue.
6. Remove scheduled cleanup cron for expired leaves.

## 3.8 Open questions

1. **Backpressure threshold**: what value for `MAX_PENDING`? Depends on
   expected peak ingress and acceptable latency.

2. **Poller timeout**: how long before a silent ranger is considered
   dead? 60s is reasonable; tune based on observed network conditions.

3. **Max attempts before DLQ**: 5 is typical; adjust based on observed
   transient failure rates.

4. **Stats retention**: should the DO track throughput history for
   dashboards? Consider Cloudflare Analytics Engine for time-series.

5. **Multi-region**: if rangers run in multiple regions, should there
   be one global DO or one per region? Single global DO is simpler;
   latency from distant rangers is acceptable for polling.

---

# Appendix: Full schema

```sql path=null start=null
-- Main queue table.
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

-- Dead letter table.
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
