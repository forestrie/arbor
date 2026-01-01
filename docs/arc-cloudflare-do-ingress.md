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
3. **Integrated design** — the complete design synthesising all parts,
   including ack-on-commit reliability analysis (section 3.8) and
   future directions for deduplication improvements (section 3.10).

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
processing. This section describes common ack patterns; the actual
implemented approach for Forestrie is in section 2.3.

### Conceptual patterns (not implemented)

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

Range-based ack (assumes contiguous seq values per-log):

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

Range ack is efficient when the consumer processes entries in order
and the seq values are contiguous within each log. However, **this
approach does not work when seq values are allocated globally** because
entries for a single log will have non-contiguous seq values.

### Implemented approach: limit-based ack

For Forestrie, seq is allocated globally across all logs, making per-log
seq values non-contiguous. The implemented solution is `ackFirst` which
deletes the first N entries by seq order for a given log. See section 2.3
for the full design and rationale.

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

## 2.3 Batch commit and limit-based ack

ranger's natural processing unit is a contiguous batch of entries for
a single log, committed together to a massif. See
[ADR-0003](adr-0003-cf-do-ingress-range-ack.md) for the original range-based
ack rationale.

### Non-contiguous sequence numbers

The DO allocates sequence numbers globally across all logs. When ranger
pulls entries for a specific log, those entries have **non-contiguous**
seq values because entries for other logs were interleaved:

```
Global sequence:  1   2   3   4   5   6   7   8   9  10  11  12
Log A entries:    *           *       *               *
Log B entries:        *   *       *       *   *   *       *
```

A pull for Log A might return entries with seq [1, 4, 6, 10], not [1, 2, 3, 4].

### Why range-based ack doesn't work for partial commits

The pull response provides `seqLo` and `seqHi` (first and last seq values)
but not per-entry seq. If ranger commits only some entries, it cannot
compute the exact seq value to ack up to:

- Pull returns: `seqLo=1, seqHi=10, entries=[e0, e1, e2, e3]`
- Actual seq values: e0=1, e1=4, e2=6, e3=10 (not known to ranger)
- Ranger commits e0, e1 (2 entries) but fails on e2
- Cannot compute ackHi: `seqLo + 2 - 1 = 2` is wrong (should be 4)

### Solution: limit-based ack

Instead of `ackRange(logId, fromSeq, toSeq)`, use `ackFirst(logId, seqLo, limit)`:

```typescript path=null start=null
async ackFirst(
  logId: ArrayBuffer,
  seqLo: number,
  limit: number,
): Promise<{ deleted: number }> {
  this.ensureSchema();
  await this.loadState();

  // Find the first N entries for this log starting from seqLo.
  const toDelete = this.ctx.storage.sql
    .exec<{ seq: number }>(
      `SELECT seq FROM queue_entries
       WHERE log_id = ? AND seq >= ?
       ORDER BY seq ASC
       LIMIT ?`,
      logId,
      seqLo,
      limit,
    )
    .toArray()
    .map((r) => r.seq);

  if (toDelete.length === 0) {
    return { deleted: 0 };
  }

  const result = this.ctx.storage.sql.exec(
    `DELETE FROM queue_entries
     WHERE seq IN (${toDelete.map(() => "?").join(",")})`,
    ...toDelete,
  );

  this.pendingCount! -= result.rowsWritten;
  return { deleted: result.rowsWritten };
}
```

Ranger call:

```go path=null start=null
func (r *Ranger) processLogGroup(ctx context.Context, group LogGroup) {
    committed, err := r.commitBatch(ctx, group.LogId, group.Entries)
    if err != nil {
        // Don't ack; entries will redeliver after visibility timeout.
        return
    }

    if committed == 0 {
        return
    }

    // Ack the first N committed entries starting from seqLo.
    // The DO will delete exactly the entries that were pulled and committed.
    if err := r.ackFirst(ctx, group.LogId, group.SeqLo, committed); err != nil {
        r.logger.Warn("ack failed", "error", err)
    }
}
```

### Correctness guarantee

The limit-based ack is correct because:

1. Pull returns entries ordered by seq ASC for that log.
2. Ranger commits entries in the same order.
3. Ack deletes the first N entries (by seq order) for that log starting
   from seqLo.
4. These are exactly the same entries that were pulled and committed.

### Wire format update

The ack request body changes from `{logId, fromSeq, toSeq}` to
`{logId, seqLo, limit}`:

```
AckRequest: [logId (bytes), seqLo (uint64), limit (uint64)]
```

Benefits:

- Single HTTP call to ack an entire batch.
- Works correctly with non-contiguous seq values.
- No per-entry seq needed in pull response (wire format remains compact).
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
  - Body: `{ logId: bytes, seqLo: number, limit: number }`
  - Response: `{ deleted: number }`
  - See section 2.3 for limit-based ack rationale.

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
- If rangers do conflict (concurrent writes to same massif), ranger's
  ETag-based writes ensure one succeeds atomically; the "losing"
  ranger's entries redeliver after visibility timeout.

**Note**: ETag-based writes only protect against concurrent write
conflicts, not against duplicate entries from missed acks. See section
3.8 for ack-on-commit reliability analysis.

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
- **seqLo/seqHi**: Ranger uses seqLo as the starting point for limit-based ack.
  seqHi is informational (last seq pulled). Individual seq values are not
  needed because entries are processed in order. See section 2.3 for why
  limit-based ack is required (non-contiguous global seq allocation).
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

        // Ack committed entries using limit-based ack.
        // See section 2.3 for why limit-based ack is required.
        if committed > 0 {
            if err := r.ackFirst(ctx, group.LogId, group.SeqLo, committed); err != nil {
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
- Limit-based acknowledgement ([ADR-0003](adr-0003-cf-do-ingress-range-ack.md))
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
│  • Methods: enqueue, pull, ackFirst, stats                      │
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
│  • For each log batch: commit to massif, ackFirst (ADR-0003)    │
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
│  • R2 notifications → sealer and ranger-cache queues            │
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
      - On success, POST `/queue/ack` with `logId`, `seqLo`, `limit`
        (see section 2.3 for limit-based ack).
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

## 3.8 Ack-on-commit reliability

Ranger's natural processing model is: pull entries, commit to massif, ack
the committed range. This section analyses the reliability implications.

### Position-based acknowledgement

The pull response groups entries by logId with `seqLo` and `seqHi`:

```
LogGroup {
  logId: bytes
  seqLo: uint64   // seq of first entry
  seqHi: uint64   // seq of last entry
  entries: [...]  // no per-entry seq
}
```

Entries within a LogGroup are ordered by seq ASC (guaranteed by the DO's
query) but **not contiguous** because seq is allocated globally across all
logs (see section 2.3). This requires limit-based ack:

```go
committedCount := r.commitBatch(group.Entries)
if committedCount > 0 {
    r.ackFirst(group.LogId, group.SeqLo, committedCount)
}
```

### Failure modes

**Ack succeeds after commit**: Normal path. Entries are deleted from the
queue. No duplicates.

**Ack fails after commit (network error, ranger crash)**: Entries remain in
the queue and redeliver after visibility timeout. Ranger will re-process
entries that were already committed to the massif.

**Partial commit**: If ranger commits entries 0-2 of a batch but fails on
entry 3, it acks with `limit=3`. Entries 3+ remain and redeliver.

### Duplicate commit risk

Unlike the previous Cloudflare Queue model where each message had its own
ack, the DO queue uses limit-based batch ack (see section 2.3). A single
missed ack can cause an entire batch of already-committed entries to
redeliver and be re-committed.

**Important**: Ranger's ETag-based conditional writes do **not** prevent
duplicate commits in this scenario. ETags ensure atomic massif updates but
do not deduplicate individual entries within a commit.

**Accepted risk**: A missed ack after successful commit will cause duplicate
entries in the massif. This is accepted for the initial implementation
because:

1. The probability is low (requires crash/failure in narrow window between
   commit completion and ack completion).
2. Duplicates are detectable (same content hash appears multiple times).
3. Multiple viable mitigation paths exist (see section 3.10).

### Comparison with previous model

| Aspect | CF Queue (per-message ack) | DO Queue (limit ack) |
|--------|---------------------------|---------------------|
| Normal path | Message deleted | Batch deleted |
| Missed ack | Single entry redelivers | Entire batch redelivers |
| Duplicate risk | One entry | Batch of entries |
| Recovery | Re-process one entry | Re-process batch |

The DO queue trades slightly higher duplicate risk for simpler semantics
and better performance (one ack call per log group vs one per entry).

## 3.9 Open questions

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

## 3.10 Future directions

This section documents potential enhancements to address the duplicate
commit risk and improve system robustness. These are not planned for
initial implementation but provide a clear path forward.

### 3.10.1 Bloom filter deduplication at commit time

The massif format includes a bloom filter over extra fields. This can be
leveraged to detect likely duplicates before committing.

**Approach**: Before committing an entry, check the massif's bloom filter.
If the entry's extra fields match, it's *probably* a duplicate. Either skip
it or perform a full scan to confirm.

**Value**: High. Reduces duplicate commits to near-zero false negatives
(bloom filter FP rate) without fundamental architecture changes.

**Viability**: High. Bloom filter already exists in massif format. Ranger
already reads massifs.

**Complexity**: Low-medium. Requires bloom filter query logic in ranger
commit path. May need to handle edge case where entry crosses massif
boundary.

### 3.10.2 Attempt-aware deduplication

Only perform deduplication checks on redelivered entries (attempt > 1).

**Approach**: Include `attempts` count in pull response. Ranger skips bloom
filter check for attempt=1 entries (first delivery, can't be duplicates).
For attempt > 1, perform bloom filter or full deduplication scan.

**Value**: Medium. Optimises the common case (first delivery) while
providing protection on redelivery.

**Viability**: High. `attempts` is already tracked in the DO schema.

**Complexity**: Low. Add `attempts` to pull response wire format. Conditional
logic in ranger.

### 3.10.3 Configurable deduplication mode per log

Allow logs to opt into stronger deduplication guarantees.

**Approach**: Store per-log configuration in massif start record or separate
config store. Options:
- `none`: No deduplication (current behavior)
- `bloom`: Bloom filter check on all entries
- `strict`: Full scan for entries with matching bloom signature

**Value**: Medium. Allows high-value logs to trade throughput for
guarantees.

**Viability**: Medium. Requires per-log config infrastructure.

**Complexity**: Medium. Config storage, per-log branching in commit path.

### 3.10.4 DO-allocated pre-sequence identifiers

Have the DO allocate a unique identifier for each pending entry, similar to
Snowflake IDs.

**Approach**: On enqueue, DO generates a globally unique pre-sequence ID
(e.g., timestamp + DO instance + counter). This ID is returned in pull
response. Ranger stores committed pre-sequence IDs in massif metadata or
separate index. On redelivery, ranger checks if pre-sequence ID was already
committed.

**Value**: High. Provides definitive duplicate detection without bloom
filter false positives.

**Viability**: High. DO already assigns seq numbers; extending to include
timestamp component is straightforward.

**Complexity**: Medium. Requires:
- Schema change to store pre-sequence ID
- Pull response format change
- Committed ID tracking in ranger (new storage requirement)

### 3.10.5 Direct registration status from DO

Allow `query-registration-status` to check the SequencingQueue DO directly
for pending entries, making `ranger-cache` redundant for this use case.

**Approach**: canopy-api queries the DO to check if a contentHash is still
pending sequencing. If found in queue, return "pending". If not in queue,
fall back to R2_MMRS lookup for sequenced entries.

**Value**: High. Simplifies architecture by removing ranger-cache
dependency for pre-sequence status. Provides real-time visibility into
queue state.

**Viability**: High. DO already has the data. Query is a simple lookup.

**Complexity**: Low. Add lookup method to DO. Update canopy-api handler.
Consider index on `content_hash` for efficient lookup.

**Note**: This doesn't eliminate ranger-cache entirely (it still serves
sequenced entry lookup), but reduces its criticality and simplifies the
pre-sequence flow.

## 3.11 Authentication

_This section is a placeholder for future authentication design._

The pull/ack HTTP endpoints currently have no authentication. Ranger sends
an `Authorization: Bearer <token>` header which forestrie-ingress does not
validate.

Future work should add bearer token validation:
- Add `QUEUE_AUTH_TOKEN` secret to forestrie-ingress worker environment
- Validate `Authorization` header against secret in pull/ack handlers
- Return 401 Unauthorized for invalid or missing tokens

## 3.12 Return path unification

This section describes how to eliminate the ranger-cache dependency for
registration status queries, reducing latency and simplifying the return path.

### 3.12.1 Problem statement

Currently, `query-registration-status` relies on ranger-cache to determine
when sequencing is complete. This adds latency because:

1. Ranger commits entries to a massif
2. Ranger writes a checkpoint to R2
3. R2 notification triggers ranger-cache update
4. canopy-api polls ranger-cache until the entry appears

The ranger-cache path adds 100-500ms latency after commit. We can eliminate
this by having the DO track sequencing results directly.

### 3.12.2 Schema changes

Add two nullable columns to `queue_entries` for storing sequencing results:

```sql
ALTER TABLE queue_entries ADD COLUMN leaf_index INTEGER DEFAULT NULL;
ALTER TABLE queue_entries ADD COLUMN massif_index INTEGER DEFAULT NULL;
```

These columns are NULL on enqueue and populated on ack. The key insight is
that **entries are retained after sequencing** (not deleted) to serve as
the sequencing result cache. This unifies the pending queue and result cache
into a single table.

- `leaf_index IS NULL` → entry is pending/unsequenced
- `leaf_index IS NOT NULL` → entry is sequenced (available for lookup)

Add indexes for the new query patterns:

```sql
-- For resolveContent lookups by content hash
CREATE INDEX IF NOT EXISTS idx_content_hash
  ON queue_entries (content_hash);

-- For cleanup queries (sequenced entries per log)
CREATE INDEX IF NOT EXISTS idx_log_leaf
  ON queue_entries (log_id, leaf_index) WHERE leaf_index IS NOT NULL;
```

### 3.12.3 Updated ackFirst signature

The `ackFirst` method now requires sequencing metadata from ranger, including
`massifHeight` for cleanup calculations:

```typescript
async ackFirst(
  logId: ArrayBuffer,
  seqLo: number,
  limit: number,
  firstLeafIndex: number,
  massifIndex: number,
  massifHeight: number,
): Promise<{ acked: number }>
```

The implementation uses `UPDATE FROM` with a window function to compute
leaf indices efficiently, then cleans up old sequenced entries:

```typescript
async ackFirst(
  logId: ArrayBuffer,
  seqLo: number,
  limit: number,
  firstLeafIndex: number,
  massifIndex: number,
  massifHeight: number,
): Promise<{ acked: number }> {
  this.ensureSchema();

  if (limit <= 0) {
    return { acked: 0 };
  }

  // Update entries with sequencing results using UPDATE FROM + window function
  const result = this.ctx.storage.sql.exec(
    `UPDATE queue_entries
     SET 
       leaf_index = ? + ranked.offset,
       massif_index = ?,
       visible_after = NULL
     FROM (
       SELECT 
         seq,
         ROW_NUMBER() OVER (ORDER BY seq ASC) - 1 as offset
       FROM queue_entries
       WHERE log_id = ? AND seq >= ? AND leaf_index IS NULL
       ORDER BY seq ASC
       LIMIT ?
     ) as ranked
     WHERE queue_entries.seq = ranked.seq`,
    firstLeafIndex,
    massifIndex,
    logId,
    seqLo,
    limit,
  );

  const acked = result.rowsWritten;

  if (acked > 0) {
    this.pendingCount = Math.max(0, this.pendingCount - acked);

    // Cleanup: retain ~2 massifs worth of sequenced entries per log
    const leavesPerMassif = 1 << massifHeight;
    const retainCount = leavesPerMassif * 2;

    this.ctx.storage.sql.exec(
      `DELETE FROM queue_entries
       WHERE log_id = ?
         AND leaf_index IS NOT NULL
         AND leaf_index < (
           SELECT COALESCE(MAX(leaf_index), 0) - ?
           FROM queue_entries
           WHERE log_id = ? AND leaf_index IS NOT NULL
         )`,
      logId,
      retainCount,
      logId,
    );
  }

  return { acked };
}
```

Key implementation details:

- `ROW_NUMBER() OVER (ORDER BY seq ASC) - 1` produces 0-based offsets
- `UPDATE FROM` with derived table is SQLite 3.33+ syntax
- Cleanup retains `2 * 2^massifHeight` entries (~32K for height 14)
- Entries are updated in-place, not deleted then re-inserted

### 3.12.4 Ranger ack update

Ranger's ack call must now include the sequencing results:

```go
type AckRequest struct {
    LogId          []byte
    SeqLo          uint64
    Limit          uint64
    FirstLeafIndex uint64  // leaf index of first entry in batch
    MassifIndex    uint64  // massif containing all entries
    MassifHeight   uint64  // for cleanup calculation
}

func (r *Ranger) ackFirst(
    ctx context.Context,
    logId []byte,
    seqLo uint64,
    limit int,
    firstLeafIndex uint64,
    massifIndex uint64,
    massifHeight uint64,
) error {
    req := AckRequest{
        LogId:          logId,
        SeqLo:          seqLo,
        Limit:          uint64(limit),
        FirstLeafIndex: firstLeafIndex,
        MassifIndex:    massifIndex,
        MassifHeight:   massifHeight,
    }
    // ... send request ...
}
```

The committer must return the first leaf index and massif index for the
batch so ranger can pass them to ack.

### 3.12.5 resolveContent method

New DO RPC method for canopy-api to query sequencing status:

```typescript
interface SequencingResult {
  leafIndex: number;
  massifIndex: number;
}

async resolveContent(
  contentHash: ArrayBuffer,
): Promise<SequencingResult | null> {
  this.ensureSchema();

  // First check sequenced_entries (completed entries)
  const sequenced = this.ctx.storage.sql
    .exec<{ leaf_index: number; massif_index: number }>(
      `SELECT leaf_index, massif_index FROM sequenced_entries
       WHERE content_hash = ?`,
      contentHash,
    )
    .toArray();

  if (sequenced.length > 0) {
    return {
      leafIndex: sequenced[0].leaf_index,
      massifIndex: sequenced[0].massif_index,
    };
  }

  // Entry is either still pending or unknown
  return null;
}
```

This requires an index on `content_hash` in `sequenced_entries` (already
the PRIMARY KEY).

### 3.12.6 Updated query-registration-status

canopy-api's `queryRegistrationStatus` handler changes:

```typescript
export async function queryRegistrationStatus(
  request: Request,
  entrySegments: string[],
  sequencingQueueNs: SequencingQueueNamespace,
  r2Mmrs: R2Bucket,
  massifHeight: number,
): Promise<Response> {
  const [logID, _, contentHashRaw] = entrySegments;
  const contentHash = contentHashRaw.toLowerCase();
  const contentHashBytes = hexToBuffer(contentHash);

  // Query the DO for sequencing result
  const doId = sequencingQueueNs.idFromName("global");
  const stub = sequencingQueueNs.get(doId);
  const result = await stub.resolveContent(contentHashBytes);

  if (!result) {
    // Still pending or unknown - return 303 with retry
    const requestUrl = new URL(request.url);
    const currentLocation = `${requestUrl.origin}${requestUrl.pathname}`;
    return seeOtherResponse(currentLocation, 1); // Short retry for fast polling
  }

  // Sequencing complete - read massif to get idtimestamp
  const idtimestamp = await getIdtimestampFromMassif(
    r2Mmrs,
    logID,
    massifHeight,
    result.massifIndex,
    result.leafIndex,
  );

  const entryId = encodeEntryId({
    idtimestamp,
    mmrIndex: leafIndexToMmrIndex(result.leafIndex),
  });

  const requestUrl = new URL(request.url);
  const permanentLocation = `${requestUrl.origin}/logs/${logID}/${massifHeight}/entries/${entryId}/receipt`;
  return seeOtherResponse(permanentLocation);
}
```

### 3.12.7 Massif reading helper

A helper function in the merklelog package reads the idtimestamp from a
massif's leaf entry:

```typescript
// In @canopy/merklelog or similar
export async function getIdtimestampFromMassif(
  r2: R2Bucket,
  logId: string,
  massifHeight: number,
  massifIndex: number,
  leafIndex: number,
): Promise<bigint> {
  const objectKey = `v2/merklelog/massifs/${massifHeight}/${logId}/${massifIndex.toString().padStart(16, "0")}.log`;

  const object = await r2.get(objectKey);
  if (!object) {
    throw new Error(`Massif not found: ${objectKey}`);
  }

  const data = await object.arrayBuffer();
  const massif = parseMassif(data);

  // Get the leaf entry at the given index
  const leafOffset = massifLeafOffset(massifHeight, leafIndex);
  const idtimestamp = readIdtimestamp(massif, leafOffset);

  return idtimestamp;
}
```

### 3.12.8 Garbage collection

Cleanup is integrated into `ackFirst` and runs on every ack. Each log
retains approximately `2 * 2^massifHeight` sequenced entries (about 2
massifs worth for typical queries). This provides:

- Bounded storage per log (~32K entries for height 14)
- Recent entries always available for status queries
- No separate cleanup job or alarm needed

The cleanup query in ackFirst:

```sql
DELETE FROM queue_entries
WHERE log_id = ?
  AND leaf_index IS NOT NULL
  AND leaf_index < (
    SELECT COALESCE(MAX(leaf_index), 0) - ?
    FROM queue_entries
    WHERE log_id = ? AND leaf_index IS NOT NULL
  )
```

### 3.12.9 Benefits

- **Reduced latency**: Registration status available immediately after commit,
  without waiting for checkpoint or ranger-cache.
- **Simplified architecture**: Removes ranger-cache from the critical path for
  status queries.
- **Single source of truth**: The DO has complete visibility into both pending
  and recently-sequenced entries.

### 3.12.10 Trade-offs

- **Storage growth**: Bounded per-log (~32K entries for height 14), cleaned
  up on each ack.
- **R2 read on status query**: Reading the massif adds latency (~50-100ms),
  but this is only on the final redirect (not during polling).
- **Ack wire format change**: Requires ranger update to send leaf/massif/height.

### 3.12.11 Latency analysis

The unified design eliminates ~350-750ms from the return path:

| Component | Current (ranger-cache) | Unified DO |
|-----------|----------------------|------------|
| Checkpoint write | ~200ms | Not on critical path |
| R2 notification | ~100-500ms | Eliminated |
| ranger-cache query | ~50ms | Eliminated |
| DO resolveContent | N/A | ~20ms |

The remaining latency bottlenecks (not addressed here) are:
- Ranger poll interval (50ms-2s with backoff)
- R2 commit latency (~500-800ms)

### 3.12.12 Future latency improvements

Two approaches could further reduce end-to-end latency:

**1. Push-based ranger notification**

Replace polling with WebSocket or Server-Sent Events from the DO to ranger.
When entries are enqueued, the DO pushes a notification to connected rangers.
This eliminates poll interval latency entirely.

Complexity: Medium. Requires WebSocket support in DO (available) and
connection management in ranger. Must handle reconnection and missed messages.

**2. Cross-log commit batching**

Batch R2 writes across multiple logs to amortize per-request overhead.
Ranger accumulates entries from multiple logs and commits them in a single
R2 write operation.

Complexity: Medium-high. Requires careful handling of partial failures
and per-log ack granularity. May conflict with per-log massif isolation.

---

# Part 4: Post-implementation performance testing

This section documents smoke test results from the deployed DO-based ingress
queue, measuring end-to-end throughput and sequencing latency.

## 4.1 Test methodology

Smoke tests are implemented in `canopy/taskfiles/scrapi.yml` as `smoke:N` tasks
where N is the number of statements. Each test:

1. POSTs N statements in parallel (background jobs with `wait`)
2. Polls all status URLs in parallel until sequenced
3. Reports POST time, total time, and throughput (stmt/s)

**Methodology limitations:**

- **Burst ingress**: All statements are POSTed as fast as possible, creating
  a burst rather than sustained load. This means ranger batches drain faster
  than they fill, resulting in smaller batch sizes than would occur under
  sustained ingress.
- **Single log**: All statements go to a single log, eliminating parallelism
  benefits from multiple rangers processing different logs.
- **Client-side measurement**: Total time includes client→Cloudflare→GCP
  network latency for each poll, not just system processing time.
- **Poll overhead**: The parallel polling phase adds ~1s minimum (poll interval
  + network round trips) even when entries are already sequenced.

## 4.2 Sequencing latency (DO-measured)

The DO records `enqueued_at` and `acked_at` timestamps, enabling precise
measurement of sequencing latency independent of client polling.

**Results from 500-entry batch (2024-12-28):**

| Metric | Value |
|--------|-------|
| Min | 605ms |
| p50 | 1,077ms |
| p95 | 1,532ms |
| p99 | 1,714ms |
| Max | 1,819ms |
| Avg | 1,081ms |

The ~1s p50 latency is dominated by R2 read/modify/write cycle time for
massif commits. This is the fundamental floor for single-entry latency.

## 4.3 Client-side throughput results

**Configuration:**
- Single ranger instance (GKE)
- QUEUE_BATCH_SIZE=100
- POLL_INTERVAL_MIN=0ms, POLL_INTERVAL_MAX=2s
- MASSIF_HEIGHT=14

| Statements | POST Time | Total Time | Throughput |
|------------|-----------|------------|------------|
| 3 | 461ms | 2,141ms | 1.4 stmt/s |
| 5 | 405ms | 2,148ms | 2.3 stmt/s |
| 10 | 1,464ms | 3,188ms | 3.1 stmt/s |
| 25 | 3,729ms | 6,346ms | 3.9 stmt/s |
| 50 | 4,195ms | 7,117ms | 7.0 stmt/s |
| 75 | 5,644ms | 8,869ms | 8.4 stmt/s |
| 100 | 6,839ms | 11,544ms | 8.6 stmt/s |
| 150 | 7,939ms | 14,379ms | 10.4 stmt/s |
| 500 | 30,387ms | 56,472ms | 8.8 stmt/s |

## 4.4 Analysis: batch fill rate limits throughput

The 500-statement test achieved only 8.8 stmt/s despite having entries
available. Ranger logs show the cause—small batch sizes:

```
22:54:52 committed count=14
22:54:53 committed count=17
22:54:54 committed count=13
22:54:55 committed count=21
22:54:56 committed count=16
22:54:57 committed count=22
22:54:58 committed count=6
...
22:55:03 committed count=2
```

Average batch size: ~12 entries (not 100).

**Why batches don't fill to 100:**

1. **Burst drains faster than it fills**: The 500 POSTs complete in ~30s.
   Each ranger commit cycle (~700ms) processes whatever has accumulated
   since the last pull. With entries arriving over 30s, batches never
   build up to 100.

2. **Tail effect**: As the burst completes, fewer entries remain, causing
   progressively smaller batches (count=6, 3, 2 at the end).

3. **Single log constraint**: All entries go to one log, so there's no
   parallelism benefit from multiple logs being processed concurrently.

## 4.5 Theoretical vs observed throughput

With the observed ~700ms R2 cycle time:

| Batch Size | Theoretical Max | Notes |
|------------|-----------------|-------|
| 12 (observed avg) | ~17 stmt/s | Matches ~8.8 stmt/s observed (with overhead) |
| 50 | ~71 stmt/s | Requires sustained 50/s ingress |
| 100 | ~143 stmt/s | Requires sustained 100/s ingress |

**Key insight**: To achieve 100 stmt/s throughput, the system needs sustained
ingress at or above 100 stmt/s so that each ranger pull returns a full batch
of 100 entries. The burst test methodology cannot demonstrate this because
entries arrive faster than they can be pulled but then stop.

## 4.6 Path to 100 stmt/s

Based on the testing, 100 stmt/s is achievable with:

1. **Sustained ingress**: Continuous load at 100+ stmt/s keeps batches full.
   This is the primary requirement.

2. **Current configuration is sufficient**: Single ranger with batch_size=100
   and ~700ms R2 cycle achieves ~143 stmt/s theoretical max.

3. **Multiple rangers (optional)**: For higher throughput or multiple active
   logs, scale rangers horizontally. The DO's consistent hashing distributes
   logs across pollers.

## 4.7 Recommendations for production load testing

To accurately measure sustained throughput:

1. **Use a load generator**: Tools like `wrk`, `vegeta`, or `k6` can sustain
   constant request rates over extended periods.

2. **Target rate, not count**: Configure the load generator for a target
   requests/second rather than total request count.

3. **Run for multiple minutes**: Allow the system to reach steady state where
   batch sizes stabilize.

4. **Monitor DO-side metrics**: Use the `/queue/debug/recent` endpoint to
   observe actual sequencing latency independent of client polling.

5. **Check ranger batch sizes**: Verify via logs that batches are filling
   to the expected size under sustained load.

---

# Part 5: Sustained-load testing with k6

This section describes a k6-based load testing approach that addresses the
limitations of the burst-oriented smoke tests documented in Part 4.

## 5.1 Motivation

Smoke tests are useful for sanity checks but cannot demonstrate steady-state
behavior because:

1. **Burst ingress**: All statements arrive as fast as the client can POST,
   then stop. Ranger batches drain faster than they fill.
2. **Per-request polling overhead**: Even with parallel polling, the test
   measures client→Cloudflare→GCP round trips, not system capacity.
3. **No rate control**: There is no way to hold ingress at a specific rate
   (e.g., exactly 100/s) for an extended period.

Sustained-load testing with k6 uses constant-arrival-rate executors to
maintain a precise request rate, allowing batches to fill and ranger to
reach steady-state throughput.

## 5.2 Target scenarios

Initial scenarios target a single log at these sustained rates:

| Scenario | Target Rate | Purpose |
|----------|-------------|----------|
| write-10ps | 10 stmt/s | Baseline; batches small but predictable |
| write-100ps | 100 stmt/s | Target throughput; batches should fill to 100 |
| write-150ps | 150 stmt/s | Exceed single-ranger capacity (~143 stmt/s) |
| write-300ps | 300 stmt/s | Stress test; observe backpressure behavior |

Each scenario runs for 3-5 minutes after a 30-60s warmup ramp to avoid
cold-start skew.

## 5.3 Configuration

Tests are configured via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| K6_CANOPY_BASE_URL | canopy-api base URL | (required) |
| K6_API_TOKEN | Bearer token for Authorization header | (required) |
| K6_MSG_BYTES | Payload size in bytes | 64 |
| K6_SAMPLE_RATE | Fraction of POSTs polled to completion | 0.01 |
| K6_STAGE_DURATION | Duration of steady-state stage | 3m |
| K6_WARMUP_DURATION | Duration of warmup ramp | 30s |

## 5.4 CBOR/COSE encoding challenges

k6 runs in a goja (Go-based) JavaScript runtime that lacks Node.js Buffer
and npm ecosystem access. The SCRAPI /entries endpoint requires COSE Sign1
payloads encoded as CBOR.

**Mitigation**: Implement minimal CBOR/COSE helpers in pure JavaScript using
TypedArrays (Uint8Array, ArrayBuffer, TextEncoder):

- `cbor.js`: Encode major types 0 (uint), 2 (bstr), 4 (array), 5 (map).
- `cose.js`: Encode COSE Sign1 structure `[protected, unprotected, payload, sig]`
  with empty protected/unprotected/signature (same as smoke test generator).

These helpers live in `canopy/perf/k6/canopy-api/lib/` and are imported by
scenario scripts.

**Alternative**: Pre-generate COSE payloads of various sizes and bundle them
as base64 in the script, decoding at runtime. This trades flexibility for
simplicity if dynamic payload generation proves problematic.

## 5.5 Async polling strategy

The SCRAPI registration flow is asynchronous:
1. POST /entries → 303 See Other with status URL
2. Poll status URL until Location header points to /receipt
3. (Optional) GET receipt

Blocking on every poll would distort arrival rate and exhaust VUs.

**Strategy**: Sample-based polling

1. For each POST, with probability K6_SAMPLE_RATE (default 1%), record the
   status URL and POST timestamp.
2. A separate k6 scenario (`poller`) with limited VUs (e.g., 5) consumes
   sampled URLs from a shared array and polls until sequenced.
3. Emit custom metric `e2e_latency_sampled` (POST timestamp → receipt observed).
4. The main writer scenario is unaffected by polling latency.

**Optional enhancement**: Periodically query `/queue/debug/recent` to extract
DO-measured `sequencingLatencyMs` percentiles and emit as custom metrics.
This provides ground-truth latency without any client polling overhead.

## 5.6 Metrics and thresholds

**Core metrics:**

| Metric | Description |
|--------|-------------|
| http_req_duration | POST /entries latency (k6 built-in) |
| http_req_failed | Error rate (k6 built-in) |
| e2e_latency_sampled | Time from POST to receipt URL (sampled) |
| sequencing_latency_p50 | DO-measured p50 (from debug endpoint) |
| sequencing_latency_p95 | DO-measured p95 (from debug endpoint) |

**Initial thresholds (non-blocking):**

```javascript
thresholds: {
  http_req_failed: ['rate<0.01'],         // <1% error rate
  http_req_duration: ['p(95)<1000'],      // p95 POST latency <1s
  e2e_latency_sampled: ['p(95)<5000'],    // p95 e2e <5s (includes poll)
}
```

Thresholds will be tightened as baseline data is collected.

## 5.7 Directory layout

```
canopy/
  perf/
    k6/
      canopy-api/
        lib/
          cbor.js           # Minimal CBOR encoder
          cose.js           # COSE Sign1 encoder
          http.js           # POST helpers, 303 parsing
        scenarios/
          write-constant-arrival.js   # Single-rate scenario
          write-sweep.js              # Multi-rate sweep
        README.md           # Usage instructions
```

## 5.8 Running tests

**Local (single rate):**

```bash
K6_CANOPY_BASE_URL=https://canopy-api.example.workers.dev \
K6_API_TOKEN=your-token \
k6 run --env RATE=100 perf/k6/canopy-api/scenarios/write-constant-arrival.js
```

**Task runner:**

```bash
task perf:k6:write:rate RATE=100 DURATION=3m
task perf:k6:write:sweep RATES="10,100,150,300" DURATION=3m
```

**CI (GitHub Actions):**

Workflow `perf-canopy.yml` runs matrix jobs for each target rate, using
secrets for API tokens. Initial runs are non-blocking; thresholds are
added incrementally as baselines are established.

## 5.9 Expected results under sustained load

With sustained 100/s ingress:

1. **Batch fill**: Ranger batches should consistently contain ~70-100 entries
   (depending on exact timing alignment with poll cycles).
2. **Commit rate**: ~1 commit per 700-1000ms, processing ~100 entries each.
3. **Throughput**: ~100 stmt/s observed (matching ingress rate).
4. **Sequencing latency**: p50 ~1s, p95 ~1.5s (dominated by R2 cycle).

At 150/s (exceeding single-ranger capacity of ~143/s):

1. **Queue growth**: DO pending count should increase over time.
2. **Backpressure**: Eventually, DO returns 503 when MAX_PENDING (100K) is
   approached, or latency degrades as queue depth grows.
3. **Diagnostic**: Use `/queue/stats` to observe pending count growth.

## 5.10 Future extensions

1. **Multi-log scenarios**: Distribute load across N logs to test ranger
   horizontal scaling via consistent hashing.
2. **Mixed read/write**: Add read scenarios (GET /entries/{id}, GET /receipt)
   to simulate monitor-style traffic.
3. **Chaos testing**: Inject ranger restarts or DO migrations during load to
   validate at-least-once delivery and recovery.
4. **Grafana dashboards**: Export k6 metrics to InfluxDB/Prometheus for
   visualization alongside ranger and DO metrics.

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
