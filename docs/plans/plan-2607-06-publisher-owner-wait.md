# Plan 2607-06 — publisher: dependency-blocked checkpoints (latency + durability)

**Status:** DRAFT
**Date:** 2026-07-17 (rev 2 — expanded to fully deliver FOR-394 alongside FOR-395)
**Related:** [FOR-395](https://linear.app/forestrie/issue/FOR-395) (latency —
Phase 1), [FOR-394](https://linear.app/forestrie/issue/FOR-394) (silent drop —
Phase 2), [FOR-393](https://linear.app/forestrie/issue/FOR-393) (the univocity
lone-peak bug that surfaced both; fixed in univocity v0.1.8),
[ADR-0008](https://github.com/forestrie/arbor/blob/main/docs/adr/adr-0008-publisher-catchup.md)
(catch-up), prior [arbor#69](https://github.com/forestrie/arbor/pull/69) (this
plan, rev 1 — Phase 1 scope only), `forest-1/infra/publisher-queue.tf`.

> **rev 2 scope.** rev 1 delivered Phase 1 (FOR-395) and *deferred* FOR-394.
> This revision folds FOR-394 back in as **Phase 2** so the plan fully delivers
> both. The two are one problem surface — "what happens to a checkpoint blocked
> on its owner" — and they compose: Phase 1 removes the false positives (a child
> that just lost a race), so that after it lands the only messages reaching the
> retry cliff are genuine poison, which is exactly what Phase 2 must capture.

## 1. Problem

A child log waits ~90s to anchor after its owner, because `owner_not_anchored`
is handled by letting the queue lease lapse rather than by waiting for the
dependency it is blocked on.

Measured on lane-A, 2026-07-17, univocity v0.1.8:

```
12:44:57  alice  owner_not_anchored   <- processed ONE SECOND too early
12:44:58  david  published
12:46:28  alice  published            <- 91s later
```

Alice lost a 1-second race with her owner, then waited a full
`VISIBILITY_TIMEOUT` (90s) for redelivery.

**This is not sealer latency.** The sealer is healthy: one checkpoint covering
100 statements in 2.7s; David's full write → seal → publish → mined was 18s.
The 91s is queue redelivery of a dependency that had already resolved.

### 1.1 Cause

`services/publisher/src/consumer/consumer.go` `finish()`:

```go
if res.ShouldAck() { q.ackMsg(ctx, msg) }
```

`ShouldAck()` is true only for Published / AlreadyAnchored / Reverted. For
`StatusOwnerNotAnchored` **nothing is sent at all** — no ack, no nack. The
message sits until its lease expires.

The infra already believes otherwise. `forest-1/infra/publisher-queue.tf:35-37`:

> "The publisher relies on redelivery for correctness: owner-not-anchored and
> transient (state-advanced) reverts **nack and redeliver** until the dependency
> publishes."

The daemon never nacks — `consumer/dto.go` carries a `Retries []lease` field
that is always sent empty, and `acknowledge()` is only called for acks. Today's
behaviour is an omission, not a design.

## 2. Constraints (established, not assumed)

**C1 — lease-expiry redelivery consumes the attempt budget.** Proven in
FOR-394: a message whose owner could never anchor was delivered exactly 21
times (1 + `max_retries=20`) over 30m58s (≈ 21 × 90s), then dropped. Nothing
acked or nacked it. So the total wait budget is finite:
`max_retries × visibility_timeout` ≈ 31 min. **Any shortening of the retry
delay shrinks total tolerance.**

**C2 — a flat fast nack is strictly worse than today.** At 2s it burns all 20
attempts in ~40s and drops a legitimately-waiting child sooner than the current
behaviour. Only an exponential ladder would be safe, and it depends on
`delay_seconds` support in Cloudflare's pull-ack API which is **unverified**.

**C3 — `VISIBILITY_TIMEOUT` must not be lowered.** `config.go:308` enforces
`VISIBILITY_TIMEOUT > PUBLISHER_RECEIPT_TIMEOUT` (and `main.go:117` warns)
precisely so a slow-to-mine tx resolves before redelivery. Shrinking it
redelivers messages whose tx is still in flight: duplicate publishes, nonce
contention, wasted gas. Correctness survives (`StatusAlreadyAnchored` is
idempotent) but it is the wrong lever.

**C4 — the publisher queue is a Cloudflare Queue**
(`forest-1/infra/publisher-queue.tf`, `http_pull` consumer), *not* the bespoke
SequencingQueue DO in canopy `forestrie-ingress` (which does have `deadLetters`
in `QueueStats` and is consumed by ranger). Queue semantics here are the
vendor's; prefer designs that do not depend on them.

**C5 — the pipeline shape decides where the fix can live** (established by
reading `consumer.go:200-224` + `batchsubmit.go:36-53`, not assumed). Per pull
cycle the publisher:

1. **assembles all log-groups concurrently** — one goroutine per log,
   `wg.Wait()`. The `owner_not_anchored` decision is made *here*, in the read
   phase (`Assemble` returns `ready=false`, `Status=owner_not_anchored`);
2. **submits the ready ones only after `wg.Wait()`** — `SubmitBatch(ready)`
   runs once *all* assembly (including any child) has finished;
3. **resolves receipts asynchronously** via a persistent per-chain collector
   that fires each `Ack` later.

Consequence: for a **co-batched** owner+child, the owner's tx is not even
submitted until after the child has been assembled, and does not anchor until it
mines after that. So at the moment the child is assessed, the owner is
*structurally* un-anchored, regardless of assembly order.

## 3. Approach: bounded post-submit drain

The rev-1 framing ("poll the owner's `logState` inside the publish/assemble
path, then retry once") is **wrong for this pipeline** (C5): a child that polls
inside its own assemble goroutine holds up `wg.Wait()`, which delays the
*owner's own submission* — self-defeating. And topological ordering of assembly
(owner-group before child-group) is **ineffective**: assembly order does not
change *when* the owner anchors, because nothing is submitted during assembly.

The mechanism that fits: after `SubmitBatch`, collect the groups that returned
`owner_not_anchored` and **re-assemble them in a bounded loop**, reading fresh
on-chain `logState` each pass, until they clear or a time bound elapses; then
release the stragglers to redeliver.

```text
blocked := groups that assembled to owner_not_anchored   // deferred, NOT released
SubmitBatch(ready)                                        // owners now submitted, mining
deadline := now + OwnerWait
for len(blocked) > 0 && now < deadline:
    sleep(OwnerPoll)
    reReady, stillBlocked := reassemble(blocked)          // fresh logState read per group
    if reReady: SubmitBatch(reReady)
    blocked = stillBlocked
release(blocked)                                          // finishGroup(owner_not_anchored) → redeliver
```

Why this shape:

- **Handles the co-batched case** (the observed failure): the owner's tx —
  submitted in *this* cycle — mines during the drain, and the child's
  re-assembly catches it. ~2–4s, not 91s.
- **Handles the cross-batch case for free**: a child whose owner anchored in a
  *prior* cycle succeeds on its **first** assemble; it never enters the drain.
- **Consumes zero retry budget** (C1): nothing is released until the bound, so
  the finite ~31-min tolerance is untouched.
- **No vendor-semantics dependency** (C2, C4): no `delay_seconds`, no nack; the
  owner-anchored signal is a chain `logState` read, which is authoritative
  regardless of our own collector.
- **Subsumes topological ordering** — it discovers the dependency by convergence
  (loop-until-dry) rather than pre-sorting, so no per-message owner
  pre-resolution/grant read is needed just to order the batch.
- **Loop *around* the pipeline, not surgery inside it** — the single-writer
  nonce counter, concurrent assembly, and async collector are untouched.

### 3.1 Why not topological ordering (the question that prompted rev 2)

Ordering the batch owner-before-child is the right *goal* but the wrong
*mechanism* here (C5). To make ordering actually gate a child on its owner you
would have to serialise assemble→submit→**mine** owner before assembling the
child — which destroys the concurrent-assemble / batch-submit / async-receipt
design built for throughput (100 statements → one checkpoint, fast). The drain
achieves the same goal (owner resolves before child) without touching that
design, and additionally covers the cross-batch case that ordering-within-a-batch
cannot. Ordering is therefore **neither necessary nor complementary** — the
drain is its correct realisation.

### 3.2 Rejected alternatives

| Option | Why not |
|--------|---------|
| Poll inside `assembleGroup` (rev-1) | C5 — a child polling in-assemble delays `wg.Wait()` and thus the owner's own submission; self-defeating for the co-batched case. |
| Topological batch ordering | §3.1 — assembly order does not change when the owner anchors; would need to serialise submit+mine, destroying the throughput pipeline. |
| Lower `VISIBILITY_TIMEOUT` | C3 — duplicates in-flight publishes; violates an enforced invariant. |
| Flat short nack | C2 — burns the budget in ~40s, drops sooner than today. |
| Exponential nack ladder | Safe but depends on unverified `delay_seconds` (C2) and consumes the attempt budget; the drain gives the same latency without either cost. |
| Event-driven waiter map (re-drive children when their owner publishes) | Strictly better in theory (zero polling) but needs cross-replica coordination. The drain captures nearly all the benefit for a fraction of the risk; revisit if profiling shows the poll cost matters. |

## 4. Phase 1 — latency: the bounded drain (FOR-395)

### W1 — config (`services/publisher/src/config.go`)

- `PUBLISHER_OWNER_WAIT` (default **20s**) — max drain duration per pull cycle.
- `PUBLISHER_OWNER_POLL` (default **2s**) — re-assembly interval.

Do **not** reuse `PUBLISHER_RECEIPT_TIMEOUT`; it bounds *tx-receipt* waiting and
is load-bearing for C3. Sizing (your 2× rule): a co-batched owner's tx mines in
~2–4s after this cycle's `SubmitBatch`, so ~20s covers the common case plus a
couple of chained levels; deeper cold chains fall through to redelivery, which
is what the budget (C1) is for. Do not size the fast path for a fully-cold chain.

### W2 — validation (`config.go`, beside the existing check at :308)

Enforce `OwnerWait + ReceiptTimeout < VisibilityTimeout`, mirroring the existing
rule. **The** safety constraint (C3): hold a message past its lease and it is
redelivered mid-flight, duplicating the publish. Defaults: 20 + 60 = 80 < 90 ✓.

### W3 — the drain (`services/publisher/src/consumer/consumer.go`)

In `processQueueMessages`, after `SubmitBatch(ready)`:

1. Refactor `assembleGroup` so an `owner_not_anchored` group is **returned as
   deferred**, not settled in place (today it calls `finishGroup` at
   consumer.go:276). The caller decides: ready → submit; deferred → drain;
   other terminal (already-anchored / reverted / chain-not-configured) →
   settle now, as today.
2. Drain loop: while deferred groups remain and `OwnerWait` not elapsed, sleep
   `OwnerPoll`, re-assemble each deferred group (fresh `logState` read),
   `SubmitBatch` any that became ready, keep the rest.
3. On timeout, `finishGroup(owner_not_anchored)` the stragglers — today's
   release-and-redeliver path, preserved as the slow tail.

The drain reads on-chain `logState` (cheap `eth_call`); it does **not** couple
to the async receipt collector — the owner anchoring is observable directly on
chain whether it was submitted by this cycle or a prior one (C5). Nothing in the
single-writer nonce / concurrent-assemble / collector machinery changes.

Concurrency note: the deferred set is built after `wg.Wait()` (assembly done),
so the drain is single-goroutine over a fixed slice — no new shared-state races.

### W4 — tests (`services/publisher`)

- co-batched owner+child in one pull → child publishes within the drain, no
  redelivery (the regression: this is the observed 91s case);
- cross-batch child whose owner is already anchored → publishes on first
  assemble, never enters the drain;
- owner never anchors → still `owner_not_anchored` after the bound, released,
  today's path preserved;
- `OwnerWait + ReceiptTimeout >= VisibilityTimeout` → config rejected (W2).

Use the existing in-memory seams (`MassifReaderFactory`,
`publishproof.ObjectGetter`) and a fake chain reader that flips the owner's
`logState` to anchored after N polls — no network.

**Phase 1 acceptance:** the measured 91s becomes ~2–4s on lane-A for the
co-batched case; retry-budget consumption unchanged (a still-blocked child uses
one delivery per `VISIBILITY_TIMEOUT`, not more); `go test ./...` green.

## 5. Phase 2 — durability: never drop silently (FOR-394)

Phase 1 removes the *false positives* from the retry cliff (a child that merely
lost a race now clears in the drain). What is left reaching exhaustion after
Phase 1 is **genuine poison** — an owner that never anchors (e.g. a terminally
reverted owner, or a malformed checkpoint). That is exactly what must not vanish.

Delivered in two independently-shippable slices, cheapest-first:

### 5a — observability (arbor Go; ~1–2h; do first, standalone value)

`QueueMessage.Attempts` is parsed (`consumer/dto.go:10`) and **never read**.

- Export a Prometheus metric for delivery attempts (the metrics layer is
  `prometheus/client_golang` at `/metrics`, `src/metrics/metrics.go`), e.g. a
  `publisher_message_attempts` histogram plus a `publisher_near_exhaustion_total`
  counter incremented when `Attempts >= threshold` (default 15 of 20).
- `WARN` log with logId + key + attempts at the same threshold.

This converts a silent drop into an **alertable** event with zero Cloudflare
work — it closes the "silent" in "silently drops" on its own. Alert rule:
`publisher_near_exhaustion_total` increase > 0.

### 5b — durable capture (choose one mechanism; ~half a day)

So the checkpoint is not just *alerted* but *recoverable*:

**Option A — native Cloudflare DLQ (recommended for standard tooling).** Add a
`cloudflare_queue` DLQ (per slot) in `forest-1/infra/publisher-queue.tf` and set
`dead_letter_queue` on the publisher consumer. On exhaustion Cloudflare moves the
message to the DLQ instead of dropping. **Blockers to verify first:** (i) does
the `http_pull` consumer support `dead_letter_queue` on provider `~> 5.5.0`?
(unverified — the pull-consumer schema differs from push); (ii) `publisher-queue.tf:47-52`
`lifecycle { ignore_changes = [settings, type] }` plus the provider-5.4x
consumer_id bug mean a settings edit will **not** apply to the existing consumer
— apply out-of-band, mirroring the existing `cloudflare:ensure-r2-notifications-publisher`
task (`forest-1/taskfiles/cloudflare.yml:565`), which already PUTs queue
config via the API for exactly this reason. Then alert on DLQ depth
(`message_backlog_count` is already in the pull response) and provide an
operator replay path (re-enqueue once the owner is unstuck).

**Option B — app-level dead-letter record (no vendor dependency).** When
`Attempts >= threshold`, before releasing, the publisher writes
`{key, logId, owner, attempts, last reason}` to a durable R2 prefix
(`publisher-deadletter/`) and emits the alert, then lets natural exhaustion
proceed. Replay = re-emit the R2 notification from the record. Fully testable in
Go; sidesteps every Cloudflare-provider issue in Option A; the cost is
re-implementing capture/replay we would otherwise get from the queue.

**Recommendation:** verify Option A's blocker (i) first (one API probe). If the
pull consumer supports a DLQ, take A — standard tooling, no app code. If not,
take B. Do **not** block 5a on this choice; 5a ships independently and delivers
most of the value (loud instead of silent).

**Phase 2 acceptance:** a checkpoint that exhausts retries produces a metric +
alert (5a) and is captured for replay, not dropped (5b); a synthetic
never-anchoring owner is observed to land in the DLQ / dead-letter record in a
test or a controlled lane-B run.

## 6. Delivery & sequencing

| Slice | Repo | Depends on | Ship |
|-------|------|-----------|------|
| Phase 1 (W1–W4) | arbor | — | first; fixes the latency, and makes the Phase-2 cliff genuine-poison-only |
| 5a observability | arbor | — | independent; can land with or before Phase 1 |
| 5b durable capture | forest-1 (A) or arbor (B) | 5a (shares the threshold) | after the A/B probe |

Phase 1 and 5a are pure arbor Go and can share one PR or land separately. 5b is
a follow-up once the mechanism is chosen.

## 7. Effort / risk

- **Phase 1:** ~half to one day. `config.go` + a drain loop in `consumer.go` +
  a small `assembleGroup` refactor + tests. **Risk: low–moderate** — it touches
  the pull-cycle control flow, but as a loop *around* the existing concurrent
  assembly/submit, not inside it; the nonce single-writer invariant, collector,
  and publish idempotency are untouched. New failure mode: worker-cycle
  occupancy during the drain, bounded by `OwnerWait`.
- **5a:** ~1–2h, pure additive metric/log. **Risk: negligible.**
- **5b:** ~half a day either option; **Risk: low** (A gated on the provider
  probe; B is plain Go).
