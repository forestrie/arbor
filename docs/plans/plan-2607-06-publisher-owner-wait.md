# Plan 2607-06 — publisher: bounded in-delivery wait for owner_not_anchored

**Status:** DRAFT
**Date:** 2026-07-17
**Related:** [FOR-395](https://linear.app/forestrie/issue/FOR-395) (this plan),
[FOR-394](https://linear.app/forestrie/issue/FOR-394) (exhausted retries silently
drop checkpoints — no DLQ; deferred, see §5),
[FOR-393](https://linear.app/forestrie/issue/FOR-393) (the univocity lone-peak
bug that surfaced this; fixed in univocity v0.1.8),
[ADR-0008](https://github.com/forestrie/arbor/blob/main/docs/adr/adr-0008-publisher-catchup.md)
(catch-up), `forest-1/infra/publisher-queue.tf` (queue settings).

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

## 3. Approach: bounded in-delivery wait

Treat `owner_not_anchored` as a **dependency wait**, not a release. On that
status, poll the owner's `logState` until it anchors or a bound elapses, then
re-run the attempt once.

Why this shape:

- **Consumes zero extra attempts** — one delivery covers the whole wait, so the
  finite budget from C1 is untouched. This is the decisive advantage over any
  nack-based scheme.
- **No vendor-semantics dependency** (C2, C4): no `delay_seconds`, no nack.
- **Subsumes topological batch ordering.** Ordering a batch owner-before-child
  would require resolving each message's owner up front (an R2 grant read per
  message) purely to sort. The same effect falls out for free: by the time the
  rest of the pulled batch is processed the owner has published, so the
  in-delivery retry succeeds. No sort, no pre-resolution.

### 3.1 Rejected alternatives

| Option | Why not |
|--------|---------|
| Lower `VISIBILITY_TIMEOUT` | C3 — duplicates in-flight publishes; violates an enforced invariant. |
| Flat short nack | C2 — burns the budget in ~40s, drops sooner than today. |
| Exponential nack ladder | Safe but unverified (`delay_seconds`, C2) and buys little once §3 lands — the only messages still reaching redelivery are ones where 90s is acceptable. Revisit only if cross-batch waits prove common. |
| Event-driven waiter map (re-drive children when their owner publishes) | Strictly better in theory (zero polling), but needs cross-replica coordination. §3 captures nearly all the benefit for a fraction of the risk. Revisit if profiling shows the poll cost matters. |

## 4. Work items

### W1 — config (`services/publisher/src/config.go`)

Add:

- `PUBLISHER_OWNER_WAIT` (default **15s**) — max in-delivery wait for the owner.
- `PUBLISHER_OWNER_POLL` (default **1s**) — `logState` poll interval.

Do **not** reuse `PUBLISHER_RECEIPT_TIMEOUT`. It bounds *tx-receipt* waiting and
is load-bearing for the C3 invariant; overloading it means raising a dependency
bound silently changes tx semantics and can break `VISIBILITY_TIMEOUT >
PUBLISHER_RECEIPT_TIMEOUT`.

Sizing the default: one link is ~20s measured (seal 2.6s + poll ≤5s + mine
~2–4s), worst case bounded by `PUBLISHER_RECEIPT_TIMEOUT`=60s. The overwhelming
case is the ~1s race, so 15s is generous for the fast path; deeper/cold chains
fall through to redelivery, which is what the budget is for. Do not size the
fast path for a cold multi-level chain.

### W2 — validation (`config.go`, beside the existing check at :308)

Enforce `OwnerWait + ReceiptTimeout < VisibilityTimeout`, mirroring the existing
rule and failing fast on misconfiguration.

This is **the** safety constraint: hold a message past its lease and it is
redelivered while still in flight, duplicating the publish. Defaults:
15 + 60 = 75 < 90 ✓.

### W3 — publish path (`services/publisher/src/publish.go`)

On `StatusOwnerNotAnchored`, poll the owner's on-chain `logState` every
`OwnerPoll` until anchored or `OwnerWait` elapses; if it anchors, re-run the
attempt once. If the bound elapses, return `StatusOwnerNotAnchored` unchanged —
today's release-and-redeliver behaviour is preserved as the slow path.

Bound the extra chain reads: one `logState` per poll (cheap `eth_call`), only
for the rare dependent-child case.

### W4 — observability (`consumer/consumer.go`, `metrics`)

`QueueMessage.Attempts` is parsed (`consumer/dto.go:10`) and **never read**.
Log it and export it; alert at ≥15 of 20. This is the tripwire whose absence
made FOR-394's drop invisible.

### W5 — tests (`services/publisher`)

- owner anchors mid-wait → published within a single delivery (no redelivery);
- owner never anchors → still `owner_not_anchored` after the bound, message
  released, today's path preserved;
- `OwnerWait + ReceiptTimeout >= VisibilityTimeout` → config rejected (W2);
- attempts surfaced in logs/metrics (W4).

Follow the existing in-memory seams (`MassifReaderFactory`,
`publishproof.ObjectGetter`) — no new network in tests.

## 5. Scope decision: FOR-394 (DLQ) is NOT in this plan

Deferred deliberately. The demo is the near-term focus and an alert does not
make the demo pass; after univocity v0.1.8 the demo path cannot reach the cliff
(the owner anchors within one delivery, not 21).

It is filed rather than folded in because it is a *correctness* hole with a
confirmed production occurrence, and it is cheap when picked up (~half a day):
a `cloudflare_queue` DLQ resource + `dead_letter_queue` in the consumer
settings, plus a backlog alert (`message_backlog_count` is already in the pull
response). Note the wrinkle at `publisher-queue.tf:47-52`:
`lifecycle { ignore_changes = [settings, type] }` means settings changes will
not apply to the existing consumer — it needs a recreate or a direct API call
(pattern exists at `taskfiles/service-ranger.yml:107`). This is Cloudflare
config, **not** bespoke queue work (C4).

## 6. Acceptance

- The measured 91s dependency wait becomes ~1–2s on lane-A for the
  owner-published-moments-later case.
- No change to retry budget consumption: a child that waits still uses one
  delivery per `VISIBILITY_TIMEOUT`, not more.
- `go test ./...` green in `services/publisher`.
- Config rejects a misconfigured `OwnerWait` (W2) rather than silently risking
  duplicate publishes.

## 7. Effort / risk

**~half a day.** One Go service; `config.go` + `publish.go` + tests, plus a
small observability change. **Risk: low.** The only new failure mode is
worker-slot occupancy while waiting, bounded by `OwnerWait` and confined to the
dependent-child case; the queue contract, verification, and publish idempotency
are all unchanged.
