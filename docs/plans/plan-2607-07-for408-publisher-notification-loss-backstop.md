# Plan 2607-07 — publisher: notification-loss backstop (FOR-408)

**Status:** ACTIVE — R1–R3 implemented 2026-07-19 (#73), hardened per
[plan-2607-08](./plan-2607-08-for408-resync-review-remediation.md) W1–W5;
R4 ops follow-ups outstanding
**Date:** 2026-07-19
**Scope:** single-repo — arbor (services/publisher; ops notes for forest-1)
**Related:** [FOR-408](https://linear.app/forestrie/issue/FOR-408),
[plan-2607-06](./plan-2607-06-publisher-owner-wait.md) (dependency-blocked
checkpoints — assumes the message arrived),
[ADR-0008](../adr/adr-0008-publisher-catchup.md) (catch-up via the *next*
message), sealer `resync.go` (the sealer-side backstop this plan mirrors),
[FOR-371](https://linear.app/forestrie/issue/FOR-371) (found during its
qualification), [FOR-409](https://linear.app/forestrie/issue/FOR-409)
(secrets-in-logs, found during the same investigation)

## 1. What happened (lane-A, 2026-07-19)

Fresh `forestrie deploy` instances stopped anchoring: the genesis log of a
new forest never got on-chain state, so every child queued behind the
hierarchical owner-gate (`owner_not_anchored`) until dead-lettered.

Timeline (publisher logs, forestrie-a; publisher image `main-d74e19d`,
which already includes plan-2607-06 Phase 1 / FOR-395):

| Time (Z) | Event |
|----------|-------|
| 12:40:54–12:41:23 | Run 1 (fresh forest `d2ae342c…`): genesis published (sizes 0→1→3), then both children. 6/6 e2e green. |
| 13:19:26 | Run 2: backlog 0→2 — messages for robert + child arrive. **No message for the genesis key, ever.** |
| 13:19:30/36/40 | R2 `Last-Modified`: sealer sealed run 2's genesis, robert, child `.sth` within 10s. All three objects exist (verified 200). |
| 13:20–13:51 | robert + child loop `owner_not_anchored` on ~90s redelivery ("owner 85281f1d has no on-chain state" — the genesis). Run 3 repeats the identical pattern (2 more looping messages, no genesis message). |
| 13:37–13:39 | Interleaved: the publisher anchors the **demo forest's** genesis re-seals (sizes 4→7→8) and two children — the pipe works for keys whose notifications arrive. |
| 13:52–14:00:18 | The four looping messages hit Cloudflare Queues max-retries and dead-letter. Backlog 0. |
| 14:03:56 | scout restarted (red herring — see §2.3). |
| 14:05:04–14:05:32 | Run 4 (fresh forest): genesis message arrives, publishes 0→1→3, children follow. 6/6 green. |

## 2. Root cause — three layers

### 2.1 Proximate: lost R2 event notifications

The publisher queue is fed by R2 event notifications on the
`v2/merklelog/checkpoints/` prefix. For two consecutive fresh forests
(~13:12–13:35Z), the notifications for the **genesis** `.sth` PUTs were
never delivered, while sibling keys written seconds later on the same
prefix were. Delivery resumed by 14:05. This is a delivery fault in the
notification pipeline (at-least-once in name, not in practice during this
window), selective in effect because genesis objects for a brand-new
forest get exactly one PUT burst — an established forest's key is
re-notified on every re-seal, so a single lost event is invisible there.

### 2.2 Structural: the publisher has no reconciliation

The pipeline is purely edge-triggered end-to-end, and every existing
recovery mechanism assumes *some* message arrives eventually:

- ADR-0008 catch-up re-anchors skipped ranges on the **next message for
  that log** — a genesis with no further writes has no next message.
- plan-2607-06 Phase 1 (FOR-395) drains children **after their owner
  publishes in-cycle** — the owner never publishes.
- The **sealer** has `resync.go`, an explicit "correctness backstop to the
  edge-triggered queue path" — which is why the late genesis *seal*
  happened at all. The **publisher has no equivalent**; one lost
  notification permanently strands an entire forest.

### 2.3 Aggravator: dependency-blocked messages burn retries to death

The four child messages dead-lettered while their dependency was
unresolvable. Had the genesis anchored at 14:01, robert and the child
would still never anchor — their messages were already in the DLQ. (Also:
the scout restart at 14:03:56 did **not** fix anything: the backlog had
already DLQ-drained at 14:00:18, scout is an HTTP find-index API with no
role in this path, and run 4's recovery is explained by notification
delivery having resumed. Recorded here because FOR-408 initially blamed
scout.)

## 3. Remediation

### R1 — reconciliation sweep (the fix)

Add a periodic sweep to the publisher, mirroring the sealer `resync.go`
pattern (in-process re-drive, never publishing to its own queue):

- Every `PUBLISHER_RESYNC_INTERVAL` (default off — plan-2607-08 W5 renamed
  it from the draft's `RESYNC_INTERVAL` to avoid the sealer's identically
  named, default-on variable): enumerate forests
  via genesis discovery (ADR-0047), list each forest's
  `v2/merklelog/checkpoints/**.sth`, read each seal's `sealedSize`,
  compare with on-chain `logState` size, and run the normal publish core
  for any log whose sealed size exceeds its anchored size.
- Ordering: process each forest root-first so the owner-gate resolves
  within one sweep (genesis → auth → data), reusing the plan-2607-06
  drain machinery.
- Idempotency is already guaranteed by the publish core
  (`StatusAlreadyAnchored` on the fresh logState read).

**Acceptance (amended by plan-2607-08 W4):** a SweepOnce-level integration
test drives a fresh forest (genesis + child seals listed, nothing
anchored) to fully anchored with **no queue consumer involved** — the
original "empty QUEUE_URL" phrasing was unimplementable as written
(Validate requires QUEUE_URL by design). Unit tests cover gap detection,
root-first ordering, no-op on fully-anchored forests, pagination token
threading, and the 2026-07-19 replay; the loss/handoff counters are
asserted via a recording metrics fake.

### R2 — stop dead-lettering dependency-blocked messages

With R1 in place, `owner_not_anchored` no longer needs queue redelivery
for correctness: **ack it** and let the sweep re-drive once the owner
anchors. This removes the retry-cliff death spiral (§2.3) and the ~90s
redelivery noise, and supersedes the "leave for redelivery" half of the
current `ShouldAck` contract. Coordinate with plan-2607-06 Phase 2: after
this, everything reaching the DLQ is genuine poison.

**Acceptance:** child sealed before owner anchors → anchors via sweep,
message acked on first delivery, DLQ stays empty in the replay test.

### R3 — observability for lost notifications

- Counter + WARN when the sweep finds a publishable gap that had no
  in-flight message ("notification loss detected", with key + lag).
- Backlog gauge and DLQ depth alert (forest-1 monitoring; the four
  dead-lettered 2026-07-19 messages should be purged once R1 lands).

**Acceptance:** the replay test asserts the loss counter increments; an
ops runbook note documents the alert and the purge.

### R4 — ops follow-ups (no code)

> Rollback note (plan-2607-08 W2): disabling PUBLISHER_RESYNC_INTERVAL
> after a period of enablement is NOT a safe rollback — see the Config
> field comment and plan-2607-08 F2.

- Pull Cloudflare queue/event-notification metrics for 13:10–14:00Z to
  characterize the delivery incident; attach findings to FOR-408.
- Until R1 ships, the manual remedy for a stranded fresh forest is
  re-touching its genesis `.sth` (copy-in-place re-emits a notification)
  — **not** restarting services.

## 4. Sequencing

R1 and R2 land together (R2 is only safe with R1), one PR, behind
`RESYNC_INTERVAL` so rollout is inert until configured; R3 in the same PR
(cheap); R4 asynchronous. Estimated one focused day including the replay
test.
