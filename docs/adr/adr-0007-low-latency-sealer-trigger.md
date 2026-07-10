# ADR-0007 — Low-latency sealer trigger: ranger seal hints, R2 events demoted to backstop

**Status:** Proposed  
**Date:** 2026-07-10  
**Linear:** FOR-335  
**Related:** [plan-2607-01](../plans/plan-2607-01-sealer-nudge-trigger.md),
[canopy scitt-hackathon demo — receipt latency](https://github.com/forestrie/canopy/blob/main/docs/demo/scitt-hackathon.md),
*Self hosted, remote, sealer* initiative

## Context

A SCITT receipt becomes available only once a sealer-signed checkpoint
(`.sth`) covering the entry exists in R2 — canopy's receipt endpoint 404s
until then. The trigger chain that gets the sealer to act is:

1. **Ranger** pulls ingress shards (`POLL_INTERVAL` max **2s**,
   `services/ranger/src/config.go`) and commits massif blobs to R2. Ranger
   publishes nothing after the commit.
2. **R2 bucket event notifications** (`PutObject`) are delivered by
   Cloudflare into a queue. Delivery latency is variable — seconds or more —
   and entirely outside our control.
3. **Sealer** pulls that queue over HTTP (`QUEUE_BATCH_SIZE` 31,
   `POLL_INTERVAL_MAX` **5s** with exponential idle backoff to the ceiling,
   `services/sealer/src/config.go`), parses the massif object key from the
   notification (`consumer/cloudflarer2.go`), and calls `CheckpointLog()`.

The signing work itself is milliseconds (ES256) plus R2 round trips. The
end-to-end receipt latency users observe (the demo documents "up to 30–90s
on an idle lane") is dominated by stage 2's delivery delay plus stage 3's
poll ceiling — i.e. by the trigger, not by any baseline cost.

Two architectural properties are deliberate and must survive any change:

- **Ranger/sealer separation.** The sealer is plausibly self-hosted (it
  holds signing authority via delegation leases) and ranger's HA story is
  cleaner alone. The sealer is **outbound-only**: it dials out to queues,
  Custodian, and the delegation coordinator; it exposes no inbound surface.
- **Triggers are hints; R2 state is truth.** `CheckpointLog()` re-derives
  its work by comparing the latest checkpoint against the massif head in R2.
  Lost, duplicate, or spurious wake-ups are harmless. Correctness never
  depends on trigger delivery.

## Decision

Make ranger the trigger origin, and treat R2 event notifications as a
lagging backstop rather than the primary wake path.

1. **Ranger emits a seal hint immediately after each massif commit** (fire
   and forget, after the R2 write and queue ack succeed). The hint carries
   the massif object key in the same JSON shape as an R2 event notification
   (`{"object": {"key": ...}}`), so the sealer's existing consumer parses it
   unchanged. Phase 1 publishes the hint to the **same Cloudflare queue**
   the sealer already pulls — this deletes the R2→event→queue leg (the one
   we cannot tune) with no sealer change at all.

2. **A seal-coordinator long-poll replaces interval polling** (phase 2). A
   small Durable Object (the SequencingQueue / delegation-coordinator
   pattern, hosted with the other canopy workers) accepts ranger nudges and
   holds the sealer's outbound long-poll request open, resolving it
   immediately on a nudge. Wake latency drops to ~100–300ms and the idle
   backoff problem disappears — an idle sealer is parked on an open request,
   not sleeping toward a 5s ceiling. Auth reuses the existing app-token
   pattern; a self-hosted sealer behind NAT still only dials out.

3. **R2 event notifications are demoted to backstop.** They stay wired
   initially to catch what the fast path cannot (ranger crash between PUT
   and hint, a future second writer). Once a periodic sealer sweep (scan for
   unsealed heads on a slow timer) is in place, the R2 event binding may be
   removed entirely.

Invariants preserved: hints are at-least-once and carry no authority; the
sealer always re-derives work from R2 state; the sealer remains
outbound-only; ranger commit success must never depend on hint delivery.

## Consequences

- Receipt availability drops from "trigger-dominated, up to tens of
  seconds" to roughly commit (~0.5s) + wake (≤5s phase 1, ~0.3s phase 2) +
  delegation lease + sign/PUT (~1s). Delegation lease acquisition becomes
  the next-largest cost and is worth caching per log.
- Ranger gains a post-commit publish step and a config dependency on the
  sealer queue (phase 1) / coordinator (phase 2). It must be non-blocking
  with a bounded retry budget; failures are logged and left to the backstop.
- Phase 2 adds a new DO and one more app token to provision. Deployment
  config (forest-1) grows the corresponding env vars.
- Two (transitionally three) trigger paths exist at once; a
  `trigger_source` metric label is required to observe which path actually
  fires, and a receipt-latency histogram to prove the improvement.

## Alternatives considered

- **Tighten `POLL_INTERVAL_MAX`** (5s → sub-second): least invasive, but
  still rides the R2 event delivery delay, burns idle requests, and floors
  out around the notification latency. Acceptable stopgap only.
- **Sealer scans R2 heads directly** (HEAD/LIST per log on a timer):
  removes the notification dependency but is O(logs) per tick — a worse
  queue. Retained only as the slow backstop sweep.
- **Push to the sealer** (webhook / RPC from ranger or Cloudflare): lowest
  latency but inverts the outbound-only trust model that justifies the
  split and the self-hosting story. Rejected.
