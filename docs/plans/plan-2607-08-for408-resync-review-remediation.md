# Plan 2607-08 — resync sweep review remediation (FOR-408)

**Status:** ACTIVE — W1–W5 implemented 2026-07-19 (this branch); F4
deferred item remains
**Date:** 2026-07-19
**Scope:** single-repo — arbor (services/publisher)
**Related:** [FOR-408](https://linear.app/forestrie/issue/FOR-408),
[plan-2607-07](./plan-2607-07-for408-publisher-notification-loss-backstop.md),
[arbor#73](https://github.com/forestrie/arbor/pull/73) (the reviewed
commit, `2abddc3`), plan-2607-06 (owner-wait / DLQ hygiene)

Adversarial review of the merged plan-2607-07 implementation. Every
High/Medium finding was verified against the code (and, where claimed,
by executing the failure path). The feature is inert (RESYNC_INTERVAL
defaults off) and deployed nowhere, so nothing here is a production
fire — but **W1 and W2 gate enablement**: do not set RESYNC_INTERVAL on
a lane until they land.

## Findings

| ID | Sev | Location | Finding |
|----|-----|----------|---------|
| F1 | High | `chainwriter.go` `Submit` vs `batchsubmit.go` `chainNonce.allocate` | Nonce split-brain: the sweep's synchronous Submit reads `PendingNonceAt` but never touches the in-process nonce counter, whose single-writer invariant the sweep now breaks. With consumer batch in flight (inflight>0, counter trusted), a sweep publish advances the account nonce invisibly → next batch allocates a duplicate nonce → "replacement underpriced" nacks the whole batch suffix (pinned fees), or the batch replaces the sweep's pooled tx and the sweep blocks 60s in waitReceipt. Self-healing but recurs exactly in the post-outage window (sweep busy + consumer redelivering) the feature exists for. |
| F2 | Med | `consumer.go` `resyncAcksOwnerGated` | Acks are coupled to the config flag, not sweep health: messages ack the moment RESYNC_INTERVAL>0 even if every sweep fails (list creds broken → construct succeeds, sweeps just WARN). And disabling after enabling strands already-acked checkpoints with no queue message, no DLQ record, and no sweep — a quiescent log is re-stranded with less evidence than FOR-408. Undocumented. |
| F3 | Med | `resync.go` coalesce + Reverted handling | Coalescing to the highest massif loses the consumer's "lower seal adjudicated on its own" property: a poison top seal (FOR-377 shape) reverts every sweep forever while the publishable lower massif is never attempted — and under R2 its message was acked, so no path drives it. Sweep also only WARNs where the consumer path raises the unpublishable ERROR alert. |
| F4 | Med | `resync.go` `SweepOnce` | Cost/latency at scale: serial full Assemble (3–6 HTTP/RPC round trips) per log per interval even in the healthy steady state; no sweep-duration metric or bound. Fine at lane scale (~3–5 req/s); at ~10k logs a sweep takes tens of minutes, silently voiding "delay of at most one interval" and running back-to-back. |
| F5 | Med | `resync_test.go`, plan §3 | Test gaps vs plan acceptance: no metrics assertions (R3 AC explicitly requires the loss counter increment); fakeLister ignores the continuation token (pagination unpinned); no list-error → sweep-error test; no Run/ctx test; the R1 "queue disabled → anchors in one interval" integration AC was not implemented (and empty QUEUE_URL fails Validate) yet plan status claims R1–R3 done. |
| F6 | Low | `cmd/publisher/main.go` | Consumer goroutine starts before NewResync's fail-fast; under a crash-looping resync misconfig the ack-owner-gated contract is briefly live with no sweep. Window practically harmless; constructing Resync first is free. |
| F7 | Low | `resync.go` gap WARN + metric help | "Notification loss detected" conflates genuine delivery faults with the deliberate R2 owner-gate handoff (acked children are anchored by the sweep by design), inflating the signal the metric exists to isolate. |
| F8 | Low | `config.go` | `RESYNC_INTERVAL`/`RESYNC_PAGE_SIZE` break the `PUBLISHER_*` prefix convention and name-collide with the sealer's `RESYNC_INTERVAL` (default 30s there, 0 here) — a copied env block silently enables the sweep and flips the ack contract. `getDuration` silently maps a unit-less `RESYNC_INTERVAL=120` to 0 (backstop believed on, actually off). Rename is free while nothing is deployed. |

Verified clean: revert adjudication is duplicate-safe (a false StatusReverted
would require on-chain size below the tx's own sealed size); Run has no
silent-death mode; pagination terminates; chain_not_configured/retry keep
their pre-existing contracts; the (height,log) grouping is strictly more
conservative than the consumer's coalesce; sweeps are serialized.

## Remediation items

### W1 (F1) — single nonce authority *(gates enablement)*

Route the sweep's submission through the batch path's nonce management:
either a `ChainWriter.SubmitReconciled` that allocates/settles one nonce
via `chainNonce`, or have the sweep build `AssembledPublish` and go
through `SubmitBatch` with a synchronous ack wait. Acceptance: a test
interleaves a sweep publish between two batch admissions and asserts no
duplicate nonce is allocated; the batch path's single-writer comment is
updated to name both writers.

### W2 (F2, F6, F7) — health-gated acks, safe rollback, honest signal *(gates enablement)*

- Consumer acks owner-gated messages only when the sweep is *healthy*: a
  shared "last successful sweep" timestamp, ack iff within 3× interval.
  Flag set but sweep failing → pre-existing redelivery contract.
- Document (config comment + plan): disabling RESYNC_INTERVAL after
  enablement is not a safe rollback; the runbook step is re-touching the
  affected `.sth` keys or re-enabling the sweep.
- Construct Resync before starting the consumer (F6).
- Split the gap signal (F7): count/WARN "notification loss" only for
  keys the consumer did not recently ack as owner-gated (shared
  seen-set), and count owner-gate handoffs separately.

### W3 (F3) — poison-top-seal fallback

Keep the per-log key list; on a Reverted highest seal, attempt the next
lower massif in the same pass and raise the unpublishable ERROR alert
(parity with the consumer path). Acceptance: replay variant with a
poison massif-1 and publishable massif-0 anchors massif-0 and alerts.

### W4 (F5) — close the test gaps, true up the plan

Metrics assertions (gap + sweep-result counters), continuation-token
threading pinned in fakeLister, list-error → error-sweep test, Run tick +
ctx-cancel test, and a SweepOnce-level integration test standing in for
the "queue disabled" AC (amend plan-2607-07 wording — Validate requires
QUEUE_URL by design). Flip plan-2607-07 status back to honest wording.

### W5 (F8) — config hygiene *(before first Doppler config exists)*

Rename to `PUBLISHER_RESYNC_INTERVAL` / `PUBLISHER_RESYNC_PAGE_SIZE`;
strict duration parsing for these keys (reject unit-less/invalid loudly
in Validate); document the sealer-name divergence.

### Deferred (F4)

Sweep scale: cheap pre-filter (cache per-key ETag/last-anchored outcome,
skip unchanged), sweep-duration histogram + overrun WARN, optional
bounded concurrency. Not needed at lane scale; required before fleet
growth. Track as its own item on FOR-408.

## Sequencing

W1+W2 one PR (both gate enablement), W3–W5 may ride the same PR or a
fast follow. Only after they merge: promote wave, set
`PUBLISHER_RESYNC_INTERVAL` on lane-a, run the confirming lifecycle
suite, then close FOR-408.

## Outcome (2026-07-19)

- **W1** the sweep submits exclusively through `SubmitBatch`/`chainNonce`
  (`sweepCore` has no `Submit`); `ChainWriter.Submit` is documented as
  the out-of-process CLI path only; regression test
  `TestSubmitBatchInterleavedSweepShareNonceAuthority` pins that an
  interleaved sweep submission takes the next counter nonce with no
  `PendingNonceAt` re-read.
- **W2** owner-gated acks now require `Resync.Healthy()` (last successful
  sweep within 3× interval; false until the first success), every such
  ack records an `OwnerGateHandoffs` entry, and the sweep classifies
  anchored keys as handoff vs genuine loss
  (`publisher_resync_owner_handoffs_total` vs `_gaps_total`); Resync is
  constructed before the consumer starts (F6); the rollback hazard is
  documented on the Config field and in plan-2607-07 R4.
- **W3** per-log candidate lists (highest first): a Reverted top seal
  raises the unpublishable ERROR (consumer parity) and the next lower
  massif is driven in the same pass; assemble-time terminal statuses
  fall through identically.
- **W4** tests: metrics assertions, token-checked pagination fake,
  list-error surface, ctx cancellation, Run/Healthy loop test; the
  plan-2607-07 R1 acceptance wording corrected.
- **W5** `PUBLISHER_RESYNC_INTERVAL`/`PUBLISHER_RESYNC_PAGE_SIZE` with
  strict parsing (set-but-invalid, unit-less, or negative values fail
  Validate loudly); sealer-name divergence documented.
- **Deferred:** F4 (pre-filter + sweep-duration histogram + bounded
  concurrency before fleet growth) stays open on FOR-408.
