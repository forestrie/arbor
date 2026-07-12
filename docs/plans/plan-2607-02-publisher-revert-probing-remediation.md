---
id: 2607-02
status: active
created: 2026-07-12
refs: [FOR-377, FOR-378, plan-2607-02-multi-forest-publisher, plan-2607-09, plan-2607-13, adr-0046, adr-0047]
---

# Plan 2607-02 — publisher revert probing remediation

**Status:** ACTIVE · **Created:** 2026-07-12 · **Phase 0 diagnosis: done 2026-07-12**

> Proposal this plan formalises:
> [proposal-publisher-revert-probing.md](proposal-publisher-revert-probing.md).
> Note: `refs` above cite the multi-forest publisher plan (also `2607-02`, in
> `devdocs/plans/`) and the reseal-boundary plan by slug to avoid the
> cross-root ordinal clash.

## Context

The publisher EOA issues many **reverting on-chain transactions**, each paying
gas for a mined revert. Root cause: the publisher discovers "this checkpoint
cannot anchor" only by **submitting a transaction and observing the revert**.

`publishCheckpoint` enforces four deterministic gates
(`univocity/src/contracts/_Univocity.sol`); the publisher mirrors only one:

| Gate | Contract site | Mirrored off-chain today |
|------|---------------|--------------------------|
| `SizeMustIncrease` | `_Univocity.sol:820` | ✅ `ErrAlreadyAnchored` (`publishproof/assemble.go:67`) — no tx |
| `MinGrowthNotMet` | `_Univocity.sol:184` | ❌ submits → reverts → burns gas |
| `MaxHeightExceeded` | `_Univocity.sol:795` | ❌ |
| `InvalidConsistencyProof` (empty/size 0) | `_Univocity.sol:165,177` | partial |

Both un-mirrored bounds (`minGrowth`, `maxHeight`) are **already in the
assembled `PublishGrant` tuple** (`publishproof/grant.go:20-22`, from
`grantstore.go:177`) — the publisher has every input to pre-check them for free
and does not. Compounding it, `classifyReceipt` (`chainwriter.go:288`) retries
**every** non-superseded revert by resubmitting (`publish.go:241`,
`consumer/consumer.go:308`), so both advanceable reverts (`MinGrowthNotMet`) and
invariant reverts (signature/proof/grant bugs) re-burn gas on every redelivery
until DLQ.

**Not a univocity defect.** `minGrowth`/`maxHeight` are deliberate controls,
correctly enforced on-chain, and vary per grant. `eth_call` simulation of the
existing entrypoint needs no contract change. This plan is **publisher-only**.

## Goal

The publisher submits **no transaction it can predict will revert**, and never
resubmits an invariant failure. Steady-state reverting-tx gas spend → ~0, with
no checkpoint ever dropped (on-chain-size ack authority unchanged).

## Phase 0 findings (2026-07-12) — priority OVERTURNED

Pulled `/metrics` + `publish result` logs from both publisher pods on
forest-dev-5 (`kubectl exec … curl localhost:9090/metrics`). Window: ~60 min
since pod start 12:59:59Z. **forestrie-a idle (0 messages); forestrie-b: 33
attempts, 100% reverting (`status=retry`).**

- **Only 6 distinct logs**, all **first checkpoints** (`…/0000000000000000.sth`,
  massif 0, `sealedSize` 1 or 3, `onchainSize` 0 — brand-new logs, never
  anchored). Each retried 2–8× → a **retry storm on a fixed set of
  deterministically-reverting bootstraps**, each retry a gas-burning on-chain
  revert.
- **Reason distribution: 31/33 masked** as
  `400 Bad Request … {"code":3,"message":"Unknown block"}`; **2/33 decoded as
  `InconsistentReceiptSignature`**. **Zero `MinGrowthNotMet`, zero
  `SizeMustIncrease`.**

Two problems, neither matching the pre-diagnosis hypothesis:

1. **Observability bug masks the true revert reason.** `tipLagBlockNotFound`
   (`chainwriter.go:416`) matches only the literal `"block not found"`, but Base
   Sepolia's RPC returns `"Unknown block"` (JSON-RPC code 3) when
   `revertReasonAt` re-calls at the *historical* revert block the public RPC has
   not indexed yet. The tip-lag retry exits immediately, returns the raw 400
   string → metric bucket `unrecognized`, real reason hidden. The 2 that slipped
   through show the true reason is `InconsistentReceiptSignature` — a
   **deterministic bootstrap/signature failure**, not a race and not minGrowth.
2. **Deterministic reverts are retried forever = the gas waste.** These 6
   bootstraps can never succeed as-is, yet redeliver + resubmit every visibility
   timeout. This is exactly the invariant-revert retry storm C3 targets.

**Re-prioritisation (supersedes the original ordering below):**

- **P-obs (new, do first):** fix `tipLagBlockNotFound` to also match
  `"unknown block"` (case-insensitive) and/or JSON-RPC error `code:3`, so reasons
  decode. Prerequisite for trustworthy metrics and for C2's decode path.
- **C3 (was Phase 3) → primary gas lever:** classify `InconsistentReceiptSignature`
  and the signature/bootstrap/grant invariant class as **terminal → ack+alert**,
  stopping the retry storm.
- **C2 (was Phase 2) → strong:** a pre-send `eth_call` at *latest* would both
  avoid the gas and sidestep the "Unknown block" masking (that error only arises
  calling at a lagging historical block).
- **C1 (was Phase 1, minGrowth) → demoted to optional optimisation:** C2's
  `eth_call` already prevents the doomed send for *every* revert class, so C1 is
  no longer needed for correctness — it would only save the `eth_call`
  round-trip for a locally-predictable minGrowth miss. Not observed in current
  traffic (all first-checkpoints). Likely **cut** unless steady-state extend
  traffic shows enough `MinGrowthNotMet` volume to justify the pre-check.
- **Upstream root cause (out of scope here) → [FOR-378](https://linear.app/forestrie/issue/FOR-378/bootstrap-first-checkpoints-revert-inconsistentreceiptsignature):**
  *why* bootstrap checkpoints revert `InconsistentReceiptSignature(algProvided,
  algLog)` is a sealer/grant/genesis defect (alg mismatch), not a publisher
  gas-hygiene bug. This plan only stops the publisher paying to rediscover it;
  FOR-378 owns the fix. Related to FOR-377 in Linear.
- **DLQ:** still to confirm (see Phase 0 residual below).

### Phase 0 residual

- ~~Cloudflare DLQ / max-retries config~~ — **dropped 2026-07-12**: with C3's
  aggressive terminal-ack, a permanently-bad checkpoint is consumed on first
  sight, so nothing accumulates for a DLQ to catch. Not needed for this work.
- Steady-state extend traffic once first-checkpoints clear, to (in)validate C1.

## Approach

Phased, **re-ordered per Phase 0**: P-obs → C3 → C2 → C1. `minGrowth` varies per
grant, so C1 (if pursued) must read `sg.Grant.MinGrowth` per checkpoint.

### Phase 0 — Diagnose the dominant revert reason *(done — see findings above)*

Gate satisfied: dominant failure is **deterministic bootstrap reverts**
(`InconsistentReceiptSignature`, largely masked by a tip-lag decode bug), not
minGrowth and not a race. Priority re-ordered accordingly.

### Phase P-obs — Fix the tip-lag reason-decode masking *(DONE 2026-07-12)*

Implemented: `tipLagBlockNotFound` now matches `"unknown block"` as well as
`"block not found"` (`chainwriter.go`), with a regression test carrying the real
Base Sepolia 400 body (`batchsubmit_test.go` `TestTipLagBlockNotFound`). Full
publisher suite green. Matching JSON-RPC `code:3` was rejected — that code also
means "execution reverted", so message-text matching is the safe choice.

<details><summary>original spec</summary>


`revertReasonAt` (`chainwriter.go:428`) re-runs the reverted tx as `eth_call` at
`rcpt.BlockNumber` to decode the reason, retrying while the public RPC tip lags.
`tipLagBlockNotFound` (`chainwriter.go:416`) only matches `"block not found"`, so
Base Sepolia's `"Unknown block"` (code 3) is treated as terminal and the raw 400
string becomes the reason (→ `unrecognized`).

- Broaden the matcher: case-insensitive `"unknown block"` **and** `"block not
  found"`; prefer keying on the JSON-RPC error `code:3` where the client exposes
  it. Add a unit test with the real Base Sepolia 400 body.
- Confirms the true revert reason in metrics/logs before C3 keys its disposition
  table on it. Cheap; unblocks everything else.
</details>

### Phase 1 — Mirror the deterministic grant bounds off-chain *(C1, demoted)*

In `AssemblePublish` (`publishproof/assemble.go`), after `sealed.MMRSize` is
known and `targetOnchain`/`sg.Grant` are read, evaluate the same bounds the
contract will, **before** encoding calldata (zero extra RPC):

- `targetOnchain.Size + sg.Grant.MinGrowth > sealed.MMRSize` → new **deferrable**
  status `StatusGrowthNotMet`: no tx, leave unacked → redeliver (same mechanism
  as `owner_not_anchored`). Resolves to `already_anchored` (→ ack) once a larger
  seal for the log anchors.
- `sg.Grant.MaxHeight != 0 && sealed.MMRSize > sg.Grant.MaxHeight` → new
  **terminal** status `StatusMaxHeightExceeded`: ack + alert (unpublishable under
  this grant; policy/config fault).

Touch points: add statuses to `PublishStatus` (`publish.go:26`), map early-exit
in `Assemble` (`publish.go:213`), extend `ShouldAck` (only `MaxHeightExceeded`
acks), and surface both in `finish`/metrics (`consumer/consumer.go:308`).
`coalesce` already picks the highest massif per log (`consumer/consumer.go:230`),
so lower seals defer silently and are subsumed — residual cost is free queue
churn, bounded by the sealer producing a large-enough seal.

### Phase 2 — Pre-send `eth_call` simulation *(C2, general guard + race fix)*

Before `SendTransaction` in both submit paths (`chainwriter.go:360` `Submit`,
`batchsubmit.go:168` `submitChainGroup`), run
`CallContract(publishCheckpoint calldata)` from the EOA at latest block. On
revert, decode with the existing `classifyRevert` (`chainwriter.go:459`) and
**do not send** — route to the Phase 3 disposition.

- Catches every deterministic revert class, incl. those Phase 1 does not model.
- Runs against **latest** state → closes the assemble-read→mine race that yields
  `SizeMustIncrease` / `InvalidConsistencyProof` under redelivery / in-flight
  overlap.
- Cost: +1 free `eth_call` + latency per publish; sends already serialise under
  the send lock so latency is tolerable. Gate behind
  `PUBLISHER_SIMULATE_BEFORE_SEND` (`config.go`), default on.
- Count avoided reverts under a distinct `simulated` path so they are visible
  and not conflated with mined reverts.

### Phase 3 — Binary revert disposition + alert *(C3, DONE 2026-07-12; see [adr-0008](../adr/adr-0008-publisher-never-sends-predicted-revert-acks-unpublishable.md))*

Implemented: `OutcomeReverted`/`StatusReverted` are now terminal **ack + alert**
(`chainwriter.go` `SubmitResult.ShouldAck`, `publish.go` `FinalizeResult` +
`PublishResult.ShouldAck`); only `OutcomeUnsubmitted` (never-mined) still retries.
`finishGroup` (`consumer.go`) acks subsumed siblings **only** on a genuine anchor
(published/already-anchored), not on an unpublishable primary — a lower massif is
adjudicated on its own. Unpublishable results log at **ERROR**
("unpublishable checkpoint terminally acked") for paging; metric stays
`publisher_publish_total{status="reverted"}` + revert reason. Tests:
`TestFinalizeResultDisposition`, `TestFinishGroup{Unpublishable…,Published…}`,
updated `classifyReceipt` revert case. Full suite + vet green.

<details><summary>original spec</summary>


Decision (grill 2026-07-12): drop-safety comes from **log self-healing**, not
from withholding acks. `AssemblePublish` catch-up (`assemble.go:73`) means the
next seal on a log re-anchors any skipped range, and the contract stores only
the latest accumulator — so an unpublishable seal loses no on-chain state on an
active log. Collapse `revertOutcome` (`chainwriter.go:302`) to **binary**:

- **published → ack (success)** — unchanged.
- **would-revert / reverted → ack + ALERT** — no redelivery. Covers
  `InconsistentReceiptSignature` and every other contract revert. (Note:
  `SizeMustIncrease` = already superseded; `MinGrowthNotMet` = this fixed-size
  seal is subsumed by a future larger seal — both self-heal, so both just ack.)

The decoded error name (from Phase P-obs) drives the **alert label**, not the
ack decision. The unacked-redeliver ("defer") path survives **only** for
`owner_not_anchored` and infra/RPC transients (same message can succeed on a
near-term retry). Dormant low-churn logs are the one gap → future re-drive
("poke") endpoint, out of scope (adr-0008).

Alerting: a distinct metric path/label ops can page on (e.g.
`publisher_publish_total{status="unpublishable"}` + the revert reason), plus a
`WARN`/`ERROR` log with the key and decoded reason.
</details>

## Verification

- **Unit** (no live chain — writer injects a fake `txSender`:
  `chainwriter_test.go`, `batchsubmit_test.go`, `publish` tests):
  - Phase 1: growth-not-met → `StatusGrowthNotMet`, **no `SendTransaction`**,
    unacked; maxHeight → `StatusMaxHeightExceeded`, acked; growth-met →
    submits as before.
  - Phase 2: simulate-reverts → not sent, classified by decoded name; simulate-ok
    → sent once.
  - Phase 3: disposition table — each error name maps to the intended
    defer/ack-success/ack-fail; on-chain-size re-read still authoritative.
- **Metrics assertions:** avoided-revert path increments; mined
  `publisher_reverts_total` does not.
- **Live validation** (forest-dev-5 a/b): after rollout, `publisher_reverts_total`
  rate for `MinGrowthNotMet` (and the Phase-0 dominant reason) trends to ~0;
  `publisher_publish_total{status="reverted"}` flat; anchor-lag unchanged
  (no seals stranded).
- **Regression guard:** confirm no valid checkpoint is deferred forever — a
  `growth_not_met` seal must flip to `already_anchored` once the sealer emits a
  seal clearing `onchain + minGrowth`.

## Open questions

1. Per-grant `minGrowth` distribution in production (informs how much Phase 1
   removes; confirmed to vary per grant — no single-threshold assumption).
2. Cloudflare DLQ / max-retries configured? (Phase 0 resolves; gates Phase 3
   urgency.)
3. `PUBLISHER_SIMULATE_BEFORE_SEND` default — recommend **on** (true general
   guard + race fix).
