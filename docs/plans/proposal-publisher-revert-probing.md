---
status: proposal
created: 2026-07-12
scope: arbor/services/publisher (+ univocity assessment)
refs: [plan-2607-02, plan-2607-09, plan-2607-13, adr-0046, adr-0047]
---

# Proposal — eliminate cost-incurring revert-probing in the publisher

**Status:** PROPOSAL (basis for an implementation plan — formalise via `/plan-new`)
**Created:** 2026-07-12

## Symptom

The publisher EOA is issuing many **failed (reverting) on-chain transactions**.
Each is mined as a revert and pays gas for nothing. The suspicion in the brief
is correct: the publisher is *relying on reverts to discover that a log has not
(sufficiently) extended*, and doing so costs a real transaction every time.

## Root cause

The publisher discovers "this checkpoint cannot anchor" only by **submitting a
transaction and observing the on-chain revert**. There are two structural
reasons, both on the publisher side.

### Cause 1 — the off-chain pre-check is incomplete

`publishCheckpoint` enforces four deterministic gates *before* it touches state
(`univocity/src/contracts/_Univocity.sol`):

| Gate | Contract site | Mirrored off-chain today? |
|------|---------------|---------------------------|
| `InvalidConsistencyProof` (empty / size 0) | `_Univocity.sol:165,177` | partial |
| `SizeMustIncrease(current, proposed)` | `_Univocity.sol:820` | **yes** — `AssemblePublish` returns `ErrAlreadyAnchored` when `targetOnchain.Size >= sealed.MMRSize` (`publishproof/assemble.go:67`), no tx sent |
| `MaxHeightExceeded(size, maxHeight)` | `_Univocity.sol:795` | **no** |
| `MinGrowthNotMet(current, proposed, minGrowth)` | `_Univocity.sol:184` | **no** |

The publisher already embraces "don't submit what you can predict will fail" for
the size gate — but it stops there. Crucially, **the two un-mirrored bounds are
already in hand**: the `PublishGrant` tuple the publisher assembles carries
`MinGrowth` and `MaxHeight` (`publishproof/grant.go:20-22`, populated from the
stored grant at `grantstore.go:177`). The publisher has every input needed to
evaluate `MinGrowthNotMet` / `MaxHeightExceeded` off-chain for free, and doesn't.

So any seal that **increases** size but by **less than the grant's `minGrowth`**
passes `AssemblePublish` (it is not already-anchored), is built into calldata,
submitted, and reverts `MinGrowthNotMet` — burning gas. In steady state this is
the dominant waste: every fine-grained seal that has not yet accumulated
`minGrowth` of growth beyond the anchored size is a paid revert.

### Cause 2 — revert classification retries deterministic failures by resubmitting

`classifyReceipt` (`chainwriter.go:288`) collapses every revert that is *not*
"on-chain size already covers us" into `OutcomeReverted` → **not acked** →
visibility-timeout redelivery → **re-assembled and re-submitted** → reverts
again (`chainwriter.go:302-317`, `publish.go:241`, `consumer/consumer.go:308`).

- **Advanceable reverts** (`MinGrowthNotMet`, races that produce
  `SizeMustIncrease`): the loop burns gas on *every redelivery* until a larger
  seal finally clears the threshold (or Cloudflare max-retries → DLQ).
- **Invariant reverts** (`ConsistencyReceiptSignatureInvalid`,
  `InvalidConsistencyProof`, `GrantRequirement`, `Delegation*`, cbor/accumulator
  errors — i.e. bugs or misconfiguration): the loop *also* burns gas on every
  redelivery until DLQ, even though retrying identical calldata against identical
  on-chain state can never succeed. The `ShouldAck` comment
  (`chainwriter.go:80`) already acknowledges a "deterministically-bad checkpoint
  loops until the give-up guard / DLQ" — each loop is a paid revert.

## Is this a univocity problem?

**No contract change is required.**

- `minGrowth` / `maxHeight` are deliberate controls — rate-limit anchoring of
  tiny increments (gas economics) and bound tree height. Enforcing them on-chain
  is correct. The anti-pattern is the publisher treating the contract as an
  oracle for *"should I anchor?"* and paying gas to ask.
- Simulating `publishCheckpoint` via `eth_call` needs **no** contract change — it
  is an ordinary external function; `eth_call` executes it against latest state
  without a state transition and surfaces the exact revert. So even the general
  backstop (C2 below) is publisher-only.
- A bespoke `view canPublish() → reasonCode` on the contract was considered and
  **rejected**: `eth_call` on the real entrypoint already gives this for free,
  and a parallel view would risk drifting from the authoritative logic.

## Proposal

Three changes, priority order. **C1 alone removes the steady-state waste**; C2
makes it robust and closes a race; C3 stops repeated burns on the bug tail.

### C1 — Mirror the deterministic grant bounds off-chain *(primary fix)*

In `AssemblePublish` (`publishproof/assemble.go`), after `sealed.MMRSize` is
known and `targetOnchain`/`sg.Grant` are read, evaluate the same bounds the
contract will, before encoding calldata:

- `targetOnchain.Size + sg.Grant.MinGrowth > sealed.MMRSize` →
  new **deferrable** status `StatusGrowthNotMet`: **no tx**, leave the message
  unacked so it redelivers (identical mechanism to `owner_not_anchored` today).
  It resolves to `already_anchored` (→ ack) as soon as a larger seal for the log
  anchors and lifts the on-chain size past it.
- `sg.Grant.MaxHeight != 0 && sealed.MMRSize > sg.Grant.MaxHeight` →
  new **terminal** status `StatusMaxHeightExceeded`: **ack + alert**. This seal
  can never anchor under this grant; it is a policy/config fault, not transient.

Zero extra RPC — both inputs are already in hand. This converts the dominant
`MinGrowthNotMet` reverting-tx into a free no-op.

Note: `coalesce` (`consumer/consumer.go:230`) already picks the highest massif
per log per batch, so with C1 the publisher only submits when the newest
available seal clears `onchain + minGrowth`; lower seals defer silently and are
subsumed. The residual cost is queue churn (redelivery), which is **free** and
bounded by the sealer eventually producing a large-enough seal.

### C2 — Pre-send `eth_call` simulation *(defense in depth + race fix)*

Before `SendTransaction` in both submit paths (`chainwriter.go:360`
`Submit`, and `batchsubmit.go:168` `submitChainGroup`), run
`CallContract(publishCheckpoint calldata)` from the publisher EOA at latest
block. On revert, decode with the existing `classifyRevert` (`chainwriter.go:459`
already maps selectors → IUnivocity names) and **do not send** — route to the C3
disposition instead.

- Catches **every** deterministic revert class, including those C1 does not model
  (proof/signature/grant bugs), for one **free** `eth_call` + latency per publish.
- Because it runs against **latest** state, it also closes the
  *assemble-read → mine* race that currently yields `SizeMustIncrease` /
  `InvalidConsistencyProof` reverts when a redelivered or in-flight-overlapping
  message re-assembles against a stale on-chain read.

Trade-off: +1 RPC round-trip per submit on the hot path. The single-writer nonce
model already serialises sends under the send lock, so the extra latency is
tolerable. Gate behind `PUBLISHER_SIMULATE_BEFORE_SEND` (recommend default on).

### C3 — Split revert disposition: defer vs terminal *(stop resubmitting invariant failures)*

Replace the binary superseded/reverted with a disposition derived from the
decoded IUnivocity error **plus** the existing fresh-logState re-read:

- **Advanceable → retry as no-tx defer:** `SizeMustIncrease`, `MinGrowthNotMet`.
  On-chain may still catch up / a larger seal supersedes. (These should now be
  caught pre-send by C1/C2; this is the safety net if one slips through.)
- **Terminal-success → ack:** `onchain.Size >= sealedSize` (today's `Superseded`).
- **Terminal-failure → ack + alert, no retry:** the invariant/bug class —
  `ConsistencyReceiptSignatureInvalid`, `InvalidConsistencyProof`,
  `InvalidCheckpointCose`, `GrantRequirement`, `Delegation*`, signature / cbor /
  accumulator errors, `MaxHeightExceeded`. Retrying identical calldata against
  identical state cannot succeed; acking (loudly alerted) stops the per-redelivery
  gas burn until DLQ.

Needs a per-error disposition table keyed on the decoded name (the ABI name set
already exists — `knownRevertNames`, `chainwriter.go:485`). **Safety preserved:**
nothing is acked *as success* without an on-chain-size confirmation; the only new
ack is ack-as-terminal-failure, correct because the seal is unpublishable as-is.

## Do first — confirm the dominant revert

Before/while implementing, query the running lane(s):
`publisher_reverts_total{reason}` and `publisher_publish_total{status="reverted"}`
(`metrics/metrics.go:59,55`).

- Expected dominant reason **`MinGrowthNotMet`** → validates C1 as the primary
  lever.
- If instead `SizeMustIncrease` / `InvalidConsistencyProof` dominate → the
  assemble→mine race is the bigger driver and **C2 rises to top priority**.

## Impact / rollout

- **Gas:** removes the reverting-tx spend entirely — the cost flagged in the
  brief. Under C1, steady-state reverts trend to ~0.
- **Safety:** no checkpoint dropped. C1/C3 only add no-tx defers and
  terminal-failure acks for structurally-unpublishable seals; the on-chain-size
  ack authority is unchanged.
- **Tests:** unit-only — the writer already injects a fake `txSender`
  (`chainwriter_test.go`, `batchsubmit_test.go`). Add: growth-not-met defer,
  maxHeight terminal, simulate-revert-no-send, and the disposition table. No
  live-chain test needed.
- **Config / observability:** `PUBLISHER_SIMULATE_BEFORE_SEND`; new statuses and
  `publish_total` labels; add a `simulated_revert` reason path so avoided reverts
  are still counted (distinct from mined reverts).
- Backwards compatible; no data migration.

## Open questions

1. **Production `minGrowth` value(s)?** Determines how much of the waste C1
   removes and whether fine-grained seals routinely fall under it.
2. **Is a Cloudflare DLQ / max-retries actually configured?** If not, invariant
   reverts loop indefinitely today and C3 is urgent, not just tidy.
3. **C2 always-on vs fallback-only?** Recommendation: always-on — it is the true
   general guard and it closes the race that C1 cannot.
