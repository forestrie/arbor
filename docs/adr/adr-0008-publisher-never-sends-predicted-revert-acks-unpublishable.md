---
status: accepted
refs: [FOR-377, plan-2607-02-publisher-revert-probing-remediation]
---

# Publisher never sends a predicted-revert tx; unpublishable checkpoints are acked, not retried

The publisher simulates `publishCheckpoint` via `eth_call` before sending and
**never submits a transaction that would revert**, so a deterministically
unpublishable checkpoint costs no gas. Such a checkpoint's queue message is
**acked (with an alert), not redelivered**: an active log self-heals because the
next seal's catch-up consistency proof
(`publishproof.AssemblePublish` / `BuildEmbeddedProofChain` anchor from the
on-chain size up to the head seal) re-anchors the skipped range, and the
contract only ever stores the latest accumulator — so no on-chain state is lost.

## Considered options

- **Keep unpublishable messages queued to auto-recover after an upstream fix** —
  rejected: unnecessary given self-healing, and it churns the queue indefinitely
  and masks the real defect instead of alerting on it.
- **Per-error allowlist to decide drop-safety** — rejected as the *safety*
  mechanism: safety comes from log self-healing, not from withholding acks. The
  decoded error name is still used for the alert and for the (rare) genuinely
  transient defer set.

## Consequences

- Contract-revert disposition is **binary**: `published → ack (success)`;
  `would-revert / reverted → ack + alert`. The unacked-redeliver ("defer") path
  survives **only** for short-lived prerequisites (`owner_not_anchored`) and
  infra/RPC transients, where the *same* message can succeed on a near-term retry.
- **Dormant / low-churn logs** are the one gap: a log that never gets another
  seal would miss its latest checkpoint on-chain. Recovery for that case is a
  future re-drive ("poke") endpoint — deliberately deferred as trivial.
- Correct disposition depends on reasons decoding, so the tip-lag reason-decode
  masking (`tipLagBlockNotFound` matching only `"block not found"`, not Base
  Sepolia's `"Unknown block"`) must be fixed first.
