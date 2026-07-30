# Implementation plans (Arbor)

> **Plan numbering.** Plans `plan-0001…` (created on or before 2026-07) are
> frozen legacy absolute ids — do not renumber them. New plans use **date
> cohorts**: `plan-YYMM-NN-<slug>.md` (e.g. `plan-2607-01-…` = 1st plan of
> July 2026); larger multi-part plans use a `plan-YYMM-NN-<slug>/` directory.
> Forward-only.

Legacy plans live as flat `docs/plan-NNNN-*.md` (migration to `docs/plans/`
optional); date-cohort plans live in this directory.

## Date-cohort plans

| Plan | Topic | Status |
|------|-------|--------|
| [plan-2607-01](plan-2607-01-sealer-nudge-trigger.md) | Low-latency sealer trigger: ranger seal hints → long-poll coordinator ([ADR-0007](../adr/adr-0007-low-latency-sealer-trigger.md), FOR-335) | draft |
| [plan-2607-02](plan-2607-02-publisher-revert-probing-remediation.md) | Stop the publisher probing for revertable checkpoints: mirror grant bounds off-chain, pre-send `eth_call`, split revert disposition ([proposal](proposal-publisher-revert-probing.md)) | draft |
| [plan-2607-03](plan-2607-03-for379-380-review-remediation.md) | FOR-379/FOR-380 review remediation (sealer trigger phases 0–1) | draft |
| [plan-2607-05](plan-2607-05-sealer-resync-impl-review-remediation.md) | Sealer resync implementation review remediation | draft |
| [plan-2607-06](plan-2607-06-publisher-owner-wait.md) | Publisher: bounded in-delivery wait for `owner_not_anchored` — a child waits 90s for lease expiry, not for its owner (FOR-395; FOR-394 deferred) | draft |
| [plan-2607-07](plan-2607-07-for408-publisher-notification-loss-backstop.md) | Publisher: reconciliation sweep so a lost R2 event notification cannot permanently strand a fresh forest; ack dependency-blocked messages instead of dead-lettering (FOR-408) | draft |
| [plan-2607-08](plan-2607-08-for408-resync-review-remediation.md) | Resync sweep review remediation: nonce split-brain (W1) + health-gated acks/safe rollback (W2) gate enablement; poison-top-seal fallback, test gaps, config hygiene (FOR-408) | draft |
| [plan-2607-09](plan-2607-09-for410-review-remediation.md) | FOR-410 boundary-base fix: review remediation | draft |
| [plan-2607-10](plan-2607-10-univocity-index-resolution/README.md) | Univocity: index+hint resolution — delete the registry scan / inline rescan / on-chain probe; 404 + verified `rootLogId` hint, no backfill machinery (FOR-510; outage band-aid arbor-flux#52) | implemented (#85) |
| [plan-2607-11](plan-2607-11-univocity-index-resolution-review-remediation.md) | plan-2607-10 implementation review remediation: 409-vs-exists genesis contract (R1 High), self-claim reaping, negative-cache bound (FOR-510) | implemented (#85) |

## Legacy plans (frozen ids)

| Plan | Topic |
|------|-------|
| [plan-0001](plan-0001-custodian-cbor-api.md) | Custodian CBOR API |
| [plan-0002](plan-0002-configmap-checksum-rollout.md) | ConfigMap checksum rollout |
| [plan-0003](plan-0003-non-custodial-checkpoint-support.md) | Non-custodial checkpoint |
| [plan-0004](plan-0004-coordinator-backed-byok-lease-proof.md) | BYOK lease proof |
| [plan-0005](plan-0005-sealer-trust-root-end-to-end.md) | Sealer trust root e2e |
| [plan-0006](plan-0006-byok-checkpoint-seal-end-to-end.md) | BYOK checkpoint seal |
| [plan-0007](plan-0007-univocity-genesis-trust-root-resolver.md) | Genesis trust-root resolver |
| [plan-0008](plan-0008-univocity-grant-store-and-authority-resolver.md) | Grant store + authority resolver |
| [plan-0009](plan-0009-forests-storage-and-uuid-logid.md) | Forests storage UUID |
| [plan-0010](plan-0010-custodian-kms-ensure-and-e2e-key-hygiene.md) | Custodian KMS ensure |
| [plan-0011](plan-0011-e2e-pipeline-recovery.md) | E2E pipeline recovery |
| [plan-0012](plan-0012-ks256-support.md) | KS256 support |

Platform orchestration: [devdocs plan-0013](../../devdocs/plans/plan-0013-custodian-implementation.md).
