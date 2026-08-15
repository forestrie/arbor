---
id: 2607-09
status: complete
created: 2026-07-19
refs: [FOR-410, FOR-368, ADR-0056, ADR-0046]
---

# Plan 2607-09 — FOR-410 boundary-base fix: review remediation

**Status:** COMPLETE (2026-07-19) · **Date:** 2026-07-19

**Outcome:** R1/R3/R4/R5 delivered in one PR (`sealPlanForMassif` extraction:
carried cross-massif peak validation with refusal on mismatch; trust-posture
documented; boundary guard reworked per review feedback: header-internal
consistency (storage position == header MassifIndex; FirstIndex == boundary
from the header's OWN height+index) — the blob header is the
replication-safe source and deployment-mutable config never feeds the
boundary math;
five integration tests on real in-memory massifs incl. rollover contiguity,
carried/blob-corruption refusals, and header forgery). R2 recorded on
ADR-0056/FOR-368; backfill-vs-preprod-reset is
[FOR-412](https://linear.app/forestrie/issue/FOR-412). R6 no action.
**Related:** [FOR-410](https://linear.app/forestrie/issue/FOR-410),
[arbor#79](https://github.com/forestrie/arbor/pull/79) (merged `ea77914`),
[ADR-0056](https://github.com/forestrie/devdocs/blob/main/archive/2607/adr/adr-0056-checkpoint-base-is-massif-entry-boundary.md),
devdocs [plan-2607-29](https://github.com/forestrie/devdocs/blob/main/plans/plan-2607-29-for368-buried-peak-verify.md)

Review of the merged FOR-410 sealer change (`226d265..ea77914`) per
review-changes (implementation lens: distributed systems + applied crypto).
The fix itself is sound and shipped; findings below are the residuals.

## Findings

| ID | Sev | Dim | Location | Finding |
|----|-----|-----|----------|---------|
| R1 | Med | Correctness | `sealer.go` seal loop | Multi-massif catch-up lost cross-blob validation: pre-change, massif `i+1`'s `CheckConsistency` received peaks **computed from massif `i`** (carried via `baseState.Peaks`), cross-validating adjacent blobs; post-change every massif's base peaks are rehydrated from **its own** peak stack, making the check self-referential on the catch-up path too. |
| R2 | Med | Correctness/docs | ADR-0056, FOR-410, plan-2607-29 | "Self-heal" is overstated: only massifs that still receive seals (the tip, or a head massif that grows again) heal. **Completed** pre-fix massifs are never re-visited (loop starts at the head checkpoint), so their drifted final `.sth`s are frozen permanently. Consequences: the retained-chain verify rung is per-log conditional (chain breaks at any legacy completed massif) and the publisher's future multi-massif relay must rebuild legacy segments from massif nodes rather than assume boundary links. |
| R3 | Low | Correctness (pre-existing) | `sealer.go` / `CheckConsistency` | Same-massif re-seal consistency has always been self-referential (base peaks rehydrated from the blob being sealed; only the *size* came from the prior checkpoint). Tamper evidence between seals rests on the signed checkpoint chain and external verifiers, not the sealer's local check. Not introduced by this diff; document the trust posture. |
| R4 | Low | Correctness | `sealer.go` invariant guard | The guard compares `proof.TreeSize1` to `mc.Start.FirstIndex` — both ultimately trace to the same blob header. Deriving the expected boundary independently via `massifs.MassifFirstLeaf(mc.Start.MassifHeight, mi)` (from the loop index, not the header) hardens it against a corrupted/forged `Start`. |
| R5 | Med | Testability | `services/sealer` | The seal loop remains untestable end-to-end: `CheckpointLog` constructs its own S3 store, so the FOR-410 behaviours (re-seal base, rollover contiguity, legacy self-heal of a still-growing head) are covered only via the extracted `decideSeal` unit plus lane observation. An integration test with an injectable store (fs or in-mem, mirroring go-merklelog's `memStore` test pattern) would cover the composed loop. |
| R6 | Low | Liveness (note) | delegation lease | The window now starts at the massif boundary; the first re-seal per log after deploy won't be covered by a pre-fix cached cert and forces one re-issuance per log. Expected, self-limiting; per-massif-stable windows are cache-friendlier thereafter. No action. |

## Design holes & non-obvious details

- **R2 is the load-bearing one for siblings**: devdocs plan-2607-29's
  retained-chain rung must treat "any non-boundary base in the fetched
  chain" as a permanent per-log condition (fall back to event-scan /
  tiles), not a transient one; and the publisher's future cross-massif
  relay keeps PR#38's rebuild-from-massif path for legacy massifs forever
  — unless a one-shot backfill resealer re-emits boundary-aligned
  checkpoints for completed massifs (legitimate, since checkpoints are
  replaceable signed artifacts, but new scope; candidate ticket).
- The invariant guard cannot fire through the current data flow
  (`BuildConsistencyProof` copies its `fromSize` argument into
  `TreeSize1`); its value is guarding future call-site regressions. R4
  makes it independently grounded.

## Remediation items

1. **R1 — restore cross-blob validation on catch-up** (small, this repo):
   carry the previous iteration's `newPeaks`/`curSize` through the loop;
   when sealing massif `i+1` in the same run and `prevSize ==
   mc.Start.FirstIndex`, require byte-equality of the rehydrated boundary
   peaks with the carried peaks before proceeding (error, do not seal, on
   mismatch). AC: unit coverage via an extracted helper; a catch-up run
   with a corrupted massif `i+1` peak stack refuses to seal.
2. **R2 — correct the record + scope siblings** (docs/Linear): amend
   ADR-0056 consequences and FOR-410 with the completed-massif limitation;
   comment on FOR-368/plan-2607-29 (retained-chain rung per-log fallback);
   file the optional backfill resealer as a candidate ticket.
3. **R4 — independent boundary derivation in the guard** (one line + test).
4. **R5 — seal-loop integration test** (medium): injectable-store seam for
   `CheckpointLog` (extract inner `sealMassifs(store, …)`), fs/in-mem store
   fixture, tests for re-seal base stability, rollover contiguity, and the
   R1 mismatch refusal.

Deferred: R3 (document only), R6 (none).

## Branch assignment

R1 + R4 as one small PR on a new branch off arbor main; R5 follows (or
stacks) with the store seam; R2 is devdocs/Linear only.
