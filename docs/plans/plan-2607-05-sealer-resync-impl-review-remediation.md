---
id: 2607-05
status: DRAFT
created: 2026-07-15
refs: [plan-2607-04, FOR-390, arbor#68, canopy#135]
---

# plan-2607-05 — Sealer resync implementation review remediation

Review of the F1-fix implementation (the level-triggered resync) shipped in
[arbor#68](https://github.com/forestrie/arbor/pull/68) + its coordinator
dependency [canopy#135](https://github.com/forestrie/canopy/pull/135), per
`review-changes` (distributed-systems + applied-crypto lens). Reviewed by the
author plus an independent adversarial pass; findings agreed.

**Status:** R1–R4 have been **fixed on the PR branches** (with tests; both
suites green). R5–R8 remain as deferred follow-ups ([FOR-392](https://linear.app/forestrie/issue/FOR-392/sealer-resync-deferred-review-follow-ups-r5-r8)).

## Scope
- **Repos/branches:** arbor `for-390-sealer-resync-impl` (#68); canopy
  `for-390-coordinator-active-endpoint` (#135). Cross-repo, coupled.
- **Diff ranges:** `main...for-390-sealer-resync-impl` (arbor),
  `main...for-390-coordinator-active-endpoint` (canopy).
- **Spec:** plan-2607-04 (the design this implements).

## Findings

| ID | Sev | Dim | Repo | Location | Finding |
|----|-----|-----|------|----------|---------|
| **R1** | **High** | Liveness | arbor | `resync.go:124-140` (`tick`) | On any `fetchActivePage` error the loop returns **without resetting `r.cursor`**; the cursor advances only on the success path. A shard-count *decrease* (or any sticky cursor 4xx) makes `decodeCursor` reject the held cursor (`get-active.ts` `c.s >= shardCount`) → the endpoint 400s forever → every tick re-sends the dead cursor and warns. The correctness backstop **silently dies** until process restart. |
| **R2** | Med | Correctness / policy | canopy | `delegation-store.ts:1511` (`handleGetActive`) | The `/active` query selects from `delegation_certificates` with **no `user_enabled`/`operator_enabled` filter**; the sibling `handleGetPending` (`:1447`) enforces it. A log an operator has kill-switched is still returned, and the resync re-drives `CheckpointLog` for it (which takes its lease from the custodian, never consulting the coordinator flags) until the stored cert expires — an administrative-control bypass and an asymmetry with `get-pending`. |
| **R3** | Med | Operational / cost | arbor | `resync.go` `resolveHeight` / `checkAndReseal` | A delegation-in-advance log (active cert, **no massif objects yet** — the core FOR-390 state) is never resolved by `resolveHeight`, which has **no negative cache**: every tick re-probes all candidate heights (`len(heights)` LISTs/log) and emits a WARN framed as a misconfig alert. At scale: `M×len(heights)` LISTs + `M` warn lines per cycle, conflating normal pre-write with misconfiguration. |
| **R4** | Low | Docs / optimization | arbor + canopy | `resync.go:61-62`; `get-active.ts:34`, `delegation-store.ts:1505` | `mmrStart`/`mmrEnd` are decoded but **unused** — `checkAndReseal` always does the head LIST + checkpoint read. The endpoint docs claim the sealer uses `mmrEnd` "to hint how far the log should be sealed, avoiding a massif read." Doc overclaim + missed optimization (not a correctness bug — the head is read authoritatively). |
| **R5** | Low | Scale | canopy | `delegation-store.ts:1511` | The `/active` scan is index-only but **O(total certs in shard)**, not O(active): `WHERE expires_at > ?` filters within the leading-`log_id` index rather than range-seeking. With no pruning of long-expired certs the per-page scan cost grows unbounded with cert accumulation. (A dedicated `(expires_at, log_id_hex32)` index would make it a range seek.) |
| **R6** | Low | Scale / liveness | arbor | `resync.go` cadence | Fixed `RESYNC_INTERVAL`×`RESYNC_PAGE_SIZE` caps the active set at ~`grace/interval×pageSize` (~12k logs at 30s/100/1h) before `fullCycle ≪ grace` weakens and a dropped seal may not be re-driven within grace. Relates to the adaptive-cadence follow-up in plan-2607-04. |
| **R7** | Low | Test coverage | arbor | `resync_test.go` | Only pure logic is unit-tested (head-size arithmetic pinned to `RangeCount`, height parse, cursor decode). The freshness→reseal **decision path** (headSize vs sealedSize → `CheckpointLog`) has no automated test with a mocked object store; acceptance is live-repro only. |
| **R8** | Low | Correctness (known gap) | arbor | `resync.go` `checkAndReseal` (defer path) | A deferred reseal is not retained in a sticky "known-unsealed" RAM set; a cert expiring out of the grace window mid-repair drops from the active set and is never re-driven. Documented follow-up in plan-2607-04 (grace covers the common case). |

### Cleared on review (no defect)
Head-size arithmetic (pinned to go-merklelog `RangeCount`, v2 fixed peak-stack
reservation, log is the trailing region); keyset pagination (unique group key →
no split/skip/dup; threshold drift only removes boundary rows); cross-shard
cursor advance (off-by-one-free, worst case one empty round-trip); concurrency
(`go test -race` clean; all shared maps under `r.mu`, cursor single-goroutine);
cache coherence (`sealedByLog` is only ever ≤ truth → wasteful idempotent no-op
reseals, never a missed reseal).

## Remediation items

**Block-merge — ✅ FIXED on the PR branches:**
1. ✅ **R1 — reset cursor on fetch error** (arbor#68). `tick` sets `r.cursor = ""`
   on any `fetchActivePage` error; `TestTickResetsCursorOnFetchError` (httptest
   400) asserts it. No longer wedges.
2. ✅ **R2 — kill-switch in `handleGetActive`** (canopy#135). Added the same
   `COALESCE((SELECT (user_enabled!=0 AND operator_enabled!=0) …),1)=1` guard as
   `handleGetPending`; a test asserts a disabled log drops out of the walk.

**Follow-ups — ✅ FIXED on the PR branch:**
3. ✅ **R3 — negative-cache unresolved heights** (arbor#68). `resolveHeight`
   backs off re-probes and logs the miss at WARN once per log (Debug after), so
   delegation-in-advance logs no longer spam WARN or re-LIST every tick.
   `TestResolveHeightNegativeCacheSkipsProbe` covers the backoff skip.
4. ✅ **R4 — use the range hint** (arbor#68). `checkAndReseal` short-circuits the
   R2 head read when cached `sealedSize >= mmrEnd`;
   `TestHintFastPathSkipsWhenSealedCoversMmrEnd` covers it.

**Deferred (Low / separate):**
- **R5** — evaluate a `(expires_at, log_id_hex32)` index + expired-cert pruning
  (ties into FOR-391 coordinator scale).
- **R6** — adaptive busy/idle resync cadence (already a plan-2607-04 follow-up).
- **R7** — decision-path test with a mocked object store.
- **R8** — sticky known-unsealed RAM retention (plan-2607-04 follow-up).
