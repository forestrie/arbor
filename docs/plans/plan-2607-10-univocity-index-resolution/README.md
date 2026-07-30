---
id: 2607-10
status: active
created: 2026-07-30
refs: [FOR-510]
---

# Plan 2607-10 — univocity index+hint resolution (delete the registry scan)

**Status:** IMPLEMENTED on arbor#85 (2026-07-30, pending merge) · **Created:** 2026-07-30

Implementation deviations (all within the locked decisions):

- Slice 01 was folded into 03 as this README anticipated — everything lands
  as one deploy, so no interim scan-goroutine/readyz gate shipped; startup
  simply binds immediately with no scan at all.
- readyz is **unconditional** (the "decide in review" point in slice 03):
  the service holds no warm state and a store probe would add R2 calls per
  probe period for nothing; store outages surface as per-request 503s.
- The chain allow-list check is satisfied by `Pool.Reader` returning
  `ErrChainNotConfigured` (503) at resolution time — no separate
  `loadForest` check was needed.
- Sealer "long backoff" is realised as classification
  (`AuthorityStatusError` / `IsAuthorityNotFound`, preserved through the
  lease error wrap) + loud warn with remedy; retry cadence is already
  per-sealing-attempt, not a tight ladder. Dedicated suppression can ride
  later if a legacy 404 ever bites.

Accepted trade-off (plan-2607-11 R5): the deleted in-RAM registry
incidentally served its cached forests through an R2 outage; now uncached
resolutions 503 during one. The positive `ForestCache` covers hot logs and
503-on-unavailable is the honest taxonomy — no warm-standby state is
reintroduced for this.

Outstanding before deploy: the OQ1 one-time read-only prod LIST assessment
(slice 04 rollout order).

Implementation review: [plan-2607-11](../plan-2607-11-univocity-index-resolution-review-remediation.md)
(1 High + 2 Medium, all remediated on arbor#85 — notably the cross-forest
genesis claim conflict is **422**, because canopy's genesis-forward maps
every 409 to idempotent "exists").

Replace the univocity trust-root service's forest-registry scan with pure
point-lookup resolution, and delete the scan, the inline rescan, and the
on-chain probe fallback entirely. No backfill or reconciliation machinery:
unresolvable logs return an actionable 404 and the caller supplies the
answer (a verified `rootLogId` hint or the scoped chain-binding routes).

## Context

The service performs a full genesis registry scan of the grants bucket
**before binding its HTTP port** (`cmd/univocity/main.go:90`). Scan time is
O(total forests) with a serial per-forest genesis GET. On 2026-07-28 the
dev (lane A) bucket outgrew the ~100s liveness budget and the pod crash
looped until arbor-flux#52 added a `startupProbe` (10 min budget). That is
a tourniquet: the scan also re-runs **inline on the request path** whenever
resolution misses (`ForestRegistry.TryRefreshScan`, rate-limited to once
per 60s, concurrent misses queued behind `scanMu`), and the resolver falls
back to `probeForests` — an `IsLogInitialized` RPC against **every** known
forest contract per miss. All three grow linearly with forest count; dev
grows every e2e run and prod is on the same curve.

The scan is not needed. The owned store already has everything required:

- a global atomic `logId → R` index (`forests/index/forest/{subject}`,
  if-none-match create, cross-forest conflict 409) written by
  `POST /api/grants` **before** the grant object — so a stored grant
  implies an index entry (see [decisions.md](decisions.md) D3);
- forest roots (`logId == R`) resolvable by one derived-key GET
  (`forests/forest/{logId}/genesis.cbor`);
- scoped routes `/api/{chainId}/{contract}/…` for callers that hold a
  chain binding (receipts and trust-root responses carry it since the
  canopy FOR-507 work);
- grant-chain verification that never trusted the resolver's answer —
  so a caller-supplied hint replaces *discovery*, not *verification*
  ([decisions.md](decisions.md) D2).

Canopy's `UNIVOCITY_SERVICE_URL` is armed on dev and prod GitHub envs
(live-verified 2026-07-30), so the genesis-forward and grant-validator
paths populate the index on both lanes today.

## Goal

`GET /api/logs/{logId}/…` resolves via: **IndexGet (O(1)) → derived-key
genesis GET (R case, O(1)) → 404** with problem-details naming the two
remedies (`rootLogId` hint, scoped route). `ForestRegistry`, the startup
scan, `TryRefreshScan`, and `probeForests` are deleted. Startup binds
immediately. Memory is O(LRU cache). No background jobs are introduced.

## Non-goals

- Dev-bucket pruning / retention for stale test forests (follow-on ops;
  admin `DELETE /api/forest/{R}` exists).
- Canopy-side changes. The univocity-forward hardening items (canopy
  plan-2607-10 R7 — same-name different repo, note the collision) ride
  separately.
- Reverting arbor-flux#52; the `startupProbe` stays as harmless cover.

## Slices

| Doc | Slice | Status |
|-----|-------|--------|
| [01-bind-before-scan.md](01-bind-before-scan.md) | Bind HTTP before the startup scan; honest readyz | folded into 03 |
| [02-resolver-rewrite.md](02-resolver-rewrite.md) | Index-first resolution, R-case fallback, 404 contract, verified `rootLogId` hint | implemented |
| [03-delete-registry.md](03-delete-registry.md) | Delete ForestRegistry / probe / rescan; config + test cleanup | implemented |
| [04-callers-and-rollout.md](04-callers-and-rollout.md) | Sealer/signer 404 vs 503 semantics; rollout, metrics, legacy repair playbook | implemented (OQ1 assessment outstanding) |

Slices 01 and 02 are independently shippable; 03 depends on 02; 04 rides
or follows 03. If sequencing pressure appears, 01 can be folded into 03
(the scan dies anyway) — it exists separately so a safe deploy exists
before the resolver semantics change.

## Handoff

See [handoff.md](handoff.md) for bootstrap order, locked decisions, and
resume prompts.
