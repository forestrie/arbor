---
id: 2607-10
status: draft
created: 2026-07-30
refs: [FOR-510]
---

# Plan 2607-10 — univocity index+hint resolution (delete the registry scan)

**Status:** DRAFT · **Created:** 2026-07-30

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
| [01-bind-before-scan.md](01-bind-before-scan.md) | Bind HTTP before the startup scan; honest readyz | draft |
| [02-resolver-rewrite.md](02-resolver-rewrite.md) | Index-first resolution, R-case fallback, 404 contract, verified `rootLogId` hint | draft |
| [03-delete-registry.md](03-delete-registry.md) | Delete ForestRegistry / probe / rescan; config + test cleanup | draft |
| [04-callers-and-rollout.md](04-callers-and-rollout.md) | Sealer/signer 404 vs 503 semantics; rollout, metrics, legacy repair playbook | draft |

Slices 01 and 02 are independently shippable; 03 depends on 02; 04 rides
or follows 03. If sequencing pressure appears, 01 can be folded into 03
(the scan dies anyway) — it exists separately so a safe deploy exists
before the resolver semantics change.

## Handoff

See [handoff.md](handoff.md) for bootstrap order, locked decisions, and
resume prompts.
