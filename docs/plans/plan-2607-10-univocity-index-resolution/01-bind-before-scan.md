# Slice 01 — bind HTTP before the startup scan; honest readyz

**Repo:** arbor · **Service:** `services/univocity` · **Status:** draft

Safety slice: remove the outage class (scan exceeding probe budgets)
independently of the resolver semantics change, so a safe deploy exists
first. Everything here is deleted or trivialised again by slice 03 —
keep the diff minimal.

## Changes

1. `cmd/univocity/main.go` — start `server.ListenAndServe()` **before**
   `registry.Scan(ctx)`. The scan moves to a goroutine; a scan failure
   logs and is **retried with backoff** rather than `os.Exit(1)` (the
   index-first path in `resolveForestForLog` still serves).
2. `/readyz` reports 503 until the first scan **succeeds** (review R4:
   completion-not-success would let a cold-registry pod take traffic
   while `maxUnavailable: 0` kills the warm one; gating on success
   instead stalls the rollout on the old, warm pod — strictly better).
   `/healthz` stays unconditional — liveness must never depend on R2.
3. Do **not** parallelise the scan GETs or touch `TryRefreshScan` here —
   slice 03 deletes both; optimising them first is wasted motion.

## Tests

- readyz gate: 503 before first scan success, 200 after; stays 503
  across a failed attempt, flips on the retry that succeeds.
- startup with an erroring lister: process stays up (healthz 200,
  readyz 503), serves index-hit requests, scan retry observed.

## Deploy note

With this slice live, the arbor-flux#52 `startupProbe` stops being
load-bearing (first `/healthz` success is immediate); leave it in place
as harmless cover.
