# Slice 01 — bind HTTP before the startup scan; honest readyz

**Repo:** arbor · **Service:** `services/univocity` · **Status:** draft

Safety slice: remove the outage class (scan exceeding probe budgets)
independently of the resolver semantics change, so a safe deploy exists
first. Everything here is deleted or trivialised again by slice 03 —
keep the diff minimal.

## Changes

1. `cmd/univocity/main.go` — start `server.ListenAndServe()` **before**
   `registry.Scan(ctx)`. The scan moves to a goroutine; a scan failure
   logs and leaves the registry empty rather than `os.Exit(1)` (the
   index-first path in `resolveForestForLog` still serves).
2. `/readyz` reports 503 until the first scan attempt **completes**
   (success or failure) so a rolling deploy doesn't shift traffic onto a
   pod whose fallback registry is still cold. `/healthz` stays
   unconditional — liveness must never depend on R2.
3. Do **not** parallelise the scan GETs or touch `TryRefreshScan` here —
   slice 03 deletes both; optimising them first is wasted motion.

## Tests

- readyz gate: 503 before scan-complete signal, 200 after (success and
  failure variants).
- startup with an erroring lister: process stays up, serves index-hit
  requests.

## Deploy note

With this slice live, the arbor-flux#52 `startupProbe` stops being
load-bearing (first `/healthz` success is immediate); leave it in place
as harmless cover.
