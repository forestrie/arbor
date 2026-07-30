# Slice 04 — caller semantics, rollout, legacy repair playbook

**Repo:** arbor (sealer, signer) + ops · **Status:** draft

## Caller classification (404 is terminal, 503 is transient) — ADDED, not aligned

Review R3: neither caller classifies status codes today, so this slice
**introduces** classification rather than adjusting it:

- **Sealer** (`authority_resolver.go:93`): every non-200 currently
  collapses into one error string (`"authority returned status=%d"`)
  and rides the caller's generic retry. Introduce a typed error carrying
  the status; 404 is *permanent-until-repaired*: warn with the logId and
  the remedy (grant re-post / hint), back off long (hours, not the
  transient ladder), never spin. 5xx keeps transient retry. Sealing for
  *other* logs is unaffected.
- **Signer** (`parent_resolver.go`): only 503 is special-cased (warn
  "transient"); any other non-200 — including a future 404 — returns
  `logid.Zero` **silently**. Without this slice the D5 flip silently
  degrades observability. Add: 404 → warn naming the parent logId and
  the remedy; other non-200 → warn at least once.
- Tests: both callers — 404 vs 503 vs 200 classification, log-line
  presence, and (sealer) that 404 does not enter the transient ladder.
- Optional (OQ2, only if a legacy 404 actually bites): thread an R hint
  from context the caller already holds (delegation certificate chain /
  lease metadata) into the new `?rootLogId=` param.

## Rollout order

1. Slice 01 deploys alone (safe under existing traffic).
2. **Pre-flip assessment (OQ1, ops, read-only, minutes):** one-time LIST
   of the prod bucket comparing `forests/forest/{R}/grants/*/{subject}`
   keys against `forests/index/forest/{subject}` entries. Empty diff
   expected (stored-grant ⇒ index invariant); any hits are repaired by
   idempotent grant re-post *before* the flip. Not shipped as code.
3. Caller alignment (this slice's sealer/signer changes) deploys before
   or with slices 02+03.
4. Slices 02+03 deploy. Watch the new `unresolved_404` log line/counter;
   every hit names a logId and is individually repairable.

## Observability

- Structured log + counter for 404-unresolved (logId, hinted R if any)
  and for hint-verified resolutions. The metrics endpoint is currently a
  stub (`main.go` `/metrics`); the log line is the requirement, the
  counter is best-effort.

## Follow-ons recorded, not done here

- Dev-bucket retention sweep for stale e2e forests. **Pre-requisite
  (review R1): `handleDeleteForest` deletes only genesis + the R index —
  it must gain a forest-scoped sweep of the forest's grant objects and
  their subject index entries** (the dangling-locator fallback in slice
  02 makes stragglers 404 rather than 5xx, but deletes should not
  manufacture garbage). Then: ops owner + cadence.
- arbor-flux#52 `startupProbe` may be relaxed once slice 01 is live
  everywhere; harmless either way.
- Canopy univocity-forward hardening (canopy plan-2607-10 R7) unchanged
  by this plan.
