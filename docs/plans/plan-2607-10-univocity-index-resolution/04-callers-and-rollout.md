# Slice 04 — caller semantics, rollout, legacy repair playbook

**Repo:** arbor (sealer, signer) + ops · **Status:** draft

## Caller alignment (404 is terminal, 503 is transient)

The 503→404 change (decisions.md D5) alters retry semantics for the two
in-cluster callers:

- **Sealer** (`authority_resolver.go`, `HTTPAuthorityResolver`): today an
  unresolved log arrives as 503 and rides the transient-retry ladder.
  After the flip, 404 must be classified as *permanent-until-repaired*:
  log at warn with the logId and the remedy (grant re-post / hint), back
  off long (hours, not the transient ladder), never spin. Sealing for
  *other* logs is unaffected.
- **Signer** (`parent_resolver.go`): same split — 404 is a terminal
  resolution failure for that parent, not "univocity transient"
  (`parent_resolver.go:111` logs transient today).
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

- Dev-bucket retention sweep for stale e2e forests (admin
  `DELETE /api/forest/{R}` exists; needs an ops owner + cadence).
- arbor-flux#52 `startupProbe` may be relaxed once slice 01 is live
  everywhere; harmless either way.
- Canopy univocity-forward hardening (canopy plan-2607-10 R7) unchanged
  by this plan.
