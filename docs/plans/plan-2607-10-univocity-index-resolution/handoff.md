# Handoff — plan 2607-10

**Bootstrap order:**

1. [README.md](README.md) — context, goal, slice index
2. [decisions.md](decisions.md) — D1–D6 locked, OQ1/OQ2 open
3. The slice doc being implemented
4. Code ground truth: `services/univocity/src/{forest_registry,resolver,grant_chain,store,handlers,handlers_write}.go`, `cmd/univocity/main.go`

**Locked decisions:** keep the write-time index (D1: uniqueness claim +
locator, never trust-bearing); hints verified O(1), never trusted (D2);
**no backfill/reconciler machinery** — 404 + individual repair (D3, Robin
explicit; invariant verified since `889ad3d`); genesis self-index
mandatory and **claim-first** (D4 as amended); unresolved = 404 not 503
(D5); dangling locators are misses, never 5xx (D7). Review R1–R6 folded
in 2026-07-30 (see decisions.md "Review record"). Do not reopen these
in-slice; reopen via decisions.md.

**Next slice:** none — all slices IMPLEMENTED on arbor#85 (2026-07-30, 01
folded into 03). Remaining: OQ1 read-only prod LIST assessment before
deploy, then merge.

**Resume prompt:**

> Implement the next draft slice of arbor plan-2607-10
> (docs/plans/plan-2607-10-univocity-index-resolution/) — univocity
> index+hint resolution, deleting the registry scan. Read README.md +
> decisions.md + the slice doc first. FOR-510 tracks it. The outage
> band-aid (arbor-flux#52 startupProbe) is already merged and lane A is
> healthy; this plan removes the scan architecture behind it.
