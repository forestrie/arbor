---
id: adr-0009-univocity-index-and-hint-resolution
title: Univocity index and hint resolution
status: accepted
created: 2026-11-27
updated: 2026-11-27
categories: [UNIVOCITY]
refs: [devdocs:ADR-0035, devdocs:ADR-0036, devdocs:ADR-0037, FOR-510, plan-2607-10-univocity-index-resolution]
supersedes: [adr-0001-genesis-driven-logid-resolution]
---

# Univocity index and hint resolution

## Context

The univocity HTTP service (`services/univocity`) answers logId-only
requests (`GET /api/logs/{logId}/…`) for the sealer and the signer, which
know a `logId` and nothing else. It used to find the forest for a `logId`
with a forest registry: a full scan of every forest's genesis document in
the logs bucket before the HTTP port bound, a rescan inline on the request
path whenever resolution missed, and a fallback probe that called
`isLogInitialized` on every known forest's contract. All three grow with
the number of forests. On 2026-07-28 the scan on lane A outgrew the
liveness budget and the pod crash looped.

The owned store already held what resolution needs:

- a global `logId → R` index (`forests/index/forest/{subject}`), created
  with if-none-match when a grant is posted and before the grant object
  is written, so a stored grant implies an index entry;
- the forest root's genesis at a derived key
  (`forests/forest/{R}/genesis.cbor`), one GET when `logId == R`;
- scoped routes `/api/{chainId}/{contract}/…` for callers that hold a
  chain binding;
- grant-chain verification against the forest's genesis identity and the
  on-chain bootstrap configuration, which never trusted the resolver's
  answer.

## Decision

1. **Keep the reverse index; it is the primitive.** `IndexCreate(subject →
   R)` with if-none-match is both the locator for subject logs (R2 lists
   by prefix only, so a random UUID cannot be reversed into its forest)
   and the atomic claim that makes `logId → R` globally unique (devdocs
   ADR-0036). The index is a locator and never bears trust: authority is
   decided by verifying the grant chain against the forest's genesis and
   the contract's `bootstrapConfig()` / `logRootKey`. A wrong index entry
   or hint can only cause a verification failure, never acceptance of a
   bad root.
2. **Resolve by point lookup only.** A logId-only request resolves as:
   index GET, then the derived-key genesis GET (the `logId == R` case),
   then **404** with problem details naming the two remedies. The forest
   registry, the startup scan, the inline rescan and the on-chain probe
   are deleted. Startup binds immediately; memory is bounded by the cache.
3. **Accept a caller-supplied `rootLogId` hint, verified, never trusted.**
   Given `(logId, R)` the service does one genesis GET for R and one grant
   GET for `logId` in that forest, then the same grant-chain verification
   it always performs. The hint replaces discovery, not verification, and
   costs the same for any number of forests.
4. **No backfill, reconciler or background machinery.** Because grant
   posting creates the index entry before the grant object, and has since
   the grant store was introduced, the only unindexed subject logs are
   ones that never went through `POST /api/grants`. Those return a named
   404 and are repaired one at a time by re-posting the grant, which is
   idempotent and recreates the index entry.
5. **The genesis self-index is mandatory and claim-first.** Posting a
   genesis creates `IndexCreate(R → R)` before writing the genesis object,
   mirroring the grant path. A claim that conflicts with another forest
   writes nothing and returns **422**, because canopy treats every 409 on
   genesis forward as an idempotent "exists".
6. **Status codes.** An unresolved log is **404**; a dangling index entry
   (its forest's genesis is gone) is a miss, not an outage, and resolves
   to 404 with a best-effort index delete. **503** is reserved for an
   unreachable store or RPC. The sealer and the signer classify 404 as
   permanent until repaired and 503 as transient.

## Consequences

- Resolution cost is constant per request and independent of forest
  count; the outage class (a scan exceeding probe budgets) is gone.
- A log initialised on chain with neither a grant object nor an index
  entry, which the probe used to find, now 404s. On the armed onboarding
  paths that set is empty; legacy cases surface by name and take the
  grant re-post repair.
- The registry incidentally served cached forests through an R2 outage.
  Uncached resolutions now return 503 during one; the positive forest
  cache covers hot logs, and no warm-standby state is reintroduced.
- Callers that treated 503 as retryable must not retry a 404 in a tight
  loop.
- Deleting a forest or a grant can leave dangling index entries; any bulk
  pruning of forests must sweep the forest's subject grants and index
  entries with it.

## Alternatives Considered

- **Keep the scan, move it off the startup path.** Removes the crash loop
  but keeps O(forests) work on every miss. Rejected.
- **List-only backfill or reconciler.** Cheap, since key structure alone
  encodes subject → R, but it is standing machinery for a failure that
  announces itself and is repaired individually. Rejected.
- **On-chain event indexer.** Heavier infrastructure (block cursors) and
  no trust gain, since the index only locates. Rejected.
- **External index store (D1, KV or a Durable Object).** The R2
  conditional-put index already gives atomic uniqueness in the same
  consistency and trust domain; a second store adds cross-store
  consistency questions. Rejected.
- **Make the hint mandatory and retire logId-only routes.** The sealer
  looks up authority for cold logs before their first checkpoint, and the
  signer resolves parents with no receipt in hand. LogId-only resolution
  through the index stays; scoped routes remain the preferred path for
  callers that hold a chain binding. Rejected.

## References

- Shipped in [arbor#85](https://github.com/forestrie/arbor/pull/85),
  merged as `7206074`: `services/univocity/src/handlers.go`,
  `handlers_write.go`, `resolve.go`.
- Supersedes [ADR-0001](retired/adr-0001-genesis-driven-logid-resolution.md),
  whose genesis binding still holds but whose registry scan and on-chain
  probe this decision deleted.
- [devdocs ADR-0035](https://github.com/forestrie/devdocs/blob/main/adr/adr-0035-univocity-owned-grant-store-and-authority-correspondence.md):
  univocity-owned grant store and authority correspondence.
- [devdocs ADR-0036](https://github.com/forestrie/devdocs/blob/main/adr/adr-0036-global-logid-r-uniqueness.md):
  global `logId → R` uniqueness.
- [devdocs ADR-0037](https://github.com/forestrie/devdocs/blob/main/adr/adr-0037-forests-storage-and-uuid-log-ids.md):
  the `forests/` storage layout.
