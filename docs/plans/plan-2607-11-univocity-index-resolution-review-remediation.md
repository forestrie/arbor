---
id: 2607-11
status: complete
created: 2026-07-30
refs: [FOR-510]
---

# Plan 2607-11 — plan-2607-10 implementation review remediation

**Status:** IMPLEMENTED (2026-07-30, on arbor#85) · **Related:** [plan-2607-10](plan-2607-10-univocity-index-resolution/README.md), arbor#85 (`3a7bd02`), FOR-510

review-changes run on the plan-2607-10 implementation (2026-07-30).
Worst = **1 High + 2 Medium**; all items were PR-local fixes on arbor#85,
none reopened the plan's locked decisions. All R1-R6 remediated (R5 =
accepted note in the plan-2607-10 README).

## R1 High — cross-forest genesis conflict is swallowed as success by canopy

`handlePostGenesis`'s new claim-first conflict returns **409** — but
canopy's genesis-forward contract (`univocity-genesis-client.ts`) maps
*every* 409 to `exists`, and `post-genesis.ts:363` treats `exists` as
idempotent success (`alreadyExisted: true`). A genuine uniqueness
violation (logId already bound as another forest's subject) would
therefore report onboarding success **with no genesis stored at
univocity**. The 409 status is contractually reserved for the
idempotent same-R "genesis exists" signal.

**Fix (arbor, this PR):** cross-forest claim conflict → **422
Unprocessable Entity** ("logId belongs to another forest"). Canopy maps
non-409 4xx → `rejected` → a loud 400 to the caller. Same-R
genesis-exists 409 unchanged. Acceptance: unit test pins 422 for the
claim conflict and 409 for the same-R retry; note the divergence from
`handlePostGrant`'s 409 (the *grant* client maps 409 → conflict
explicitly, so that contract is fine as-is).

## R2 Medium — dangling-locator self-heal can reap the genesis claim

`resolveForestForLog`'s dangling-locator branch deletes the index entry
whenever the target genesis is absent. For a **self-claim** (`r ==
logID`) that state is exactly the claim-first crash window between
`IndexCreate(R,R)` and `PutGenesisIfAbsent` — deleting it forfeits the
in-flight genesis's uniqueness reservation to any concurrent claimant.

**Fix:** skip the self-heal delete when `r == logID` (resolution still
falls through to the R-case miss → 404; the claim survives for the
genesis retry). Acceptance: test — self-claim without genesis resolves
404 and the index entry remains.

## R3 Medium — unbounded negative cache on a public 404 path

`ForestCache.PutNegative` grows an unbounded map; expired entries are
only deleted when the *same* key is queried again. The logId-only routes
are unauthenticated and now 404 cheaply, so a random-logId spray grows
the map without bound — on the 256Mi-limited pod that is an OOM
crash-loop vector. (The shape predates this PR, but the miss path is now
the primary public path.)

**Fix:** bound the negative map with the same evict-oldest ring as the
positive side (shared or separate cap). Acceptance: test — inserting
`cap+n` negatives holds size ≤ cap.

## Low / deferred

- **R4:** hint (`?rootLogId=`) wiring on `/authority` untested — the
  tests exercise `/root` only; add one authority-route hint test.
- **R5 (note, accept):** the in-RAM registry previously served cached
  forests through an R2 outage; now uncached resolutions 503 during
  outage. Positive cache covers hot logs and the taxonomy is honest —
  record in plan-2607-10 README, no code change.
- **R6:** `ForestCache.Clear` is dead code after `OnRegistryScan`'s
  removal — delete it.

## Verified sound (for the record)

- Sealer classification is `errors.As`-only; nothing string-matches
  "authority returned" — and the error text is byte-identical anyway.
- Claim-first ordering runs *after* `verifyGenesisAnchor`, so RPC
  failures cannot strand claims.
- Hint failures never write negative-cache entries (a wrong hint cannot
  404-poison unhinted resolution).
- The grant path's 409 contract (`handlePostGrant` / canopy grant
  client 409 → conflict) is untouched.
- Zero-enumeration is test-pinned (`TestResolve_NeverEnumerates`).
