# Slice 02 — index-first resolution, R-case fallback, 404 contract, verified hint

**Repo:** arbor · **Service:** `services/univocity` · **Status:** draft

The semantic core. After this slice the registry is dead code on every
request path (slice 03 removes the corpse).

## Resolution algorithm (`resolveForestForLog`, grant_chain.go)

For `logId` (no hint):

1. `Store.IndexGet(logId)` → R found → `loadForest(R)` → done.
   (Existing code path, unchanged — O(1), LRU-cached.)
2. Miss → **R case:** `loadForest(logId)` directly (derived-key genesis
   GET; `parseGenesisDoc` already enforces `doc.Forest.R == key`).
   Hit → **self-heal** `IndexCreate(logId → logId)` best-effort → done.
3. Miss → `ErrLogNotResolved` → **404** problem-details:

   > log {logId} is not indexed by this univocity instance; supply
   > `?rootLogId={R}` or use `/api/{chainId}/{contract}/logs/{logId}/…`

   `ErrDoesNotExist` from the store is a miss; any other store error is
   a real 503 (unavailable ≠ unknown — same taxonomy rule as the canopy
   FOR-506 work).

With `?rootLogId={R}` on the logId-only GET routes (`/root`,
`/public-root`, `/authority`):

1. `loadForest(R)` — 404 (forest unknown) if the genesis is absent.
2. `logId == R` → resolved (degenerate R case).
3. Else `Store.GetGrant(R, logId)` must exist → resolved; the endpoint's
   existing chain verification (`verifyGrantChain` / on-chain
   `logRootKey`) then decides as it always has. Absent grant → 404 that
   names both the logId and the hinted R (a *wrong* hint must not read
   as "log does not exist").

The hint is **never trusted** (decisions.md D2): it selects which forest
to verify against; verification is unchanged and O(1).

## Write-path hardening

- `handlePostGenesis`: self-index failure becomes a request failure
  (5xx, idempotent retry) instead of a warn (decisions.md D4).

## Removed behavior

- `resolveForest`'s fallback into `Resolver.Resolve` is deleted here
  (the field can linger until slice 03). No call path may reach
  `TryRefreshScan` or `probeForests` after this slice.
- `ErrLogNotResolved` → 503 mapping (`handlers.go:72`,
  `writeAuthorityError`) becomes 404 (decisions.md D5).

## Tests

- Resolution: index hit; R-case fallback (+ self-heal entry created);
  unknown → 404 with remedy text; store outage → 503 not 404.
- Hint: valid subject hint; `hint == logId`; wrong-forest hint → 404
  naming both ids; hint to absent forest → 404; hinted resolution still
  runs chain verification (a bad grant chain under a correct hint fails
  exactly as before).
- Genesis self-index: failure now fails the POST; retry succeeds.
- Contract pin: no test may observe a scan/probe during resolution
  (assert zero `ListObjects` calls on the request path).
