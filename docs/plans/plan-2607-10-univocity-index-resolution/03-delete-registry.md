# Slice 03 — delete ForestRegistry / probe / rescan; config + test cleanup

**Repo:** arbor · **Service:** `services/univocity` · **Status:** draft

Pure deletion once slice 02 has removed every caller.

## Deletions

- `forest_registry.go` (`ForestRegistry`, `Scan`, `TryRefreshScan`).
- `resolver.go` `probeForests`, `matchGenesisIdentity`, and the
  registry-backed `Resolve` (if `ForestResolver` survives at all, it is
  only as the owner of `forestLRUCache`; consider folding the cache into
  the API/store layer and deleting the type).
- `cmd/univocity/main.go`: registry construction, startup scan goroutine
  from slice 01; readyz reverts to a cheap store-reachability check (or
  unconditional — decide in review; it must not list).
- `API.Resolver` field and the `a.Resolver != nil` fallback branch.

## Config

- `GENESIS_SCAN_MIN_INTERVAL` is dual-used as the scan circuit-breaker
  **and** the negative-cache TTL (`NewForestResolver` negTTL). Keep the
  env var accepted-but-ignored for one release (log a deprecation line),
  introduce `LOG_FOREST_NEG_TTL` (default: current value, 60s) for the
  negative cache, which stays — it bounds repeated 404 lookups.
- `RPC_CHAIN_IDS` allow-list check moves from scan-time
  (`rpcURLs[entry.ChainID]` filter in `scanLocked`) to `loadForest`
  (refuse to serve a forest whose chain is not configured — same
  behavior, per-lookup instead of per-scan).

## Tests

- Delete registry/scan/probe suites; port any still-meaningful cases
  (chain-filter, ambiguity → gone by construction) onto the new paths.
- Startup: no `ListObjects` call at all (assert on the mock lister).
- `ListForests` (store) survives — the admin/delete tooling and the
  scoped logs listing may still want it — but nothing on the resolution
  or startup path may call it.
