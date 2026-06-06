# Plan 0009: Forests storage and UUID log IDs

**Status**: DRAFT  
**Date**: 2026-06-06  
**Related**: [ADR-0004](adr/adr-0004-forests-storage-and-uuid-log-ids.md),
[plan-0008](plan-0008-univocity-grant-store-and-authority-resolver.md),
[canopy plan-0030](../../canopy/docs/plans/plan-0030-forests-storage-and-uuid-logid.md)

## Goal

Refactor univocity owned-store paths and off-chain log ID representation per
ADR-0004.

## Tasks

1. Add `services/pkgs/logid` with `UUID [16]byte` and contract/CBOR padding helpers.
2. Migrate univocity `Store`, handlers, registry, and grant chain to new layout.
3. Port grant class flags; route grants to `auth-log/` or `data-log/`.
4. Update sealer authority resolver and signer parent resolver for UUID paths.
5. Update unit tests; `go test ./...` in univocity.

## Dev migration (clean break)

After deploy **univocity** then **canopy-api**, wipe legacy prefixes in
`forest-dev-5-logs` and canopy `R2_GRANTS` (clean break; no dual-read):

```sh
# Univocity grants bucket (forest-dev-5-logs) — list legacy objects
wrangler r2 object list forest-dev-5-logs --prefix forest/
wrangler r2 object list forest-dev-5-logs --prefix index/log/

# Delete per object (or use bulk S3 API). Canopy genesis copies:
task cloudflare:genesis:delete LOG_ID=<uuid-R>
```

Re-run forest genesis POST and bootstrap grants; verify e2e with `task test:e2e`.

## Verification

- `go test ./...` under `services/univocity/src`
- Sealer authority resolver tests pass with UUID fixtures
