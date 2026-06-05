---
Status: DRAFT
Date: 2026-06-03
Related: [plan-0003](plan-0003-non-custodial-checkpoint-support.md), [plan-0005](plan-0005-sealer-trust-root-end-to-end.md), [ADR-0001](adr/adr-0001-genesis-driven-logid-resolution.md), [canopy CONTEXT.md](../../canopy/CONTEXT.md)
---

# Plan 0007: Univocity genesis-driven trust-root resolver

## Goal

Refactor `services/univocity` into a **two-layer** trust-root service:

1. **Scoped proxy** — `GET /api/{chainId}/{contract}/…` reads one Univocity contract (explicit chain + address).
2. **LogId-only layer** — `GET /api/logs/{logId}/root` and `GET /api/logs/{logId}/public-root` resolve the forest from curator genesis in R2 and on-chain probes; consumers (signer, sealer) never pass chain/contract.

Chain binding enters only via canopy `POST /api/forest/{R}/genesis`. Ranger and the register surface stay forest-agnostic.

## Configuration

| Variable | Required | Purpose |
|----------|----------|---------|
| `UNIVOCITY_RPC_URLS` | yes | JSON map `chainId` → RPC URL; fail-fast if missing/empty |
| `GENESIS_R2_URL` | yes | S3-compatible URL for canopy **grants** bucket (`R2_GRANTS`) |
| `AWS_ACCESS_KEY_ID` | yes | SigV4 for genesis LIST/GET |
| `AWS_SECRET_ACCESS_KEY` or `R2_TOKEN` | yes | SigV4 secret |
| `GENESIS_SCAN_MIN_INTERVAL` | no (default 60s) | Circuit breaker between registry refresh scans |
| `LOG_FOREST_CACHE_SIZE` | no (default 10000) | Bounded `logId → forest` cache |

## Forest registry and `resolve(logId)`

- **Startup:** required `Scan()` of `forest/*/genesis.cbor` before HTTP serves.
- **v1 genesis only** (`genesis-version`, `chain-id`, `univocity-addr`, `bootstrap-logid`).
- **Refresh:** scan-on-miss when resolve fails, gated by `GENESIS_SCAN_MIN_INTERVAL`; full replace of forest list; clear positive cache on refresh.
- **Resolve steps:**
  1. Positive cache hit.
  2. Genesis identity: `logId == R` → forest without RPC.
  3. Probe `isLogInitialized(logId)` per forest; 0 → miss; 1 → win; >1 → **503** ambiguous.
  4. Refresh scan + retry 2–3 once.
  5. Still unknown → **503** transient + negative cache.

## Consumer contracts

- **Signer:** `GET /api/logs/{parentLogId}/root` → `{exists, rootLogId}`; **503** → warn + ParentKeys fallback.
- **Sealer:** `GET /api/logs/{logId}/public-root` with `Accept: application/cbor` → `TrustRootResponse {logId, alg, x, y}`; **404** → Custodian fallback; **503** → retry (no fallback).
- **KS256** logs: **404** from univocity (ES256-only).

## Out of scope

- Canopy API changes, Ranger key/metadata changes, massif layout changes.

## Verification

```sh
cd services/univocity/src && go build ./... && go test ./...
cd services/signer/src && go test ./...
cd services/sealer/src && go test ./...
```
