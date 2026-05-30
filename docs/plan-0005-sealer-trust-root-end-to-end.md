# Sealer trust-root end-to-end via a real non-Custodian proxy

**Status:** DRAFT (§2–3 implemented; §4 canopy e2e done via plan-0023)  
**Date:** 2026-05-30  
**Related:** [plan-0003](plan-0003-non-custodial-checkpoint-support.md),
[plan-0004 (ACCEPTED)](plan-0004-coordinator-backed-byok-lease-proof.md),
[canopy plan-0023 (ACCEPTED)](../canopy/docs/plans/plan-0023-coordinator-public-root.md)

## Goal

Cut the Sealer trust-root proxy out of Custodian for BYOK logs. Deployed Sealer
reads `TRUST_ROOT_URL` from the public delegation-coordinator
(`GET /api/logs/{logId}/public-root`), falls back to Custodian public-key lookup on
404, and keeps delegation issuance on in-cluster Custodian (proxy to coordinator
for wallet-managed logs).

North-star (plan-0003): full BYOK checkpoint seal — see plan-0003 and follow-on
plan for gap 4 (Ranger → Sealer → MMRS).

## Scope status

| § | Item | Status |
|---|------|--------|
| 1 | Coordinator `public-root` endpoint | **Done** (canopy plan-0023) |
| 2 | `SelectingTrustRootClient` + `HTTPTrustRootClient` bearer | **Done** |
| 3 | Deployed BYOK lease stretch (`E2E_COORDINATOR_SEALER_STRETCH=1`) | **Done** (Go test) |
| 4 | Canopy coordinator e2e BYOK public-root | **Done** (plan-0023 / `coordinator-byok-public-root.spec.ts`) |
| 5 | arbor-flux `TRUST_ROOT_URL` + `TRUST_ROOT_TOKEN` | **Done** |
| — | `CUSTODIAN_URL` deprecation note at startup | **Done** (existing warning) |

## Implementation notes

- `HTTPTrustRootClient` sends `Authorization: Bearer` when `TRUST_ROOT_TOKEN` is set.
- `ErrTrustRootNotFound` (HTTP 404) triggers Custodian fallback; other coordinator
  errors fail closed.
- `main.go` wires `NewSelectingTrustRootClient`.
- arbor-flux: sealer `TRUST_ROOT_URL=https://coordinator.{DNS_SUB}.{DNS_APEX}`;
  `TRUST_ROOT_TOKEN` copied from `canopy-{lane}` `COORDINATOR_APP_TOKEN`;
  `DELEGATION_ISSUER_URL=http://custodian:9092`.

## Out of scope (this plan)

- Full Ranger → Sealer → MMRS BYOK seal e2e (next plan toward plan-0003 north-star).
- Univocity contracts and on-chain root publication.
- Canopy receipt authority coordinator-first (canopy plan-0024 suggested).
- SCRAPI non-custodial bootstrap grant.
- Mandate / hardware-backed root productionization.

## Verification

```sh
cd arbor/services/sealer/src
go test -race -v ./... -run 'BYOK|Delegation|TrustRoot|Selecting|Config'

# Deployed stretch (after coordinator + custodian + sealer rollout)
E2E_COORDINATOR_SEALER_STRETCH=1 \
  TRUST_ROOT_URL=https://coordinator.forest-2.forestrie.dev \
  TRUST_ROOT_TOKEN=<from doppler canopy-{lane}> \
  DELEGATION_ISSUER_URL=https://custodian.../v1 \
  DELEGATION_ISSUER_TOKEN=<custodian app token> \
  go test -race -v ./... -run 'BYOKCoordinatorStretch'

cd ../canopy
pnpm --filter @canopy/delegation-coordinator run test
doppler run --project canopy --config dev -- \
  pnpm --filter @canopy/api-e2e test:e2e:coordinator
```

## Follow-up

Replace coordinator KV `public-root` with Univocity chain-derived roots (same CBOR
shape). Enable full BYOK checkpoint seal on deployed stack once Sealer trust +
delegation path is stable in production.
