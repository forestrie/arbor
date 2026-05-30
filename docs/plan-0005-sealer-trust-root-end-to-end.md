# Sealer trust-root end-to-end via a real non-Custodian proxy

**Status:** DRAFT  
**Date:** 2026-05-30  
**Related:** [plan-0003](plan-0003-non-custodial-checkpoint-support.md),
[plan-0004](plan-0004-coordinator-backed-byok-lease-proof.md),
[canopy plan-0021](../../canopy/docs/plans/plan-0021-delegation-coordinator-apis.md)

## Goal

Cut the Sealer trust-root proxy out of Custodian. Today every deployed
sealer reads `TRUST_ROOT_URL` and `DELEGATION_ISSUER_URL` from the same
Custodian host. plan-0004 proved the two-seam architecture exists end to
end and the coordinator can proxy delegation issuance for wallet-managed
logs, but Sealer's trust root is still a Custodian public-key endpoint
adapted by `CustodianPublicTrustRootClient`. The next slice points
`TRUST_ROOT_URL` at a real non-Custodian service that returns the
CBOR `TrustRootResponse` directly, so that an entire BYOK checkpoint
round trip can be proven without Custodian holding the trust-root key.

This is still the **lease and verify** slice. It does not deploy
Univocity contracts, does not implement an on-chain publisher, and does
not move chain-provenance binding into the COSE to-be-signed payload.

## Scope

1. Deploy a small non-Custodian trust-root proxy that serves
   `GET /api/logs/{logId}/public-root` returning the same CBOR shape
   defined in `services/sealer/src/trust_root_response.go`. Production
   wiring uses `delegation-coordinator` as the proxy host (it already
   stores BYOK material per log id; the public-root endpoint is added
   beside the existing `/api/material` and `/api/signing-route` routes).
   The endpoint is explicitly marked as a stop-gap until Univocity is
   live; comments in the worker source name it as such.
2. Promote Sealer to use `HTTPTrustRootClient` against
   `TRUST_ROOT_URL=https://coordinator.{env}.forestrie.dev` for any log
   whose `public-root` lookup succeeds, falling back to
   `CustodianPublicTrustRootClient` (current behaviour) for logs whose
   root is still Custodian-held. The selector is presence-based: try
   `TRUST_ROOT_URL/api/logs/{logId}/public-root`; on 404 fall back. This
   keeps custodial logs working without operator-per-log config.
3. Wire the BYOK lease test in
   `services/sealer/src/request_log_delegation_byok_test.go` to drive
   the **deployed** coordinator's `public-root` endpoint with a runner-
   provisioned test root, then verify the issuance proxy chain end to
   end. Replace the in-test `httptest` trust-root fake with a coordinator
   roundtrip when `E2E_COORDINATOR_SEALER_STRETCH=1`.
4. Add a Canopy coordinator e2e covering BYOK `public-root` upload,
   custody-keys absent, and `POST /api/delegations` returning material
   that verifies against the uploaded public root. Reuses
   `coordinator-byok-material.spec.ts` setup.
5. Mark `CUSTODIAN_URL` for removal from sealer config and add a CHANGELOG
   note describing the two-seam migration path. The deprecation warning
   already logs at startup.

## Out of scope

- Univocity contracts and any on-chain root publication.
- Replacing the coordinator's public-root endpoint with an RPC adapter.
- Moving chain-provenance binding (`Domain`, `ChainID`,
  `ContractAddress`) from wire-only into the COSE to-be-signed payload.
- Productionizing Mandate COSE delegation certificate assembly.
- Hardware-backed BYOK root key custody.

## Verification

```sh
cd arbor/services/sealer/src
go test -race -v ./... -run 'BYOK|Delegation|TrustRoot'

cd ../../../..
task test:unit && task test:integration

cd ../canopy
pnpm --filter @canopy/delegation-coordinator run test
doppler run --project canopy --config dev -- \
  pnpm --filter @canopy/api-e2e test:e2e:coordinator
E2E_COORDINATOR_SEALER_STRETCH=1 \
  CANOPY_FQDN=api-forest-2.forestrie.dev \
  CANOPY_BASE_URL=https://api-forest-2.forestrie.dev \
  doppler run --project canopy --config dev -- \
  pnpm --filter @canopy/api-e2e exec playwright test \
    tests/system/coordinator-delegation-issuance.spec.ts
task test:e2e:doppler
```

After ledger-a rollout, exercise a wallet-managed log through the deployed
sealer (currently blocked behind sealer's per-log selector landing in
step 2 above).

## Follow-up

Once the coordinator-hosted `public-root` proxy is exercised, the next
plan replaces it with a Univocity-backed adapter: same CBOR shape, but
the public root is derived from chain state rather than a coordinator
KV. At that point the chain-provenance fields on the wire types stop
being placeholders and become inputs to the freshness check described
in plan-0003 "Stale or malicious trust-root proxy response".
