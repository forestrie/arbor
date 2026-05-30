# Coordinator-backed BYOK lease proof

**Status:** ACCEPTED  
**Date:** 2026-05-25  
**Related:** [plan-0003](plan-0003-non-custodial-checkpoint-support.md),
[canopy plan-0021](../../canopy/docs/plans/plan-0021-delegation-coordinator-apis.md),
[mandate plan-0001](../../mandate/docs/plans/plan-0001-bootstrap.md)

## Goal

Prove the next non-custodial checkpoint slice without deployed Univocity
contracts: a non-Custodian root key can authorize delegation material through
the Delegation Coordinator API shape, and Sealer can verify that material via
an HTTP trust-root client that talks to a non-Custodian trust-root proxy (a
fake in tests today, Univocity in production tomorrow).

This is a lease and issuer proof. It is not the full on-chain publisher, live
Univocity RPC adapter, or final Canopy receipt-authority swap.

Sealer never talks to contracts. It reads roots from `TRUST_ROOT_URL` and
delegation material from `DELEGATION_ISSUER_URL`; both are HTTP services and
either can be non-Custodian.

## Current status

- Custodial delegation seams are complete: Custodian implements
  `POST /api/delegations`; Sealer has `TrustRootClient` and
  `DelegationIssuer`; Canopy has `ReceiptAuthorityResolver`.
- The Delegation Coordinator APIs are deployed and covered for the direct
  coordinator path.
- Receipt Authority BYOK remains incomplete: production Canopy trust roots are
  still Custodian-backed.
- Mandate has a bootstrap wallet UI, but its delegation material signing is not
  yet production COSE certificate assembly.

## Scope

1. Add a Sealer `HTTPTrustRootClient` that fetches the plan-0003 CBOR shape
   from `GET {TRUST_ROOT_URL}/api/logs/{logId}/public-root` and adapts the
   `{logId, alg, x, y}` portion into the existing `LogSigningKey` (PEM) for
   the lease verify path. The CBOR response also carries optional
   `chainId`, `contractAddress`, `domain` fields, but **these are wire-only
   forward-compat placeholders today**: no internal sealer type consumes
   them and no signer or verifier reads them. They are reserved for future
   cryptographic binding of chain provenance, which is expected to flow
   through log data itself rather than transport metadata. See the comment
   on `TrustRootResponse` and `delegationcert.DelegationIssueRequest`.
2. Add an Arbor BYOK lease test that drives Sealer against two independent
   HTTP fakes: a fake trust-root server (returns the test-owned root's x,y
   as CBOR) and a fake issuer server (signs the delegation cert with the
   same non-Custodian root). Sealer is wired with `HTTPTrustRootClient` and
   `HTTPDelegationIssuer` pointing at the two URLs; positive, wrong-root,
   and wrong-log cases are covered.
3. Custodian routing for `POST /api/delegations` uses a single source of
   truth — the local KMS. If the log has a custody key, sign locally; if
   the key is absent (`ErrNoCustodianKeyForLogID`) and
   `DELEGATION_COORDINATOR_URL` is set, proxy the request to the
   coordinator; if neither path resolves, return 404 with the not-found
   problem detail. The coordinator never declares routing — there is no
   per-request `signing-route.mode` probe.
4. Add a Canopy coordinator e2e that exercises pending miss, BYOK material
   submit, successful issue, and pending clearance through deployed
   coordinator APIs.
5. Add a Canopy unit fixture proving delegated receipt verification can use
   an injected non-Custodian root without Custodian HTTP.

## Out of scope

- Deploying Univocity contracts.
- Implementing a live Univocity RPC or ABI client.
- ERC-1271 / Safe signing.
- Full `publishCheckpoint`.
- Full `register-grant` / `register-signed-statement` no-Custodian system e2e.
- Productionizing Mandate COSE certificate assembly.

## Verification

```sh
cd arbor/services/sealer/src
go test -race -v ./... -run 'BYOK|Delegation|TrustRoot'

cd ../../../..
task test:unit

cd ../canopy
pnpm --filter @canopy/delegation-coordinator run test
pnpm --filter @canopy/api test -- receipt-authority-resolver delegation-verify
doppler run --project canopy --config dev -- \
  pnpm --filter @canopy/api-e2e test:e2e:coordinator
task test:e2e:doppler
```

## Follow-up

Promote `HTTPTrustRootClient` to production wiring once `services/univocity`
exposes a non-mock `/api/logs/{logId}/public-root`. Then promote the Canopy
resolver to a production `UnivocityTrustRootAdapter`, and move Mandate from
bootstrap signing to real COSE delegation certificate assembly.

## Verification record

**Date:** 2026-05-30

- Arbor PR [#7](https://github.com/forestrie/arbor/pull/7) merged via merge
  commit `29f08dc`. Branch `fix/custodian-docker-delegationcert`.
  - `681f58b` HTTP trust-root seam + coordinator proxy
  - `5f8f320` single-source-of-truth routing + drop chain fields
- Arbor pre-flight (local): `go vet ./services/...` clean across sealer,
  custodian, univocity, delegationcert; `task test:unit` and
  `task test:integration` both green.
- GitHub Actions Build and Deploy run
  [#26683837980](https://github.com/forestrie/arbor/actions/runs/26683837980)
  succeeded. Pushed `ranger`, `scout`, `sealer`, `custodian` images at tag
  `main-29f08dc-411`.
- Flux ImageUpdateAutomation pushed 4 bumps to
  `arbor-flux/flux/image-updates`, each touching only `clusters/ledger-a/`;
  arbor-flux PR
  [#12](https://github.com/forestrie/arbor-flux/pull/12) merged via merge
  commit `93ce464`.
- `kubectl -n forestrie-a` confirms `sealer` and `custodian` Deployments
  rolled out to tag `main-29f08dc-411`. Startup logs show:
  - `sealer`: `TRUST_ROOT_URL=http://custodian:9092`,
    `DELEGATION_ISSUER_URL=http://custodian:9092`,
    `CUSTODIAN_URL` retained as deprecated alias with a warning.
  - `custodian`: `DELEGATION_COORDINATOR_URL=https://coordinator.forest-2.forestrie.dev`,
    `DELEGATION_COORDINATOR_TOKEN` populated.
- Canopy e2e against `api-forest-2.forestrie.dev` (ledger-a catalog
  hostname):
  - `task test:e2e:doppler` → 13 passed (3 integration, 2 custodian, 8
    system) covering bootstrap grant mint, register-grant via
    forestrie-ingress, child auth grant, and auth→data log delegation
    chain.
  - `pnpm --filter @canopy/api-e2e test:e2e:coordinator` → 12 passed
    covering Phase 3 coordinator APIs, BYOK material miss/store/issue
    flow, custodian pre-wallet proxy route, and signing-route wallet
    marking.
  - `E2E_COORDINATOR_SEALER_STRETCH=1` stretch run of
    `coordinator-delegation-issuance.spec.ts` → 2 passed (dev + prod
    projects). Proves: mark wallet-managed → POST `/api/delegations`
    miss creates pending entry → POST runner-signed BYOK material
    clears pending → subsequent POST `/api/delegations` returns the
    stored material via custodian proxy.
