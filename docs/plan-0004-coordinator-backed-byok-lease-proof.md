# Coordinator-backed BYOK lease proof

**Status:** DRAFT  
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
   (`{logId, alg, x, y, chainId, contractAddress, domain, ...}`) from
   `GET {TRUST_ROOT_URL}/api/logs/{logId}/signing-key` and adapts it into the
   existing `LogSigningKey` (PEM) for the lease verify path.
2. Carry trust-root domain data into Sealer's generic delegation issuer request.
3. Add an Arbor BYOK lease test that drives Sealer against two independent
   HTTP fakes: a fake trust-root server (returns the test-owned root's x,y as
   CBOR) and a fake issuer server (signs the delegation cert with the same
   non-Custodian root). Sealer is wired with `HTTPTrustRootClient` and
   `HTTPDelegationIssuer` pointing at the two URLs; positive, wrong-root, and
   wrong-log cases are covered, and the test asserts ABI metadata
   (domain / chainId / contractAddress) propagates from the trust-root fake
   into the issuer request.
4. Add a Canopy coordinator e2e that exercises pending miss, BYOK material
   submit, successful issue, and pending clearance through deployed coordinator
   APIs.
5. Add a Canopy unit fixture proving delegated receipt verification can use an
   injected non-Custodian root without Custodian HTTP.

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
exposes a non-mock `/api/logs/{logId}/signing-key`. Then promote the Canopy
resolver to a production `UnivocityTrustRootAdapter`, and move Mandate from
bootstrap signing to real COSE delegation certificate assembly.
