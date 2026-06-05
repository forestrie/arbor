# BYOK checkpoint seal end-to-end

**Status:** DRAFT  
**Date:** 2026-05-30  
**Related:** [plan-0003](plan-0003-non-custodial-checkpoint-support.md),
[plan-0004](plan-0004-coordinator-backed-byok-lease-proof.md),
[plan-0005](plan-0005-sealer-trust-root-end-to-end.md),
Canopy [plan-0025 — queue-independent grant authorization](https://github.com/forestrie/canopy/blob/main/docs/plans/plan-0025-queue-independent-grant-authorization.md)
(removes SequencingQueue dependence from grant authorization; supersedes the
`auth-data-log-chain` MMRS-readiness retry from the BYOK seal RCA)

## Goal

Prove the plan-0003 gap-4 checkpoint path on the deployed stack: a
wallet-managed log id with no Custodian KMS key flows through SCRAPI register,
forestrie-ingress, Ranger massif commit, Sealer checkpoint signing, R2/MMRS
receipt assembly, and client-side BYOK receipt verification.

The runner acts as the wallet for this bounded proof. It holds an in-memory
ES256 root key, uploads the public root to the delegation coordinator, signs
pending delegation material for Sealer ephemeral delegated keys, and verifies
the returned receipt chain.

## Scope

1. Coordinator pending requests include the full delegated public key and are
   idempotent per `(logId, mmrStart, mmrEnd, delegatedPublicKey)`. Multiple
   distinct keys for the same log/range are allowed so multiple Sealer replicas
   are correctness-safe.
2. Sealer caches pending ephemeral delegated keypairs in RAM. A coordinator
   material-missing 503 maps to `ErrDelegationPending`; the queue message is
   left unacked and the next delivery retries with the cached key when possible.
3. Canopy receipt authority resolution tries coordinator `public-root` first
   and falls back to Custodian for custodial logs.
4. An opt-in Playwright system spec (`E2E_BYOK_SEAL_STRETCH=1`) performs
   non-Custodian bootstrap grant and entry registration through receipt.

## Key decisions

### In-RAM ephemeral keys

Sealer keeps random delegated keypairs only in process memory while material is
pending. This avoids a deterministic derivation seed that would act as a
fleet-wide skeleton key: leaking one seed would reconstruct every log's
checkpoint key. If the pod restarts, Sealer simply requests a new ephemeral key
and the wallet signs a new pending request.

### Multiple ephemerals

The system does not require one canonical delegated key per log. Checkpoints are
self-describing: each checkpoint embeds its delegation certificate in
unprotected label `1000`, and verification chains that specific delegated key to
the log root. R2 checkpoint writes are first-writer-wins with an equal-size
no-op, so concurrent Sealers can race safely; at most one checkpoint persists
per massif.

`replicas: 1` remains the efficient deployment default because the Sealer queue
distributes work. More replicas without log affinity may create extra pending
delegation rows and wallet signatures, but not inconsistent receipts.

## Follow-up: efficient horizontal scaling

Horizontal scale-out should use log-id-prefix sharding, similar to
forestrie-ingress, so each log has one Sealer owner and one in-RAM ephemeral
retry cache. This is out of scope for the gap-4 proof. Open questions:

- whether Cloudflare Queue messages can be partitioned by log prefix;
- whether to use per-shard queues or shard-aware consumers;
- how to rebalance shard ownership during scale events.

## Verification

```sh
cd arbor/services/sealer/src
go test -v ./... -run 'DelegationLeaseManager_|HTTPDelegationIssuer_MapsMaterialMissing'

cd ../../../../canopy
pnpm --filter @canopy/delegation-coordinator test
pnpm --filter @canopy/api test -- receipt-authority-resolver
pnpm --filter @canopy/api-e2e test -- byok-delegation-cbor
pnpm --filter @canopy/api-e2e typecheck
```

Deployed stretch (catalog host, not `api-dev`):

```sh
E2E_BYOK_SEAL_STRETCH=1 \
  CANOPY_BASE_URL=https://api-forest-2.forestrie.dev \
  CUSTODIAN_URL=https://api-forest-2.forestrie.dev \
  task test:e2e:doppler -- tests/system/byok-checkpoint-seal.spec.ts
```

See [canopy plan-0024](../../canopy/docs/plans/plan-0024-byok-checkpoint-seal-rca.md) and
[ADR-0003](../../canopy/docs/adr-0003-delegation-pending-202-accepted.md) for pending
**202 Accepted** and coordinator material validation.
