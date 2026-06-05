---
Status: DRAFT
Date: 2026-06-05
Related: [plan-0003](plan-0003-non-custodial-checkpoint-support.md), [plan-0005](plan-0005-sealer-trust-root-end-to-end.md), [plan-0007](plan-0007-univocity-genesis-trust-root-resolver.md), [ADR-0001](adr/adr-0001-genesis-driven-logid-resolution.md), [ADR-0002](adr/adr-0002-univocity-owned-grant-store-and-authority-correspondence.md), [ADR-0003](adr/adr-0003-global-logid-r-uniqueness.md), [canopy plan-0029](../../canopy/docs/plans/plan-0029-delegate-grant-validation-to-univocity.md), [CONTEXT.md](../CONTEXT.md)
---

# Plan 0008: Univocity owned grant store and authority resolver

## Goal

Move genesis + grant storage ownership to the arbor univocity service and add a
trusted, cryptographically-anchored "is this delegation authorized?" resolver so
checkpoints can be sealed for logs **before they exist on-chain**, removing the
Custodian/coordinator central-trust dependency for the pre-chain window. **No
on-chain contract changes.**

## Why (assessment outcome)

The in-flight design ([plan-0007](plan-0007-univocity-genesis-trust-root-resolver.md))
cannot resolve `logId → auth log` before a log's first checkpoint is on-chain
(`resolveForest` → 503), so the sealer leans on a Custodian/coordinator fallback
for the pre-chain window — the central trust we want to remove. The new design
stores the grant **signature chain** off-chain and verifies it, anchored to the
immutable on-chain bootstrap key.

**Authority correspondence:** on-chain authority = grant **inclusion in owner
MMR** + **checkpoint/delegation signature** vs the log root key; the off-chain
grant **COSE envelope** is the same authority expressed at ingress. The contract
never inspects the grant envelope, so tightening "who signs the envelope" needs
**no contract change** (the leaf preimage carries no signature; `publishCheckpoint`
is permissionless — `_msgSender()` is event-only). See [ADR-0002](adr/adr-0002-univocity-owned-grant-store-and-authority-correspondence.md).

## Core invariants

- A grant is signed by the **owner's root key** (`grantData_O`); it establishes
  the **target's root key** (`grantData_T`). At the root, `T = O = R` and the key
  is the bootstrap key (self-referential bootstrap grant).
- Two distinct keys per non-root link: the **delegation/checkpoint** for `T`
  verifies against `grantData_T`; the **grant envelope** for `T` verifies against
  `grantData_O`. They coincide only at the root.
- Grant issuance is a **root-key (non-delegatable)** operation; the delegation
  profile (`forestrie.univocity.delegation.v1`) is **checkpoint-signing only**.
- A subject `logId` belongs to **exactly one** forest `R` globally (uniqueness
  enforced at canopy's edge; see [ADR-0003](adr/adr-0003-global-logid-r-uniqueness.md)).
- Off-chain anchor is bound to chain: univocity verifies
  `genesis.key == contract.bootstrapConfig()` per forest (cached).

## Hybrid resolution (the authorize decision)

```mermaid
sequenceDiagram
    autonumber
    participant Sealer
    participant Issuer as Untrusted issuer
    participant Univ as Univocity (trusted)
    participant Chain as Univocity contract
    Sealer->>Issuer: request delegation for ephemeral key (logId, mmr range)
    Issuer-->>Sealer: delegation cert (signed by D root key, unverified)
    Sealer->>Univ: POST /api/authorize { certificate }
    Univ->>Univ: index logId(D) -> R; load D grant; verify cert sig vs grantData_D
    alt D on-chain
        Univ->>Chain: logRootKey(D) == grantData_D ?
    else D cold
        Univ->>Univ: verify D grant envelope vs K(O); resolve K(O) = logRootKey(O) [chain] or recurse grant store; root anchors at bootstrapConfig()
    end
    Univ-->>Sealer: 200 { authorized, authLogId, rootKey{alg,x,y}, chainId, contract, source } | 401
    Sealer->>Sealer: local VerifyDelegationLease vs returned rootKey; bind chainId/contract; sign checkpoint
```

## Univocity service (`services/univocity/src`)

Refactor-replace the scan-canopy-R2 + O(N) probe path; univocity now **owns**
storage.

- **Storage layout** (S3/R2 via existing `s3.Client`):
  - genesis: `forest/{hex64(R)}/genesis.cbor` (univocity-owned).
  - grants: `forest/{hex64(R)}/grants/{hex64(subject)}.cbor` (raw transparent
    statement bytes).
  - index: `index/log/{hex64(subject)} → R` (32 bytes), created with conditional
    `If-None-Match: *` for atomic uniqueness.
- `POST /api/forest/{R}/genesis` (token-auth): verify
  `genesis.key == contract.bootstrapConfig()` (cached per `(chainId, contract)`);
  store; 201/409. `AllowUnanchoredGenesis` relaxes the anchor for local/dev/e2e.
- `POST /api/grants` (token-auth): decode transparent statement; idempotent index
  create (`logId → R`): new → 201, match → 200, conflict → 409; verify the grant
  chain (envelope vs `K(O)` via chain-or-recursion; bootstrap vs
  `bootstrapConfig()`); store per-forest grant. Reject (4xx) invalid chains so
  only chain-valid grants persist.
- `POST /api/authorize` (token-auth; the trusted endpoint; POST carries the cert):
  CBOR `{ certificate, logId? }`; resolve `R` via index; verify cert signature vs
  `grantData_D`; establish `K(O)` / anchor by the hybrid rule; respond
  `200 { authorized, logId, rootLogId, alg, x, y, chainId, contract, source }`
  or `401`. ES256 delegated path only.
- Resolver: `resolve(logId)` = index → R, then chain (`logRootKey`) or grant-store
  recursion. `GET /api/logs/{logId}/public-root` keeps the same CBOR
  `TrustRootResponse` shape, now backed by chain-or-grant.
- GC: none. Admin `DELETE /api/forest/{R}` and
  `DELETE /api/forest/{R}/grants/{subject}` (admin-token) for explicit cleanup.
- Config: `UNIVOCITY_API_TOKEN`, `UNIVOCITY_ADMIN_TOKEN`,
  `UNIVOCITY_ALLOW_UNANCHORED_GENESIS`, `GENESIS_R2_URL` (grants bucket),
  `UNIVOCITY_RPC_URLS` (per-chain RPC, not per-contract).

## Sealer (`services/sealer/src`)

- After obtaining the (untrusted) delegation from `DELEGATION_ISSUER_URL`, call
  univocity `POST /api/authorize`; gate sealing on `200`. Keep local
  `VerifyDelegationLease` against the returned `rootKey` (defense in depth); bind
  returned `chainId`/`contract` into the lease (closes the plan-0003
  cross-deployment replay gap).
- Enabled when `UNIVOCITY_AUTHORIZE_URL` is set (`UNIVOCITY_API_TOKEN` bearer).
- Follow-up (not v1): refuse checkpointing a log whose authoritative `R`
  disagrees with a known binding.

## Arbor-flux

- New `univocity` service (deployment/service/serviceaccount/podmonitoring +
  per-slot ingressroute/external-dns/doppler CR), port 9091.
- Taskfile: `service:*:univocity`, `service:secrets:generate:univocity`
  (UNIVOCITY_API_TOKEN/ADMIN_TOKEN; distribute API token to the sealer),
  `service:populate-config:univocity` (GENESIS_R2_URL, UNIVOCITY_RPC_URLS,
  UNIVOCITY_ALLOW_UNANCHORED_GENESIS), provision-cloudflare R2 creds.
- Sealer populate adds `UNIVOCITY_AUTHORIZE_URL=http://univocity:9091`.

## Out of scope / deferred

- Univocity Solidity contract changes (none required).
- Grant-issuance delegation (owners issue grants via ephemeral keys) — non-goal.
- KS256 delegated checkpoints (ES256-only delegated path).
- Automatic grant GC strategy (start with explicit deletion).
- Sealer R-disagreement hardening (follow-up).
- Univocity image automation (ImageRepository/ImagePolicy) — tag pinned for now.

## Verification

- `cd services/univocity/src && go build ./... && go test ./...`
- `cd services/sealer/src && go test ./...`; `go vet ./services/...`
- canopy: see [plan-0029](../../canopy/docs/plans/plan-0029-delegate-grant-validation-to-univocity.md).
