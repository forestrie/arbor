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

## Hybrid resolution (the authority lookup)

Authority resolution is a non-mutating lookup keyed by `logId`. Univocity returns
the authoritative root key + chain binding; the sealer verifies the (untrusted)
delegation certificate **locally** against that key. The certificate is never
sent to univocity and there is no allow/deny verdict on the wire — the
authorization decision is the sealer's local verification.

```mermaid
sequenceDiagram
    autonumber
    participant Sealer
    participant Issuer as Untrusted issuer
    participant Univ as Univocity (trusted)
    participant Chain as Univocity contract
    Sealer->>Univ: GET /api/logs/{logId(D)}/authority
    Univ->>Univ: index logId(D) -> R; load forest
    alt D on-chain
        Univ->>Chain: logRootKey(D)
    else D cold
        Univ->>Univ: verify D grant envelope vs K(O); resolve K(O) = logRootKey(O) [chain] or recurse grant store; root anchors at bootstrapConfig()
    end
    Univ-->>Sealer: 200 { logId, rootLogId, alg, x, y, chainId, contract, source } | 503/502
    Sealer->>Issuer: request delegation for ephemeral key (logId, mmr range)
    Issuer-->>Sealer: delegation cert (signed by D root key, unverified)
    Sealer->>Sealer: local VerifyDelegationLease vs returned rootKey; bind chainId/contract; sign checkpoint
```

## Univocity service (`services/univocity/src`)

Refactor-replace the scan-canopy-R2 + O(N) probe path; univocity now **owns**
storage.

- **Storage layout** (S3/R2 via existing `s3.Client`; superseded path detail in
  [ADR-0004](adr/adr-0004-forests-storage-and-uuid-log-ids.md)):
  - genesis: `forests/forest/{uuid-R}/genesis.cbor` (univocity-owned).
  - grants: `forests/forest/{uuid-R}/grants/auth-log|data-log/{uuid-subject}.cbor`
    (raw transparent statement bytes).
  - index: `forests/index/forest/{uuid-subject}` (ASCII UUID of `R`), created with
    conditional `If-None-Match: *` for atomic uniqueness.
- `POST /api/forest/{R}/genesis` (token-auth): verify
  `genesis.key == contract.bootstrapConfig()` (cached per `(chainId, contract)`);
  store; 201/409. `AllowUnanchoredGenesis` relaxes the anchor for local/dev/e2e.
- `POST /api/grants` (token-auth): decode transparent statement; idempotent index
  create (`logId → R`): new → 201, match → 200, conflict → 409; verify the grant
  chain (envelope vs `K(O)` via chain-or-recursion; bootstrap vs
  `bootstrapConfig()`); store per-forest grant. Reject (4xx) invalid chains so
  only chain-valid grants persist.
- `GET /api/logs/{logId}/authority` (the trusted lookup; non-mutating, no token,
  no cert): resolve `R` via index; establish `K(D)` / anchor by the hybrid rule
  (chain `logRootKey` when initialized, else the chain-valid stored `grantData`);
  respond CBOR `{ logId, rootLogId, alg, x, y, chainId, contract, source }`.
  Resolution failures are `503` (not resolvable) / `502` (chain or store
  unavailable). The sealer verifies the certificate locally against the returned
  key. ES256 only.
- Resolver: `resolve(logId)` = index → R, then chain (`logRootKey`) or grant-store
  recursion. `GET /api/logs/{logId}/public-root` keeps the same CBOR
  `TrustRootResponse` shape (on-chain only); `/authority` adds cold-log
  resolution + chain binding + `source`.
- GC: none. Admin `DELETE /api/forest/{R}` and
  `DELETE /api/forest/{R}/grants/{subject}` (admin-token) for explicit cleanup.
- Config: `UNIVOCITY_API_TOKEN`, `UNIVOCITY_ADMIN_TOKEN`,
  `UNIVOCITY_ALLOW_UNANCHORED_GENESIS`, `GENESIS_R2_URL` (grants bucket),
  `UNIVOCITY_RPC_URLS` (per-chain RPC, not per-contract).

## Sealer (`services/sealer/src`)

- Resolve the log's authority from univocity `GET /api/logs/{logId}/authority`
  (cold-log capable), then request the (untrusted) delegation from
  `DELEGATION_ISSUER_URL` and run local `VerifyDelegationLease` against the
  returned `rootKey` — that local verification is the authorization gate. Bind
  returned `chainId`/`contract` into the lease (closes the plan-0003
  cross-deployment replay gap).
- Enabled when `UNIVOCITY_AUTHORITY_URL` is set (`UNIVOCITY_API_TOKEN` bearer,
  optional since the key material is public).
- Follow-up (not v1): refuse checkpointing a log whose authoritative `R`
  disagrees with a known binding.

## Arbor-flux

- New `univocity` service (deployment/service/serviceaccount/podmonitoring +
  per-slot ingressroute/external-dns/doppler CR), port 9091.
- Taskfile: `service:*:univocity`, `service:secrets:generate:univocity`
  (UNIVOCITY_API_TOKEN/ADMIN_TOKEN; distribute API token to the sealer),
  `service:populate-config:univocity` (GENESIS_R2_URL, UNIVOCITY_RPC_URLS,
  UNIVOCITY_ALLOW_UNANCHORED_GENESIS), provision-cloudflare R2 creds.
- Sealer populate adds `UNIVOCITY_AUTHORITY_URL=http://univocity:9091`.

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
