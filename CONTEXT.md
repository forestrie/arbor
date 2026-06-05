# Arbor

Arbor hosts Forestrie operational services (sealer, signer, ranger, univocity)
that extend transparency logs and publish checkpoints to Univocity contracts.

## Language

**Forest**:
The namespace of logs sharing one bootstrap root authority log `R`, as defined
in canopy. Univocity resolves consumer requests against forests discovered from
genesis documents.
_Avoid_: deployment, stack (use only for ops topology).

**Bootstrap root auth log (`R`)**:
The forest root authority log id; matches genesis `bootstrap-logid` and
on-chain `rootLogId` after bootstrap.
_Avoid_: bootstrap log alone (conflicts with bootstrap grant).

**Forest genesis document**:
Curator-written CBOR at `forest/{hex64(R)}/genesis.cbor` in the grants bucket.
Source of `(chain-id, univocity-addr)` for univocity's forest registry.
_Avoid_: genesis grant.

**Chain binding**:
`(chain-id, univocity contract address)` for the forest, from genesis v1.
_Avoid_: pinning chain/contract in sealer or signer config.

**Trust-root service**:
The univocity HTTP read proxy for contract log state (`logConfig`, `logRootKey`,
`isLogInitialized`). Exposes scoped and logId-only routes.
_Avoid_: auth-log service.

**Forest registry**:
Univocity's in-memory list of forests loaded from genesis R2 objects.

**Owner root key vs target root key**:
A grant is signed by the **owner's root key** (`grantData_O`) and establishes the
**target's root key** (`grantData_T`). They coincide only at the root, where
`T = O = R` and the key is the bootstrap key (self-referential bootstrap grant).
The grant **envelope** for `T` verifies against `grantData_O`; the
**delegation/checkpoint** for `T` verifies against `grantData_T`.
_Avoid_: "the grant's own key" (self-signing) for non-root links.

**Grant issuance vs checkpoint delegation**:
Grant issuance is a **root-key, non-delegatable** operation. The delegation
profile (`forestrie.univocity.delegation.v1`) is **checkpoint-signing only** —
it never authorizes issuing grants.
_Avoid_: conflating delegation certs with grant issuance authority.

**Authority resolver (authorize)**:
Univocity's trusted decision `POST /api/authorize`: resolve `logId → R` (global
index), verify the delegation cert against `grantData_D`, establish `K(O)` by the
hybrid rule (on-chain `logRootKey` or grant-store recursion, anchored at
`bootstrapConfig()`), and return `{ rootKey, chainId, contract, source }` or 401.
_Avoid_: "trust-root lookup" for the cert decision (that is the public-root read).

**Owned grant store**:
Univocity-owned S3/R2 objects: genesis (`forest/{hex64(R)}/genesis.cbor`), grants
(`forest/{hex64(R)}/grants/{hex64(subject)}.cbor`), and the global index
(`index/log/{hex64(subject)} → R`, created with `If-None-Match: *`). Persists only
until a log's first checkpoint; no long-term backup.
_Avoid_: "canopy grant storage" (canopy no longer owns it).

**Forest uniqueness (`logId → R`)**:
A subject `logId` belongs to exactly one forest `R` globally, enforced atomically
at grant POST (201 new / 200 idempotent / 409 conflict).

## Example dialogue

**Dev:** Sealer got a massif event with only `logId` — how does it pick the contract?

**Expert:** It calls univocity `GET /api/logs/{logId}/public-root`. Univocity
loaded forests from genesis in the grants bucket, probed `isLogInitialized`, and
calls the right contract. Sealer never sees `chainId` or the contract address
unless it chooses to read optional CBOR fields later.

## Related

- [canopy CONTEXT.md](../canopy/CONTEXT.md) — forest and genesis terminology
- [plan-0007](docs/plan-0007-univocity-genesis-trust-root-resolver.md)
- [plan-0008](docs/plan-0008-univocity-grant-store-and-authority-resolver.md) — owned grant store + authority resolver
- [ADR-0001](docs/adr/adr-0001-genesis-driven-logid-resolution.md)
- [ADR-0002](docs/adr/adr-0002-univocity-owned-grant-store-and-authority-correspondence.md)
- [ADR-0003](docs/adr/adr-0003-global-logid-r-uniqueness.md)
