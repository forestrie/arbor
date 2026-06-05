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

## Example dialogue

**Dev:** Sealer got a massif event with only `logId` — how does it pick the contract?

**Expert:** It calls univocity `GET /api/logs/{logId}/public-root`. Univocity
loaded forests from genesis in the grants bucket, probed `isLogInitialized`, and
calls the right contract. Sealer never sees `chainId` or the contract address
unless it chooses to read optional CBOR fields later.

## Related

- [canopy CONTEXT.md](../canopy/CONTEXT.md) — forest and genesis terminology
- [plan-0007](docs/plan-0007-univocity-genesis-trust-root-resolver.md)
- [ADR-0001](docs/adr/adr-0001-genesis-driven-logid-resolution.md)
