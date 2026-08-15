# ADR-0006 — Genesis-authoritative root key for BYOK forests

**Status:** Accepted  
**Date:** 2026-06-23  
**Linear:** FOR-123  
**Related:** [ARC-0022 BYOK user-log delegation](https://github.com/forestrie/devdocs/blob/main/archive/2606/arc/arc-0022-byok-user-log-delegation-and-operator-hosted-sealing.md),
[ADR-0002 univocity owned grant store](adr-0002-univocity-owned-grant-store-and-authority-correspondence.md)

## Context

Imutable Univocity contracts expose `bootstrapConfig()` as the contract
deployer's bootstrap identity. Mode C BYOK forests store the **user's** KS256
(or ES256) root in the forest genesis document under canopy onboard-token auth,
while the on-chain contract key remains the deployer.

Grant chain verification previously resolved the forest root via on-chain
`bootstrapConfig()` only, so root grants signed by the user's key failed even
when genesis and coordinator `publicRoot` matched the user wallet.

## Decision

When a stored forest genesis document declares `(alg, key)` that **differs**
from on-chain `bootstrapConfig()` for the same `(chainId, contract)`:

1. **Genesis POST** — allow the mismatch (`verifyGenesisAnchor` does not reject).
2. **Grant verification** — `bootstrapConfig()` / `ownerRootKey` for
   `owner == R` prefer the **stored genesis identity** over the contract
   deployer key.

When genesis and contract keys **match**, behavior is unchanged (contract-anchored
bootstrap forests).

## Trust boundary

Genesis write is authorized by canopy (onboard token or endorsement grant) and
stored by univocity under `UNIVOCITY_API_TOKEN`. The operator/user chooses
`bootstrapKey` at genesis time; downstream grant verification trusts that
declared root for the forest.

On-chain split-view protection still uses the contract's checkpoint-signer policy;
this ADR only affects **off-chain grant chain** verification in the univocity
owned store.

## Consequences

- True wallet-held KS256 BYOK root grants verify without using the provisioned
  contract bootstrap private key in e2e.
- Forests with genesis keys that accidentally mismatch contract deployer key
  are treated as BYOK (intentional for Mode C; operators must not typo keys on
  contract-anchored forests).
