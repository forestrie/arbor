---
Status: DRAFT
Date: 2026-06-06
Related: [plan-0011](plan-0011-e2e-pipeline-recovery.md), [plan-0008](plan-0008-univocity-grant-store-and-authority-resolver.md), [plan-0007](plan-0007-univocity-genesis-trust-root-resolver.md), univocity [ADR-0003](../../univocity/docs/adr/adr-0003-bootstrap-keys-opaque-constructor.md)
---

# Plan 0012: KS256 support in arbor univocity service

## Goal

Extend `services/univocity` so forests bootstrapped with **KS256** (`-65799`, 20-byte
Ethereum address / ERC-1271) anchor and resolve the same way as **ES256** (`-7`,
64-byte P-256 `x‖y`), using the contract's opaque `(alg:int, key:bstr)` identity
everywhere.

## Scope (Workstream B)

### Genesis

- `GenesisDoc` carries `(Alg, Key)` opaque bytes (20 or 64).
- `parseGenesisDoc` reads v2 labels `bootstrap-alg` (`-68014`) and
  `bootstrap-key` (`-68015`), matching `bootstrapConfig()`.
- Legacy v1 genesis with embedded EC2/P-256 COSE_Key remains supported (alg
  inferred as ES256, key = `x‖y`).
- `verifyGenesisAnchor` compares `(alg,key)` to on-chain `bootstrapConfig()`.

### Grant chain

- Bootstrap cache stores `(alg,key)`; length validation branches on `bootstrapAlg`
  (64 for ES256, 20 for KS256).
- Grant envelope verification:
  - ES256: SHA-256 Sig_structure + P-256 ECDSA (unchanged).
  - KS256: Keccak-256 Sig_structure + `ecrecover` (EOA) or ERC-1271 via the RPC
    pool (`chain.go`).
- Root grant `grantData` compared to bootstrap using length-discriminated opaque
  bytes.
- Initialized on-chain logs use `logConfig().rootKey` (20 or 64) instead of
  assuming ES256 `logRootKey(x,y)`.

### Trust-root / authority API

- CBOR responses emit `(alg:int, key:bstr)` (`TrustRootResponse`,
  `authorityResponse`).
- Remove 404 when `logConfig.rootKey` is 20 bytes (KS256).
- JSON public-root retains ES256 `rootKeyX`/`rootKeyY` for P-256 logs and adds
  `rootKey` hex for KS256.

### delegationcert (shared package)

- `VerifyCertificateSignatureKS256` in
  `services/pkgs/delegationcert/verify_certificate_ks256.go` (keccak +
  ecrecover/ERC-1271); uses existing `CoseAlgKS256 = -65799` from
  `build_certificate.go`.

## Out of scope

- Canopy genesis v2 POST (Workstream D).
- Sealer trust-root client migration (Workstream C).
- On-chain KS256 delegation contract changes (Workstream A).
- ES256K (`-47`) removal (Workstream 0).

## Verification

```sh
cd services/univocity/src && go test ./...
cd services/pkgs/delegationcert && go test ./...
```

## Follow-ups

- Coordinate `(alg,key)` wire migration with sealer and canopy (plan KS256
  delegation support, todo `wire-opaque-algkey`).
- E2E against a deployed KS256-bootstrap Univocity once Workstreams A and E land.
