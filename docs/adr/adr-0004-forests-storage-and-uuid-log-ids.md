# Forests storage layout and UUID log IDs

**Status**: ACCEPTED  
**Date**: 2026-06-06  
**Related**: [ADR-0002](adr-0002-univocity-owned-grant-store-and-authority-correspondence.md),
[ADR-0003](adr-0003-global-logid-r-uniqueness.md),
[plan-0009](../plan-0009-forests-storage-and-uuid-logid.md)

## Context

The owned grant store ([ADR-0002](adr-0002-univocity-owned-grant-store-and-authority-correspondence.md))
used `forest/{hex64(R)}/…` object keys with 64-character hex of a 32-byte padded
wire log id. MMRS massifs already use canonical UUID strings. Off-chain code
carried two incompatible encodings.

Auth-log and data-log creation grants share one flat grant namespace today; the
public data buffer treats them as distinct log classes (`GF_AUTH_LOG` vs
`GF_DATA_LOG`).

## Decision

**Log ID (semantic):** 16-byte UUID is the canonical off-chain identity in
application code. On-chain `bytes32` and grant/genesis CBOR still use 32-byte
right-padded wire form at those boundaries only.

**Storage layout** (co-located with MMRS in the logs bucket; `v2/merklelog/` unchanged):

- `forests/forest/{uuid-R}/genesis.cbor`
- `forests/forest/{uuid-R}/grants/auth-log/{uuid-A}.cbor`
- `forests/forest/{uuid-R}/grants/data-log/{uuid-D}.cbor`
- `forests/index/forest/{uuid-subject}` — body is ASCII canonical UUID of `R`

Grant objects are routed by `GF_AUTH_LOG` / `GF_DATA_LOG` in the grant bitmap.

**Migration:** clean break for dev ephemeral objects (no dual-read). Re-bootstrap
after deploy.

**HTTP API routes** stay `/api/forest/{logId}/genesis`, `/api/grants`, etc.;
path segments use canonical UUID strings, not hex64.

## Why

Aligns storage paths with MMRS, separates auth vs data grant namespaces to match
the protocol, and removes padded-hex path segments from off-chain ergonomics
without changing on-chain or credential wire formats.

## Consequences

- ADR-0002 path bullets are superseded by this ADR for layout only; authority
  model unchanged.
- Univocity, canopy, sealer, and signer must use shared UUID parsing at edges.
- Custodian KMS labels remain 32-char hex (external edge format).
