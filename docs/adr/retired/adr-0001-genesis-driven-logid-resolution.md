---
id: adr-0001-genesis-driven-logid-resolution
title: Genesis-driven logId resolution in univocity
status: superseded
created: 2026-06-05
updated: 2026-11-12
refs: [devdocs:ADR-0037]
superseded-by: adr-0009-univocity-index-and-hint-resolution
---

# Genesis-driven logId resolution in univocity

Superseded by [ADR-0009](../adr-0009-univocity-index-and-hint-resolution.md):
the forest registry scan and the on-chain probe are deleted, and
resolution is by index and verified hint. The genesis binding of
`(R, chainId, contract)` still holds.

Arbor signer and sealer only know a `logId` at request time (queue messages and delegation payloads carry no chain or contract). We rejected pinning `(chainId, contractAddress)` per service and encoding them in R2 object keys.

**Decision:** Univocity maintains a forest registry from curator **v1 genesis** documents in the logs bucket (`forests/forest/{uuid-R}/genesis.cbor`; see [devdocs ADR-0037](https://github.com/forestrie/devdocs/blob/main/adr/adr-0037-forests-storage-and-uuid-log-ids.md)), refreshed on a scan-on-miss circuit breaker. `resolve(logId)` uses genesis identity for `logId == R`, then on-chain `isLogInitialized` probes across registered forests, with ambiguous multi-forest matches returning 503.

**Why:** Genesis is already the authoritative binding of `(R, chainId, univocity contract)`; this keeps Ranger and SCRAPI forest-agnostic while giving signer/sealer logId-only HTTP APIs.
