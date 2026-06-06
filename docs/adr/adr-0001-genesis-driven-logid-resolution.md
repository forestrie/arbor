# Genesis-driven logId resolution in univocity

Arbor signer and sealer only know a `logId` at request time (queue messages and delegation payloads carry no chain or contract). We rejected pinning `(chainId, contractAddress)` per service and encoding them in R2 object keys.

**Decision:** Univocity maintains a forest registry from curator **v1 genesis** documents in the logs bucket (`forests/forest/{uuid-R}/genesis.cbor`; see [ADR-0004](adr-0004-forests-storage-and-uuid-log-ids.md)), refreshed on a scan-on-miss circuit breaker. `resolve(logId)` uses genesis identity for `logId == R`, then on-chain `isLogInitialized` probes across registered forests, with ambiguous multi-forest matches returning 503.

**Why:** Genesis is already the authoritative binding of `(R, chainId, univocity contract)`; this keeps Ranger and SCRAPI forest-agnostic while giving signer/sealer logId-only HTTP APIs.
