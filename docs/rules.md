---
id: rules
title: Rules of the road for arbor
version: 1.0.0
created: 2026-08-15
amended: 2026-11-27
---

# Rules of the road for arbor

ranger, sealer, publisher, custodian, sharder and the univocity HTTP
service. Read with the
[platform rules](https://github.com/forestrie/protocol/blob/main/rules/platform.md);
these do not restate them. `⤷` marks a rule that specialises a platform
rule into a concrete check.

### A1 — Base every checkpoint on the massif entry boundary
The signed checkpoint base (`TreeSize1`) MUST be a massif entry boundary; on
re-seal after drift it snaps back to the boundary, emitting `sth(a→c)`, and
the retained `.sth` chain verifies boundary-to-boundary.
**Why:** publisher relay and offline growth verification rebuild proofs from
these boundaries; drift to an intermediate overwritten size breaks both.
⤷ specialises P2, P9.
[devdocs ADR-0056](https://github.com/forestrie/devdocs/blob/main/adr/adr-0056-checkpoint-base-is-massif-entry-boundary.md).
**Enforced-by:** test:services/sealer/src/sealer_boundary_test.go, test:services/sealer/src/sealer_sealplan_test.go

### A2 — Sign the consistency receipt as the checkpoint
The sealer signs the draft-bryce COSE Sign1 consistency receipt directly (v3,
publishable as calldata); no bespoke format plus a sibling document.
**Why:** one format that the contract verifies, SCRAPI serves, and an offline
monitor checks; conversion at publish time is fragile.
⤷ specialises P4, P16.
[devdocs ADR-0046](https://github.com/forestrie/devdocs/blob/main/adr/adr-0046-checkpoint-is-consistency-receipt.md).
**Enforced-by:** test:services/pkgs/publishproof/receipt_test.go, review

### A3 — Never cache a completed checkpoint
Checkpoints are overwritten on re-seal; the sealer and publisher MUST NOT
persist or cache one as immutable.
**Why:** a cached `sth(b→c)` pins a superseded proof after the re-seal
produced `sth(a→c)`.
⤷ specialises P15.
[devdocs ADR-0057](https://github.com/forestrie/devdocs/blob/main/adr/adr-0057-published-artifact-cache-policy.md).
**Enforced-by:** test:services/pkgs/s3storage/merklelog/cachecontrol_test.go, review

### A4 — Route logs to fixed shards, one log per goroutine
Canopy's ingress hash-routes each log to a fixed shard count (modulus);
ranger discovers and pulls the shards and keeps one log in one goroutine
within its shard. No per-log Durable Objects, no single global DO. Scale
is shard count × replicas.
**Why:** preserves per-log grouping and prevents intra-process massif-write
contention while scaling horizontally.
[devdocs ADR-0006](https://github.com/forestrie/devdocs/blob/main/adr/adr-0006-do-sharding.md),
with the per-shard supplements
[ADR-0008](https://github.com/forestrie/devdocs/blob/main/adr/adr-0008-cf-do-ingress-consistent-hashing.md),
[ADR-0009](https://github.com/forestrie/devdocs/blob/main/adr/adr-0009-cf-do-ingress-range-ack.md),
[ADR-0010](https://github.com/forestrie/devdocs/blob/main/adr/adr-0010-cf-do-ingress-fixed-visibility-timeout.md).
**Enforced-by:** review

### A5 — Derive standing sealing keys at boot; keep nothing at rest
The sealer's standing delegate keys are shared across logs and
KMS-MAC-derived at boot, keyed by an epoch and an index and by nothing
log-specific, so they re-derive deterministically after pod churn; the
per-log, per-window (MMR range), TTL-bounded binding is on the delegation
certificate, not the key. No long-lived private key is persisted, and the
operator never holds the user root `K(L)`. The epoch is the MAC key
version number: epoch *e* is derived under `cryptoKeyVersions/<e>`, fixed
by construction and never chosen from listing state, so a key-version
rotation and an epoch bump are one act and the N/N−1 overlap covers it;
the MAC key never auto-rotates and is per lane.
**Why:** certificates survive restarts and rotations without on-demand
signer latency, and BYOK custody is preserved.
⤷ specialises P6.
[protocol ADR-0050](https://github.com/forestrie/protocol/blob/main/adr/adr-0050-delegation-in-advance.md)
· [devdocs ARC-0022 §3](https://github.com/forestrie/devdocs/blob/main/arc/arc-0022-byok-user-log-delegation-and-operator-hosted-sealing.md)
· [runbook ops-0016](https://github.com/forestrie/devdocs/blob/main/ops/ops-0016-kms-mac-key-version-rotation.md).
**Enforced-by:** test:services/sealer/src/delegate_keys_test.go, review

### A6 — Resolve `(chainId, contract)` from public R2 genesis
The sealer and publisher resolve each forest's chain binding
`(chainId, contract)` from public R2 genesis, never from deployment-wide
env vars and never from the univocity service. A log's root key, its
anchoring state and whether it is conflicted come only from the univocity
authority endpoint, as devdocs ADR-0075 requires; that endpoint does not
supply the chain binding.
**Why:** a permissionless third-party publisher or offline monitor can
then find the chain binding from public data alone.
⤷ specialises P14.
[devdocs ADR-0047](https://github.com/forestrie/devdocs/blob/main/adr/adr-0047-publisher-resolves-contract-from-public-r2-genesis.md)
· [devdocs ADR-0034](https://github.com/forestrie/devdocs/blob/main/adr/adr-0034-forest-genesis-chain-binding-required.md)
· [devdocs ADR-0075](https://github.com/forestrie/devdocs/blob/main/adr/adr-0075-sec-child-root-claimed-once.md).
**Enforced-by:** test:services/pkgs/publishproof/resolve_test.go, review

### A7 — Do not assume succinct absence proofs
The Urkle trie root is currently unanchored (not covered by the MMR or the
signature). Do not build sealer or publisher features that assume succinct
exclusion proofs; anchoring the trie root in the signed checkpoint is
prerequisite platform work.
**Why:** regime (b) of P13 does not exist yet.
⤷ specialises P13.
[devdocs ARC-0027 §4.2](https://github.com/forestrie/devdocs/blob/main/arc/arc-0027-delegation-edges-and-outcomes.md).
**Enforced-by:** review

### A8 — Keep custody keys inside KMS
The custodian signs via KMS with per-log dynamic custody keys under a
scoped IAM model; custody private key material MUST NOT leave KMS.
**Why:** custody is the trust boundary; an exportable key defeats it.
[devdocs ARC-0018](https://github.com/forestrie/devdocs/blob/main/arc/arc-0018-custodian-kms-iam-and-dynamic-keys.md)
· [devdocs ADR-0033](https://github.com/forestrie/devdocs/blob/main/adr/adr-0033-custodian-key-service.md).
**Enforced-by:** review

### A9 — Resolve authority only through the univocity grant store
The off-chain genesis and grant store (`services/univocity`) is the
authority resolver: `logId → R` and grant-to-authority correspondence
resolve there, not from operator-held or ad hoc state.
**Why:** authority resolution must trace to the univocity-owned store bound
to the on-chain root; sourcing it elsewhere re-internalises operator trust.
⤷ specialises P10, P14.
[devdocs ADR-0035](https://github.com/forestrie/devdocs/blob/main/adr/adr-0035-univocity-owned-grant-store-and-authority-correspondence.md).
**Enforced-by:** review
