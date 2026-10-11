# Rules of the road — arbor (Go services)

ranger, sealer, custodian, sharder, univocity HTTP service. Load with
[platform.md](https://github.com/forestrie/forestrie-agents/blob/main/rules-of-the-road/platform.md); these do not restate it. `⤷` = specialises a
platform rule into a concrete check.

Glossary/links: [`arc-arbor` skill](https://github.com/forestrie/forestrie-agents/blob/main/arc-context/arc-arbor/SKILL.md).

---

### A1 — Checkpoint base is the massif entry boundary
The signed checkpoint base (`TreeSize1`) MUST be a massif entry boundary; on
re-seal after drift it snaps back to the boundary, emitting `sth(a→c)`, and the
retained `.sth` chain verifies boundary-to-boundary. **Why:** publisher relay
and offline growth verification rebuild proofs from these boundaries — drift to
an intermediate overwritten size breaks both.
⤷ specialises P2/P9. [ADR-0056](https://github.com/forestrie/devdocs/blob/main/archive/2607/adr/adr-0056-checkpoint-base-is-massif-entry-boundary.md).

### A2 — The sealed checkpoint *is* the consistency receipt
The sealer signs the draft-bryce COSE Sign1 consistency receipt directly (v3,
publishable as calldata) — no bespoke format plus a sibling document. **Why:**
one format that the contract verifies, SCRAPI serves, and an offline monitor
checks; conversion at publish time is fragile.
⤷ specialises P4/P16. [ADR-0046](https://github.com/forestrie/devdocs/blob/main/archive/2607/adr/adr-0046-checkpoint-is-consistency-receipt.md).

### A3 — Never cache a completed checkpoint
Checkpoints are overwritten on re-seal; the sealer/publisher MUST NOT persist or
cache one as immutable. **Why:** a cached `sth(b→c)` pins a superseded proof
after the re-seal produced `sth(a→c)`.
⤷ specialises P15. [ADR-0057](https://github.com/forestrie/devdocs/blob/main/archive/2607/adr/adr-0057-published-artifact-cache-policy.md).

### A4 — Fixed-shard routing, one log per goroutine
ranger hash-routes each log to a fixed shard count (modulus), and one log stays
in one goroutine within its shard — no per-log Durable Objects, no single global
DO. Scale is shard count × replicas. **Why:** preserves per-log grouping and
prevents intra-process massif-write contention while scaling horizontally.
[ADR-0006](https://github.com/forestrie/devdocs/blob/main/archive/2601/adr/adr-0006-do-sharding.md),
with the per-shard supplements: [ADR-0008](https://github.com/forestrie/devdocs/blob/main/archive/2601/adr/adr-0008-cf-do-ingress-consistent-hashing.md) (consistent hashing),
[ADR-0009](https://github.com/forestrie/devdocs/blob/main/archive/2601/adr/adr-0009-cf-do-ingress-range-ack.md) (range ack),
[ADR-0010](https://github.com/forestrie/devdocs/blob/main/archive/2601/adr/adr-0010-cf-do-ingress-fixed-visibility-timeout.md) (visibility timeout).

### A5 — Standing delegated sealing keys, derived at boot, nothing at rest
The sealer's standing delegate keys are shared across logs and KMS-MAC-derived
at boot, keyed by an epoch and an index and by nothing log-specific, so they
re-derive deterministically after pod churn; the per-log, per-window (MMR
range), TTL-bounded binding is on the delegation certificate, not the key. No
long-lived private key is persisted, and the operator never holds the user root
`K(L)`. **The epoch is the MAC key version number**: epoch *e* is derived under
`cryptoKeyVersions/<e>`, fixed by construction and never chosen from listing
state, so a key-version rotation and an epoch bump are one act and the N/N−1
overlap covers it; the MAC key never auto-rotates. **Why:** certificates survive
restarts and rotations without on-demand signer latency, and BYOK custody is
preserved.
⤷ specialises P6 (BYOK). [ADR-0050](https://github.com/forestrie/protocol/blob/main/decisions/adr-0050-delegation-in-advance.md) (amendment 2026-09-26) · [ARC-0022 §3](https://github.com/forestrie/devdocs/blob/main/archive/2606/arc/arc-0022-byok-user-log-delegation-and-operator-hosted-sealing.md) · runbook: devdocs ops-0016.

### A6 — Resolve `(chainId, contract)` from public R2 genesis
The sealer and publisher resolve each forest's chain binding from public R2
genesis — never from deployment-wide env vars, never by calling the univocity
HTTP resolver. **Why:** this is what lets a permissionless third-party publisher
or offline monitor work from public data alone.
⤷ specialises P14. [ADR-0047](https://github.com/forestrie/devdocs/blob/main/archive/2607/adr/adr-0047-publisher-resolves-contract-from-public-r2-genesis.md) · [ADR-0034](https://github.com/forestrie/devdocs/blob/main/archive/2606/adr/adr-0034-forest-genesis-chain-binding-required.md).

### A7 — Do not assume succinct absence proofs
The Urkle trie root is currently unanchored (not covered by the MMR or the
signature). Do not build sealer/publisher features that assume succinct
exclusion proofs; anchoring the trie root in the signed checkpoint is
prerequisite platform work. **Why:** see P13 — regime (b) does not exist yet.
⤷ specialises P13. [ARC-0027 §4.2](https://github.com/forestrie/devdocs/blob/main/arc/arc-0027-delegation-edges-and-outcomes.md).

### A8 — Custodian: KMS-native custody, no private material exported
The custodian signs via KMS with per-log dynamic keys under a scoped IAM model;
private key material MUST NOT leave KMS. **Why:** custody is the trust boundary —
an exportable key defeats it.
[ARC-0018](https://github.com/forestrie/devdocs/blob/main/archive/2603/arc/arc-0018-custodian-kms-iam-and-dynamic-keys.md) · [ADR-0033](https://github.com/forestrie/devdocs/blob/main/archive/2603/adr/adr-0033-custodian-key-service.md).

### A9 — The Univocity service owns the off-chain grant store & authority correspondence
The off-chain genesis + grant store (`services/univocity`) is the authority
resolver: `logId → R` and grant → authority correspondence resolve there, not
from operator-held or ad-hoc state. **Why:** authority resolution must trace to
the Univocity-owned store bound to the on-chain root — sourcing it elsewhere
re-internalises operator trust.
⤷ specialises P14/P10. [ADR-0035](https://github.com/forestrie/devdocs/blob/main/archive/2603/adr/adr-0035-univocity-owned-grant-store-and-authority-correspondence.md).
