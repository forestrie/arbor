---
name: arc-arbor
description: Arbor domain glossary (Go services on GKE). Use when a task touches ranger, sealer, custodian, the grant store, or GKE services.
when_to_use: "Queue consumers, sealing, KMS signing, grant store, shard assignments, GKE workloads, Go service tests."
user-invocable: false
---

# arc-context: arbor (GKE services)

Minimal glossary for **arbor** — Go microservices: ranger, sealer, custodian,
sharder, univocity HTTP service.

**Load when:** queue consumers, sealing, KMS signing, grant store, shard
assignments, GKE workloads, Go service tests.

**Do not bulk-read** — use [arbor/AGENTS.md](https://github.com/forestrie/arbor/blob/main/AGENTS.md).

---

## Core terms

| Term | Meaning |
|------|---------|
| **ranger** | Pulls from SequencingQueue / R2; sequences into MMR massifs |
| **sealer** | Signs checkpoints; resolves contract via univocity public-root |
| **custodian** | KMS-backed key custody and signing |
| **sharder** | K8s operator for shard assignments |
| **univocity service** | Grant store, authority resolver, trust-root HTTP (`services/univocity`) |
| **massif** | MMR storage segment; see go-merklelog in `_deps` |
| **logId → R** | Grant store uniqueness — see devdocs ADR-0035–0037 |

## Go dependencies (`services/_deps`)

Arbor clones sibling libraries into `services/_deps` (gitignored), from
[go-merklelog](https://github.com/forestrie/go-merklelog), [go-univocity](https://github.com/forestrie/go-univocity), [go-sigv4](https://github.com/forestrie/go-sigv4) and others.
Read source there for MMR, signing, and storage behaviour — do not guess APIs.

| Dependency | Role |
|------------|------|
| **go-merklelog** | Core MMR and massif libraries |
| **go-merklelog-fs** / **go-merklelog-azure** / **go-merklelog-datatrails** | Storage backends |
| **go-univocity** | Grant chain, Univocity HTTP client helpers |
| **go-sigv4** | SigV4 for R2/S3-compatible APIs |
| **go-datatrails-common** | Shared Go utilities |
| **go-datatrails-serialization** / **go-datatrails-simplehash** | Serialization helpers |
| **taskfiles** | go-task definitions shared with other repos |

Service-level `go.work` under `services/ranger` and `services/sealer` reference
these paths locally.

## Authoritative docs

| Topic | Path |
|-------|------|
| Agent router | [AGENTS.md](https://github.com/forestrie/arbor/blob/main/AGENTS.md) |
| Service layout | [docs/agents/services.md](https://github.com/forestrie/arbor/blob/main/docs/agents/services.md) |
| Platform ADRs (stubs) | [docs/adr/](https://github.com/forestrie/arbor/tree/main/docs/adr) — canonical in devdocs |
| Ops runbooks | [devdocs/ops/](https://github.com/forestrie/devdocs/tree/main/ops) |

## Platform cross-links

| Domain | Where |
|--------|-------|
| Ingress / API | [arc-canopy](../arc-canopy/SKILL.md) |
| GitOps deploy | [arc-infra](../arc-infra/SKILL.md) |
| On-chain verification | [arc-univocity](../arc-univocity/SKILL.md) |
| MMR / COSE profile | [draft-bryce-cose-receipts-mmr-profile](https://github.com/robinbryce/draft-bryce-cose-receipts-mmr-profile) |

## Gotchas

- Never log raw secrets; ranger logs SHA-256 digests only
- Platform ADRs/ARCs live in **devdocs**, not arbor stubs alone
- Deploy via arbor-flux GitOps — not from arbor source commits
