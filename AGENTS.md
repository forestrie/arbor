# AGENTS.md

Arbor: Go microservices for Forestrie (ranger, sealer, custodian, univocity
HTTP service). Human setup: [README.md](README.md), [DEVELOPMENT.md](DEVELOPMENT.md).
Platform glossary: [devdocs/glossary.md](../devdocs/glossary.md).

## Services

| Service | Role |
|---------|------|
| **ranger** | Queue consumer for Cloudflare Queue / R2 notifications |
| **sharder** | Kubernetes operator for shard assignments |
| **custodian** | KMS-backed key custody and signing |
| **univocity** (`services/univocity`) | Grant store, authority resolver, trust-root HTTP |

Sibling repos: **canopy** (SCRAPI Workers), **forest-1** (GKE/Flux), **univocity**
(on-chain contracts).

## Commands

- **Build/test a service**: `cd services/<name> && go test ./...`
- **Ranger locally**: configure env per `services/ranger/config.go`; health on `:9090`
- **Deploy**: GitOps via arbor-flux; see [devdocs ops](../devdocs/ops/README.md)

## Gotchas (critical)

- Platform ADRs/ARCs live in **devdocs**, not this repo — see stubs under `docs/adr/`.
- Grant store and `logId → R` uniqueness: [devdocs ADR-0035–0037](../devdocs/adr/).
- Never log raw secrets; ranger logs SHA-256 digests only.
- Sealer resolves contract via univocity `GET /api/logs/{logId}/public-root`.

## Documentation map

- **Agent index**: [docs/agents/README.md](docs/agents/README.md)
- **Plans**: [docs/plans/README.md](docs/plans/README.md) (flat `docs/plan-*.md` today)
- **Platform**: [../devdocs/](../devdocs/)
- **Extended layout / service detail**: [docs/agents/services.md](docs/agents/services.md)
