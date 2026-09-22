# AGENTS.md

Arbor: Go microservices for Forestrie (ranger, sealer, custodian, univocity
HTTP service). Human setup: [README.md](README.md), [DEVELOPMENT.md](DEVELOPMENT.md).
Platform glossary: [devdocs/glossary.md](../devdocs/glossary.md).

## Git worktrees

The **home clone** (`~/Dev/personal/forestrie/arbor`) stays on **`main`**
(fast-forwarded to `origin/main`). Do not check out feature branches here.

**Agents and parallel work** use a git worktree under **`../.worktrees/`**
(resolves to `~/Dev/personal/forestrie/.worktrees/`):

```bash
git fetch origin
git worktree add ../.worktrees/arbor-for-<issue>-<slug> \
  -b robin/for-<issue>-<slug> origin/main
git worktree add ../.worktrees/arbor-for-<issue>-<slug> robin/for-<issue>-<slug>
```

When work merges to `main`, remove the worktree:
`git worktree remove ../.worktrees/<name>`. Do **not** use
`~/Dev/personal/forestrie-wt/` (retired).

**A fresh worktree or clone does not build until `_deps` and `go.work` exist.**
Both are gitignored and nothing creates them: `services/_deps/` is a set of
hand-cloned sibling repos (go-merklelog, go-merklelog-{azure,datatrails,fs,
provider-testing}, go-datatrails-{common,serialization,simplehash}, go-sigv4,
go-univocity, taskfiles) and `services/{sealer,ranger,publisher}/go.work` are
per-service workspace files that `use` them. Without them a service fails on
missing `go.sum` entries, which looks like a broken dependency. In a worktree,
borrow them from the home clone (nothing is committed):

```bash
ln -s ~/Dev/personal/forestrie/arbor/services/_deps services/_deps
for s in sealer ranger publisher; do
  cp ~/Dev/personal/forestrie/arbor/services/$s/go.work* services/$s/
done
```

For a brand-new machine, clone each repo listed above into `services/_deps/`
and copy the `go.work` files from an existing checkout.

`task bootstrap` clones the same repos itself (see each `.env.bootstrap`'s
`GIT_CLONES`/`GIT_CHECKOUTS`). Most deps float on a default branch, but
go-merklelog is pinned to a commit SHA via `GIT_CHECKOUTS` (in the root
`.env.bootstrap` and in `services/{ranger,publisher,sealer}/.env.bootstrap`)
so an arbor image tag identifies its sealer/verifier code (FOR-568 review
finding O1). The pin uses `^<sha>`, not `@<sha>`: `git-bootstrap.v2.sh`
strips up to the *first* `@` before looking for the ref marker (it expects
`git@host:...` SSH URLs), so on our `https://` URLs an `@<ref>` suffix is
silently ignored (NOOP) and never checked out — `^<ref>` works for both a
branch and a bare commit SHA, since it ends up as `git checkout <ref>`. To
bump go-merklelog, edit the `^<sha>` in every one of those files to the new
commit and re-run `task bootstrap`.

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
- **Cursor rules**: [branch-naming](.cursor/rules/branch-naming.mdc), [go-comments](.cursor/rules/go-comments.mdc), [types-single-responsibility](.cursor/rules/types-single-responsibility.mdc)
