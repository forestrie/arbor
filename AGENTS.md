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
`GIT_CLONES`/`GIT_CHECKOUTS`). Every dep floats on a default branch there,
including go-merklelog (`^main`) — fine for local/dev, but it means an
arbor image tag alone would not identify its sealer/verifier code
(FOR-568 review finding O1). So **anything that gets deployed** — every
workflow that builds and pushes an image
(`.github/workflows/build-deploy.yml`, both jobs in
`.github/workflows/release.yaml`) — runs `task bootstrap:release`
instead. That task runs plain `bootstrap` and then re-checks-out
go-merklelog at the commit in `GO_MERKLELOG_PIN`
(`Taskfile.dist.yml`'s `vars:`), via a `.env.bootstrap.release` overlay
in each of the same four directories, selected with
`ENV_SCOPE=.bootstrap.release`. **To bump the deployed go-merklelog,
change `GO_MERKLELOG_PIN` in `Taskfile.dist.yml` — one line.** Local/dev
work (plain `task bootstrap`, `go-test.yml`) keeps floating on `main` and
is untouched.

The pin uses `^<ref>`, never `@<ref>`: `git-bootstrap.v2.sh` strips up to
the *first* `@` in an entry before it goes looking for the ref marker
(correct for `git@host:...` SSH URLs, where that `@` is part of the
address), so on our `https://` URLs an `@<ref>` suffix is silently
ignored (NOOP) and nothing is checked out — don't reintroduce it. `^<ref>`
doesn't hit this and works for a branch, tag or bare commit SHA alike,
since it ends up as a plain `git checkout <ref>`.

go-merklelog now tags each module on release (e.g. `massifs/v0.7.0`,
`mmr/v0.5.0`), so `GO_MERKLELOG_PIN` should track the relevant module tag
rather than a bare commit SHA going forward.

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
