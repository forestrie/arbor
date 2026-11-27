# AGENTS.md

Arbor: Go microservices for Forestrie (ranger, sealer, custodian, univocity
HTTP service). Human setup: [README.md](README.md), [DEVELOPMENT.md](DEVELOPMENT.md).
Platform glossary: [protocol/glossary.md](https://github.com/forestrie/protocol/blob/main/glossary.md).

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
arbor image tag alone would not identify its sealer/verifier code. So **anything that gets deployed** — the
one workflow that builds and pushes images,
`.github/workflows/build-deploy.yml` — runs `task bootstrap:release`
instead. `task bootstrap:release` runs plain `bootstrap` and then re-checks-out
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

`.github/workflows/release.yaml` builds nothing: `task release:retag`
adds `vX.Y.Z` to the digest build-deploy pushed as `main-<sha7>-<run>`
for the tagged commit, and fails if there is none, so a release image
is the image lane A ran. Never add a
rebuild back to release.yaml, as a fallback or otherwise. build-deploy
refuses to push a `main-*` tag that already exists (`task
release:assert-unpushed`): a GitHub re-run keeps the run number and would
move it. Dispatch a new run instead.

## Services

| Service | Role |
|---------|------|
| **ranger** | Pulls canopy's ingress shards, commits massifs to R2, posts seal hints to the sealer queue |
| **sharder** | Kubernetes operator for shard assignments |
| **custodian** | KMS-backed key custody and signing |
| **univocity** (`services/univocity`) | Grant store, authority resolver, trust-root HTTP |

Sibling repos: **canopy** (SCRAPI Workers), **forest-1** (GKE/Flux), **univocity**
(on-chain contracts).

## Commands

- **Build/test a service**: `cd services/<name> && go test ./...`
- **Ranger locally**: entry point `services/ranger/src/cmd/ranger/main.go`;
  12-factor env per `services/ranger/src/config.go`. Required: `QUEUE_URL`,
  `QUEUE_TOKEN`, `MASSIF_HEIGHT`, `R2_URL`, `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY` (or `R2_TOKEN`), `WORKER_CIDR`, `POD_IP`. Health
  on `PORT` (default `9090`): `/healthz`, `/readyz`, `/version`
- **Deploy**: GitOps via arbor-flux; see [devdocs ops](https://github.com/forestrie/devdocs/blob/main/ops/README.md) (private)

## Gotchas (critical)

- Platform ADRs/ARCs live in **devdocs**, not this repo. Arbor's own
  decisions are in [docs/adr/](docs/adr/README.md) and its invariants in
  [docs/rules.md](docs/rules.md).
- Grant store and `logId → R` uniqueness: devdocs [ADR-0035](https://github.com/forestrie/devdocs/blob/main/adr/adr-0035-univocity-owned-grant-store-and-authority-correspondence.md), [ADR-0036](https://github.com/forestrie/devdocs/blob/main/adr/adr-0036-global-logid-r-uniqueness.md), [ADR-0037](https://github.com/forestrie/devdocs/blob/main/adr/adr-0037-forests-storage-and-uuid-log-ids.md) (private).
- Never log raw secrets; ranger logs SHA-256 digests only.
- The sealer takes each log's root key only from univocity
  `GET /api/logs/{logId}/authority`, and only once the log is anchored; the
  publisher asks the same route whether a log is conflicted.

## Documentation map

- **Decisions**: [docs/adr/](docs/adr/README.md); **rules**: [docs/rules.md](docs/rules.md)
- **Plans and status**: [forestrie/work](https://github.com/forestrie/work) (private). None live in this repo.
- **Platform**: [devdocs](https://github.com/forestrie/devdocs) — architecture, arc/, adr/ (private)
- **Team rules and skills**: synced from [forestrie-agents](https://github.com/forestrie/forestrie-agents) (private) by `agentfiles sync` with `sync/arbor.manifest`. Rules in [.claude/rules/](.claude/rules/), skills in [.agents/skills/](.agents/skills/). Do not edit the copies; change forestrie-agents and re-sync. The exception is the rules digest, [.claude/rules/rules-of-the-road.md](.claude/rules/rules-of-the-road.md), which `dox digest` generates from `docs/rules.md` and the platform rules.
