---
name: dox
description: "How to use dox, the docs checker, in Forestrie repos: lint before committing docs, allocate ids with dox next/new, leave the baseline to dox, never skip silently, check the graph before retiring."
when_to_use: Writing, moving, retiring or allocating an ADR, ARC, named doc, rules file, plan or status doc; a `docs` CI job failed; touching `.dox.toml` or `.dox-baseline.json`.
paths: ["**/adr/**", "**/arc/**", "**/plans/**", "**/status/**", "**/rules/**", "**/docs/**", "**/.dox.toml", "**/.dox-baseline.json"]
user-invocable: false
---

# dox

[dox](https://github.com/robinbryce/dox) checks Forestrie docs against
[forestrie/dox](https://github.com/forestrie/dox), the machine form of
[docs-layout](../docs-layout/SKILL.md). Each repo's committed `.dox.toml`
pins the forestrie/dox version (`schema_ref`); the `docs` CI job runs
`dox lint` on every PR. Keys and checks:
[contract](https://github.com/robinbryce/dox/blob/v0.3.0/docs/contract.md).

## Setup

- Install: `uv tool install git+https://github.com/robinbryce/dox@v0.3.0`.
- `export DOX_SCHEMA_REPO=forestrie/dox` (the forestrie `.envrc` sets it).
  Without it dox exits 2.

## Rules

- **Lint before committing docs.** Run `task docs:lint` where the
  Taskfile has it, else `dox lint --changed`. Every finding prints a
  `fix:` line; apply it. Do not push a docs change that fails locally.
- **Allocate ids only with dox.** `dox next <type>` prints the next free
  id; `dox new <type> <slug> [--dir]` allocates and scaffolds from the
  forestrie/dox template. Both scan `origin`'s default branch and open
  PRs. Plans and status docs: in a forestrie/work worktree. ADRs and
  ARCs: in their home repo. Never hand-pick a number.
- **Never hand-edit `.dox-baseline.json`.** It records findings that
  predate the gate. `dox lint --update-baseline` drops entries that no
  longer occur and never adds any; commit the shrink with the fix. A new
  finding is fixed, not baselined.
- **Never `--skip` silently.** If a check must be skipped, say which and
  why in the PR description; dox reports skips in its output.
- **Check the graph before retiring or superseding.** `dox graph --json`
  lists `backlinks` (who cites the document) and `into_retired` (live
  docs citing retired ones). Rewrite inbound links in the same change.
- **Retire with `dox retire`.** `dox retire <ref> --by <ref>` (or
  `--absorbed-into <ref>`) sets the status, writes the link fields on both
  sides, `git mv`s the document to `retired/` and rewrites relative links.
  Run it with `--dry-run` first. Its `moved <old> <new>` lines are the
  moves map for links from other repositories.
- **The rules digest is generated.** After editing `docs/rules.md` or
  bumping the protocol pin in `.dox.toml` `[digest]`, run `dox digest` and
  commit `.claude/rules/rules-of-the-road.md`.
- **Indexes are generated.** After adding or retiring ADRs or ARCs, run
  `dox index`; never edit between the `dox:index` markers.

## Exit codes

| Code | Meaning | Do |
|------|---------|----|
| 0 | Clean (warnings allowed) | Commit |
| 1 | Errors | Apply the fixes |
| 2 | Usage or configuration error | Check `DOX_SCHEMA_REPO`, `.dox.toml` |
| 3 | A remote source was unreachable | Retry; `--offline` for `next`/`new` only when you accept the risk |
