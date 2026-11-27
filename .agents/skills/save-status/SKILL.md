---
name: save-status
description: Checkpoint Forestrie work in flight into a status doc in forestrie/work that a fresh agent session can resume from, with FOR issues, worktrees and plan refs.
when_to_use: The user says "save status", "checkpoint this", or is ending a session another will pick up.
argument-hint: "[FOR-123 | plan id | free-text hints]"
---

# save-status: checkpoint work in flight

Write or refresh one `status-YYMM-NN-<slug>.md` in
[forestrie/work](https://github.com/forestrie/work) `status/`, such that a
fresh session reading it (plus the repo context hooks) can continue the
work. Naming, frontmatter and links follow
[docs-layout](../../rules/docs-layout/SKILL.md). Status docs never go in a
code repo or devdocs.

Arguments: `$ARGUMENTS`

When the personal `core:save-status` skill is installed, it does the same
job with the forestrie profile's `status_root`; either is fine.

## Steps

1. **Establish the workstream** from the hints, or from the whole session:
   `FOR-*` issues, worktrees and branches (`<user>/for-<n>-<slug>`), plan
   ids, canon documents touched. Note the `arc-*` glossary skills the next
   session should load.
2. **Use a forestrie/work worktree**, never the primary clone's `main`:
   reuse the one in the current task container if there is one, else
   `git -C <work clone> worktree add ../.worktrees/work-<slug> -b <branch> origin/main`.
3. **Prefer update in place.** If a live `status/` doc already tracks this
   workstream (same issue, plan id or slug), refresh it.
4. **Otherwise allocate** with [dox](../../rules/dox/SKILL.md), from the
   work worktree:

   ```bash
   dox new status <slug>
   ```

   It takes the next ordinal for the current month from origin's default
   branch and open PRs, and scaffolds the doc. Never hand-pick. Put the
   lead issue in the slug: `status-2611-03-for-632-docs-layout.md`.
5. Run `dox lint --changed`, then commit and open (or update) the PR in
   forestrie/work.

## Content

```yaml
---
id: status-2611-03-for-632-docs-layout
title: <workstream>
status: active
created: <date>
updated: <date>
repos: [<repos touched>]
issues: [FOR-632]
plans: [<plan ids, if any>]
refs: [<canon refs, e.g. devdocs:ADR-0071>]
---
```

Then a short overview with links to the plans and canon that matter, and:

- **Status**: what is done, with PR links
- **Notables**: design choices and discoveries made along the way
- **Next steps**: in order
- **Blockers**: dependencies and open questions

On update, rewrite these sections in place and bump `updated`; do not
append a log. Set `status: complete` when the workstream lands and move
the doc to `archive/<YYMM>/`.
