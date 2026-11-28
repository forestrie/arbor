---
name: docs-layout
description: "The one specification for Forestrie docs: where ADRs, ARCs, named living docs, rules files, plans and status snapshots live, how they are named and numbered, their YAML frontmatter and status values, how they link, and how they retire."
when_to_use: Creating, editing, moving, retiring or citing any ADR, ARC, living doc, rules file, plan or status doc in a Forestrie repo, choosing where a document belongs, or when grill-with-docs points at its own ADR-FORMAT.md.
paths: ["**/adr/**", "**/arc/**", "**/plans/**", "**/status/**", "**/rules/**", "**/docs/**"]
user-invocable: false
---

# Forestrie docs layout

The single convention for Forestrie documentation, from
[devdocs ADR-0071](https://github.com/forestrie/devdocs/blob/main/adr/adr-0071-documentation-system-v2/README.md).
It replaces the old `plan-docs`, `adr-format` and forestrie `save-status`
conventions. Where anything else disagrees (an older repo README, a
vendored `ADR-FORMAT.md`, a hand-written `.cursor/rules` copy), this wins.

Frontmatter schemas (JSON Schema 2020-12) and the machine-checked form of
this specification are in [forestrie/dox](https://github.com/forestrie/dox).
[dox](https://github.com/robinbryce/dox) checks them (`dox lint`) and
allocates ids against the remote (`dox next <type>`, `dox new <type>
<slug>`); set `DOX_SCHEMA_REPO=forestrie/dox`.

## Canon and work

**Canon** says what is true and why. **Work** says what is in flight.

| Type | Role | Home | Schema |
|------|------|------|--------|
| ADR | one decision; immutable once `accepted` | `adr/` in the repo it affects; devdocs when cross-repo; protocol when implementation independent | `adr` |
| ARC | numbered design for an area; retires once realised | `arc/`, same homes as ADRs | `arc` |
| Named living doc | current state of an area, revised in place | anywhere in the owning repo (`architecture.md`, `docs/<area>.md`, runbooks, protocol spec, product briefs) | `named-doc` |
| Rules file | versioned invariants | `protocol/rules/platform.md`; each repo's `docs/rules.md` | `rules` |
| Plan | work in flight | [forestrie/work](https://github.com/forestrie/work) `plans/` | `plan` |
| Status snapshot | resumable checkpoint of a workstream | forestrie/work `status/` | `status` |

- Code repos, devdocs, protocol and product hold **no plans or status
  docs**. Repos that still have them move them to the work home in their
  normalisation change.
- Canon cites canon only. Never put a plan id, status id or tracker id
  (`FOR-123`) in canon prose. Plans may cite anything.
- Do not read the work home to build context. Open a plan by its id, or
  list the plans for an issue by searching `issues:`.

In a repo, canon lives under `docs/` (`docs/adr/`, `docs/arc/`,
`docs/rules.md`, `docs/<area>.md`). devdocs, protocol and product are docs
repos and use the same directories at their root.

## Files and directories

- A document is one file, `<id>.md`, or a directory `<id>/` whose
  `README.md` is the document. Other files in the directory are parts of
  it and carry no frontmatter of their own.
- Use a directory only when the document needs parts: an ADR with a
  research appendix, a plan with slices.
- Plan directory layout: `README.md` (the plan, with a slice table),
  `NN-<slug>.md` slices numbered locally from `01`, optional `handoff.md`
  and `decisions.md`. Nothing else (`overview.md`, `subplan-NN-*` are
  retired forms).
- Soft-wrap prose at about 79 characters, breaking at punctuation.

## Ids

The `id` field equals the filename stem, or the directory name for a
directory document.

| Type | id | Allocated by |
|------|----|--------------|
| ADR | `adr-NNNN-<slug>`; `adr-NNNN-sec-<slug>` if security critical | `dox new adr <slug>` in the home |
| ARC | `arc-NNNN-<slug>` | `dox new arc <slug>` in the home |
| Named doc, rules file | `<slug>` | the author |
| Plan | `plan-YYMM-NN-<slug>` | `dox new plan <slug> [--dir]` in forestrie/work |
| Status | `status-YYMM-NN-<slug>` | `dox new status <slug>` in forestrie/work |

- Numbers are 4 digits; plan and status ordinals are 2 digits within the
  month (`YYMM`) the document was created.
- **Allocate against the remote, with dox.** `dox next <type>` and
  `dox new` fetch `origin` and scan its default branch and open pull
  requests across every directory that can hold the series (`retired/`,
  `archive/*/`), never just your
  working tree. Never hand-pick a number. See [dox](../dox/SKILL.md).
- Each repo, plus devdocs, protocol and product, is its own namespace, and
  numbers continue from the highest id already in that home: devdocs from
  ADR-0071, protocol from its existing ADR-0069 and ARC-0019.
- Existing duplicate ids and frozen legacy `plan-NNNN-<slug>` ids keep
  their names. The slug tells them apart; never renumber.

## Citing

- In prose, cite as `<home>:<TYPE>-<NNNN>`: `devdocs:ADR-0071`,
  `canopy:ARC-0004`, `protocol:ADR-0067`. A bare `ADR-0071` is valid only
  inside its own home. Use the full stem (`devdocs:adr-0023-grant-format`)
  when the number is a known duplicate.
- Frontmatter link fields take the same forms, plus repo-relative paths
  (`architecture.md`, `protocol:rules/platform.md#p4`) and https URLs.
- Markdown links: relative within a repo; across repos
  `https://github.com/forestrie/<repo>/blob/main/<path>`. Pin to a commit
  SHA only when pointing at specific lines of code. No `(local: ../...)`
  parentheticals.

## Frontmatter

Every document starts with YAML frontmatter that validates against its
type's schema. No bold `**Status:**` / `**Date:**` header block; the `#`
title follows the frontmatter. Fields outside the schema are rejected,
except `x-<name>` extension fields.

Common to all: `id`, `title`, `status`, `created`, `updated` (dates as
`YYYY-MM-DD`). Rules files have `version` and `amended` instead of
`status` and `updated`.

Typed links, used on any type where they apply:

| Field | Shape | Meaning |
|-------|-------|---------|
| `supersedes` | list | documents this replaces; each carries `superseded-by` back |
| `superseded-by` | one ref | the document that replaced this one |
| `absorbed-into` | list | living docs or rules that now carry this document's substance |
| `decisions` | list | in-force ADRs and ARCs that shaped this document |
| `refs` | list | anything else: canon, work ids, `FOR-*` issues |

Per type:

| Type | Adds | Required beyond common |
|------|------|------------------------|
| ADR | `categories` (upper case), `amends` | `superseded-by` when `superseded` |
| ARC | `categories` | `absorbed-into` when `absorbed`; `superseded-by` when `superseded` |
| Named doc | `owner` (GitHub user or `org/team`), `review-by` | `owner`, `review-by`, `decisions`; `superseded-by` when `superseded` |
| Plan | `repos`, `issues`, `outcome` | `repos`, `issues`; `outcome` when `complete` |
| Status | `repos`, `issues`, `plans` | — |
| Rules | `version` (semver), `amended` | `version`, `created`, `amended` |

```yaml
---
id: plan-2611-01-docs-layout-spec
title: Docs layout spec and schemas
status: active
created: 2026-11-01
updated: 2026-11-01
repos: [forestrie-agents, devdocs]
issues: [FOR-632]
refs: [devdocs:ADR-0071]
---
```

## Status values

| Type | Values |
|------|--------|
| ADR | `discuss`, `ready`, `accepted`, `rejected`, `superseded`, `deprecated` |
| ARC | `draft`, `accepted`, `absorbed`, `superseded`, `abandoned` |
| Named doc | `draft`, `current`, `superseded` |
| Plan, status | `draft`, `active`, `blocked`, `complete`, `abandoned` |
| Rules file | none; versioned |

ADR meanings:

- `discuss`: being debated. Prototypes only if they inform the decision.
- `ready`: sound enough to implement at risk; may still evolve. Do not sink
  significant effort before this.
- `accepted`: stakeholders bought in; applies to production engineering.
- `rejected`: kept so the approach is not re-litigated.
- `superseded`: another ADR replaced it (`superseded-by`).
- `deprecated`: the context went away; nothing replaced it.

`implemented`, `complete`, `proposed`, `historical` and free text are not
ADR statuses. Work done is a plan state.

## Writing an ADR

Write one only when the decision is hard to reverse, surprising without
context, and the result of a real trade-off. Otherwise a comment or a
living-doc note is enough.

Sections: **Context**, **Decision**, **Consequences**, **Implementation**
(if applicable), **Alternatives Considered**, **References**. Scale depth
to reversibility; do not pad a light decision.

Once `accepted`, change only `status`, `updated` and the link fields. A
changed decision is a new ADR with `supersedes:`. A consolidation ADR may
restate a topic and supersede a cluster at once.

## Writing a plan or status doc

Plans and status docs go in a forestrie/work worktree, created with
`dox new plan` and `dox new status` (which `/plan-new` and `/save-status`
run). A plan has a `## Rules check` section
listing each rule id it touches (platform `P#`, repo rule ids), each
marked honoured or amendment proposed with a link. An unjustified
violation blocks the plan and its PRs. Code PRs link the plan; they do not
carry it.

**Closing a plan.** Mark it `complete` only after its durable outcome has
landed in canon (an ADR per decision taken, the ARC or living doc whose
current state changed, a rules amendment if an invariant moved). List
those in `outcome:`, or write `outcome: "none: <reason>"`. Then `git mv`
it to `archive/<YYMM>/` (month closed). Abandoned plans archive the same
way. `dox lint` checks that a closed plan has an `outcome:` and sits in
`archive/`.

## Retiring canon

`adr/` and `arc/` hold the documents an agent should read: those in
force that no living doc has absorbed, and those in discussion. In the same
change that sets `superseded`, `rejected`, `deprecated`, `absorbed` or
`abandoned`, or adds `absorbed-into`, `git mv` the document to
`adr/retired/` or `arc/retired/` and rewrite inbound links to the new path.
Find them first with `dox graph --json` (`backlinks`; afterwards
`into_retired` must not name it).

Retirement by absorption: once a named living doc or rule carries an ADR's
or ARC's substance, record `absorbed-into:` on it and retire it.

- An absorbed **ARC** takes status `absorbed`.
- An absorbed **ADR** keeps its status (normally `accepted`): the decision
  still holds, and ADRs have no `absorbed` status. The absorbing document
  lists it in `decisions:`.
- `superseded-by` appears only on a `superseded` document; a decision that
  merely went away is `deprecated`, with no link.

Never leave a "moved" stub file behind. Never hand-maintain an index of a
series; indexes are generated (`dox index`).

**The baseline.** A repo's `.dox-baseline.json` records findings that
predate its dox gate. It only shrinks: fix a finding, then
`dox lint --update-baseline`. Never hand-edit it or baseline a new
finding.

## Rules files

Platform rules: forestrie/protocol `rules/platform.md` (`P#`). Each
repository's rules: its own `docs/rules.md` (`A#` arbor, `C#` canopy,
`U#` univocity, `T#` univocity-tools, `M#` mandate, `F#` forest-1, `FX#`
arbor-flux). forestrie-agents holds no rule content.

Each rule is one heading, checked by dox (`rules-shape`):

```markdown
### C1 — Offline verify calls nothing
What the rule requires, in a sentence or two.
**Why:** what breaks if it is violated.
[ADR-0045](https://github.com/forestrie/protocol/blob/main/adr/adr-0045-receipt-verify-offline-contract.md).
**Enforced-by:** test:<path of a test that fails if the rule breaks>, review
```

- **Enforced-by** lists what fails when the rule breaks: `hook:<name>`,
  `lint:<check>`, `test:<path>`, or `review` when nothing mechanical does.
  `review`-only rules are the mechanisation backlog.
- A repository rule that narrows a platform rule says so: `⤷ specialises
  P2`. It never restates the platform rule.
- Fundamental only: if breaking it would not break the trust, economic or
  decentralisation model, or a headline product claim, it belongs in an
  ADR, not here.
- Bump `version` and `amended` in the amending change: MAJOR removes or
  redefines a rule, MINOR adds one, PATCH rewords. Link the amendment from
  the ADR that motivated it, and tick **rules** in the PR's Docs impact
  block.

**The digest.** Every session loads `.claude/rules/rules-of-the-road.md`:
one line per platform and repository rule, generated by `dox digest`
between `dox:digest` markers (devdocs ADR-0074). The repository's
`.dox.toml` names it and pins the platform rules at a protocol tag:

```toml
[digest]
out = ".claude/rules/rules-of-the-road.md"
include = ["protocol:rules/platform.md@rules-v1.0.0"]
```

After changing `docs/rules.md` or bumping the pin, run `dox digest` and
commit the result; CI's `digest-fresh` fails otherwise.

## Forestrie values for `core:planning`

| Param | Value |
|-------|-------|
| `plans_root` | forestrie/work `plans/` |
| `status_root` | forestrie/work `status/` |
| `decisions_home` | per repo (`docs/adr/`, `docs/arc/`); devdocs for cross-repo; protocol when implementation independent |
| `id_scheme.plans` | date cohort `plan-YYMM-NN-<slug>` |
| `id_scheme.decisions` | absolute `adr-NNNN` / `arc-NNNN`, namespaced by home |
| `issue_refs` | Linear `FOR-*`, in `issues:` |
| migration | one scripted normalisation per repo (ADR-0071 section 9), not forward-only |
