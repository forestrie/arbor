---
name: go-comments
description: "Go comment conventions for arbor and the shared Go libraries: package comments, exported symbol docs, and signposting cross-repo wire contracts instead of duplicating devdocs prose."
when_to_use: Writing or reviewing Go code in arbor or go-merklelog / go-univocity / go-sigv4.
paths: ["**/*.go"]
user-invocable: false
---

# Go comments

**Scope:** Go source in **arbor** and shared libraries (`go-merklelog`, `go-univocity`,
`go-sigv4`, etc.).

## Principles

1. **Signpost cross-repo contracts.** Ranger, sealer, and custodian interact with
   canopy Workers, R2, Queues, and univocity HTTP/on-chain — link to the owning
   doc when local code assumes a wire shape.
2. **Package comment** on every non-`main` package: one paragraph on purpose and
   primary consumers.
3. **Exported symbols** need doc comments. Follow standard Go conventions.
4. **Do not duplicate** devdocs ADR/ARC prose — link
   [devdocs](https://github.com/forestrie/devdocs) and repo `docs/agents/`.

## Key signposts

| Topic | Where |
|-------|-------|
| MMR / massif behaviour | [forestrie/go-merklelog](https://github.com/forestrie/go-merklelog) |
| Grant / Univocity client | [forestrie/go-univocity](https://github.com/forestrie/go-univocity) |
| R2 SigV4 | [forestrie/go-sigv4](https://github.com/forestrie/go-sigv4) |
| COSE MMR profile | [draft-bryce-cose-receipts-mmr-profile](https://github.com/robinbryce/draft-bryce-cose-receipts-mmr-profile) |
| Platform glossary | [devdocs/glossary.md](https://github.com/forestrie/devdocs/blob/main/glossary.md) |

Repo-specific Go comment rules may also live in arbor `.cursor/rules/go-comments.mdc`.
