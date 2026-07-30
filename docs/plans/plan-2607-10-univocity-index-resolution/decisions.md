# Decisions — plan 2607-10

Q/A record from the 2026-07-30 architecture session (Robin + agent), after
the lane A outage root-cause. Each decision is locked unless reopened
explicitly.

## D1 — Keep the reverse index; it is the right primitive

The index is required for subject-log resolution (R2 lists by prefix only;
a random UUID cannot be reversed into its forest) **and** it is the atomic
global-uniqueness claim: `IndexCreate(subject → R)` with if-none-match is
what prevents two forests from binding the same logId. Without it, a
hinted verifier would happily validate the same logId against either
forest — logId ambiguity is exactly the split-view shape univocity exists
to prevent. The index stays **at write time regardless** of how reads
work. Deleting the *scan* is not deleting the *index*.

Trust posture: the index is a **locator, never trust-bearing**. The
authority decision is `verifyGrantChain` against the forest's genesis
identity anchored to on-chain `bootstrapConfig()` / `logRootKey`. A wrong
or malicious index entry (or hint) can only produce a verification
failure — DoS-shaped, never acceptance of a bad root.

## D2 — Caller-supplied `rootLogId` hints: verified, O(1), zero new trust surface

Given `(logId, hint R)`: one genesis point GET for R, one grant point GET
at `forests/forest/{R}/grants/{class}/{logId}.cbor`, grant-chain
verification against that one contract (≤2 RPC). Constant per request,
independent of forest count — and **identical to the verification the
service already performs after resolution today**. The hint replaces
discovery, not verification; it is never trusted. Degenerate case
`hint == logId` is the R case (genesis GET alone).

## D3 — No backfill, no reconciler, no background machinery (Robin's call)

Rationale: a write-ordering invariant makes it unnecessary.
`handlePostGrant` runs `IndexCreate` **before** `PutGrant` and aborts on
conflict, so **a stored grant implies an existing index entry** — and
this holds for *all* eras: the index was born in the same commit as the
grant store itself (`889ad3d`, plan-0008) with claim-first ordering from
day one, and only the store writes grant objects (review-verified
2026-07-30). The only unindexed subject logs are ones that never went
through `POST /api/grants` — i.e. registered while canopy's grant
validator was unarmed. Those 404
loudly at a named logId and are repaired individually by an idempotent
grant re-post (the 200 path recreates the index entry). A one-time
read-only LIST comparing grant objects to index entries in the prod bucket
is the optional pre-flip assessment (ops, minutes, never shipped as code).

Rejected alternatives, for the record:

- **list-only backfill/reconciler** — cheap (key structure alone encodes
  subject→R and R→R, no GETs/RPC) but standing machinery for a
  self-announcing, individually-repairable failure; not worth owning.
- **on-chain event indexer** — heavier infra (block cursors), no trust
  gain since the index is locator-only.
- **external index store (D1/KV/DO)** — the R2 conditional-put index
  already gives atomic uniqueness in the same consistency and trust
  domain; a second store adds cross-store consistency questions for
  nothing.
- **hint-mandatory everywhere / deprecate logId-only routes** — the
  sealer's authority lookup exists precisely for cold logs before their
  first checkpoint and the signer's parent resolution has no receipt in
  hand; logId-only + index stays. Scoped routes remain the *preferred*
  path for binding-holding callers.

## D4 — Genesis self-index becomes mandatory, and **claim-first** (amended, review R2)

`handlePostGenesis` currently creates the genesis object first
(`handlers_write.go:70`) and self-indexes best-effort afterwards (`:76`)
— the opposite of the grant path. Making the self-index merely
*mandatory* in that order would still leave partial state on failure
(object exists, identity unclaimed) and lets a logId that is already a
*subject* in another forest acquire a genesis object, after which the
index and the R-case read fallback disagree about the same id.

Amended decision: mirror the grant path — `IndexCreate(R → R)` **first**
(cross-forest conflict → 409, nothing written), `PutGenesisIfAbsent`
second (failure → 5xx, idempotent retry; the claim is already safe to
re-run). The R case also has the derived-key genesis GET fallback at
read time, so this is belt-and-braces, not load-bearing alone.

## D5 — 404 contract (was 503)

`ErrLogNotResolved` currently maps to **503** "log not resolved"
(`handlers.go:72`). Post-change an unresolved log is a **404** with
problem-details naming the remedies: supply `?rootLogId=` or use
`/api/{chainId}/{contract}/…`. 503 remains reserved for genuine
unavailability (store/RPC unreachable). This is a semantic change for
callers that treat 503 as transient-retry — slice 04 aligns the sealer
and signer before/with the flip.

## D6 — What `probeForests` covered that now 404s

The probe could resolve a log that is initialized on-chain but has no
grant object and no index entry. On the armed paths this set is empty
(logs are initialized via flows that post the grant first); legacy
exceptions surface as named 404s with the D3 repair path. Accepted.

## D7 — Dangling locators resolve as misses, never 5xx (added, review R1)

An index entry whose forest genesis is absent is a stale *locator*, not
an unavailable service: resolution treats it as a miss (fall through to
the R case, then 404) with a best-effort index self-heal delete. Only
transport/store failures are 503. This matters because the delete paths
manufacture exactly this state today (`handleDeleteForest` leaves the
forest's subject grants + indexes; `handleDeleteGrant`'s index delete is
warn-only), and the dev-pruning follow-on would do so at scale. The
delete-side fix (forest-scoped sweep) is a pre-requisite of the pruning
follow-on, recorded in slice 04.

## Review record

review-changes run 2026-07-30 (forestrie-agents command) on the draft:
3 Medium (R1 → D7 + slice 02/04, R2 → D4 amendment, R3 → slice 04
caller-classification rewrite), 3 Low (R4 → slice 01 readyz-on-success,
R5 → slice 02 cache rules, R6 → plans README tidy). All folded into
these documents 2026-07-30; none altered D1–D3, D5, D6. Findings also
on FOR-510.

## Open questions

- **OQ1:** does any *prod* log predate the arming of
  `UNIVOCITY_SERVICE_URL` on the prod lane? (D3 assessment answers this;
  a handful of re-posts if yes.)
- **OQ2:** can the sealer extract an R hint from the delegation
  certificate chain it already holds? Not needed for the design (index
  covers grant-registered logs) — worth a look in slice 04 only if a
  legacy 404 actually bites.
