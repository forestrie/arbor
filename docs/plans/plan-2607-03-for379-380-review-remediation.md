---
id: 2607-03
status: executed (re-review 2026-07-12; R2 open as a rollout gate)
created: 2026-07-12
refs: [ADR-0007, plan-2607-01, FOR-379, FOR-380, FOR-383]
---

# plan-2607-03 — FOR-379/FOR-380 review remediation (sealer trigger phases 0–1)

## Verification (re-review, 2026-07-12)

All items executed and verified by a second review-changes pass:

- **R1 ✅** publish detached (`go c.sealHints.PublishSealHints(...)`); acceptance
  test proves `processLogGroup` returns while a blocking publisher is in
  flight. Race-clean under `go test -race` (the mode CI runs).
- **R2 ⏳ open by design** — rollout gate: confirm
  `sealer_seal_trigger_total{source="ranger_hint"}` increments on lane A and
  no body-wrapper unmarshal warnings (plan-2607-01 exit criteria + FOR-380).
- **R3 ✅** `merklelogtest.MemClient` + rollover test. Fake fidelity verified
  against the real backends: GetOptions range semantics match the documented
  contract (zero-value full read, 1-byte probe); `FailIfExists` never reaches
  an ObjectClient without `IfNoneMatch:"*"` (Replacer pairs them), so the
  fake's stronger create-only check cannot diverge for real callers.
- **R4 ✅ (upgraded)** [arbor#52](https://github.com/forestrie/arbor/pull/52).
  Executing it surfaced that `test:unit` ended with `exit 0` — test failures
  did not fail even the main-branch pipeline. Fixed in #52 alongside the new
  PR gate; all 13 modules verified passing hermetically before arming.
- **R5/R7 ✅** plan-2607-01 updated (names, wire contract, lag caveat, R2 gate).
- **R6 ✅** documented (by-design). **R8 ✅** covered by the ack-failure test.

New (Low/informational) from the re-review — deferred: MemClient's list
continuation is a snapshot offset (fine single-threaded; doc-comment worthy);
#52's `paths:` filter means a later required-check branch protection would
block doc-only PRs (use a job-level filter if/when protection is enabled);
`tibdex/github-app-token@v1` is tag-pinned (matches existing build-deploy
practice — sweep both together if hardening); plan-2607-01 is edited by both
#51 and #48 in disjoint hunks (second to land may need a trivial rebase).

Remediation plan from a review-changes pass over the two-PR stack implementing
[plan-2607-01](plan-2607-01-sealer-nudge-trigger.md) phases 0–1:

- [arbor#50](https://github.com/forestrie/arbor/pull/50) — FOR-379 phase 0
  (sealer `seal_trigger_total{source}` + `checkpoint_lag_seconds`)
- [arbor#51](https://github.com/forestrie/arbor/pull/51) — FOR-380 phase 1
  (ranger seal hints; stacked on #50)

Review lens: backend implementation (distributed systems / tamper-evident logs
at scale). Verified against the ADR-0007 invariants: hints carry no authority
(sealer re-derives from R2 state — upheld, asserted by the dedupe test); ranger
commit success never depends on hint delivery (upheld — fire-and-forget, but
see R1); sealer remains outbound-only (upheld — no new inbound surface).

**No High findings. The stack is mergeable**; R1–R4 below are fix-in-stack or
fast-follow, R5+ deferred/documented.

## Findings summary

| ID | Sev | Dim | Location | Finding |
|----|-----|-----|----------|---------|
| R1 | Med | Liveness | `ingress/consumer.go` publish-after-ack | Inline hint publish extends the poll cycle: groups run in per-poll goroutines but `wg.Wait()` gates the next pull, so a dead/slow hint queue adds up to ~4.4s per massif key (2 attempts × 2s + delay) to the shard's poll cadence. Commit path unaffected; sequencing throughput degrades while the hint queue is down. |
| R2 | Med | Correctness (verify) | `sealhint/publisher.go` wire contract | The pull-side encoding assumption (`content_type:"text"` ⇒ pull delivers the JSON-string token the sealer double-decodes) is reasoned from the consumer's decode of R2 events and unit-tested at the publisher, but not verified against a live Cloudflare queue. Failure mode is benign and observable (hints acked-as-invalid, `seal_trigger_total{ranger_hint}`=0, R2 backstop keeps sealing) but the phase-1 exit criterion silently fails until noticed. |
| R3 | Med | Test coverage | `committer.go` `MassifObjectKeys` | Key recording (rollover + final commit) has no direct test — existing committer tests are constructor-only. Wrong keys ⇒ hints reference nonexistent objects ⇒ sealer parses log/height from the path and re-derives, so a *wrong-but-well-formed* key still seals the right log; a malformed key is dropped as invalid. Low blast radius, but the exit-criterion measurement depends on keys being right. |
| R4 | Med | Best practice (CI) | `.github/workflows/` | Pre-existing, not introduced by this stack: arbor has **no PR-triggered `go test`** workflow (build-deploy runs on push to main). The review gate for arbor (`go test ./...` per service) is local-only. |
| R5 | Low | Correctness (docs) | `sealer.go` `observeCheckpointLag` | Catch-up seals (multi-massif loop after an idle gap or backfill) observe genuinely large lags into the histogram, skewing p50/p90 interpretation of the baseline. Correct data, needs an interpretation caveat where the baseline is recorded. |
| R6 | Low | Liveness (by design) | `committer.go` error paths | If a rollover commit succeeds but the final commit errors, the rolled-over massif's hint is dropped for that round (no ack ⇒ redelivery; only the *current* massif key is recorded next round). The R2 event backstop covers the old massif. Intentional under "hints are best-effort"; documented here. |
| R7 | Low | Best practice | metric naming | plan-2607-01 names the failure counter `seal_hint_publish_failures_total`; implementation uses the service-prefixed `ranger_seal_hint_publish_failures_total` (+ a success counter), consistent with every other ranger metric. Plan should be updated to the implemented names, not vice versa. |
| R8 | Low | Test coverage | `ingress/consumer.go` | The publish-after-ack ordering (hints only on the ack-success path) is untested; would need pull/ack stubs. The property is simple and visible in review; cover opportunistically when the ingress consumer next grows a test harness. |

## Remediation items

### R1 — decouple hint publishing from the poll cycle (fix in stack, #51)

Publish asynchronously after ack so a slow/dead hint queue cannot stretch
`wg.Wait()`: either (a) `go c.sealHints.PublishSealHints(ctx, keys)` — bounded
by the publisher's own 2-attempt/2s-per-attempt budget, at most one goroutine
per committed group; or (b) keep inline but cut the budget (1 attempt, 500ms).
Prefer (a): it preserves the retry and matches "fire-and-forget" literally.

**Acceptance:** with the hint queue unreachable, shard poll cadence is
unchanged (test: stub publisher that blocks 2s; assert pollCycle duration is
not extended). No goroutine leak: publisher context is the poll ctx, cancelled
on shutdown.

### R2 — verify the wire contract at rollout (ops step, FOR-380 AC)

At lane-A rollout, before calling phase 1 done: confirm
`sealer_seal_trigger_total{source="ranger_hint"}` increments and the sealer
logs no `failed to unmarshal message body wrapper` warnings for hint messages.
If the encoding assumption is wrong, adjust the publisher's `content_type` /
body encoding (single-line change; publisher test pins whatever the verified
contract is).

**Acceptance:** written into FOR-380 as a rollout checklist item (done —
tracked there); one lane-A cycle observed with `ranger_hint` dominating.

### R3 — committer key-recording test (fast follow)

Add a `CommitLogGroup` test exercising rollover using the same in-memory /
filesystem massif store approach as the massifs-layer tests, asserting
`MassifObjectKeys` = exactly the object paths of the massifs written (old massif
on rollover + final), via `store.ObjectPath`.

**Acceptance:** test fails if a key is dropped, duplicated, or computed for the
wrong massif index.

### R4 — PR-triggered Go test workflow (separate PR, pre-existing gap)

Add `.github/workflows/go-test.yml`: on `pull_request`, matrix over
`services/{ranger,sealer,publisher,custodian,univocity,scout}`, run
`gofmt -l`, `go vet ./...`, `go test ./...` with the per-service `go.work`
staged the way `services/*/Dockerfile` does (the `_deps` clones make this the
non-trivial part — mirror the Dockerfile COPY set or vendor a setup script).

**Acceptance:** #50/#51-shaped changes cannot merge with failing service tests.

### R5 — baseline interpretation caveat (docs, with the FOR-379 baseline)

When recording the lane-A p50/p90 baseline into plan-2607-01, note that
`checkpoint_lag_seconds` includes catch-up seals; quote p50 alongside p90/p99
and prefer steady-state windows for the before/after comparison.

### Deferred (documented only)

R6 (by-design best-effort hints), R7 (update plan-2607-01 metric names when
recording the baseline), R8 (opportunistic ingress-consumer test harness).

## Branch assignment

| Item | Where |
|------|-------|
| R1 | `robin/for-380-ranger-seal-hints` (amend #51) |
| R2 | FOR-380 rollout checklist (Linear) |
| R3 | fast-follow branch off #51 (or amend #51 if trivial with existing store fakes) |
| R4 | new branch, separate PR (repo-wide CI, not this feature) |
| R5, R7 | plan-2607-01 edit alongside the FOR-379 baseline capture |
