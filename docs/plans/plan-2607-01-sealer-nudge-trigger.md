---
id: 2607-01
status: phases 0–1 live on lane A (2026-07-12); staged on lane B pending promotion; phases 2–3 pending
created: 2026-07-10
refs: [ADR-0007, FOR-335, FOR-334, FOR-379, FOR-380]
---

# plan-2607-01 — Sealer nudge trigger (ranger seal hints → long-poll coordinator)

Implements [ADR-0007](../adr/adr-0007-low-latency-sealer-trigger.md): replace
the R2 event-notification wake path with ranger-originated seal hints, then a
long-poll coordinator; demote R2 events to backstop. Target: receipt
availability in ~1–2s on a warm lane, single-digit seconds when idle.

**Invariants (from the ADR, restated as review gates):** hints are hints —
`CheckpointLog()` re-derives all work from R2 state; ranger commit success
never depends on hint delivery; the sealer stays outbound-only.

---

## Phase 0–1 rollout results (lane A, 2026-07-12)

Landed: [#50](https://github.com/forestrie/arbor/pull/50) (phase 0),
[#53](https://github.com/forestrie/arbor/pull/53) (phase 1; supersedes #51),
[#52](https://github.com/forestrie/arbor/pull/52) (PR test gate). Deployed to
lane A as `main-5a71fb1-460`; enabled via `forest-dev-5/svc_ranger-a`
(`SEAL_HINT_QUEUE_URL` = the sealer's `QUEUE_URL`; token: the sealer's queue
token reused — push-verified — pending a dedicated Queues-push token, which
needs an operator-minted CF API token). **Lane B: keys pre-staged on
`svc_ranger-b`; inert until the next promotion carries a ranger release with
the hint code (lane-B runs promoted semver images — v0.1.14 predates it).**

**Baseline (hints off, `system-e2e` traffic, warm lane):** 7 checkpoints,
`sealer_checkpoint_lag_seconds` mean **15.7s**, all in the (10, 20] bucket;
triggers 14/14 `r2_event`.

**After (hints on, same e2e):** +7 checkpoints, lag mean **15.4s**, all still
(10, 20]; triggers +14 `ranger_hint` / +14 `r2_event`;
`ranger_seal_hints_published_total` 7 (one per massif commit),
`…failures_total` 0; zero sealer parse warnings. The wire contract was also
verified independently pre-rollout: hand-published hints with the exact
publisher encoding were consumed as valid by the production sealer.

**Interpretation — functionally proven, latency win masked on this traffic
shape:**

- Every commit produced exactly one hint; delivery, parsing, and
  source-attribution all work. Duplicate wake (hint + R2 event per massif)
  is harmless as designed (28 CheckpointLog executions → 14 written
  checkpoints; the extras no-op).
- `sealer_checkpoint_duration_seconds` mean is **1.2s** — signing/proof/PUT
  and the lease *API call* are not the residual. The ~15s lag on *fresh* logs
  is dominated by **delegation issuance** (coordinator → agent webhook →
  submit) deferring the first seal (`ErrDelegationPending` → no ack →
  redelivery), which the e2e's log-per-run pattern hits on every log. This is
  precisely the ADR risk row "delegation lease becomes dominant latency —
  follow-up: per-log lease caching".
- **Exit-criterion nuance:** `ranger_hint` cannot *dominate* `r2_event` in
  raw counts while both paths deliver one message per massif — counts are
  equal by construction until phase 3 demotes R2 events (or first-wake
  attribution is added). The meaningful phase-1 signals — hints published ==
  massifs committed, zero failures, zero parse errors — are all green.
- The idle-lane case (where R2-event delivery lazily costs 30–90s and the
  hint should win big) is not exercised by burst e2e traffic; measure it
  once delegation issuance latency is addressed, on an already-delegated log.

**Discovered en route:** lane-A e2e had been red since canopy #118 deployed —
npm's `canopy-e2e-kit@0.5.1` predated the strict-CBOR migration; republished
as 0.5.2 ([canopy#119](https://github.com/forestrie/canopy/pull/119)), which
restored lane-A e2e (7 passed; 3 remaining failures are mandate Mode-C
webhook specs + the missing `CANOPY_OPS_ADMIN_TOKEN` in the GitHub lane-a
environment — tracked separately, unrelated to sequencing).

---

## Phase 0 — Baseline observability (do first, ships alone)

Without this we cannot prove the win or see which path fires.

Implemented in [arbor#50](https://github.com/forestrie/arbor/pull/50)
(FOR-379). Metric names as landed carry the service prefix, consistent with
every other sealer/ranger metric (plan-2607-03 R7):

- Sealer: `sealer_seal_trigger_total{source}` counter. Source is inferable
  today only as `r2_event`; the label set is fixed so later phases extend it
  (`ranger_hint`, `long_poll`, `sweep`; unknown values clamp to `unknown`).
- Sealer: `sealer_checkpoint_lag_seconds` histogram — massif `lastID`
  idtimestamp vs checkpoint write time (both already available in
  `CheckpointLog()`). **Interpretation caveat (plan-2607-03 R5):** catch-up
  seals (multi-massif loops after idle gaps or backfills) observe genuinely
  large lags; quote p50 alongside p90/p99 and prefer steady-state windows for
  the before/after comparison.
- Canopy (optional, cross-repo): registration→receipt latency is already
  observable from e2e poll timings; capture the current lane-A numbers in
  this plan before phase 1 lands.

Touches: `services/sealer/src/metrics/`, `consumer/consumer.go`,
`sealer.go`.

## Phase 1 — Ranger seal hints into the existing sealer queue

Smallest change that removes the uncontrollable leg (R2→event→queue).

Implemented in [arbor#51](https://github.com/forestrie/arbor/pull/51)
(FOR-380). Two wire-contract details the abbreviated body below glosses over,
discovered against the consumer and pinned by tests: the hint must carry
`"action": "PutObject"` (the consumer gates on it) and is published with
`content_type: "text"` so the pull delivers the JSON-string token the
consumer double-decodes. The hint additionally carries
`hintSource: "ranger_hint"` for wake-path attribution (older sealers ignore
it).

- Ranger config: `SEAL_HINT_QUEUE_URL`, `SEAL_HINT_QUEUE_TOKEN` (empty =
  feature off). `services/ranger/src/config.go`.
- Ranger: after a log group commits and acks
  (`consumer/ingress/consumer.go` → `processLogGroup`), publish one hint per
  written massif: body `{"object": {"key": "<massif object key>"}}` — the
  exact shape the sealer already parses (`sealer/src/consumer/cloudflarer2.go`),
  so **no sealer consumption change**. Fire-and-forget: detached from the
  poll cycle (publish starts after ack; the poll loop never waits on it —
  plan-2607-03 R1), bounded retry (2 attempts, short timeout), failure logs +
  `ranger_seal_hint_publish_failures_total` (successes:
  `ranger_seal_hints_published_total`); never blocks or fails the commit
  path.
- Dedupe consideration: sealer may now see the same massif key twice (hint +
  R2 event). Already harmless — `CheckpointLog()` groups by log and
  re-derives — asserted in `consumer/grouping_test.go`, not by argument.
- Deploy config (cross-repo, forest-1): env vars for ranger; producer token
  for the sealer queue.
- Tests: unit test for the publisher (success, retry, disabled, wire
  contract); publish-after-ack ordering + poll-cadence isolation
  (`ingress/publish_after_ack_test.go`); massif key recording across rollover
  (`committer/committer_massif_keys_test.go`); e2e (lane A) soft assertion
  that registration→receipt < 10s p50.

Exit criteria: `sealer_seal_trigger_total{source="ranger_hint"}` dominates
`r2_event` on lane A; receipt p50 measurably below phase-0 baseline. Rollout
verification (plan-2607-03 R2): confirm `ranger_hint` increments and the
sealer logs no body-wrapper unmarshal warnings — the string-token pull
encoding is unit-tested but must be confirmed once against a live queue.

## Phase 2 — Seal-coordinator long-poll (kills the poll ceiling)

- Canopy (cross-repo): `seal-coordinator` DO (or an extension of the
  forestrie-ingress worker family):
  - `POST /nudge` — ranger, app-token auth; body = massif object key;
    stores into a small per-log dirty set (DO storage), resolves any parked
    waiter.
  - `GET /wait?cursor=` — sealer, separate app token; long-poll (~25s hold,
    below Workers' limits); returns pending keys + next cursor, or empty on
    timeout. At-least-once; cursor is an optimization, not a correctness
    mechanism.
- Ranger: nudge the coordinator instead of (or in addition to) the queue
  publish — config `SEAL_COORDINATOR_URL` / token.
- Sealer: long-poll client loop alongside the existing queue pull; config
  `SEAL_COORDINATOR_URL` / token (empty = disabled). Each wake feeds the
  same per-log work grouping as queue messages.
- Tests: DO unit tests (nudge-then-wait, wait-then-nudge, cursor replay);
  sealer client loop with a stub coordinator; chaos case — coordinator down
  → phase-1 queue path still triggers.

Exit criteria: wake latency (nudge→`CheckpointLog` start) p50 < 500ms on
lane A; sealer idle request rate lower than interval polling.

## Phase 3 — Demote / retire R2 event notifications

- Sealer: periodic sweep — on `SWEEP_INTERVAL` (default 60s) list heads for
  known logs and seal any unsealed gap; `source="sweep"`. Known-logs
  discovery follows the existing shard-discovery pattern rather than a full
  bucket scan.
- Observe one full lane cycle: if `source="r2_event"` only ever fires
  duplicate work, remove the R2 event binding from deployment config
  (forest-1) and delete the notification-specific parsing comments (the
  message shape stays, now fed by hints).

## Risks

| Risk | Mitigation |
|------|------------|
| Hint lost (ranger crash post-PUT, pre-hint) | Backstop: R2 events (phases 1–2), sweep (phase 3) |
| Duplicate triggers double-seal | Impossible by construction (state-derived work); asserted by test in phase 1 |
| Coordinator outage | Fast path degrades to queue/backstop; sealer loop treats long-poll errors as timeout + jitter |
| Delegation lease becomes dominant latency | Out of scope here; per-log lease caching noted in ADR-0007 as follow-up |
| Token sprawl (producer + two coordinator tokens) | Reuse existing app-token provisioning in forest-1; document in service READMEs |

## Sequencing / ownership

Phases 0–1 are arbor-only and independently shippable; phase 2 spans
canopy + arbor (coordinator first, behind config); phase 3 is cleanup after
soak. Each phase is its own PR(s) against this plan; update `status:` in the
frontmatter as phases land.
