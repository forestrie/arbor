---
id: 2607-01
status: draft
created: 2026-07-10
refs: [ADR-0007, FOR-335, FOR-334]
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

## Phase 0 — Baseline observability (do first, ships alone)

Without this we cannot prove the win or see which path fires.

- Sealer: add `seal_trigger_total{source}` counter. Source is inferable
  today only as `r2_event`; the label exists so later phases extend it
  (`ranger_hint`, `long_poll`, `sweep`).
- Sealer: `checkpoint_lag_seconds` histogram — massif `lastID` idtimestamp
  vs checkpoint write time (both already available in `CheckpointLog()`).
- Canopy (optional, cross-repo): registration→receipt latency is already
  observable from e2e poll timings; capture the current lane-A numbers in
  this plan before phase 1 lands.

Touches: `services/sealer/src/metrics/`, `consumer/consumer.go`,
`sealer.go`.

## Phase 1 — Ranger seal hints into the existing sealer queue

Smallest change that removes the uncontrollable leg (R2→event→queue).

- Ranger config: `SEAL_HINT_QUEUE_URL`, `SEAL_HINT_QUEUE_TOKEN` (empty =
  feature off). `services/ranger/src/config.go`.
- Ranger: after a log group commits and acks
  (`consumer/ingress/consumer.go` → `processLogGroup`), publish one hint per
  written massif: body `{"object": {"key": "<massif object key>"}}` — the
  exact shape the sealer already parses (`sealer/src/consumer/cloudflarer2.go`),
  so **no sealer change**. Fire-and-forget: bounded retry (e.g. 2 attempts,
  short timeout), failure logs + `seal_hint_publish_failures_total`; never
  blocks or fails the commit path.
- Dedupe consideration: sealer may now see the same massif key twice (hint +
  R2 event). Already harmless — `CheckpointLog()` groups by log and
  re-derives — but assert this in a test rather than by argument.
- Deploy config (cross-repo, forest-1): env vars for ranger; producer token
  for the sealer queue.
- Tests: unit test for the publisher (success, retry, disabled); e2e (lane
  A) soft assertion that registration→receipt < 10s p50.

Exit criteria: `seal_trigger_total{source="ranger_hint"}` dominates
`r2_event` on lane A; receipt p50 measurably below phase-0 baseline.

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
