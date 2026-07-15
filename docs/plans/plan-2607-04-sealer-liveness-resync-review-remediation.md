---
id: 2607-04
status: DRAFT
created: 2026-07-15
refs: [ADR-0007, plan-2607-01, FOR-390, arbor#66, canopy#133]
---

# plan-2607-04 — Sealer liveness review + active-set resync remediation

Liveness/performance review of the sealer trigger model, and the remediation:
add a **level-triggered resync** over the **active-delegation set** as the
correctness backstop, keeping the edge-triggered R2/hint path as the low-latency
fast path — the Kubernetes-controller pattern (watch + resync). This
concretises the **phase-3 sweep** named (but left unimplemented) in
[ADR-0007](../adr/adr-0007-low-latency-sealer-trigger.md) /
[plan-2607-01](plan-2607-01-sealer-nudge-trigger.md).

**Two parts are kept deliberately distinct:** §1–2 are **review findings** (the
current state and its defects); §3–5 are the **planned approach** (a proposal,
not yet built) refined via a grill-with-docs session on 2026-07-15.

---

## §1 — Review findings (current sealer)

Reviewed as a distributed-systems/scale engineer, liveness+performance lens.
Confirmed against the code and **three live reproductions this session** (root,
`David-auth`, `AUTH2` — a first checkpoint that deferred on delegation and was
never re-driven).

| ID | Sev | Finding |
|----|-----|---------|
| **F1** | **High** | **Edge-triggered sealing with no level-triggered backstop.** Triggers are R2 `PutObject` notifications + ranger seal hints — both *edges* on a massif write. A seal that defers (`ErrDelegationPending`/`Expired`) or hard-fails is redelivered at most `max_retries=3` (**no dead-letter queue** in `forest-1/infra/sealer-queue.tf`), then **dropped**; after that the head is **never re-sealed until a new write**. Idle/low-write logs lose their checkpoint indefinitely. This is the core defect. |
| **F2** | Med | **Deferrals/failures invisible in prod.** The deferral logs at `INFO` (below the deployed `notice` level) with no metric, so a stuck sealer is indistinguishable from an idle one. (Fix in flight: [arbor#66](https://github.com/forestrie/arbor/pull/66) — WARN + `sealer_checkpoint_deferred_total`; open, not deployed.) |
| **F3** | Med | **In-memory lease cache** → restart/redeploy is a per-log re-issuance storm *and* any in-flight/dropped seal during the restart is lost (the loss is F1). |
| **F4** | Med | **No duplicate-edge debounce.** hint + R2 event per massif ⇒ ~2× `CheckpointLog` executions, roughly half of them no-op re-derivations that still pay R2 reads. |
| **F5** | Med | **Single idle cadence.** The queue consumer self-tunes busy↔idle via exponential backoff for the *edge* path, but there is no separate cadence for a corrective scan — there is no corrective scan at all (F1). |
| **F6** | Low* | **Advance-cert-TTL vs requested-lease-TTL coupling.** `defaultDelegationTTL` (60m) == the advance-cert TTL left only a ~2-min delegate→seal budget; lease-verify conflates "valid for *this* seal" with "cacheable for the full window". *Fixed for the demo by [canopy#133](https://github.com/forestrie/canopy/pull/133) (6h cert); the design smell remains.* |
| **F7** | Low | **`max_retries=3`, no DLQ** → dropped seal events vanish with no retained trace. |

### Design holes / non-obvious details
- **"Triggers are hints; R2 is truth"** (ADR-0007 invariant): `CheckpointLog`
  already re-derives all work from R2 state, so *any* extra/spurious/late wake is
  harmless. This is precisely what makes a level-triggered resync safe and
  cheap — it need only be a **detector** that enqueues hints.
- The **phase-3 sweep** is already scaffolded (`SealTriggerSourceSweep` in
  `metrics/seal_trigger_total.go`) but has **no implementation**.

---

## §2 — Findings → remediation mapping

**Does the active-set resync proposal (§3) address every finding? No — be
explicit:**

| Finding | Addressed by the resync proposal? |
|---------|-----------------------------------|
| **F1** (edge-only, no backstop) | **Yes — this is the core fix.** |
| **F7** (dropped work) | Yes — resync re-drives; *and* add a DLQ as a cheap independent net (§4). |
| **F3** (restart re-seal gap) | **Partial** — resync re-drives seals lost across a restart; the *re-issuance storm* is separate (mitigated by the 6h cert + optional lease-cache persistence). |
| **F2** (observability) | **No — independent.** Ship arbor#66; the resync also needs its own `sweep`-sourced metrics. |
| **F4** (duplicate-edge debounce) | **No — independent** (orthogonal in-process debounce). |
| **F5** (busy/idle cadence) | **Subsumed** — the resync loop *is* the second cadence; the edge path keeps its existing backoff. |
| **F6** (TTL coupling) | **No — largely fixed** (#133); revisit the lease-verify semantics separately. |

---

## §3 — Planned approach (proposal — grilled 2026-07-15)

**Kubernetes-controller pattern: edge-triggered *watch* for latency +
level-triggered *resync* for correctness.** The sealer runs two independent
loops.

### 3.1 Fast path — unchanged
The existing R2/hint queue consumer stays as-is (low latency, already
busy/idle-adaptive via exponential backoff). It carries latency.

### 3.2 Work set — active-or-recently-expired delegations + sealer RAM
The resync's candidate set is **logs with a delegation cert whose
`expires_at > now − grace`** — i.e. active *or* recently expired. Constraint:
`resyncCyclePeriod + maxSealTime ≪ grace ≪ delegationTTL`. With the 6h cert TTL,
`grace ≈ 1h` and a full resync cycle of minutes means a dropped seal is
re-driven many times before its cert leaves the set; a fully-sealed idle log ages
out with no work. The sealer additionally keeps a **RAM set of "seen-unsealed,
not-yet-confirmed-sealed" logs**, so a head under repair stays watched even if
its cert expires mid-repair. (Rebuilt from the coordinator on boot; loss is
self-healing — the next resync re-observes it.)

### 3.3 Coordinator API — server-side-aggregated `active` (sealer stays shard-agnostic)
`GET /api/delegations/active?cursor={opaque}&limit={n}` on the coordinator:
- The **coordinator** owns the fan-out over its `COORDINATOR_SHARD_COUNT` shard
  DOs (the *only* party that knows N) and returns
  `[{logId, expiresAt, mmrEnd}]` for `expires_at > now − grace` + an **opaque
  next-cursor**. Because a resync needs no global ordering, it pages
  **shard-by-shard** (cursor = `(shardIndex, keysetCursor)`) — **one DO per
  page, no cross-shard merge**. Index-only via the existing
  `idx_delegation_certificates_coverage (log_id_hex32, expires_at, mmr_start, mmr_end)`.
- The **sealer treats the cursor as opaque**, never learns N, so **resharding is
  transparent** and there is **no shard-count config to drift**. (Confirmed:
  `COORDINATOR_SHARD_COUNT` is the coordinator's own, single source of truth,
  independent of ingestion's `QUEUE_SHARD_COUNT`.)
- The sealer reads it **directly** (it already dials the coordinator as
  `TRUST_ROOT_URL`); plain read, bearer-authed, no signing.

### 3.4 Resync loop — one page per tick, spread over intervals
Each resync tick: fetch **one page**, and for each candidate compare its massif
head to its latest checkpoint in R2 (the freshness check `CheckpointLog` already
does); for each **unsealed** head, **enqueue a `sweep`-sourced seal hint** into
the existing seal queue (same `{object:{key}}` shape, `hintSource:"sweep"`) —
sealing stays one path with one concurrency cap and one dedupe; the resync is a
cheap *detector*, not a sealer. One page/tick means a large active set is walked
over many ticks (`fullCycle = ⌈|active|/pageSize⌉ × tick`) — the RAM-spread.

### 3.5 Cadence
A **fixed slow resync tick** suffices for a backstop (it only needs `fullCycle ≪
grace`). Busy/idle adaptation of the *resync* (speed a cycle that found unsealed
heads, slow one that found none) is an **optional refinement**, not core — the
edge path already owns latency.

---

## §4 — Remediation items (acceptance criteria + assignment)

**Core (the F1 fix):**
1. **canopy — coordinator `active` endpoint** (§3.3). *AC:* keyset-paged,
   shard-by-shard, opaque cursor; index-only; returns active-or-recently-expired
   per-log rows; bearer-authed; unit test that a paged full walk returns every
   log with a cert `expires_at > now−grace` exactly once across a reshard-stable
   cursor. *Repo:* canopy (delegation-coordinator).
2. **arbor — sealer resync loop + RAM known-unsealed set** (§3.2/3.4/3.5). *AC:*
   a dropped/deferred first checkpoint is re-driven and sealed within one resync
   cycle **without any new write**; resync enqueues `sweep`-sourced hints;
   per-tick work is O(page); `sealer_seal_trigger_total{source="sweep"}` and a
   `sealer_resync_*` gauge set exist. Live-repro the exact F1 scenario and show
   it self-heals. *Repo:* arbor (sealer).

**Independent (do regardless of the resync):**
3. **F2 — merge/deploy arbor#66** (deferral WARN + `sealer_checkpoint_deferred_total`).
4. **F7 — add a dead-letter queue** to the seal queue in
   `forest-1/infra/sealer-queue.tf` so dropped events are retained (belt-and-braces
   with the resync). *Repo:* forest-1.
5. **F4 — duplicate-edge debounce** (short-window dedupe by object key across
   hint+R2 event). *Repo:* arbor (sealer consumer).

**Deferred / revisit:**
6. **F6 — lease-verify semantics** — decouple "valid for this seal" from
   "cacheable for the window" so the advance-cert TTL need not exceed the lease
   TTL by construction. Low priority given #133.
7. **F3 — lease-cache persistence** (optional) to cut the restart re-issuance
   storm; the resync + 6h cert already remove the *correctness* impact.

---

## §5 — Notes
- The resync makes `max_retries`/DLQ tuning non-load-bearing for *correctness*
  (the resync is the backstop) — DLQ (item 4) becomes a diagnostics aid, not a
  safety requirement.
- ADR-0007 should be updated to record item 1–2 as the concrete phase-3 design
  (or a short follow-up ADR) once accepted.

## §6 — Deliberately out of scope: does the coordinator need to shard at all?
The `active` endpoint (item 1) is specified with an **opaque cursor precisely so
this plan does not depend on the answer** — the sealer never learns
`COORDINATOR_SHARD_COUNT`, so the coordinator can keep N=4, drop to N=1, or
reshard later with **zero sealer change**. That decoupling is the only thing this
plan needs to get right now; the shard-count decision itself is deferred.

Whether the coordinator sharding earns its cost is a **separate
production-readiness question** (load-estimate-driven, coordinator-wide, not a
liveness fix) → **tracked as a Linear in "Ship a reliable production platform",
not changed here.** Framing for that issue:
- **Buys:** aggregate throughput past a single DO's single-threaded ceiling;
  storage past a single DO's limit; hot-log isolation.
- **But near-term:** per-log delegation state is tiny (a few certs/routes — far
  from any single-DO storage limit); delegation-in-advance + sealer lease-caching
  make coverage-retrieval *not* per-seal, pushing the throughput ceiling far out;
  N=1 is **already supported** (`handler.ts` fallback) so un-sharding is a config
  flip + trivial (dev-sized) migration.
- **Costs it imposes today:** `get-pending` and `post-delegate-keys` already
  **fan out writes/reads to every shard** (N× amplification); the `active`
  endpoint needs shard-by-shard paging *because* of N>1; resharding is a
  cert-migration hazard.
- **Likely conclusion (to confirm with load numbers):** sharding is speculative
  for current+near-term scale; lease-caching + keyset pagination are the load
  levers that matter first. Keep N configurable, default low, shard when measured
  issue/seal rates demand it.
