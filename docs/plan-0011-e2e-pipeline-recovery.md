---
Status: DRAFT
Date: 2026-06-06
Related: [plan-0008](plan-0008-univocity-grant-store-and-authority-resolver.md), [plan-0010](plan-0010-custodian-kms-ensure-and-e2e-key-hygiene.md)
---

# Plan 0011: E2E pipeline recovery (univocity 502 + receipt 404 + rollout)

## Goal

Root-cause and fix the three blocking system e2e failures: worker→univocity
502, receipt/checkpoint 404, and cluster/CI rollout drift. Use Doppler
**`forest-dev-5`** (arbor-flux secrets) and **`cloudflare-account` / `dev`**
(Cloudflare APIs) for investigation.

The authority-resolver **feature work is complete**; this plan closes the
**operational verification** gap.

## Symptom summary (2026-06-06)

| Failure | Symptom | Likely layer |
|---------|---------|--------------|
| Genesis / public-root | `univocity … returned 502 (15 bytes)` | Cloudflare edge cannot reach univocity origin |
| Receipt resolve | 404 until 30s after status redirects to `/receipt` | `.log` exists, `.sth` missing → sealer not sealing |
| CI Deploy Workers | `COORDINATOR_APP_TOKEN already in use` | Wrangler re-`secret put` on existing binding |
| Cluster images | ledger-a on `main-8db9eed-424` | New build `main-6be353c-425` not rolled out |

Custodian ensure + e2e key hygiene: shipped (`6be353c` arbor, `b5c8a94` canopy).

## Receipt pipeline inference

Failing tests get **303** on register-grant and **redirect to receipt URL** on
status polling → sequencing, ranger, and massif `.log` writes work. Persistent
receipt **404** means [`resolve-receipt.ts`](../../canopy/packages/apps/canopy-api/src/scrapi/resolve-receipt.ts)
cannot find `v2/merklelog/checkpoints/{h}/{uuid}/{index}.sth`.

**Primary hypothesis:** sealer is not creating checkpoints.

Sealer seal path per massif notification:

1. `GET http://univocity:9091/api/logs/{uuid}/authority`
2. `POST http://custodian:9092/api/delegations`
3. Write `.sth` to R2

Failure at 1 or 2 → no checkpoint → receipt 404.

## Phase 0 — Observability baseline

### Doppler (`forest-dev-5`)

```bash
doppler secrets get DNS_SUB DNS_APEX RANGER_INGRESS_QUEUE_URL SEALER_QUEUE_URL GRANTS_R2_URL \
  -p forest-dev-5 -c infra --plain

doppler secrets get UNIVOCITY_AUTHORITY_URL DELEGATION_ISSUER_URL TRUST_ROOT_URL \
  UNIVOCITY_API_TOKEN DELEGATION_ISSUER_TOKEN TRUST_ROOT_TOKEN QUEUE_URL \
  -p forest-dev-5 -c svc_sealer-a --plain

doppler secrets get GENESIS_R2_URL UNIVOCITY_RPC_URLS UNIVOCITY_API_TOKEN \
  -p forest-dev-5 -c svc_univocity-a --plain
```

Canopy worker: `UNIVOCITY_SERVICE_URL` + `UNIVOCITY_API_TOKEN` from forest
consumer / GitHub `dev` (must match active slot `svc_univocity-a`).

### Doppler (`cloudflare-account`, config `dev`)

DNS, R2 notifications, queue wiring:

```bash
doppler run -p cloudflare-account -c dev -- <cf API / wrangler commands>
```

Verify R2 `PutObject` under `v2/merklelog/massifs/` delivers to sealer queue
([forest-1/infra/sealer-queue.tf](https://github.com/forestrie/forest-1/blob/main/infra/sealer-queue.tf)).

### Cluster (`forestrie-a`)

```bash
kubectl -n forestrie-a logs deploy/sealer --tail=200
kubectl -n forestrie-a logs deploy/ranger --tail=100
kubectl -n forestrie-a port-forward deploy/sealer 9090:9090
curl -s localhost:9090/metrics | rg sealer_
```

Watch: `sealer_messages_processed_total` up, `sealer_logs_checkpointed_total`
flat → seal failures.

### R2 spot-check (one failed e2e log `R`)

In MMRS bucket (`forest-dev-5-logs`):

- Expect: `v2/merklelog/massifs/14/{R-uuid}/0000000000000000.log`
- Missing: `v2/merklelog/checkpoints/14/{R-uuid}/0000000000000000.sth`

### In-cluster smoke

```bash
curl -sf -H 'Accept: application/cbor' \
  "http://univocity.forestrie-a.svc:9091/api/logs/{R-uuid}/authority"
```

## Phase 1 — Image rollout (arbor-flux)

Promote ledger-a to **`main-6be353c-425`** (custodian ensure + forests/UUID).

- Check Flux image automation / `flux/image-updates` merge conflicts
- Manual pin in `clusters/ledger-a/services/*/kustomization.yaml` if needed
- `kubectl rollout status` for custodian, univocity, sealer, ranger, scout

## Phase 2 — Worker → univocity 502

**Hypothesis:** 15-byte 502 body is Cloudflare edge (`error code: 502`), not
univocity application JSON.

| Check | Action |
|-------|--------|
| External health | `curl https://univocity.a.{DNS_SUB}.{DNS_APEX}/healthz` |
| In-cluster | `curl http://univocity:9091/healthz` |
| Worker env | `UNIVOCITY_SERVICE_URL` + token vs `svc_univocity-a` |
| Ingress | [arbor-flux univocity IngressRoute](https://github.com/forestrie/arbor-flux) → port 9091 |

Fix: re-sync tokens, correct URL/slot, repair Traefik backend.

## Phase 3 — Receipt pipeline RCA (sealer) — primary focus

Decision tree:

1. `.log` missing → ranger / ingress
2. `.log` yes, sealer queue empty → R2 notification / `SEALER_QUEUE_*`
3. Sealer logs `resolve authority` → univocity grants store / `forests/` paths / RPC
4. Sealer logs `delegation issuer` → custodian tokens / `POST /api/delegations`
5. Sealer logs `deferred` → BYOK (unlikely for bootstrap e2e)
6. R2 write errors → sealer credentials

**Hypothesis A (authority):** cold bootstrap log `R` needs grant in univocity
store (`forests/forest/{R}/grants/...`) and successful
`GET /api/logs/{R}/authority`.

**Hypothesis B (delegation):** `DELEGATION_ISSUER_TOKEN` drift or custodian
delegation handler failure.

**Hypothesis C (queue):** sealer never receives massif PutObject notifications.

## Phase 4 — Deploy Workers CI

[`canopy/.github/workflows/deploy-workers.yml`](../../canopy/.github/workflows/deploy-workers.yml):
skip or guard `wrangler secret put COORDINATOR_APP_TOKEN` when binding exists
(CF error 10053).

## Phase 5 — Verification gates

1. `go test` arbor sealer/univocity/custodian
2. `pnpm --filter @canopy/api-e2e test:e2e:custodian`
3. `task test:e2e` (system project)
4. CI Tests + API e2e job green

Success: all receipt-polling system specs pass, including
`univocity-genesis-chain-binding.spec.ts`.

## Relation to authority-resolver initiative

| Original scope | Status |
|----------------|--------|
| Univocity grant store + authority | Done (code) |
| Canopy delegate genesis/grants | Done |
| Sealer authority path | Done |
| Flux wiring | Done (manifests); runtime image drift |
| E2e verify | **This plan** |

## Execution order

1. Phase 0 baseline (one failed run)
2. Phase 1 rollout `main-6be353c-425`
3. Phase 3 sealer RCA (receipt 404)
4. Phase 2 worker 502
5. Phase 4 deploy CI
6. Phase 5 full e2e

## Out of scope

- Solidity changes
- Per-run R2/MMR log cleanup automation
- Sealer R-disagreement hardening
