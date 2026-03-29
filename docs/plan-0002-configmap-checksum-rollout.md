---
Status: DRAFT
Date: 2026-03-23
Related: [plan-0001-custodian-cbor-api.md](plan-0001-custodian-cbor-api.md); repo **forestrie/arbor-flux** (not arbor)
---

# Plan 0002: ConfigMap checksum annotations + CI (automatic rollouts)

## Goal

When a GitOps-managed **`service-configmap.yaml`** changes in **arbor-flux**,
the corresponding workload **rolls out automatically** without
`kubectl rollout restart`. Achieved by **Pod template annotations** on the
**Deployment** whose values are **SHA-256 (hex)** of the ConfigMap file bytes,
updated by a **script** enforced in **CI**.

## Background (agent: do not skip)

- **`envFrom.configMapRef`** is resolved at **Pod start**. Editing the
  ConfigMap in place does **not** restart Pods.
- Annotations belong on **`spec.template.metadata.annotations`** of the
  **Deployment**, not on the ConfigMap resource.
- Changing an annotation changes the pod template → **new ReplicaSet** →
  rolling update.

## Repository and inventory

**Repo:** `github.com/forestrie/arbor-flux` (branch `main`).

**ConfigMaps** (one per service per environment):

| Environment | Paths |
|-------------|--------|
| dev | `clusters/gke-dev/services/{ranger,sealer,scout,custodian}/service-configmap.yaml` |
| prod | `clusters/gke-prod/services/{ranger,sealer,scout,custodian}/service-configmap.yaml` |

**Deployments** (base): `base/services/<service>/deployment.yaml` — each lists
`envFrom.configMapRef.name: <service>-config` (verify names match before
patching).

**Secrets:** applied out-of-band / other workflows — **do not** checksum in this
plan (out of scope).

---

## Canonical hash (normative)

**Input:** The exact **file bytes** of `service-configmap.yaml` as committed
(UTF-8), **whole file**, from first byte to last byte (includes
`apiVersion`, `metadata`, `data`, comments if any).

**Output:** `SHA256` as **64 lowercase hex characters** (no `sha256:` prefix).

**Command (reference):** `shasum -a 256 <path>` → take first field; normalize
to lowercase for consistency.

**Rationale:** Whole-file hash is trivial to implement and audit; avoids
partial-YAML edge cases. Editors must not reformat unrelated whitespace if you
want stable hashes — or accept that formatting-only PRs trigger rollouts
(usually acceptable).

---

## Annotation contract (normative)

- **Key:** `checksum/config` on each **Deployment’s** pod template (each
  workload has exactly one `service-configmap.yaml` → one hash).

- **Value:** 64-char lowercase hex SHA-256 of that overlay’s
  `service-configmap.yaml`.

(If a service later gains a second ConfigMap, extend to keys like
`checksum/config-2` or `checksum/config.<logical-name>` — not needed for the
current four services.)

---

## Deliverable layout (agent: create these)

For **each** of the eight `(env, service)` pairs above:

1. Add a **Kustomize patch** file next to the ConfigMap, e.g.  
   `clusters/gke-dev/services/custodian/deployment-config-hash.yaml`

2. Patch content: **Strategic-merge** (or JSON6902) patch targeting
   `Deployment/<service>` in that namespace, setting **only**:

   ```yaml
   spec:
     template:
       metadata:
         annotations:
           checksum/config: "<64-hex>"
   ```

3. Register the patch in that overlay’s **`kustomization.yaml`**:

   ```yaml
   patches:
     - path: deployment-config-hash.yaml
   ```

   (Merge with existing `patches:` — preserve order if docs require.)

**Do not** put the volatile hash in `base/` — hashes differ per overlay file.

---

## Task: `arbor-flux` — `task sync-service-config-checksums`

**Behavior (implement exactly):** Implemented in `arbor-flux/Taskfile.yml` (go-task).

1. For each fixed tuple  
   `(clusters/gke-dev|gke-prod)/services/(ranger|sealer|scout|custodian)`:
   - `CM=.../service-configmap.yaml`
   - `PATCH=.../deployment-config-hash.yaml`
   - Assert `yq '.metadata.name' "$CM"` equals `<service>-config`.
   - `HASH=$(shasum -a 256 "$CM" | awk '{print tolower($1)}')` (or `sha256sum`
     equivalent on Linux).
   - **Idempotently write** `PATCH` with annotation `checksum/config: "$HASH"`.
2. Exit 0 when done.

**Idempotency:** Running twice with no file changes produces **no git diff**.

**Dependencies:** [go-task](https://taskfile.dev/), `shasum` or `sha256sum`,
`yq` v4 (`mikefarah/yq`).

---

## CI: `.github/workflows/validate-service-config-checksums.yaml` (arbor-flux)

**Trigger:** `pull_request` and `push` to `main`, paths:

- `clusters/**/services/**/service-configmap.yaml`
- `clusters/**/services/**/deployment-config-hash.yaml`
- `Taskfile.yml`
- `.github/workflows/validate-service-config-checksums.yaml`

**Steps:**

1. Checkout
2. Install `yq` (same as other forestrie workflows)
3. Run `task sync-service-config-checksums`
4. `git diff --exit-code` — **fail** if working tree dirty (checksums out of
   sync)

**Optional follow-up:** on `push` to `main` only, same job with
`continue-on-error: false` — already covered by push trigger.

---

## Agent implementation order (checklist)

1. Clone **arbor-flux**; confirm eight `service-configmap.yaml` paths exist.
2. For each service, read `base/services/<svc>/deployment.yaml` and record
   `metadata.name` of Deployment and `configMapRef.name`.
3. Add `deployment-config-hash.yaml` in each of eight overlay dirs with a
   **placeholder** hash (`0` × 64 or `deadbeef…`) and correct annotation key.
4. Add `patches:` entry in each overlay `kustomization.yaml` (merge with
   existing patches).
5. Run **`kubectl kustomize clusters/gke-dev/services/custodian`** (etc.) locally
   to verify build succeeds.
6. Implement **`Taskfile.yml`** (`sync-service-config-checksums`); run it;
   commit
   updated patches with **real** hashes.
7. Add **GitHub Actions** workflow; open PR touching one key in a dev
   ConfigMap → confirm CI fails before script run, passes after.
8. Merge; **Flux** reconciles; confirm **new ReplicaSet** without manual
   restart (`kubectl rollout history deployment/<svc> -n forestrie-dev`).
9. Document in **`arbor-flux/README.md`** (short section): edit ConfigMap →
   run `task sync-service-config-checksums` before commit, or let CI teach you.

---

## Acceptance criteria

- Editing any of the eight `service-configmap.yaml` files without updating the
  corresponding hash patch **fails CI** after running the sync script check.
- After a merged ConfigMap + hash change, **Pods restart** via Deployment
  rollout (observe new `ReplicaSet` or newer `metadata.generation`).
- `task sync-service-config-checksums` is **deterministic** and **idempotent**.

## Out of scope

- **Secrets** (`custodian-secrets`, etc.) — not in this repo’s checksum flow.
- **Volume-mounted** ConfigMaps (if added later).
- Changing **image** automation — unchanged; image bumps continue as today.

## Effort

~**0.5–1 day** for an agent with repo write access (script + 8 patches +
kustomization edits + one workflow + README + one verification pass).
