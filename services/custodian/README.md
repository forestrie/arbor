# Custodian

Key custody and short-lived token issuance service for Forestrie. See [ADR-0033](https://github.com/forestrie/devdocs/blob/main/adr/adr-0033-custodian-key-service.md) and [Plan 0013](https://github.com/forestrie/devdocs/blob/main/plans/plan-0013-custodian-implementation.md).

## Endpoints

- `GET /api/keys/{keyId}/public` — Public key for a key (no auth).
- `POST /api/keys` — Create a key for a log owner (normal app token). Body: `{"key_owner_id":"...","alg":"ES256"|"KS256","labels":{...}}` (labels optional; GCP labels: lowercase, `[a-z0-9_-]`, max 63 chars; `owner_id` is always set from key_owner_id).
- `POST /api/keys/list` — List keys matching labels (normal app token). Body: `{"labels":{"k":"v",...},"predicate":"and"|"or"}`. Returns `{"keys":[{"key_id":"...","version":N,"count":M},...]}`; `count` omitted when 1.
- `POST /api/keys/{keyId}/delete` — Schedule destruction of all key versions (bootstrap app token only). Key versions enter DESTROY_SCHEDULED; material is destroyed after the key ring's destroy window.
- `POST /api/keys/{keyId}/versions/delete-from` — Schedule destruction of versions with version number ≤ N (bootstrap app token only). Body: `{"version": N}`.
- `POST /api/token` — Short-lived token for custody_signer (normal app token). Body: `{"key_owner_id":"..."}`.
- `POST /api/token/bootstrap` — Short-lived token for delegation_signer / bootstrap (bootstrap app token only).

## Configuration

Env (ConfigMap): `LOG_LEVEL`, `SHUTDOWN_TIMEOUT`, `PORT`, `GCP_PROJECT_ID`, `GCP_LOCATION`, `DELEGATION_SIGNER_SA_EMAIL`, `CUSTODY_SIGNER_SA_EMAIL`, `CUSTODY_KEY_RING_ID`.

Secrets (Secret `custodian-secrets`): `APP_TOKEN`, `BOOTSTRAP_APP_TOKEN`. Create the secret in the cluster (e.g. `kubectl create secret generic custodian-secrets --from-literal=APP_TOKEN=... --from-literal=BOOTSTRAP_APP_TOKEN=... -n forestrie-dev`).

## Build

From arbor repo root:

```bash
task custodian:build
task custodian:push IMAGE_TAG=main-abc1234-1
```

## Deploy

Custodian is deployed by Flux from arbor-flux (base + gke-dev/gke-prod overlays). Ensure forest-1 Terraform has been applied so the custody key ring and custodian/custody_signer SAs exist.
