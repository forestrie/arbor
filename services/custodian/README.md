# Custodian

Key custody and KMS signing service for Forestrie. See [ADR-0033](https://github.com/forestrie/devdocs/blob/main/adr/adr-0033-custodian-key-service.md) and [Plan 0013](https://github.com/forestrie/devdocs/blob/main/plans/plan-0013-custodian-implementation.md).

## Wire format

- **All `/api/keys/...` endpoints** use **`application/cbor`** for successful responses and request bodies (where a body exists).
- **Errors** use **`application/problem+cbor`** with RFC 7807 fields: `type`, `title`, `status`, `detail` (canonical CBOR maps via `github.com/fxamacker/cbor/v2`).
- **`POST .../sign`** normally returns **`application/cose; cose-type="cose-sign1"`** — raw **untagged `COSE_Sign1`** (four-element array). Payload is the **32-byte SHA-256 digest** (bstr) being attested; protected headers include `alg` (ES256 `-7` or ES256K `-47`), `cty` `application/forestrie.custodian-statement+cbor`, and `kid` (16-byte bstr, SHA-256 of uncompressed EC point, first 16 octets — same rule as sealer delegation tooling). **Google Cloud KMS returns ECDSA signatures in ASN.1 DER; Custodian converts them to fixed-width r‖s (64 bytes for P-256 / secp256k1) before emitting CBOR.** Verification uses standard COSE `Sig_structure` + IEEE P1363 **r||s** signatures.
- **`POST .../sign`** with CBOR **`rawSignatureOnly`: true** (together with **`payloadHash`** or **`payload`** as for normal sign) returns **`application/cbor`** body **`{ signature: h'…' }`** only — **64-byte** IEEE P1363 **r‖s**, no custodian `cty` wrapper. Used by the delegation-signer Worker to build Forestrie delegation COSE (Plan 0016).
- **Ops routes** (not under `/api/keys`): `/healthz`, `/readyz`, `/metrics` stay plain text; **`/version`** stays **JSON** (registered in `cmd/custodian/main.go`).

Requests with a body must send **`Content-Type: application/cbor`**. Otherwise the server responds with **415** and a problem+cbor body.

## Endpoints

- `GET /api/keys/{keyId}/public` — Public key (no auth). CBOR: `keyId`, `publicKey`, `alg`. Custody keys are served from the in-memory store (same ids as create/list). **`GET .../:bootstrap/public`** is **not** in the store; it reads the PEM from **`BOOTSTRAP_KMS_CRYPTO_KEY_ID`** via Cloud KMS `GetPublicKey` (same resource as `POST .../:bootstrap/sign`). If that env is unset, the server returns **503** (same as bootstrap sign when unset). Integration against real KMS is not covered by unit tests; verify manually with curl against a deployed instance.
- Optional query **`log-id=true`** (or **`log-id=1`**) on **`/api/keys/{keyId}/…`** treats **`{keyId}`** as a **log id** (hex); Custodian resolves to a custody **`keyId`** or **`:bootstrap`** using KMS labels `forestrie_log_id=<normalized hex>`. **`ROOT_LOG_ID`** env enables list-miss → **`:bootstrap`** when the root key is not listed in the custody ring.
- `POST /api/keys` — Create key (normal app token). CBOR body: `keyOwnerId`, optional `alg` (`ES256`|`KS256`), optional `labels`. Response: `keyId`, `publicKey`, `alg`.
- `GET /api/keys/list` — List keys (normal app token). Query: one or more label parameters (e.g. `forestrie_log_id=<hex>`), optional `predicate` (`and`|`or`). Response: same CBOR as POST.
- `POST /api/keys/list` — List keys (normal app token). CBOR body: `labels`, optional `predicate` (`and`|`or`). Response: `keys` array of `{keyId, version, count?}`.
- `GET /api/keys/curator/log-key` — Resolve **log id → Custodian `keyId`** (normal app token). Query: **`logId=<hex>`**. Response CBOR: `keyId` (custody short id or **`:bootstrap`**).
- `POST /api/keys/{keyId}/delete` — Destroy all versions (bootstrap app token). Response: `keyId`, `destroyedCount`.
- `POST /api/keys/{keyId}/versions/delete-from` — Destroy versions ≤ N (bootstrap app token). CBOR body: `version` (int ≥ 1). Response: `keyId`, `destroyedCount`.
- `POST /api/keys/{keyId}/sign` — Returns **COSE_Sign1** bytes (see above), or **raw signature** CBOR when **`rawSignatureOnly`** is true. CBOR body: exactly one of **`payloadHash`** (bstr, 32 bytes) or **`payload`** (bstr; server computes SHA-256 for the committed digest); optional **`rawSignatureOnly`** (bool). **`APP_TOKEN`** for custody keys; key id **`:bootstrap`** requires **`BOOTSTRAP_APP_TOKEN`** and **`BOOTSTRAP_KMS_CRYPTO_KEY_ID`**.

## Configuration

Env (ConfigMap): `LOG_LEVEL`, `SHUTDOWN_TIMEOUT`, `PORT`, `GCP_PROJECT_ID`, `GCP_LOCATION`, `CUSTODY_SIGNER_SA_EMAIL`, `CUSTODY_KEY_RING_ID`, `BOOTSTRAP_KMS_CRYPTO_KEY_ID` (bootstrap root CryptoKey for `:bootstrap` signing), **`ROOT_LOG_ID`** (optional lowercase hex; list-miss → **`:bootstrap`**), **`LOG_ID_CACHE_SIZE`** (in-process LRU for log-id → key-id; defaults to **1024** when unset; set **0** to disable).

Secrets (Secret `custodian-secrets`): `APP_TOKEN`, `BOOTSTRAP_APP_TOKEN`. Create the secret in the cluster (e.g. `kubectl create secret generic custodian-secrets --from-literal=APP_TOKEN=... --from-literal=BOOTSTRAP_APP_TOKEN=... -n forestrie-dev`).

## Build

From arbor repo root:

```bash
task custodian:build
task custodian:push IMAGE_TAG=main-abc1234-1
```

## Deploy

Custodian is deployed by Flux from arbor-flux (base + gke-dev/gke-prod overlays). Ensure forest-1 Terraform has been applied so the custody key ring and custodian/custody_signer SAs exist.
