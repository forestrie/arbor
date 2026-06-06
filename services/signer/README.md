# Signer service (Plan 0004 subplan 04)

Delegation API for **bootstrap** and **parent log** keys. Used by the queue consumer (subplan 05) or canopy (subplan 06) to obtain a **signature** over a grant payload (or its hash) without holding any private key material. No key material leaves the signer.

## Endpoints

### POST /delegate/bootstrap

Request a signature using the **bootstrap (local) key**. Use this for signing the **initial (root) grant** when the contract is not yet bootstrapped.

**Request body (JSON):**

- `payload_hash` (optional): 32-byte digest as hex (64 hex chars). Exactly one of `payload_hash` or `payload`.
- `payload` (optional): raw bytes as base64. Signer computes SHA-256 to get the digest.

**Response (200):**

```json
{ "signature": "<hex>" }
```

Signature is the ECDSA signature (raw r||s from KMS) as hex. Attach to the grant as the signer’s signature; verifies with the configured bootstrap public key.

**Errors:** 400 (invalid body), 503 (bootstrap key not configured).

---

### POST /delegate/parent

Request a signature using the key for a **parent (auth) log**. Use this for signing grants that create a **child** authority or data log under that parent, or for the sealer to sign checkpoints for data logs under that auth log.

**Request body (JSON):**

- `parent_log_id` (required): auth log id as a canonical dashed UUID.
- `payload_hash` (optional): same as bootstrap.
- `payload` (optional): same as bootstrap.

**Response (200):** same as bootstrap.

**Key resolution:** If `parent_log_id` equals the **root** log id (from `SIGNER_UNIVOCITY_URL` GET /api/root or from config), the signer uses the **bootstrap key**. Otherwise the signer looks up the key in `SIGNER_PARENT_KEYS` (JSON map of log id hex → KMS key resource name). In a simple deployment with only the root auth log, the bootstrap key is used for both bootstrap and parent.

**Errors:** 400 (invalid body), 404 (no key configured for parent), 503 (signer not configured).

---

## Configuration (env)

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | HTTP port (default 9092). |
| `LOG_LEVEL` | No | debug, info, warn, error. |
| `SIGNER_BOOTSTRAP_KEY_ID` | **Yes** | GCP KMS key resource name (e.g. `projects/P/locations/L/keyRings/R/cryptoKeys/K`). Must exist before univocity contract deploy/init. |
| `SIGNER_UNIVOCITY_URL` | No | Base URL of auth-log status service (subplan 02). When set, parent == root uses bootstrap key. |
| `SIGNER_PARENT_KEYS` | No | JSON object: `{"<uuid>": "<kmsKeyId>", ...}`. Keys are canonical UUID strings (32-hex accepted at config load only). |

## Flow for queue consumer / canopy

1. **Bootstrap grant:** Build grant payload (per go-univocity / subplan 01). Compute digest (e.g. SHA-256 of inner or of grant bytes). POST /delegate/bootstrap with `payload_hash: "<hex>"`. Get `signature`; attach to grant. No private key in consumer.
2. **Derived grant:** Same, but POST /delegate/parent with `parent_log_id: "<root or parent auth log id>"` and `payload_hash`. Attach signature to grant.

Signature verifies with the public key that the univocity contract expects for that log (bootstrap key for root, parent’s rootKey for children).

## Build and run

From `services/signer/src`:

```bash
go build -o signer ./cmd/signer
./signer
```

Requires GCP application default credentials (or workload identity) with `cloudkms.cryptoKeyVersions.useToSign` on the bootstrap (and parent) keys.
