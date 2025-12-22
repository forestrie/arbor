# Forester operations

This document describes how the forester service is configured in
`forestrie/arbor` and how its Kubernetes manifests and GitHub workflows
provide credentials and configuration.

## Role of forester

Forester is a Cloudflare Queue consumer that listens for R2 notifications
about newly written massif data objects. For each relevant massif object
it:

- Reads the massif and its Urkle leaf table from R2 using the
  S3-compatible API.
- Derives `(massifHeight, mmrIndex, idtimestamp)` triples for each
  leaf.
- Writes a small receipt cache into Cloudflare KV of the form:
  `ranger/v1/{logId}/latest/{contentHashHex}`.

Important:

- Forester **never writes massifs or checkpoints back to R2**.
- All R2 access from forester is read-only, regardless of the strength
  of the credentials it receives.

## Environment variables

The forester binary is configured entirely via environment variables.
Only the most important values are listed here.

### Queue configuration

These values control how forester talks to the Cloudflare Queues HTTP
API:

- `FORESTER_QUEUE_URL` – base URL for the queue HTTP API. This includes
  the numeric queue identifier.
- `FORESTER_QUEUE_API_TOKEN` – bearer token for the queue HTTP API.
- `FORESTER_QUEUE_BATCH_SIZE` – number of messages to pull per request
  (must be between 1 and 32).
- `POLL_INTERVAL` – how often to poll the queue.
- `VISIBILITY_TIMEOUT` – visibility timeout for pulled messages.

The queue URL and batch size are set via the `forester-config`
ConfigMap in `arbor-flux`. The queue API token is injected from the
`forester-secrets` Secret.

### R2 configuration (read-only)

Forester only reads existing massif and checkpoint objects from R2 via
the S3-compatible API. It never writes objects back.

R2-related variables used by forester are:

- `R2_PUBLIC_URL` – public HTTPS endpoint for the R2 bucket containing
  the massif data and checkpoints.
- `AWS_ACCESS_KEY_ID` – access key used for SigV4-authenticated reads.
- `AWS_SECRET_ACCESS_KEY` – secret key used for SigV4-authenticated
  reads.
- `AWS_REGION` – region for SigV4 signing, defaults to `auto` for R2.

In code this is surfaced as `Config.R2PublicReadURL` plus the AWS
credential fields. The S3 client is created with:

- `baseURL = R2_PUBLIC_URL`
- `bearerToken = ""` (no R2 bearer token is used)
- `accessKeyID = AWS_ACCESS_KEY_ID`
- `secretAccessKey = AWS_SECRET_ACCESS_KEY`

Because we always provide AWS credentials, the client uses SigV4
signing and never falls back to bearer-token based writes.

### Cloudflare KV configuration

Forester writes receipt cache entries into a Cloudflare KV namespace
using a single writer token:

- `CLOUDFLARE_ACCOUNT_ID` – Cloudflare account identifier.
- `RANGER_MMR_INDEX_NAMESPACE_ID` – KV namespace used for receipt
  entries.
- `RANGER_MMR_MASSIFS_NAMESPACE_ID` – KV namespace id for massif
  metadata (wired for future use).
- `FORESTER_KV_API_TOKEN` – bearer token that authorises writes into the
  relevant KV namespace. Forester uses this exclusively for KV bulk
  writes.

The receipt cache TTL is controlled via:

- `FORESTER_KV_TTL_SECONDS` – per-entry TTL in seconds. `0` disables the
  TTL and writes non-expiring entries.

## How credentials are provisioned

Forester credentials are provided by a combination of GitHub Actions
workflows and GitOps-managed manifests in `arbor-flux`.

### R2 credentials from `sync-r2-config`

The `.github/workflows/sync-r2-config.yaml` workflow in `arbor-flux`:

1. Reads Terraform outputs from the `forest-1` repo to determine the
   R2 bucket name and public URL.
2. Uses the `R2_WRITER_TOKEN` GitHub secret (currently
   `RANGER_R2_WRITER_TOKEN`) and `RANGER_R2_WRITER_ID` to construct:
   - `R2_PUBLIC_URL` – bucket public URL.
   - `R2_WRITE_URL` – write endpoint for ranger/sealer.
   - `AWS_ACCESS_KEY_ID` – shared access key id.
3. Derives an `AWS_SECRET_ACCESS_KEY` by hashing `R2_WRITER_TOKEN`.
4. Renders ConfigMaps and Secrets for `ranger` and `sealer` from shared
   templates.
5. Renders a `forester-r2` Secret that contains only
   `AWS_SECRET_ACCESS_KEY`.

For forester this yields:

- `R2_PUBLIC_URL` and `AWS_ACCESS_KEY_ID` from the shared `ranger-r2`
  ConfigMap.
- `AWS_SECRET_ACCESS_KEY` from the `forester-r2` Secret.

Forester never consumes `R2_WRITER_TOKEN` directly and never writes
objects into the R2 bucket.

### Queue and KV tokens from `sync-ranger-secrets`

The `.github/workflows/sync-ranger-secrets.yaml` workflow creates and
updates the secrets that hold queue and KV tokens:

- `ranger-secrets` – queue token for ranger.
- `sealer-secrets` – queue token for sealer.
- `forester-secrets` – contains:
  - `queue-api-token` – reused queue token for forester.
  - `kv-api-token` – a KV-scoped token (`FORESTER_KV_API_TOKEN`).

The forester Deployment in `arbor-flux` wires these as:

- `FORESTER_QUEUE_API_TOKEN` from `forester-secrets/queue-api-token`.
- `FORESTER_KV_API_TOKEN` from `forester-secrets/kv-api-token`.

## Invariants and expectations

Operationally, we rely on the following invariants for forester:

- Forester uses R2 only for **read** access to massifs and checkpoints.
- R2 credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
  `R2_PUBLIC_URL`) are derived from a high-privilege R2 writer token in
  GitHub Actions, but that writer token is never exposed directly to the
  forester Deployment.
- All write authority held by forester is scoped to Cloudflare KV via
  `FORESTER_KV_API_TOKEN`.
- Queue and KV tokens are delivered only via Kubernetes Secrets
  (`forester-secrets`) and never hard-coded in manifests or code.
