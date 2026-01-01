# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Repository overview

- Go microservices for the Forestrie transparency log system.
- Two main services:
  - **ranger** – queue consumer for Cloudflare Queue / R2 object notifications.
  - **sharder** – Kubernetes operator managing shard assignments.
- Infrastructure and API context:
  - **Canopy** (sibling repo) provides the SCITT/SCRAPI API, Cloudflare Queues, and R2 buckets.
  - **forest-1** (sibling repo) provides the GKE cluster and Flux GitOps infrastructure where these services run.

## Architecture and layout

### Service layout

- Services live under `services/` as independent Go modules (`github.com/forestrie/arbor/services/{service}`).
- `LAYOUTmd` documents the intended longer-term mono-repo structure (tools/libs/proto/ops). When adding new services or shared code, align with that layout and prefer:
  - One service = one Go module = one container.
  - Shared functionality in `libs/` modules (authkit, sdk, etc.) only when genuinely shared, not prematurely.
  - Tooling (e.g., `golangci-lint`, `buf`) pinned via a future `tools/` Go module instead of ad-hoc installation.

### Ranger service (queue consumer)

- **Entry point:** `services/ranger/cmd/ranger/main.go`
  - Loads config via `ranger.LoadConfig()` from `config.go`.
  - Configures a global JSON `slog` logger and sets log level using environment-driven `LOG_LEVEL`.
  - Starts:
    - HTTP health server on `PORT` (default `9090`) exposing `/healthz`, `/readyz`, `/version`.
    - Queue consumer loop via `consumer.NewQueueConsumer(...).ConsumeQueue(ctx)` running in its own goroutine.
  - Handles OS signals (INT/TERM), cancels context, and gracefully shuts down the health server with `SHUTDOWN_TIMEOUT`.

- **Configuration:** `services/ranger/config.go`
  - `Config` struct holds all 12-factor env configuration: queue settings, R2 settings, logging, shutdown, `TRUST_CANOPY`.
  - `LoadConfig`:
    - Reads env vars, applies defaults, derives `R2_PUBLIC_URL` if not explicitly set.
    - Maps string log levels (including numeric values) to `slog.Level`, logs the resolved level.
    - Logs config values and secret digests (SHA-256 of secrets; never logs raw secrets).
  - `Config.Validate` ensures required fields like `RANGER_QUEUE_URL`, `RANGER_QUEUE_API_TOKEN`, `R2_WRITE_URL`, `R2_WRITER_TOKEN`, and queue batch size constraints.

- **HTTP connectivity:** `services/ranger/connections.go`
  - `HTTPClient` wraps a tuned `http.Transport`:
    - Connection pooling (`MaxIdleConns`, `MaxIdleConnsPerHost`).
    - Keep-alives tuned around queue polling interval.
    - Reasonable dial/TLS/response timeouts.
  - `Do` method:
    - Executes requests with context.
    - On error, closes idle connections and logs a warning, relying on the transport to reconnect.

- **Queue consumer:** files under `services/ranger/consumer/`
  - `QueueConsumer` encapsulates:
    - `ranger.Config`.
    - Shared `*ranger.HTTPClient`.
    - `*slog.Logger`.
  - `ConsumeQueue`:
    - Uses a ticker based on `POLL_INTERVAL`.
    - On each tick, calls `PullAndProcessMessages`.
    - Stops cleanly when context is cancelled.
  - `PullAndProcessMessages`:
    - Builds `.../messages/pull` request to Cloudflare Queue with `batch_size` and `visibility_timeout_ms`.
    - Uses Bearer auth via `RANGER_QUEUE_API_TOKEN`.
    - Decodes pull response into `QueuePullResponse`, logs message count and backlog.
    - For each message:
      - Calls `ProcessMessage`; if successful, calls `AcknowledgeMessage` (`.../messages/ack`).
      - If processing or ack fails, logs warnings but continues with remaining messages.
  - `ProcessMessage`:
    - Unwraps Cloudflare Queue body into an R2 notification payload.
    - Filters to `PutObject` events.
    - Parses object key paths (e.g., `logs/{logId}/leaves/{hash}`) via `parseObjectPath`, validating structure and hex hash.
    - When `TRUST_CANOPY` is false, currently exits early (no verification); when true, calls `VerifyObjectHash` to read from R2 and verify the hash, logging failures but consuming messages regardless.

- **R2 client and storage integration:**
  - `services/ranger/r2/`:
    - `Client` wraps the Cloudflare R2 HTTP API using an abstract `HTTPDoer` (implemented by `ranger.HTTPClient`).
    - Provides `PutObject`, `GetObject`, `ListObjects`, and `DeleteObject` with structured error types and small, focused options structs.
  - `services/ranger/storage/`:
    - `Factory` constructs merklelog storage primitives (e.g., `Replacer`, `Store`) backed by an `r2.Client`.
    - Integrates with `github.com/forestrie/go-merklelog` storage interfaces to let higher layers operate on logs by ID without embedding R2 details everywhere.

- **Testing and MinIO-based integration:** `services/ranger/tests/testcontext.go`
  - `TestContext` wires together:
    - An `r2.Client` pointed at a MinIO bucket.
    - A `ranger/storage.Factory` for merklelog operations.
    - Test helpers from `go-merklelog` (e.g., `mmrtesting`, `providers`).
  - Uses env vars (`R2_MINIO_ENDPOINT`, `R2_MINIO_BUCKET`, `R2_MINIO_BEARER_TOKEN`) with sensible defaults.
  - `ensureMinioAvailable` hits `minio/health/live` and conditionally skips tests with a message that references `task -f Taskfile_minio.yml minio:start`.

### Sharder service (Kubernetes operator)

- **Entry point:** `services/sharder/cmd/sharder/main.go`
  - Constructs a `controller-runtime` manager with:
    - Base Kubernetes scheme + `ShardAssignment` API (`api/v1alpha1`).
    - Leader election enabled with `LeaderElectionID: "shard-operator"`.
  - Registers `controllers.PodShardReconciler` and starts the manager with a signal handler.

- **API types:** `services/sharder/api/v1alpha1/shardassignment_types.go`
  - `ShardAssignment` CRD:
    - `Spec`:
      - `OwnerSelector` – label selector for owner pods.
      - `HolderName`, `HolderUID` – track which pod currently holds the shard.
    - `Status`:
      - `Phase` – e.g., `"Unassigned"` or `"Held"`.
  - `ShardAssignmentList` list type and accompanying `DeepCopyInto` methods are defined explicitly.

- **Controller:** `services/sharder/controllers/shard_controler.go`
  - Implements the operator reconciliation loop using controller-runtime, expected to:
    - Watch Pods and `ShardAssignment` resources.
    - Assign shard IDs via pod annotations (e.g., `shard.gav.dev/id`).
    - Coordinate claims/releases so that at most one pod holds a given shard.

### CI/CD and deployment

- **CI workflow:** `.github/workflows/build-deploy.yml`
  - Trigger: push to `main` touching `services/**` or the workflow file.
  - Uses:
    - `arduino/setup-task` to install `go-task`.
    - Google `auth` and `setup-gcloud` actions with Workload Identity Federation.
  - Steps:
    - Compute `image_tag` as `main-<short-sha>-<run-number>`.
    - Configure Docker for Artifact Registry (`europe-west2-docker.pkg.dev`).
    - Authenticate to GKE cluster `forest-dev-1` in region `europe-west2`.
    - Ensure/patch `ranger-secrets` secret (injects `queue-api-token` from `RANGER_QUEUE_API_TOKEN` GitHub secret).
    - Run `task ranger:build` and `task ranger:push` with `IMAGE_TAG`.
  - Flux (in the forest-1 repo) handles image automation and applies Kustomize manifests to the `forestrie-arbor` namespace.

- **Task-based build system:** `Taskfile.dist.yml`
  - Centralizes:
    - GCP auth (`registry-auth`, `cluster-auth`, `gcp-auth`).
    - Test orchestration (`test`, `test:unit`, `test:integration`).
    - Service-specific tasks via includes (e.g., `taskfiles/service-ranger.yml`).
  - Relies on additional `taskfiles/` checked out via the `bootstrap` task.

## Common development commands

All commands below are run from the repo root unless otherwise noted.

### Bootstrapping taskfiles

Run once per clone to pull in shared taskfiles (including testing and MinIO helpers):

```bash
task bootstrap
```

This uses `git-bootstrap` to populate `taskfiles/` (e.g., `gotest.yml`, `Taskfile_minio.yml`, `service-ranger.yml`).

### Building and running services

**Build and run ranger locally (binary-only):**

```bash
cd services/ranger
go build ./cmd/ranger
./ranger
```

Before running, set at least:

```bash
export RANGER_QUEUE_URL="https://api.cloudflare.com/client/v4/accounts/{account_id}/queues/{queue_name}"
export RANGER_QUEUE_API_TOKEN="your-queue-token"
export LOG_LEVEL="debug"          # optional
export PORT="9090"                # optional, defaults to 9090
```

Ranger exposes:

- `GET /healthz` – liveness.
- `GET /readyz` – readiness.
- `GET /version` – version, commit, build date (populated by ldflags in CI and Task-based builds).

**Task-based Docker build and push for ranger:**

These commands are defined via `Taskfile.dist.yml` and `taskfiles/service-ranger.yml`:

```bash
# Authenticate to GCP (Artifact Registry + GKE)
task gcp-auth

# Build image with metadata
task ranger:build IMAGE_TAG=dev-local

# Push image (requires registry auth)
task ranger:push IMAGE_TAG=dev-local
```

**Deploy ranger to GKE (when the deploy task is available):**

As documented in `DEVELOPMENT.md`:

```bash
task gcp-auth
task ranger:deploy IMAGE_TAG=dev \
  RANGER_QUEUE_URL="https://api.cloudflare.com/client/v4/accounts/{account_id}/queues/{queue_name}" \
  RANGER_QUEUE_API_TOKEN="your-queue-token"
```

Deployment assumes the forest-1 infra and Flux wiring are already in place.

### Testing

**Run all tests via Taskfile:**

```bash
task test
```

This runs:

- `task test:unit` – unit tests (delegates to `gotest:unit`).
- `task test:integration` – integration tests, including MinIO-backed tests.

**Unit tests only:**

```bash
task test:unit
```

**Integration tests (requires MinIO):**

```bash
# Starts MinIO (via optional Taskfile_minio.yml include)
task test:integration
```

Integration tests use MinIO as an R2 emulator; they will be skipped if MinIO is not reachable. You can control MinIO connection via:

- `R2_MINIO_ENDPOINT` (default `http://127.0.0.1:9000`)
- `R2_MINIO_BUCKET` (default `ranger-r2-tests`)
- `R2_MINIO_BEARER_TOKEN` (optional)

### Running a single Go test

For service-local tests, you can bypass Taskfile and use `go test` directly in the relevant Go module.

Examples for ranger:

```bash
# From repo root
cd services/ranger

# Run a single test in the module by name pattern
go test ./... -run 'TestNameSubstring'

# Run tests for a specific package only
go test ./consumer -run 'TestSpecificCase'
```

Use the same pattern in `services/sharder` for operator tests once they are implemented.

### Linting and static analysis

Project-specific linting commands are not currently defined in the Taskfile includes, but `LAYOUTmd` expects a `tools/` module to pin tools like `golangci-lint`.

Until that exists:

- Prefer running standard Go tooling from each service module, for example:

```bash
cd services/ranger
go vet ./...
```

- If you install `golangci-lint` (globally or via a tools module), the conventional command is:

```bash
golangci-lint run ./...
```

When adding linting to this repo, prefer wiring it through a `tools/` Go module and Taskfile tasks rather than ad-hoc scripts.

## Documentation

All architecture documents (ARCs), decision records (ADRs), operational runbooks
(ops), and implementation plans now live in the shared **devdocs** repository at
`../devdocs/`. This repository should not contain ADRs, ARCs, or plans - use
devdocs instead.

Key devdocs locations:
- `../devdocs/adr/` - Architecture Decision Records
- `../devdocs/arc/` - Architecture documents
- `../devdocs/ops/` - Operational runbooks
- `../devdocs/plans/` - Implementation plans

When referencing documentation in commits or code comments, use devdocs paths.

## Guidance for future changes

- **Respect service boundaries:** Keep ranger- and sharder-specific logic inside
  their respective modules under `services/`. Extract shared functionality into
  `libs/` only when it is genuinely shared across services.
- **Align with documented layout:** Use `LAYOUTmd` as the source of truth for
  how new services, libs, proto definitions, and ops tooling should be
  structured.
- **Integrate with existing CI/CD:** When adding new tasks or deployment logic,
  align with the existing Taskfile + GitHub Actions + Flux pattern rather than
  introducing parallel pipelines.
- **Configuration via env only:** Follow the existing pattern in `ranger.Config`
  when adding new configuration, including validation and safe logging of
  configuration values and secrets.
- **Documentation in devdocs:** All ADRs, ARCs, ops docs, and plans should be
  created in the devdocs repository, not in this repository's docs/ folder.
