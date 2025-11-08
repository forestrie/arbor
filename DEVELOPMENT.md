# Arbor Development Guide

Arbor is a Go-based microservices repository containing backend services for the Forestrie transparency log system. Services are deployed to Google Kubernetes Engine (GKE) and integrate with Cloudflare infrastructure managed by Canopy.

## Repository Overview

Arbor contains independently deployable microservices written in Go:

- **ranger**: Queue consumer service that processes Cloudflare Queue messages for R2 object notifications
- **sharder**: Kubernetes operator that manages shard assignments for distributed workloads

Services follow 12-factor principles, use structured logging, and are designed for Kubernetes deployment.

## Project Relationships

### Canopy Integration

Canopy (sibling repository) provides the SCITT/SCRAPI transparency log API and frontend. It manages Cloudflare R2 buckets and Queues. Ranger consumes messages from queues created and populated by Canopy's R2 event notifications.

**Message Flow**:
1. Canopy Worker API receives requests and writes objects to R2
2. R2 event notifications are sent to Cloudflare Queue
3. Ranger consumes messages from the queue via HTTP pull
4. Ranger processes notifications (currently extracts log metadata, validates hashes)

### Forest-1 Infrastructure

Forest-1 (sibling repository) provides the GKE cluster infrastructure where Arbor services are deployed. It uses Terraform for infrastructure provisioning and Flux for GitOps-based service delivery.

**Deployment Flow**:
1. Code changes trigger GitHub Actions workflow
2. Services are built as Docker images and pushed to GCP Artifact Registry
3. Kubernetes manifests are applied to the GKE cluster (forest-dev-1)
4. Services run in the `forestrie-arbor` namespace

## Architecture

### Service Architecture

Services are structured as independent Go modules:

```
services/
├── ranger/           # Queue consumer service
│   ├── cmd/ranger/   # Application entry point
│   ├── config.go     # 12-factor configuration
│   ├── consumer.go   # Queue consumption logic
│   ├── k8s/          # Kubernetes manifests
│   └── Dockerfile    # Multi-stage container build
└── sharder/          # Kubernetes operator
    ├── cmd/sharder/  # Operator entry point
    ├── api/v1alpha1/ # Custom resource definitions
    ├── controllers/  # Reconciliation logic
    └── config/       # RBAC and deployment configs
```

### Configuration

All services use environment variables for configuration (12-factor):

**Ranger**:
- Required: `RANGER_QUEUE_URL`, `RANGER_QUEUE_API_TOKEN`
- Optional: `PORT` (default: 9090), `LOG_LEVEL`, `POLL_INTERVAL`, `VISIBILITY_TIMEOUT`, `SHUTDOWN_TIMEOUT`
- R2 integration: `R2_BUCKET_NAME`, `R2_ACCOUNT_ID`, `R2_PUBLIC_URL`, `TRUST_CANOPY`

### Deployment

Services are deployed as Kubernetes Deployments with:
- Health check endpoints (`/healthz`, `/readyz`, `/version`)
- Resource limits and requests
- Security contexts (non-root, read-only filesystem where possible)
- ConfigMaps for non-sensitive configuration
- Secrets for credentials

## Development Workflow

### Prerequisites

- Go 1.23+
- Docker
- kubectl (for local testing)
- gcloud CLI (for GCP operations)
- Task (taskfile.dev) for build automation
- GCP credentials configured (for deployment)

### Local Development

**Build**:
```bash
cd services/ranger
go build ./cmd/ranger
```

**Run Locally**:
```bash
export RANGER_QUEUE_URL="https://api.cloudflare.com/client/v4/accounts/{id}/queues/{name}"
export RANGER_QUEUE_API_TOKEN="your-token"
export LOG_LEVEL="debug"
./ranger
```

**Build Docker Image**:
```bash
task ranger:build
```

**Deploy to GKE** (requires authentication):
```bash
task gcp-auth
task ranger:push IMAGE_TAG=dev
task ranger:deploy IMAGE_TAG=dev RANGER_QUEUE_URL="..." RANGER_QUEUE_API_TOKEN="..."
```

### CI/CD

Arbor services use **Flux GitOps** for automated deployment, managed by the forest-1 infrastructure repository.

**Deployment Flow**:
1. Code changes trigger GitHub Actions workflow (`.github/workflows/build-push-ranger.yaml`)
2. Docker image is built and pushed to Artifact Registry with tag `main-{sha}-{timestamp}`
3. Flux ImageRepository detects the new image in Artifact Registry
4. Flux ImagePolicy selects the latest image based on alphabetical sorting
5. Flux ImageUpdateAutomation updates the image tag in `kustomization.yaml` (commits to arbor repo)
6. Flux Kustomization reconciles the deployment with the new image tag
7. Deployment rolls out automatically to GKE cluster

**GitHub Actions Workflow**:
- Triggers on push to `main` when `services/ranger/**` changes
- Uses Workload Identity Federation for GCP authentication (no static keys)
- Builds images with build metadata (version, commit, build date)
- Tags images with format: `main-{short-sha}-{timestamp}` for traceability
- Skips runs for Flux ImageUpdateAutomation commits (actor `fluxcdbot`, message `Update from image update automation`) to avoid build loops

**Required GitHub Variables**:
- `GCP_WORKLOAD_IDENTITY_PROVIDER`: Workload Identity provider (set by forest-1 bootstrap)
- `GCP_PROJECT_ID`: GCP project ID (defaults to `forest-dev-1`)

**Required Kubernetes Secrets** (managed separately):
- `ranger-secrets` in `forestrie-arbor` namespace:
  - `queue-api-token`: Bearer token for queue access

Non-secret configuration, including the Cloudflare queue URL, lives in the `ranger-config` ConfigMap generated from `services/ranger/k8s/kustomization.yaml`.

**See**: [ADR-001: Flux GitOps Deployment](docs/adr-001-flux-gitops-deployment.md) for detailed rationale and architecture.

### Testing

Run tests:
```bash
task test
```

Unit tests:
```bash
task test:unit
```

Integration tests (requires Azurite for local queue simulation):
```bash
task test:integration
```

## Services

### Ranger

Queue consumer that processes Cloudflare Queue messages. Currently handles R2 object notifications by:
- Extracting log metadata from object paths (`logs/{logID}/fence-{index}/{hash}`)
- Validating SHA256 hashes (optional, configurable via `TRUST_CANOPY`)
- Processing notifications asynchronously

**Health Endpoints**:
- `GET /healthz`: Liveness probe
- `GET /readyz`: Readiness probe  
- `GET /version`: Version information (version, commit, buildDate)

**Configuration**: See `docs/ops-ranger.md` for detailed configuration and operational notes.

### Sharder

Kubernetes operator that manages shard assignments for distributed workloads. Provides:
- Custom Resource: `ShardAssignment`
- Pod annotation: `shard.gav.dev/id`
- Automatic shard assignment and release based on pod lifecycle

**Status**: In development. See `services/sharder/` for implementation details.

## Documentation

- **Architecture**: `docs/arc-services.md` - Service architecture and design patterns
- **Operations**: `docs/ops-*.md` - Deployment, configuration, and operational guides
  - `docs/ops-ranger.md` - Ranger service operations and configuration
  - `docs/ops-first-deploy.md` - First deployment setup guide

## Build System

Taskfile-based build automation (`Taskfile.dist.yml`):
- Consistent build process across local and CI
- Service-specific tasks in `taskfiles/service-*.yml`
- Shared tasks for testing, authentication, and deployment

## Project Context

- **GCP Project**: forest-dev-1
- **GKE Cluster**: forest-dev-1 (europe-west2)
- **Artifact Registry**: europe-west2-docker.pkg.dev/forest-dev-1/forestrie
- **Kubernetes Namespace**: forestrie-arbor
- **Go Modules**: Independent modules per service (`github.com/forestrie/arbor/services/{service}`)
