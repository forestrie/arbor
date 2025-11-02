# Ranger Service - Current Status & Analysis

## Overview
Ranger is a 12-factor Go microservice for consuming messages from Cloudflare Queue via HTTP pull consumer, designed for deployment on GKE. The core service implementation is complete, infrastructure is in place, but there are critical deployment blockers that need resolution.

## Current Implementation Status

### ✅ Fully Implemented

**Core Service** (`cmd/ranger/main.go`):
- Graceful shutdown on SIGTERM/SIGINT with configurable timeout
- Kubernetes health endpoints: `/healthz`, `/readyz`, `/version`
- Structured JSON logging with configurable levels (debug/info/warn/error)
- Concurrent goroutine management (health server + queue consumer)
- Version info support via ldflags injection

**Configuration** (`config.go`):
- 12-factor environment variable configuration
- Required: `QUEUE_URL`, `QUEUE_API_TOKEN`
- Optional with defaults: `PORT` (8080), `LOG_LEVEL` (info), `POLL_INTERVAL` (5s), `VISIBILITY_TIMEOUT` (30s), `SHUTDOWN_TIMEOUT` (30s)
- Validation on startup

**Queue Consumer** (`consumer.go`):
- HTTP pull-based message consumption from Cloudflare Queue
- Visibility timeout support
- Automatic acknowledgment after processing
- Error handling with continued processing
- Bearer token authentication

**Infrastructure**:
- **Dockerfile**: Multi-stage build (Go 1.23 → Alpine 3.19), non-root user, security hardened
- **K8s Manifests**: Deployment with ConfigMap, Secret, security context, resource limits, health probes
- **K8s Service**: ClusterIP service on port 9090
- **GitHub Workflow**: Build, push to Artifact Registry, deploy to GKE cluster

## 🔴 Critical Issues (Deployment Blockers)

### 1. Image Tag Mismatch
**Problem**: Workflow and K8s deployment reference different image tags
- **Workflow** (`.github/workflows/build-deploy.yml:36`): Tags with git SHA → `ranger:${github.sha}`
- **K8s Deployment** (`k8s/deployment.yaml:31`): References → `ranger:latest`

**Impact**: Deployments will fail (image not found) or use stale cached images

**Solution Options**:
- Option A: Update `k8s/deployment.yaml:31` to use SHA-based tags (recommended for immutability)
- Option B: Add `latest` tag in workflow alongside SHA tags

### 2. Build Args Missing from Workflow
**Problem**: Dockerfile expects version build args that workflow doesn't provide
- **Dockerfile:18** expects: `VERSION`, `COMMIT`, `BUILD_DATE` as build args
- **Workflow:38** doesn't pass any `--build-arg` flags

**Impact**: Version info always shows "dev", "unknown", "unknown" (main.go:21-24)

**Solution**: Add build args to workflow:
```yaml
--build-arg VERSION=${GITHUB_REF_NAME:-dev}
--build-arg COMMIT=${GITHUB_SHA}
--build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
```

### 3. Secrets Not Initialized
**Problem**: K8s deployment references secrets that don't exist
- **K8s deployment.yaml:122-123** contains placeholder values
- Workflow doesn't create or manage these secrets

**Impact**: Service will fail validation on startup (config.go:54-58 checks)

**Solution**: Initialize secrets before first deployment:
```bash
kubectl create secret generic ranger-secrets \
  --from-literal=queue-url="https://api.cloudflare.com/client/v4/accounts/{ID}/queues/{NAME}" \
  --from-literal=queue-api-token="your-actual-token"
```

### 4. No Initial Deployment Path
**Problem**: Workflow assumes deployment already exists
- **Workflow:50** only does `kubectl set image` (update operation)
- No `kubectl apply -f k8s/` step

**Impact**: First deployment must be done manually

**Solution**: Add deployment apply step before image update, or run manually once:
```bash
kubectl apply -f services/ranger/k8s/
```

## 🟡 Design Issues (Non-Blocking)

### 5. Port Default Inconsistency
- **config.go:42**: Defaults to `8080`
- **Dockerfile:43** & **K8s**: Use `9090`

**Impact**: Minor - works because K8s explicitly sets `PORT=9090` env var, but inconsistent

**Recommendation**: Update config.go default to `9090` for consistency

### 6. ImagePullPolicy Inefficiency
- **K8s deployment.yaml:32**: Uses `imagePullPolicy: Always`
- With SHA-based immutable tags, `IfNotPresent` would be more efficient

### 7. Incomplete Version Management
- **main.go:16-19** references `.goreleaser.yml` that doesn't exist
- No goreleaser configuration found in repository

## 🚧 Incomplete Implementation

### ProcessMessage Logic (Stub)
**Location**: `consumer.go:107-119`

**Current State**: Only logs message body, no business logic

**Impact**: Service is functionally incomplete - doesn't process messages meaningfully

**TODO**: Implement actual message processing logic based on business requirements

## 📊 GitHub Workflow Analysis

**File**: `.github/workflows/build-deploy.yml`

**Current Flow**:
```
Trigger: Push to main (when services/** or workflow changes)
├─ Authenticate to GCP via Workload Identity Federation
├─ Configure Docker for Artifact Registry (europe-west2)
├─ Build: docker build ./services/ranger
├─ Tag: europe-west2-docker.pkg.dev/forest-dev-1/forestrie/ranger:${github.sha}
├─ Push: SHA-tagged image to Artifact Registry
├─ Get GKE credentials: forest-dev-1 cluster in europe-west2
├─ Update deployment: kubectl set image deployment/ranger
└─ Wait for rollout: kubectl rollout status
```

**What Works**:
- GCP authentication using Workload Identity (secure, no keys)
- Docker build and push to Artifact Registry
- Automatic deployment on main branch push
- Basic rollout status checking

**What's Missing**:
- Build args for version information
- Secret initialization/management
- Initial deployment capability (only updates existing)
- Test execution before deployment
- Multi-service support (hardcoded to `ranger`)
- Rollback mechanism on failure
- `latest` tag management

## File Structure

```
services/ranger/
├── cmd/ranger/
│   └── main.go              # Service entry point (complete)
├── config.go                # 12-factor config (complete)
├── consumer.go              # Queue consumer (stub ProcessMessage)
├── go.mod                   # Go module definition
├── go.sum                   # Dependency checksums
├── Dockerfile               # Multi-stage build (complete)
├── k8s/
│   ├── deployment.yaml      # Deployment, ConfigMap, Secret (needs secret values)
│   └── service.yaml         # ClusterIP service (complete)
├── ranger-initial-prompt.md # Original session notes
└── last-session.md          # This file

../../.github/workflows/
└── build-deploy.yml         # CI/CD workflow (needs fixes)
```

## Architecture Notes

### Package Design
- `main` package: Thin entry point for service initialization
- `ranger` package: Core business logic (config, consumer)
- Clear separation enables testing and reusability

### Concurrency Model
- Main goroutine: Waits for shutdown signals
- Health server goroutine: Serves HTTP health endpoints
- Consumer goroutine: Polls queue with ticker loop
- All goroutines respect context cancellation for graceful shutdown

### Error Handling Philosophy
- Configuration errors: Fail fast on startup with clear messages
- Queue connection errors: Log and retry on next poll interval
- Message processing errors: Log and continue (don't stop consumer)
- Individual message failures are isolated

### GCP/GKE Configuration
- **Project**: forest-dev-1
- **Region**: europe-west2
- **Cluster**: forest-dev-1
- **Artifact Registry**: europe-west2-docker.pkg.dev/forest-dev-1/forestrie
- **Workload Identity**: Enabled via GitHub OIDC federation

## 🎯 Priority-Ordered Next Steps

### Priority 1: Critical Deployment Blockers

1. **Fix Image Tag Strategy** (CRITICAL)
   - Decision needed: SHA-only or SHA + latest?
   - Update either workflow or k8s/deployment.yaml for consistency
   - Recommended: Use SHA tags in deployment for immutability

2. **Add Build Args to Workflow** (HIGH)
   - Add `--build-arg` flags to docker build command
   - Pass VERSION, COMMIT, BUILD_DATE
   - Ensures proper version tracking in production

3. **Initialize Kubernetes Secrets** (CRITICAL)
   - Create `ranger-secrets` with actual Cloudflare Queue credentials
   - Update placeholder values in k8s/deployment.yaml or use external secrets manager
   - Validate service can start with real credentials

4. **Add Initial Deployment Support** (HIGH)
   - Either: Add `kubectl apply -f k8s/` to workflow
   - Or: Document manual first-time deployment steps
   - Or: Use `kubectl apply` instead of `kubectl set image` (safer, idempotent)

### Priority 2: Core Functionality

5. **Implement ProcessMessage Business Logic** (BLOCKING)
   - Update `consumer.go:107-119`
   - Define what the service should actually do with queue messages
   - Add error handling specific to business logic

### Priority 3: Quality & Consistency

6. **Standardize Port Configuration** (MINOR)
   - Change `config.go:42` default from 8080 to 9090
   - Ensures consistency across all configuration layers

7. **Add Tests** (RECOMMENDED)
   - Unit tests for consumer logic
   - Integration tests with mock Cloudflare Queue
   - Test graceful shutdown behavior
   - Integrate with existing Taskfile test infrastructure

### Priority 4: Optional Enhancements

8. **Improve Workflow Robustness**
   - Add test execution before deployment
   - Add rollback on failed deployment
   - Support for multiple services (detect changes, build only affected)
   - Add `latest` tag management if needed

9. **Add Observability** (Optional)
   - Prometheus metrics endpoint (`/metrics`)
   - Request/message counters, duration histograms
   - Queue depth/lag metrics if available
   - OpenTelemetry tracing integration

10. **Enhanced Error Handling** (Optional)
    - Retry logic with exponential backoff
    - Dead letter queue for failed messages
    - Circuit breaker for queue availability
    - Better correlation IDs for debugging

11. **Add goreleaser Config** (Optional)
    - Create `.goreleaser.yml` as referenced in main.go
    - Standardize release process
    - Generate changelogs automatically

## Deployment Checklist

Before first production deployment:

- [ ] Decide on image tag strategy (SHA vs SHA+latest)
- [ ] Update workflow with build args for version info
- [ ] Create Kubernetes secrets with real Cloudflare credentials
- [ ] Apply K8s manifests: `kubectl apply -f services/ranger/k8s/`
- [ ] Verify health endpoints respond
- [ ] Implement ProcessMessage with actual business logic
- [ ] Add unit tests for core consumer logic
- [ ] Test locally with real or mock Cloudflare Queue
- [ ] Validate graceful shutdown works correctly
- [ ] Document what the service does (business logic)
- [ ] Update port default to 9090 in config.go
- [ ] Push to main → verify automatic deployment works
- [ ] Monitor logs for successful message processing

## Testing Locally

### Prerequisites
```bash
export QUEUE_URL="https://api.cloudflare.com/client/v4/accounts/{account_id}/queues/{queue_id}"
export QUEUE_API_TOKEN="your-token-here"
export LOG_LEVEL="debug"
export PORT="9090"
```

### Build and Run
```bash
cd services/ranger
go build ./cmd/ranger
./ranger
```

### Expected Behavior
- Service starts on port 9090
- JSON logs to stdout
- Polls queue every 5 seconds
- Health endpoints respond at http://localhost:9090/healthz, /readyz, /version
- Gracefully shuts down on CTRL+C

### Test Health Endpoints
```bash
curl http://localhost:9090/healthz  # Should return "ok"
curl http://localhost:9090/readyz   # Should return "ready"
curl http://localhost:9090/version  # Should return version JSON
```

## Cloudflare Queue API Reference

The implementation assumes these Cloudflare Queue HTTP endpoints:

**Pull Messages:**
```http
POST {QUEUE_URL}/pull?visibility_timeout_ms={timeout}
Authorization: Bearer {QUEUE_API_TOKEN}
Content-Type: application/json

Response:
{
  "messages": [
    {
      "id": "message-id",
      "timestamp": "2024-10-28T...",
      "body": {...},
      "attempts": 1
    }
  ]
}
```

**Acknowledge Message:**
```http
POST {QUEUE_URL}/ack/{message_id}
Authorization: Bearer {QUEUE_API_TOKEN}

Response: 200 OK or 204 No Content
```

## Questions for Next Session

1. What should `ProcessMessage()` actually do? What's the business logic for consumed messages?
2. Image tag strategy: SHA-only (immutable) or SHA + latest (convenience)?
3. Secret management: Manual kubectl or external secrets manager (GCP Secret Manager)?
4. Should we add retry logic with exponential backoff for failed message processing?
5. Do we need metrics/observability before production deployment?
6. Should we support multiple concurrent message processors (currently single-threaded)?
7. Is there a need for a dead letter queue for persistently failing messages?

## Related Services

- `services/sharder` - Another service in the monorepo (not examined in current session)

## Repository Context

- **Working Directory**: `/Users/robin/Dev/personal/forestrie/arbor/services/ranger`
- **Git Repo**: forestrie/arbor (main branch)
- **Module**: `github.com/forestrie/arbor/services/ranger`
- **Go Version**: 1.23
- **GCP Project**: forest-dev-1
- **K8s Cluster**: forest-dev-1 (europe-west2)
