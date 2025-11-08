# Service Architecture

Architectural patterns and design decisions for Arbor services.

## Service Design Principles

### 12-Factor Application

All services follow 12-factor principles:
- Configuration via environment variables
- Stateless execution
- Logging to stdout (structured JSON)
- Disposability (graceful shutdown)
- Build/release/run separation

### Package Organization

Services use a consistent package structure:
- `cmd/{service}/`: Application entry point (thin, focused on wiring)
- Package root: Core business logic modules
- `k8s/`: Kubernetes deployment manifests
- `config/`: RBAC and operator configuration (for operators)

### Concurrency Model

- Main goroutine: Signal handling and orchestration
- Separate goroutines: Health server, consumer loops, reconciliation
- Context-based cancellation for graceful shutdown
- No shared mutable state between goroutines

## Ranger Service Architecture

### Components

1. **Configuration Module** (`config.go`)
   - Environment variable loading with validation
   - Sensible defaults for optional parameters
   - Fail-fast validation on startup

2. **Queue Consumer** (`consumer.go`)
   - HTTP pull-based message consumption
   - Ticker-based polling with configurable interval
   - Visibility timeout for message locking
   - Automatic acknowledgment after processing

3. **HTTP Client** (`connections.go`)
   - Persistent HTTP client with connection pooling
   - Bearer token authentication
   - Context-aware requests for cancellation

4. **Health Server** (`main.go`)
   - Kubernetes-compatible health endpoints
   - Concurrent execution with consumer
   - Graceful shutdown with timeout

### Message Flow

```
Cloudflare Queue
    ↓ (HTTP POST /pull)
Ranger Consumer
    ↓ (Parse R2 Notification)
ProcessMessage()
    ↓ (Extract metadata, validate)
Business Logic (TODO)
```

### Error Handling

- **Configuration errors**: Fail fast on startup
- **Queue connection errors**: Log and retry on next poll
- **Message processing errors**: Log and continue (isolated failures)
- **Shutdown**: Graceful with configurable timeout

## Sharder Service Architecture

### Kubernetes Operator Pattern

Sharder implements a Kubernetes operator using controller-runtime:

1. **Custom Resource**: `ShardAssignment`
   - Spec: Owner selector, holder name/UID
   - Status: Phase (Unassigned/Held)

2. **Controller**: `PodShardReconciler`
   - Watches Pods with `app=writer` label
   - Manages shard assignments via annotations
   - Automatic shard release on pod deletion

3. **Reconciliation Loop**
   - Claim shard when pod created (if not assigned)
   - Release shard when pod deleted
   - Handle concurrent claims atomically

### Shard Management

- Shards are represented as `ShardAssignment` CRs
- Pods receive shard assignment via annotation: `shard.gav.dev/id`
- Controller ensures at most one pod holds a shard at a time

## Deployment Architecture

### Container Image

- Multi-stage Docker builds (Go builder → Alpine runtime)
- Non-root user execution (UID 1000)
- Minimal base images (Alpine or distroless)
- Build-time version injection via ldflags

### Kubernetes Deployment

- Deployment with rolling update strategy
- ConfigMap for non-sensitive configuration
- Secrets for credentials (created from GitHub Actions secrets)
- Resource limits and requests
- Security contexts (non-root, read-only where possible)
- Health probes (liveness, readiness)

### CI/CD Pipeline

- GitHub Actions workflow builds and pushes images when `services/**` changes
- Images tagged `main-<short-sha>-<run>` for sortable, traceable versioning
- Flux ImageRepository/ImagePolicy/ImageUpdateAutomation propagate new tags into manifests
- Kustomize manifests stay co-located with service code; no manual `kubectl apply`
- Taskfile commands mirror CI steps for local builds or debugging

## Design Decisions

### Why HTTP Pull for Queue Consumption?

- Cloudflare Queue provides HTTP API, not push webhooks
- Allows control over polling rate and backpressure
- Simpler than maintaining persistent connections
- Visibility timeout prevents duplicate processing

### Why Structured JSON Logging?

- Kubernetes log aggregation expects structured logs
- Easier parsing and filtering
- Standard practice for microservices
- Go's `slog` package provides efficient JSON output

### Why Independent Go Modules?

- Services may have different dependency versions
- Enables independent versioning and releases
- Reduces coupling between services
- Aligns with microservice principles

### Why Taskfile for Builds?

- Consistency between local and CI environments
- Reduces workflow duplication
- Easy to extend with service-specific tasks
- Self-documenting build process

## Future Considerations

### Scalability

- Horizontal scaling via Kubernetes Deployment replicas
- Consider message partitioning for ranger if needed
- Operator leader election already handles multiple replicas

### Observability

- Structured logging is foundation for observability
- Future: Prometheus metrics endpoint (`/metrics`)
- Future: OpenTelemetry distributed tracing
- Future: Queue depth/lag metrics

### Reliability

- Current: Basic error handling and retries
- Future: Exponential backoff for failed messages
- Future: Dead letter queue support
- Future: Circuit breaker for queue availability
