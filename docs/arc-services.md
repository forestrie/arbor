# Service Architecture

Architectural patterns and design decisions for Arbor microservices.

## Design Principles

### 12-Factor Application

All services follow 12-factor principles:

- Configuration via environment variables
- Stateless execution
- Logging to stdout (structured JSON)
- Disposability (graceful shutdown)
- Build/release/run separation

### Package Organization

Services use consistent package structure:

- `cmd/{service}/`: Application entry point (thin, focused on wiring)
- Package root: Core business logic modules
- Deployment manifests: In arbor-flux repository (GitOps)
- `config/`: RBAC and operator configuration (for operators)

### Concurrency Model

- Main goroutine: Signal handling and orchestration
- Separate goroutines: Health server, consumer loops, reconciliation
- Context-based cancellation for graceful shutdown
- No shared mutable state between goroutines

## Service Components

### Ranger Service

**Purpose**: Cloudflare Queue consumer for R2 object notifications

**Components:**
1. **Configuration Module**: Environment variable loading with validation
2. **Queue Consumer**: HTTP pull-based message consumption
3. **HTTP Client**: Persistent client with connection pooling
4. **Health Server**: Kubernetes-compatible health endpoints

**Message Flow:**
```
Cloudflare Queue
    ↓ (HTTP POST /pull)
Ranger Consumer
    ↓ (Parse R2 Notification)
ProcessMessage()
    ↓ (Extract metadata, validate)
Business Logic
```

**Error Handling:**
- Configuration errors: Fail fast on startup
- Queue connection errors: Log and retry on next poll
- Message processing errors: Log and continue (isolated failures)
- Shutdown: Graceful with configurable timeout

### Scout Service

**Purpose**: Service discovery and health monitoring

**Architecture**: Similar patterns to Ranger with service-specific logic

## Deployment Architecture

### Container Images

- Multi-stage Docker builds (Go builder → Alpine runtime)
- Non-root user execution (UID 1000)
- Minimal base images (Alpine or distroless)
- Build-time version injection via ldflags

### Kubernetes Deployment

- Deployment with rolling update strategy
- ConfigMap for non-sensitive configuration
- Secrets for credentials (synced from GitHub Actions secrets)
- Resource limits and requests
- Security contexts (non-root, read-only where possible)
- Health probes (liveness, readiness)

### CI/CD Pipeline

- GitHub Actions workflow builds images when `services/**` changes
- Images tagged `main-<short-sha>-<run>` for sortable, traceable
  versioning
- Flux ImageRepository/ImagePolicy/ImageUpdateAutomation propagate
  new tags into manifests
- Manifests in arbor-flux repository (GitOps)
- See [ops-cd-flow.md](../forest-1/docs/ops-cd-flow.md) for complete
  workflow

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

### Why Separate arbor-flux Repository?

- Prevents automated commits to source repository
- Clear separation: code vs deployment manifests
- Enables GitOps without polluting source history
- See ADR-001 in forest-1 for detailed rationale

## Future Considerations

### Scalability

- Horizontal scaling via Kubernetes Deployment replicas
- Consider message partitioning for ranger if needed
- Operator leader election handles multiple replicas

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

## References

- 12-Factor App: https://12factor.net/
- Kubernetes Best Practices:
  https://kubernetes.io/docs/concepts/configuration/overview/
- Go Concurrency Patterns:
  https://go.dev/blog/pipelines
