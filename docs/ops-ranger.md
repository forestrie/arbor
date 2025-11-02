# Ranger Service Operations

Operational guide for the Ranger queue consumer service.

## Overview

Ranger is a 12-factor Go microservice that consumes messages from Cloudflare Queue via HTTP pull. It processes R2 object notifications and extracts log metadata for downstream processing.

## Configuration

### Required Environment Variables

- `RANGER_QUEUE_URL`: Cloudflare Queue HTTP endpoint URL
  - Format: `https://api.cloudflare.com/client/v4/accounts/{account_id}/queues/{queue_name}`
- `RANGER_QUEUE_API_TOKEN`: Bearer token for Cloudflare Queue authentication

### Optional Environment Variables

- `PORT`: Health check server port (default: `9090`)
- `LOG_LEVEL`: Log level: `debug`, `info`, `warn`, `error` (default: `info`)
- `POLL_INTERVAL`: Queue poll interval (default: `5s`)
- `VISIBILITY_TIMEOUT`: Message visibility timeout (default: `30s`)
- `SHUTDOWN_TIMEOUT`: Graceful shutdown timeout (default: `30s`)

### R2 Integration Variables

- `R2_BUCKET_NAME`: R2 bucket name (for validation)
- `R2_ACCOUNT_ID`: Cloudflare account ID (for public URL construction)
- `R2_PUBLIC_URL`: Override R2 public URL (auto-constructed if not set)
- `TRUST_CANOPY`: If true, verify hash by reading object; if false, trust path hash (default: `false`)

## Kubernetes Deployment

### Resource Requirements

- Requests: 100m CPU, 64Mi memory
- Limits: 500m CPU, 256Mi memory

### Health Checks

- **Liveness**: `GET /healthz` (fails if service cannot respond)
- **Readiness**: `GET /readyz` (fails if service cannot process messages)
- **Version**: `GET /version` (returns version metadata)

### Secrets

Ranger requires a Kubernetes secret `ranger-secrets` in namespace `forestrie-arbor`:
- `queue-url`: Cloudflare Queue endpoint
- `queue-api-token`: Bearer token

**Create secret**:
```bash
kubectl create secret generic ranger-secrets \
  --from-literal=queue-url="https://api.cloudflare.com/client/v4/accounts/{id}/queues/{name}" \
  --from-literal=queue-api-token="your-token" \
  --namespace=forestrie-arbor
```

### ConfigMap

Non-sensitive configuration is stored in `ranger-config` ConfigMap:
- `log-level`: Log level
- `poll-interval`: Poll interval duration
- `visibility-timeout`: Message visibility timeout
- `shutdown-timeout`: Shutdown timeout duration

## Deployment

### First Deployment

1. Ensure namespace exists:
   ```bash
   kubectl create namespace forestrie-arbor
   ```

2. Create secrets (see above)

3. Apply manifests:
   ```bash
   kubectl apply -f services/ranger/k8s/
   ```

4. Verify deployment:
   ```bash
   kubectl get pods -n forestrie-arbor -l app=ranger
   kubectl logs -n forestrie-arbor -l app=ranger
   ```

### Automated Deployment

GitHub Actions workflow automatically deploys on push to `main` when `services/ranger/**` changes. See `DEVELOPMENT.md` for CI/CD details.

### Manual Deployment

```bash
task gcp-auth
task ranger:build
task ranger:push IMAGE_TAG=dev
task ranger:deploy IMAGE_TAG=dev RANGER_QUEUE_URL="..." RANGER_QUEUE_API_TOKEN="..."
```

## Monitoring

### Logs

Ranger outputs structured JSON logs. Key events:
- Service startup with version info
- Queue poll attempts and results
- Message processing (success/failure)
- Configuration validation errors
- Graceful shutdown

**View logs**:
```bash
kubectl logs -n forestrie-arbor -l app=ranger --tail=100 -f
```

### Health Endpoints

```bash
# Port forward to localhost
kubectl port-forward -n forestrie-arbor svc/ranger 9090:9090

# Check health
curl http://localhost:9090/healthz
curl http://localhost:9090/readyz
curl http://localhost:9090/version
```

## Troubleshooting

### Pod Fails to Start

**Configuration errors**:
- Check logs for validation errors
- Verify secrets are correctly set: `kubectl get secret ranger-secrets -n forestrie-arbor -o yaml`

**Image pull errors**:
- Verify image exists in Artifact Registry
- Check service account has image pull permissions

### Service Cannot Connect to Queue

- Verify `RANGER_QUEUE_URL` is correct
- Verify `RANGER_QUEUE_API_TOKEN` is valid and has queue read permissions
- Check network connectivity from cluster to Cloudflare API

### Messages Not Processing

- Check logs for poll results and errors
- Verify queue has messages: `wrangler queues consumer list {queue-name}`
- Increase log level to `debug` for detailed polling information

### High Memory Usage

- Reduce `POLL_INTERVAL` if processing large batches
- Check for message processing errors causing retries
- Review resource limits in deployment manifest

## Message Processing

### Message Format

Ranger processes R2 notification messages:

```json
{
  "account": "...",
  "action": "object-create",
  "bucket": "...",
  "object": {
    "key": "logs/{logID}/fence-{index}/{hash}",
    "size": 1234,
    "eTag": "..."
  },
  "eventTime": "..."
}
```

### Processing Logic

1. Extract log metadata from object path
2. Validate SHA256 hash (if `TRUST_CANOPY=false`, reads object and computes hash)
3. Process notification (current implementation logs details)

**Note**: Business logic in `ProcessMessage()` may need extension based on requirements.

## Known Issues and Limitations

1. **ProcessMessage stub**: Current implementation only logs messages. Business logic needs implementation based on requirements.

2. **No retry logic**: Failed messages are logged but not retried. Consider implementing exponential backoff or dead letter queue handling.

3. **Single-threaded processing**: Messages are processed sequentially. For higher throughput, consider parallel processing with configurable concurrency.

## Security Considerations

- Service runs as non-root user (UID 1000)
- Secrets are stored in Kubernetes Secrets, not in code
- Queue API token should have minimal required permissions (queue read/consume only)
- Consider network policies to restrict pod egress to Cloudflare API only
