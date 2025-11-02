# Ranger Kubernetes Deployment

This directory contains the Kubernetes manifests for deploying the ranger service to GKE.

## Files

- `deployment.yaml` - Deployment, ConfigMap, and Secret definitions
- `service.yaml` - ClusterIP service for internal access

## Prerequisites

1. GKE cluster is running (from forest-1 infrastructure)
2. Artifact Registry repository exists: `europe-west2-docker.pkg.dev/forest-dev-1/forestrie`
3. Cloudflare Queue credentials available

## Configuration

### Secrets (Required)

Before deploying, update the secrets in `deployment.yaml`:

```yaml
stringData:
  queue-url: "https://api.cloudflare.com/client/v4/accounts/YOUR_ACCOUNT_ID/queues/YOUR_QUEUE_NAME"
  queue-api-token: "YOUR_QUEUE_API_TOKEN"
```

Or use `kubectl` to create the secret:

```bash
kubectl create secret generic ranger-secrets \
  --from-literal=queue-url="https://api.cloudflare.com/..." \
  --from-literal=queue-api-token="your-token" \
  --dry-run=client -o yaml | kubectl apply -f -
```

### ConfigMap (Optional)

Adjust polling behavior in the ConfigMap section of `deployment.yaml`:

- `log-level`: debug, info, warn, error (default: info)
- `poll-interval`: How often to poll the queue (default: 5s)
- `visibility-timeout`: Message visibility timeout (default: 30s)
- `shutdown-timeout`: Graceful shutdown timeout (default: 30s)

## Manual Deployment

```bash
# Deploy to cluster
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

# Check status
kubectl get pods -l app=ranger
kubectl logs -l app=ranger -f

# Check service
kubectl get svc ranger
```

## GitHub Actions Deployment

The ranger service is designed to work with the GitHub Actions CI/CD pipeline defined in the forest-1 repo.

### Workflow Example

Create `.github/workflows/deploy-ranger.yml` in the forest-1 repo:

```yaml
name: Build and Deploy Ranger

on:
  push:
    branches: [main]
    paths:
      - 'arbor/services/ranger/**'
      - '.github/workflows/deploy-ranger.yml'

permissions:
  contents: read
  id-token: write

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: forestrie/arbor
          path: arbor

      - id: auth
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: 'projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-pool-XXXX/providers/github-provider'
          service_account: 'forest-dev-1-github-ci@forest-dev-1.iam.gserviceaccount.com'

      - name: Set up Cloud SDK
        uses: google-github-actions/setup-gcloud@v2

      - name: Configure Docker for Artifact Registry
        run: gcloud auth configure-docker europe-west2-docker.pkg.dev

      - name: Build and push Docker image
        env:
          IMAGE_URL: europe-west2-docker.pkg.dev/forest-dev-1/forestrie/ranger
          IMAGE_TAG: ${{ github.sha }}
        run: |
          cd arbor/services/ranger
          docker build -t ${IMAGE_URL}:${IMAGE_TAG} -t ${IMAGE_URL}:latest .
          docker push ${IMAGE_URL}:${IMAGE_TAG}
          docker push ${IMAGE_URL}:latest

      - name: Deploy to GKE
        env:
          CLUSTER_NAME: forest-dev-1
          CLUSTER_REGION: europe-west2
          IMAGE_URL: europe-west2-docker.pkg.dev/forest-dev-1/forestrie/ranger
          IMAGE_TAG: ${{ github.sha }}
        run: |
          gcloud container clusters get-credentials ${CLUSTER_NAME} --region=${CLUSTER_REGION}

          # Update deployment image
          kubectl set image deployment/ranger ranger=${IMAGE_URL}:${IMAGE_TAG}

          # Wait for rollout
          kubectl rollout status deployment/ranger --timeout=300s
```

## Image URLs

- **Latest**: `europe-west2-docker.pkg.dev/forest-dev-1/forestrie/ranger:latest`
- **Tagged**: `europe-west2-docker.pkg.dev/forest-dev-1/forestrie/ranger:SHA`

## Service Access

The ranger service is internal-only (ClusterIP):

- **DNS**: `ranger.default.svc.cluster.local:9090` (adjust namespace as needed)
- **Health checks**:
  - Liveness: `http://ranger:9090/healthz`
  - Readiness: `http://ranger:9090/readyz`
  - Version: `http://ranger:9090/version`

## Resource Limits

Default resource allocation:

- **Requests**: 100m CPU, 64Mi memory
- **Limits**: 500m CPU, 256Mi memory

Adjust based on actual queue throughput and message processing requirements.

## Troubleshooting

```bash
# Check pod status
kubectl get pods -l app=ranger

# View logs
kubectl logs -l app=ranger --tail=100 -f

# Describe deployment
kubectl describe deployment ranger

# Check secrets are mounted correctly
kubectl get secret ranger-secrets -o yaml

# Port forward for local testing
kubectl port-forward svc/ranger 9090:9090
curl http://localhost:9090/healthz
```

## Scaling

```bash
# Scale replicas (if queue supports multiple consumers)
kubectl scale deployment ranger --replicas=3

# Update autoscaling (optional)
kubectl autoscale deployment ranger --min=1 --max=5 --cpu-percent=80
```

## Cleanup

```bash
kubectl delete -f deployment.yaml
kubectl delete -f service.yaml
```
