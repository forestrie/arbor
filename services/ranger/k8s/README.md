# Ranger Kubernetes Deployment

This directory contains the Kubernetes manifests for deploying the ranger service to GKE using **Kustomize** and **Flux GitOps**.

## Files

- `kustomization.yaml` - Kustomize manifest with namespace, resources, images, and ConfigMap generator
- `deployment.yaml` - Deployment definition (no image tag - managed by Flux ImageUpdateAutomation)
- `service.yaml` - ClusterIP service for internal access

## Deployment Architecture

Ranger is deployed via **Flux GitOps** with automatic image updates:

1. **Kustomize Structure**: Manifests organized using Kustomize for namespace, labels, and ConfigMap management
2. **Flux Kustomization**: Forest-1 repository creates Flux Kustomization that references this directory
3. **ImageUpdateAutomation**: Flux automatically updates image tags when new images are pushed to Artifact Registry
4. **Automated Deployment**: Code changes → image build → manifest update → deployment (all automated)

See [ADR-001: Flux GitOps Deployment](../../../docs/adr-001-flux-gitops-deployment.md) for detailed architecture and rationale.

## Kustomize Structure

The `kustomization.yaml` defines:

- **Namespace**: `forestrie-arbor` (created by forest-1)
- **Resources**: deployment.yaml, service.yaml
- **Common Labels**: Consistent labeling across resources
- **Images**: Image reference for ImageUpdateAutomation to update tags
- **ConfigMap Generator**: Non-sensitive configuration (log-level, poll-interval, etc.)

The image tag in `kustomization.yaml` is automatically updated by Flux ImageUpdateAutomation when new images are available.

## Prerequisites

1. GKE cluster running (managed by forest-1)
2. Artifact Registry repository: `europe-west2-docker.pkg.dev/forest-dev-1/forestrie`
3. Flux GitOps installed and configured in cluster
4. Forest-1 GitRepository pointing to arbor repository
5. ImageUpdateAutomation configured for ranger images

## Configuration

### Secrets (Required)

Secrets are managed separately (not in Git). Create the secret in the cluster:

```bash
kubectl create secret generic ranger-secrets \
  --from-literal=queue-url="https://api.cloudflare.com/client/v4/accounts/YOUR_ACCOUNT_ID/queues/YOUR_QUEUE_NAME" \
  --from-literal=queue-api-token="YOUR_QUEUE_API_TOKEN" \
  --namespace=forestrie-arbor \
  --dry-run=client -o yaml | kubectl apply -f -
```

**Note**: Secrets are not managed by GitOps for security. Future enhancement: Use SOPS or Sealed Secrets.

### ConfigMap (Managed by Kustomize)

Configuration is managed via `kustomization.yaml` configMapGenerator:

- `log-level`: debug, info, warn, error (default: info)
- `poll-interval`: How often to poll the queue (default: 5s)
- `visibility-timeout`: Message visibility timeout (default: 30s)
- `shutdown-timeout`: Graceful shutdown timeout (default: 30s)

To change configuration, edit `kustomization.yaml` and commit. Flux will reconcile the changes.

## Deployment Flow

### Automated Deployment (Normal Flow)

1. **Code Change**: Developer pushes code to arbor `main` branch
2. **Image Build**: GitHub Actions workflow builds and pushes Docker image
   - Tag format: `main-{short-sha}-{timestamp}`
   - Pushed to: `europe-west2-docker.pkg.dev/forest-dev-1/forestrie/ranger`
3. **Image Detection**: Flux ImageRepository detects new image
4. **Policy Selection**: Flux ImagePolicy selects latest image (alphabetical sort)
5. **Manifest Update**: Flux ImageUpdateAutomation updates `kustomization.yaml` image tag
6. **Reconciliation**: Flux Kustomization reconciles deployment
7. **Rollout**: Deployment automatically rolls out with new image

### Manual Deployment (Emergency Only)

For emergency deployments or local testing:

```bash
# Build and push image locally
task ranger:build
task ranger:push IMAGE_TAG=dev

# Apply manifests directly (bypasses Flux)
kubectl apply -k .
```

**Note**: Direct kubectl apply bypasses GitOps and may cause drift. Use only for emergency or local testing.

## Image Management

### Image Tagging

Images are tagged with format: `main-{short-sha}-{timestamp}`

- **Sortable**: Timestamp ensures chronological ordering
- **Traceable**: SHA links to source commit
- **Unique**: Timestamp prevents tag collisions
- **Automated**: Flux ImageUpdateAutomation updates manifests automatically

### Image Update Process

1. New image pushed to Artifact Registry
2. Flux ImageRepository scans for new tags
3. Flux ImagePolicy filters and selects latest tag
4. Flux ImageUpdateAutomation updates `kustomization.yaml`
5. Flux commits change to arbor repository
6. Flux Kustomization reconciles deployment

## Service Access

The ranger service is internal-only (ClusterIP):

- **DNS**: `ranger.forestrie-arbor.svc.cluster.local:9090`
- **Health checks**:
  - Liveness: `http://ranger:9090/healthz`
  - Readiness: `http://ranger:9090/readyz`
  - Version: `http://ranger:9090/version`

## Resource Limits

Default resource allocation:

- **Requests**: 100m CPU, 64Mi memory
- **Limits**: 500m CPU, 256Mi memory

Adjust in `deployment.yaml` and commit. Flux will reconcile changes.

## Troubleshooting

### Check Flux Status

```bash
# Check Flux Kustomization status
flux get kustomizations ranger -n flux-system

# Check ImageRepository status
flux get image repository ranger -n flux-system

# Check ImagePolicy status
flux get image policy ranger -n flux-system

# Check ImageUpdateAutomation status
flux get image update arbor -n flux-system

# View Flux logs
flux logs --kind=Kustomization --name=ranger
```

### Check Deployment Status

```bash
# Check pod status
kubectl get pods -n forestrie-arbor -l app=ranger

# View logs
kubectl logs -n forestrie-arbor -l app=ranger --tail=100 -f

# Describe deployment
kubectl describe deployment ranger -n forestrie-arbor

# Check secrets are mounted correctly
kubectl get secret ranger-secrets -n forestrie-arbor -o yaml
```

### Image Update Issues

```bash
# Check if ImageRepository is finding images
flux get image repository ranger -n flux-system -o yaml

# Check ImagePolicy selection
flux get image policy ranger -n flux-system -o yaml

# Manually trigger image update
flux reconcile image update arbor -n flux-system

# Check if manifest was updated
git log --oneline -n 10 --grep="image"
```

### Manual Rollback

```bash
# Option 1: Revert manifest commit in arbor repo
git revert <commit-hash>
git push

# Option 2: Update kustomization.yaml to pin previous image tag
# Edit kustomization.yaml, change image tag, commit

# Option 3: Emergency kubectl patch (bypasses Flux)
kubectl patch deployment ranger -n forestrie-arbor \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"ranger","image":"europe-west2-docker.pkg.dev/forest-dev-1/forestrie/ranger:previous-tag"}]}}}}'
```

## Scaling

```bash
# Scale replicas (if queue supports multiple consumers)
kubectl scale deployment ranger --replicas=3 -n forestrie-arbor

# Or update deployment.yaml and commit (GitOps approach)
```

## Cleanup

```bash
# Remove via Flux (recommended)
# Delete Flux Kustomization in forest-1 repository

# Or remove directly
kubectl delete -k . -n forestrie-arbor
```

## References

- [ADR-001: Flux GitOps Deployment](../../../docs/adr-001-flux-gitops-deployment.md)
- [Kustomize Documentation](https://kustomize.io/)
- [Flux Image Update Automation](https://fluxcd.io/flux/components/image/imageupdateautomations/)
