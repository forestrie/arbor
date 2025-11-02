# First Deployment Setup

Configuration required for initial deployment of services to GKE.

## Prerequisites

- GitHub repository with Actions enabled
- GCP project (forest-dev-1) with GKE cluster deployed
- Workload Identity Federation configured for GitHub Actions
- Appropriate IAM permissions for the service account

## GitHub Actions Secrets

The deployment workflow requires secrets for service credentials. These are injected into Kubernetes during deployment.

### Ranger Service

**Settings → Secrets and variables → Actions → New repository secret**

| Secret Name | Description | Example Value |
|------------|-------------|---------------|
| `RANGER_QUEUE_URL` | Cloudflare Queue HTTP endpoint URL | `https://api.cloudflare.com/client/v4/accounts/{account_id}/queues/{queue_name}` |
| `RANGER_QUEUE_API_TOKEN` | Bearer token for Cloudflare Queue authentication | `your-api-token-here` |

**Via GitHub CLI**:
```bash
gh secret set RANGER_QUEUE_URL --body "https://api.cloudflare.com/client/v4/accounts/{id}/queues/{name}"
gh secret set RANGER_QUEUE_API_TOKEN --body "your-api-token-here"
```

## Automated Deployment

Once secrets are configured, deployment is automated:

1. Push changes to `main` branch affecting `services/**` or `.github/workflows/build-deploy.yml`
2. GitHub Actions workflow triggers automatically
3. Service is built, pushed to Artifact Registry, and deployed to GKE
4. Kubernetes secrets are created/updated from GitHub Actions secrets
5. Deployment rollout is monitored

## Verification

After workflow completes:

```bash
# Get cluster credentials
gcloud container clusters get-credentials forest-dev-1 --region=europe-west2

# Verify deployment
kubectl get deployment ranger -n forestrie-arbor
kubectl get pods -n forestrie-arbor -l app=ranger

# Check service health
kubectl port-forward -n forestrie-arbor svc/ranger 9090:9090
curl http://localhost:9090/healthz
curl http://localhost:9090/version
```

## Cluster Configuration

- **Project**: forest-dev-1
- **Region**: europe-west2
- **Cluster**: forest-dev-1
- **Artifact Registry**: europe-west2-docker.pkg.dev/forest-dev-1/forestrie
- **Namespace**: forestrie-arbor

## Service Account Permissions

The GitHub Actions service account requires:
- `roles/container.developer` - Deploy to GKE
- `roles/artifactregistry.writer` - Push Docker images
- Workload Identity User binding to Kubernetes service account

## Troubleshooting

### Workflow Fails with "Secret not found"

Verify all required secrets are configured in GitHub Actions with exact names.

### Deployment Fails with Authentication Error

Verify Workload Identity Federation is correctly configured and service account has appropriate permissions.

### Pods Fail to Start with "ImagePullBackOff"

Verify service account has permission to pull from Artifact Registry and image was successfully pushed.

### Pods Fail to Start with Configuration Error

Check pod logs:
```bash
kubectl logs -n forestrie-arbor -l app=ranger
```

Common issues include missing or invalid secret values.

## Adding Additional Services

For new services:

1. Add required secrets to GitHub Actions following pattern `{SERVICE_NAME}_{SECRET_KEY}`
2. Update `.github/workflows/build-deploy.yml` to include the new service
3. Ensure Kubernetes manifests exist in `services/{service_name}/k8s/`
4. Document required secrets
