# First Deployment Setup

This document describes the configuration required to enable automated deployment of services in this repository to GKE.

## Prerequisites

- GitHub repository with Actions enabled
- GCP project with GKE cluster deployed
- Workload Identity Federation configured for GitHub Actions
- Appropriate IAM permissions for the service account

## Required GitHub Actions Secrets

The deployment workflow requires GitHub Actions secrets to be configured for service credentials. These secrets are injected into the cluster during deployment.

### Ranger Service

Navigate to the repository settings and configure the following secrets:

**Settings → Secrets and variables → Actions → New repository secret**

| Secret Name | Description | Example Value |
|------------|-------------|---------------|
| `RANGER_QUEUE_URL` | Cloudflare Queue HTTP endpoint URL | `https://api.cloudflare.com/client/v4/accounts/{account_id}/queues/{queue_name}` |
| `RANGER_QUEUE_API_TOKEN` | Bearer token for Cloudflare Queue authentication | `your-api-token-here` |

### Adding Secrets via GitHub UI

1. Navigate to repository settings
2. Select "Secrets and variables" from the left sidebar
3. Click "Actions"
4. Click "New repository secret"
5. Enter the secret name exactly as specified above
6. Paste the secret value
7. Click "Add secret"
8. Repeat for each required secret

### Adding Secrets via GitHub CLI

```bash
gh secret set RANGER_QUEUE_URL --body "https://api.cloudflare.com/client/v4/accounts/{account_id}/queues/{queue_name}"
gh secret set RANGER_QUEUE_API_TOKEN --body "your-api-token-here"
```

## Deployment Process

Once secrets are configured, deployment is fully automated:

1. Push changes to the `main` branch that affect `services/**` or `.github/workflows/build-deploy.yml`
2. GitHub Actions workflow triggers automatically
3. Workflow authenticates to GCP using Workload Identity Federation
4. Service Docker image is built with version metadata
5. Image is pushed to Artifact Registry with git SHA tag
6. Kubernetes secrets are created/updated from GitHub Actions secrets
7. Kubernetes manifests are applied to the cluster
8. Deployment rollout is monitored for completion

## Verification

After the workflow completes successfully:

```bash
# Get cluster credentials
gcloud container clusters get-credentials forest-dev-1 --region=europe-west2

# Verify deployment
kubectl get deployment ranger
kubectl get pods -l app=ranger

# Check service health
kubectl port-forward svc/ranger 9090:9090
curl http://localhost:9090/healthz
curl http://localhost:9090/version
```

## Cluster Configuration

The workflow is configured for the following GCP resources:

- **Project**: forest-dev-1
- **Region**: europe-west2
- **Cluster**: forest-dev-1
- **Artifact Registry**: europe-west2-docker.pkg.dev/forest-dev-1/forestrie

If deploying to a different environment, update the corresponding environment variables in `.github/workflows/build-deploy.yml`.

## Service Account Permissions

The GitHub Actions service account requires the following IAM roles:

- `roles/container.developer` - Deploy to GKE
- `roles/artifactregistry.writer` - Push Docker images
- Workload Identity User binding to the appropriate Kubernetes service account

## Troubleshooting

### Workflow Fails with "Secret not found"

Verify that all required secrets are configured in GitHub Actions with the exact names specified above.

### Deployment Fails with Authentication Error

Verify that Workload Identity Federation is correctly configured and the service account has appropriate permissions.

### Pods Fail to Start with "ImagePullBackOff"

Verify that the service account has permission to pull from Artifact Registry and that the image was successfully pushed.

### Pods Fail to Start with Configuration Error

Check pod logs for specific configuration issues:

```bash
kubectl logs -l app=ranger
```

Common issues include missing or invalid secret values.

## Adding Additional Services

To add deployment configuration for new services:

1. Add required secrets to GitHub Actions following the naming pattern `{SERVICE_NAME}_{SECRET_KEY}`
2. Update `.github/workflows/build-deploy.yml` to include the new service
3. Ensure Kubernetes manifests exist in `services/{service_name}/k8s/`
4. Document required secrets in this file

## Future Improvements

The current implementation uses GitHub Actions secrets for credential management. This approach is suitable for initial deployment and small-scale projects. For production environments or multiple services, consider:

- External Secrets Operator with GCP Secret Manager
- Sealed Secrets for encrypted secrets in Git
- Helm charts for service and infrastructure configuration
- ArgoCD or Flux for GitOps-based continuous deployment

These improvements can be implemented once full project requirements are established.
