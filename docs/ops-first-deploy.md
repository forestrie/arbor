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

With secrets in place, deployments are fully automated via GitHub Actions and Flux:

1. Push changes to `main` that impact `services/**` or `.github/workflows/build-deploy.yml`
2. GitHub Actions builds `ranger` and tags the image as `main-<short-sha>-<run>`
3. Flux ImageRepository detects the new tag, ImagePolicy selects it, and ImageUpdateAutomation commits the tag to `services/ranger/k8s/kustomization.yaml`
4. Flux Kustomization reconciles the updated manifest into the cluster

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

## Kubernetes Secrets

Flux does not manage sensitive data; create the `ranger-secrets` secret once:

```bash
kubectl create secret generic ranger-secrets \
  --from-literal=queue-url="https://api.cloudflare.com/client/v4/accounts/{id}/queues/{name}" \
  --from-literal=queue-api-token="your-api-token-here" \
  --namespace=forestrie-arbor
```

Update the secret manually if credentials change.

## Troubleshooting

### Workflow Fails with "Secret not found"

Verify all required secrets are configured in GitHub Actions with exact names.

### Deployment Fails with Authentication Error

Verify Workload Identity Federation is correctly configured and service account has appropriate permissions.

### Pods Fail to Start with "ImagePullBackOff"

- Confirm the GitHub Actions workflow completed successfully
- Check Flux image automation resources:
  ```bash
  flux get image policy ranger -n flux-system
  flux get image update arbor -n flux-system
  ```
- Verify the artifact exists in Artifact Registry

### Pods Fail to Start with Configuration Error

- Ensure `ranger-secrets` is present and contains valid values
- Check application logs:
  ```bash
  kubectl logs -n forestrie-arbor -l app=ranger
  ```
