# ADR-001: Flux GitOps Deployment for Arbor Services

## Status

Accepted

## Context

Arbor services (ranger, sharder) are currently deployed manually using `kubectl` commands via Task-based workflows. This approach has several limitations:

1. **Manual deployment**: Requires local access and manual execution
2. **No automation**: Deployment doesn't happen automatically on code changes
3. **Image tag management**: Manual image tag substitution in deployment manifests
4. **No audit trail**: Deployment changes not tracked in version control
5. **Drift risk**: Manual kubectl apply can cause configuration drift from Git

The infrastructure repository (forest-1) already uses Flux for GitOps-based deployment of infrastructure components (Traefik, ExternalDNS, cert-manager). Arbor services should follow the same pattern for consistency and automation.

## Decision

We will implement Flux GitOps deployment for Arbor services with the following components:

1. **Arbor repository as source of truth**: Service Kubernetes manifests remain in arbor repository alongside service code
2. **Flux GitRepository**: Forest-1 references arbor repository via GitRepository source
3. **Flux Kustomization**: Forest-1 creates Flux Kustomization resources that reference arbor GitRepository
4. **ImageUpdateAutomation**: Flux automatically updates image tags in arbor manifests when new images are pushed
5. **Kustomize-based manifests**: Services use Kustomize for manifest organization (aligned with existing forest-1 patterns)

## Consequences

### Positive

- **Automated deployment**: Code changes automatically trigger image build → manifest update → deployment
- **GitOps compliance**: All deployment changes tracked in Git with audit trail
- **Reduced manual steps**: No local kubectl access required for deployment
- **Consistent with infrastructure**: Same deployment model as other cluster components
- **Image tag automation**: Flux ImageUpdateAutomation handles image tag updates automatically
- **Rollback capability**: Git-based rollbacks via commit reverts
- **Namespace management**: Forest-1 owns namespace creation (infrastructure concern)

### Negative

- **Flux write access required**: ImageUpdateAutomation needs write access to arbor repository (SSH key or GitHub App)
- **Git commit noise**: Flux will create commits for image tag updates (mitigated with [ci skip] in commit message)
- **Two-repository monitoring**: Deployment status requires checking both arbor and forest-1 repositories
- **Initial setup complexity**: Requires GitRepository, Kustomization, and ImageUpdateAutomation configuration

### Neutral

- **Image tagging strategy**: Uses `main-{sha}-{timestamp}` format for sortable, traceable tags
- **Manual secrets**: Secrets still managed manually via kubectl (future: SOPS/Sealed Secrets)
- **Service code coupling**: Deployment manifests tied to service repository (intentional design choice)

## Implementation Details

### Repository Structure

- **Arbor**: `services/ranger/k8s/kustomization.yaml` - Kustomize manifest with image reference
- **Forest-1**: `clusters/gke-dev/sources/arbor-gitrepository.yaml` - GitRepository pointing to arbor
- **Forest-1**: `clusters/gke-dev/forestrie-arbor/ranger.yaml` - Flux Kustomization for ranger service
- **Forest-1**: `clusters/gke-dev/image-automation/` - ImageRepository, ImagePolicy, ImageUpdateAutomation

### Image Tagging

Images are tagged with format: `main-{short-sha}-{timestamp}`

- Sortable: Timestamp ensures chronological ordering
- Traceable: SHA links to commit
- Unique: Timestamp prevents collisions
- Compatible with ImageUpdateAutomation alphabetical policy

### Workflow

1. Developer pushes code to arbor `main` branch
2. GitHub Actions builds Docker image with tag `main-{sha}-{timestamp}`
3. Image pushed to Artifact Registry
4. Flux ImageRepository detects new image
5. Flux ImagePolicy selects latest image (alphabetical sort)
6. Flux ImageUpdateAutomation updates `kustomization.yaml` in arbor repo
7. Flux Kustomization reconciles deployment with new image tag
8. Deployment rolls out automatically

## Alternatives Considered

### Option 1: Forest-1 Owns All Manifests

**Rejected**: Would require cross-repository updates for every service change, tight coupling, harder for service developers

### Option 2: Helm Charts

**Deferred**: More complex than Kustomize, migration path exists if needed in future

### Option 3: Semantic Versioning Tags

**Rejected**: Requires manual version bumps, doesn't align with automated workflow

### Option 4: Manual kubectl Deployment (Current)

**Rejected**: Doesn't address limitations outlined in Context

## References

- [Flux Image Update Automation](https://fluxcd.io/flux/components/image/imageupdateautomations/)
- [Flux GitRepository](https://fluxcd.io/flux/components/source/gitrepositories/)
- [Kustomize](https://kustomize.io/)
- ADR-001 in forest-1: Arbor GitRepository Integration
