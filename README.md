# Arbor

Go microservices for the Forestrie transparency log system.

Arbor contains backend services deployed to GKE that integrate with Cloudflare infrastructure managed by Canopy. Services follow 12-factor principles and are designed for Kubernetes.

## Services

- **ranger**: Queue consumer for processing Cloudflare Queue messages (R2 object notifications)
- **sharder**: Kubernetes operator for managing shard assignments

## Quick Start

See [DEVELOPMENT.md](DEVELOPMENT.md) for:
- Development workflow and prerequisites
- Architecture and design
- Deployment and operations
- Project relationships (Canopy, Forest-1)
- Service documentation

## Documentation

- [DEVELOPMENT.md](DEVELOPMENT.md) - Development guide and project overview
- [docs/arc-services.md](docs/arc-services.md) - Service architecture and design patterns
- [docs/ops-ranger.md](docs/ops-ranger.md) - Ranger service operations
- [docs/ops-first-deploy.md](docs/ops-first-deploy.md) - First deployment setup
