# Arbor

Go microservices for the Forestrie transparency log system.

Arbor contains backend services deployed to GKE that integrate with Cloudflare infrastructure managed by Canopy. Services follow 12-factor principles and are designed for Kubernetes.

## Services

- **ranger**: Pulls canopy's ingress shards, commits massifs to R2 and posts seal hints to the sealer queue
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
- [devdocs ARC-0006](https://github.com/forestrie/devdocs/blob/main/arc/arc-0006-services.md) - Service architecture and design patterns
