# ADRs (Arbor)

Repo-local decisions for the arbor services. Platform-wide decisions live in
[devdocs/adr](../../../devdocs/adr/) — that series and this one number
independently; cross-repo references should link by URL, not bare id.

| ADR | Decision | Status |
|-----|----------|--------|
| [adr-0002](adr-0002-univocity-owned-grant-store-and-authority-correspondence.md) | Univocity-owned grant store and authority correspondence | — |
| [adr-0003](adr-0003-global-logid-r-uniqueness.md) | Global logId R uniqueness | — |
| [adr-0004](adr-0004-forests-storage-and-uuid-log-ids.md) | Forests storage and UUID log ids | — |
| [adr-0005](adr-0005-custodian-kms-ensure-and-e2e-software-keys.md) | Custodian KMS ensure and e2e software keys | Accepted |
| [adr-0006](adr-0006-genesis-authoritative-byok-root-key.md) | Genesis-authoritative root key for BYOK forests | Accepted |
| [adr-0007](adr-0007-low-latency-sealer-trigger.md) | Low-latency sealer trigger: ranger seal hints, R2 events demoted to backstop | Proposed |
| [adr-0008](adr-0008-publisher-never-sends-predicted-revert-acks-unpublishable.md) | Publisher never sends a predicted-revert tx; unpublishable checkpoints acked (self-heal), not retried | Accepted |
