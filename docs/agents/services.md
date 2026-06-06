# Services (Arbor)

## Ranger

- Entry: `services/ranger/cmd/ranger/main.go`
- Config: `services/ranger/config.go` (12-factor env)
- Health: `PORT` default `9090` — `/healthz`, `/readyz`, `/version`
- Queue loop: `consumer.NewQueueConsumer(...).ConsumeQueue`
- Required env: `RANGER_QUEUE_URL`, `RANGER_QUEUE_API_TOKEN`, `R2_WRITE_URL`, `R2_WRITER_TOKEN`

## Univocity service

- Go HTTP service at `services/univocity/`
- Owns grant store, forest registry, authority resolver
- See [plan-0008](../plan-0008-univocity-grant-store-and-authority-resolver.md)

## Custodian

- KMS-backed signing; see devdocs [plan-0013](../../../devdocs/plans/plan-0013-custodian-implementation.md)

## Layout

Services under `services/` as independent Go modules. Shared code in `libs/` when
genuinely shared. See `LAYOUTmd` for target mono-repo structure.
