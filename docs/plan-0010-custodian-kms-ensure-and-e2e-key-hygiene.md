---
Status: ACCEPTED
Date: 2026-06-05
Related: [ADR-0005](adr/adr-0005-custodian-kms-ensure-and-e2e-software-keys.md), [plan-0001](plan-0001-custodian-cbor-api.md), canopy [packages/tests/canopy-api/README.md](../../canopy/packages/tests/canopy-api/README.md)
---

# Plan 0010: Custodian KMS ensure and e2e key hygiene

## Goal

Make custodian custody key provisioning **fully idempotent** (KMS-first ensure),
minimize KMS key churn in Playwright e2e, and document SOFTWARE-only keys for
dev/e2e cost safety.

## Custodian (arbor)

- Rename create → **ensure** in code (`EnsureKeyForOwner`, `handleEnsureKey`,
  `EnsureKeyRequest` / `EnsureKeyResponse`).
- Keep HTTP **`POST /api/keys`** unchanged.
- **KeyStore** caches by **`selfLogId`** only; KMS is source of truth.
- Response includes optional **`created`** bool; **200** existing / **201** new.

## E2e (canopy)

| Category | Specs | Key strategy |
|----------|-------|--------------|
| Per-run | grants-bootstrap, bootstrap-log-first-entry, bootstrap-child-auth-grant, auth-data-log-chain, coordinator-api | `randomUUID()` + `e2e-run-id` label |
| Static | univocity-genesis-chain-binding, custodian-api | Registry UUIDs + `e2e-static-key: true` |

- Helpers: `postCustodianEnsureEs256Key` with explicit `protectionLevel: "SOFTWARE"`.
- **`globalTeardown`**: list keys by `e2e-run-id` + `e2e-test-key`, best-effort delete.
- Task: `custodian:keys-delete-by-label`.

## Docs

- [CONTEXT.md](../CONTEXT.md) glossary: custody key, ensure, bootstrap KMS root key.
- [services/custodian/README.md](../services/custodian/README.md): ensure semantics.
- forest-1 `kms.tf`: comment on SOFTWARE default.

## Verification

- `go test ./...` in `services/custodian/src`.
- Deploy custodian; `task test:e2e` (system + custodian projects).
