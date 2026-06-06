---
Status: ACCEPTED
Date: 2026-06-05
Related: [plan-0010](../plan-0010-custodian-kms-ensure-and-e2e-key-hygiene.md), [ADR-0004](adr-0004-forests-storage-and-uuid-log-ids.md), [devdocs ADR-0033](https://github.com/forestrie/devdocs/blob/main/adr/adr-0033-custodian-key-service.md)
---

# Custodian KMS ensure and e2e SOFTWARE keys

Custodian **`POST /api/keys`** is an **ensure** operation: GCP KMS is the source of
truth for custody key existence (`CryptoKey` id = normalized `selfLogId`). The
handler looks up the key first, creates only on `NotFound`, and returns **200**
when the key already exists or **201** when newly created. An in-process cache
keyed by `selfLogId` avoids repeat KMS calls within a pod lifetime.

**E2e and dev** use **`protectionLevel: SOFTWARE`** for dynamic custody keys
(Terraform bootstrap P-256 root defaults to SOFTWARE in forest-1). HSM custody
keys and the optional secp256k1 HSM root are out of scope for automated e2e.

Reuse-safe Playwright suites use **static log UUIDs** (stable KMS ids). Suites
that need MMRS-cold bootstrap or global forest uniqueness mint **per-run** keys
labeled with `e2e-run-id`; a best-effort `globalTeardown` deletes those keys by
label. Static keys carry `e2e-static-key: true` and are never auto-deleted.

**Considered:** Keeping an in-memory `keyOwnerId` gate as primary idempotency
(rejected — lost on restart while KMS keys persist). Renaming the HTTP path to
`/api/keys/ensure` (rejected — route unchanged for compatibility).
