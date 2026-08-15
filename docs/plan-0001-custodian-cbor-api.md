---
Status: DRAFT
Date: 2025-03-23
Related: ../services/custodian/README.md, [plan-0010](plan-0010-custodian-kms-ensure-and-e2e-key-hygiene.md), ../services/sealer/src/sealer.go, ../services/sealer/src/global_delegation.go; [forest-1 arc-delegation-signer-cose-cbor-scitt.md](https://github.com/forestrie/forest-1/blob/main/docs/arc-delegation-signer-cose-cbor-scitt.md); external [ADR-0033](https://github.com/forestrie/devdocs/blob/main/archive/2603/adr/adr-0033-custodian-key-service.md)
---

# Plan 0001: Custodian HTTP API — exclusive CBOR + COSE_Sign1 signing

## Goal

- Make **all custodian API** request and response bodies **CBOR** (no JSON on those routes), with errors as **`application/problem+cbor`** (RFC 7807 field set).
- Frame **`POST /api/keys/{keyId}/sign`** as **obtaining a `COSE_Sign1`** object (response is the raw Sign1 bytes, COSE-aware `Content-Type`), so clients already handling delegation certificates and checkpoints can reuse the same verify path.
- Use **`github.com/fxamacker/cbor/v2` only** for deterministic CBOR (do **not** use `go-datatrails-common/cbor`).
- **Operational** routes keep **JSON** (or plain text where they already are): **`/version`**, **`/healthz`**, **`/readyz`**, **`/metrics`** — unchanged for k8s/Prometheus ergonomics.

Consumers are entirely under our control; **no JSON compatibility shim** on the custodian API surface.

## Current surface (JSON today)

| Method | Path | Request body | Success response |
|--------|------|----------------|------------------|
| GET | `/api/keys/{id}/public` | — | JSON object |
| POST | `/api/keys` | JSON | JSON |
| POST | `/api/keys/list` | JSON | JSON |
| POST | `/api/keys/{id}/delete` | — | JSON |
| POST | `/api/keys/{id}/versions/delete-from` | JSON | JSON |
| POST | `/api/keys/{id}/sign` | JSON | JSON |

Errors: `application/problem+json` (`problemdetails.go`).

## Target contract

### Ops vs API

| Route group | Format |
|-------------|--------|
| `/api/keys/...` (all key/custody endpoints) | **CBOR** / **problem+cbor** / **COSE** for sign response only |
| `/healthz`, `/readyz`, `/metrics` | **unchanged** (plain text stubs today; keep as-is or JSON only where already JSON) |
| `/version` | **JSON** (unchanged) |

### Content types (API)

- **Requests with a body:** require `Content-Type: application/cbor` (reject with **415** + problem+cbor if missing or wrong).
- **Successful responses (non-sign):** `Content-Type: application/cbor`, encoded with **fxamacker** using a **deterministic `EncMode`** (RFC 8949 §4.2: canonical map key order, shortest int encoding, etc.).
- **`POST .../sign` success:** response body = **serialized `COSE_Sign1`** (four-element CBOR array per RFC 9052), `Content-Type` aligned with existing in-repo usage (e.g. `application/cose; cose-type="cose-sign1"` as in sealer stress tests / delegation client expectations). **No** outer CBOR wrapper around the Sign1.

### Errors

- **Always** `Content-Type: application/problem+cbor`; same fields as today: `type`, `title`, `status`, `detail` (with `cbor` struct tags).
- **No** `Accept`-based JSON fallback.

### CBOR field naming (non-COSE maps)

Use **camelCase** text keys in custodian request/response maps (e.g. `keyOwnerId`, `publicKey`) unless a normative doc mandates integer keys (delegation/checkpoint payloads use int keys; custodian resource DTOs can stay tstr keys for readability).

## Signing: COSE_Sign1 (required)

The sign endpoint **returns a `COSE_Sign1`** verifiable with the **same conventions** as delegation certificates and checkpoints in [forest-1 `arc-delegation-signer-cose-cbor-scitt.md`](https://github.com/forestrie/forest-1/blob/main/docs/arc-delegation-signer-cose-cbor-scitt.md):

- **Structure:** `[ protected_bstr, unprotected_map, payload_bstr, signature_bstr ]`.
- **Protected header:** deterministically encoded CBOR map, then wrapped as **bstr** (standard COSE).
- **Signature:** ECDSA **r || s**, 32+32 bytes for P-256 and secp256k1 per profile (normalize KMS output if needed).
- **Build/sign:** use **`github.com/veraison/go-cose`** (already in sealer) to assemble headers and `Sig_structure`; feed **KMS `AsymmetricSign`** digest (SHA-256 over the bytes the client asked to bind) as required by the chosen payload profile below.

**Payload profile (to specify in implementation + arc addendum):**

- Define a **stable `cty`** (label `3` in protected header), e.g. `application/forestrie.custodian-statement+cbor`, and whether the **COSE payload** is:
  - **(Recommended)** the **32-byte SHA-256 digest** as a **bstr** when the client submits `payload` (server hashes) or `payloadHash` (client-supplied digest), so the signed bytes are unambiguous and small; or
  - the **raw message bytes** as **bstr** if you require byte-for-byte signing without an intermediate hash commitment.

Pick one and document it; verifiers must treat **payload bytes** as the **ToBeSigned** input that was digested for KMS (`ECDSA(SHA-256, …)` per key algorithm). The plan assumes **payload = 32-byte digest as bstr** unless product prefers raw content.

**Unprotected header:** empty map `{}` initially; reserve SCITT/Forestrie labels per arc for future receipts if needed.

## KID and protected-header policy — extent and approach

This is the main “extra” work beyond swapping JSON for CBOR: **custodian must emit Sign1 objects that existing tooling can verify** without ad-hoc one-off rules.

### What the arc already fixes

The Forestrie COSE arc defines:

| Label | Meaning | Custodian obligation |
|-------|---------|----------------------|
| `1` (`alg`) | ES256 **-7** or ES256K **-47** | Set from the **KMS key’s curve** (P-256 vs secp256k1), same mapping as delegation root keys. |
| `3` (`cty`) | Payload type hint (tstr) | Introduce a **custodian-specific** `cty` string (documented alongside delegation/checkpoint types). |
| `4` (`kid`) | **bstr** key id | **SHOULD** follow arc: **`kid = SHA-256(pubkey_bytes)[0:16]`** (16 bytes), same as sealer’s `kidFromECDSAPublicKey` in `global_delegation.go`. |

Protected headers MUST be **deterministically** CBOR-encoded before being wrapped in `protected` bstr (arc § “Deterministic CBOR requirements”).

### Work items (concrete)

1. **`kid` derivation (moderate, localized)**  
   - After resolving the **CryptoKeyVersion** used for signing, call **`GetPublicKey`** (same family as key creation).  
   - Parse the returned PEM/SPKI to an **`ecdsa.PublicKey`**.  
   - Compute **`kid`** = first 16 bytes of **SHA-256** of **`elliptic.Marshal(pub.Curve, pub.X, pub.Y)`** (uncompressed point), **identical to sealer** `kidFromECDSAPublicKey` in `sealer.go` — **not** SPKI DER.  
   - **Extent:** one small helper module + tests against a **golden vector** (known pubkey → known kid) aligned with sealer tests.

2. **`alg` selection (small)**  
   - Map KMS key metadata / algorithm enum to **-7** vs **-47**.  
   - Reject or never emit for algorithms outside ES256/ES256K until the arc extends.

3. **`cty` and payload semantics (spec + code)**  
   - Add a short **addendum** to the forest-1 arc (or a new `arc-custodian-cose.md`) stating custodian Sign1 **protected** fields and **payload** format.  
   - **Extent:** documentation + one enum/constant in code; verifier code paths only need to branch on `cty` like they do for `application/forestrie.delegation+cbor`.

4. **`crit` and custom headers (minimal by default)**  
   - Arc: omit **`crit`** unless new unknown critical headers appear. Custodian should start with **only** `alg`, `cty`, `kid` in protected.

5. **Verification “same tooling”**  
   - **Extent:** ensure a **go-cose** `Verify` (or equivalent) succeeds when given: response bytes, trust anchor = **the same pubkey** fetch path clients already use (e.g. compare `kid` to pubkey derived from `GET /api/keys/.../public` or from your registry).  
   - Optional: add an **integration test** in arbor that verifies a custodian Sign1 with the same parser as **`delegation_signer_client.go`** (decode four-element array, parse protected map, check `alg`/`kid`/`cty`).

### What this is **not**

- **No** new KMS IAM for COSE (still `AsymmetricSign` only).  
- **No** requirement to put the full KMS resource name in `kid` (arc deliberately uses **pubkey-derived** short `kid`).  
- **No** COSE encryption (`COSE_Encrypt`); Sign1 only.

## CBOR stack

- **Only** `github.com/fxamacker/cbor/v2`: configure `EncMode` / `DecMode` for **deterministic encoding** (see fxamacker docs for `CanonicalCBOR` / sort mode).  
- **Do not** add `go-datatrails-common/cbor` to custodian.

## File layout (single responsibility)

| File | Responsibility |
|------|------------------|
| `cbor_codec.go` | fxamacker deterministic `EncMode`/`DecMode`; `Marshal`/`Unmarshal` helpers for API maps. |
| `problem_detail.go` | `ProblemDetail` + `writeProblem` (problem+cbor only). |
| `http_cbor.go` | Body read (limit), `requireCBORContentType`, `writeCBOR` for non-COSE responses. |
| `types_key_create.go` | Create request/response types + `cbor` tags. |
| `types_key_list.go` | List request/response / list entry types. |
| `types_key_delete.go` | Delete / delete-from types. |
| `types_key_public.go` | Public key response type. |
| `types_key_sign.go` | **Sign request** CBOR types only (payload vs payloadHash); no Sign1 assembly here. |
| `cose_sign1.go` | Build **`COSE_Sign1`**: protected/unprotected, payload bstr, call KMS, place **r||s** signature; uses go-cose + fxamacker for header CBOR. |
| `kid.go` | **`kidFromECDSAPublicKey`** (or shared logic with tests mirroring sealer). |

Handlers remain thin: auth → decode → domain → marshal or `writeCOSESign1`.

## Implementation phases

1. **Infrastructure** — fxamacker modes, `http_cbor`, problem+cbor only; 415 tests.  
2. **Migrate endpoints** — all key routes except sign: CBOR request/response; move types to `types_*.go`.  
3. **COSE sign** — `cose_sign1.go` + `kid.go`; wire `POST .../sign`; arc addendum for `cty` + payload.  
4. **Tests** — round-trip CBOR; Sign1 structure + verify with go-cose / shared parser patterns.  
5. **Consumers** — update callers to CBOR + parse Sign1.  
6. **Docs** — README + link to arc addendum.

## Effort assessment

| Scope | Effort (one engineer) |
|-------|------------------------|
| CBOR-only API + problem+cbor + types split + fxamacker | **~2–3 days** |
| COSE_Sign1 for `/sign` + `kid`/`alg`/`cty` policy aligned with arc + tests | **+1.5–2.5 days** |
| Arc doc addendum + consumer updates | **~0.5–1 day** |

**Overall: ~4–6 days** for the full plan as revised (COSE required, KID/header policy as above).

## Risks and mitigations

- **`kid` mismatch vs sealer:** Mitigate with **shared test vector** or a tiny shared package later; minimally, **copy the exact `kidFromECDSAPublicKey` algorithm** from sealer (`SHA-256(elliptic.Marshal(...))[:16]`).  
- **KMS signature vs COSE:** Confirm GCP returns **raw r||s** for EC keys; normalize if not.  
- **Determinism:** Golden tests for protected header bstr (hex fixture).

## Acceptance criteria

- Custodian **API** handlers (under `/api/keys`) use **no JSON**; ops routes keep JSON/text as today.  
- **`POST .../sign`** returns **raw COSE_Sign1** with correct media type.  
- **fxamacker/cbor/v2** only for CBOR; **veraison/go-cose** for Sign1 assembly/verify in tests.  
- Arc (or addendum) documents custodian **`cty`**, payload bytes, and protected headers.  
- Verifier can use **the same COSE parsing and `kid` semantics** as delegation/checkpoint tooling.

## Out of scope

- Changing Bearer app-token auth.  
- KMS IAM beyond what signing already needs.  
- COSE encryption, receipts in unprotected headers (unless you explicitly add a follow-up).
