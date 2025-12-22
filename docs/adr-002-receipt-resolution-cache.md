# ADR-002: Receipt Resolution Cache (contentHash → idtimestamp)

## Status

Proposed (Supersedes prior draft)

## Context

The SCRAPI registration flow in `canopy-api` stores a statement in `R2_LEAVES`
at a content-addressed path:

- `logs/{logId}/leaves/{contentHash}`

Where `contentHash` (SHA-256) is the **transient request identifier**.

The `ranger` service later sequences the statement into the Merkle log, assigns
it a final sequenced `idtimestamp` (Snowflake64), and commits the entry into an
MMR massif stored in `R2_MMRS`.

We want `canopy-api` to implement SCRAPI `resolve-receipt` efficiently by doing
an **O(1) cache lookup** that resolves:

- `(logId, contentHash) → idtimestamp`

The Forester service is the natural place to populate this cache because it is
notified when log objects are committed (via R2/Queue notifications), and can
process a whole commit’s worth of leaves and issue a single bulk update.

### Constraints / Requirements

- **Efficient writes**: Forester should batch updates (Cloudflare KV bulk or
  Redis pipeline) rather than per-leaf writes.
- **Deterministic resolution**: A receipt key should map to exactly one final
  `idtimestamp` (idempotent writes within the ingress expiry window).
- **Support whole-log recovery**: If the cache is empty, Forester can rebuild
  it from the committed log objects.
- **Bounded growth**: Avoid values that grow unbounded over time.

## Decision

We will implement a **receipt-resolution cache** keyed by `(logId, contentHash)`
and populated from the committed log index.

### Key insight

The transient request id is the **content hash**. Ingress writes are **create
only**, so re-registering identical content is **idempotent** until the
pre-sequence object expires and is deleted. After expiry, the same content may
be re-registered and will sequence again, producing a new `idtimestamp`.

This implies a natural cache rule:

- The cache entry for a given `(logId, contentHash)` should always resolve to
  the **most recent** sequenced `idtimestamp` for that content hash.

### Receipt cache schema (v1)

- **Cache key**: `receipts/v1/{logId}/{contentHashHex}`
- **Cache value**: `idtimestamp` encoded as a decimal string.

## Options Considered

### Option 1: Persist ingress request metadata in log index extras (rejected)

Persist ingress request metadata in an authenticated per-leaf index field
(Urkle extras), so Forester can reconstruct request-specific mappings by
scanning the committed log.

**Pros**

- **Deterministic**: ingress metadata can provide a 1:1 mapping to a specific
  sequenced entry
- **Efficient rebuild**: cache can be repopulated from committed log objects
- **Bounded values**: no unbounded lists
- **Auditable**: if the trie root is anchored, the metadata becomes part of an
  authenticated commitment (via the trie), improving auditor confidence

**Cons**

- Requires careful, versioned encoding of the extra field
- Adds small per-leaf index overhead

### Option 2: contentHash temporary id with create-only ingress (chosen)

Use `contentHash` as the transient SCRAPI identifier and enforce create-only
writes at ingress. Cache maps `contentHash → idtimestamp` with “latest wins”
semantics.

**Pros**

- **SCRAPI-neutral log**: no SCRAPI request metadata needs to be persisted into
  the log index extras.
- **Bounded duplicates**: idempotent within the ingress expiry window; re-seq
  only after expiry.
- **Simple KV**: one lookup per resolve.

**Cons**

- **Intentional “latest wins”**: reusing an expired content-hash id will resolve
  to the most recent registration if re-registered later.
- Requires ingress lifecycle/expiry policy to be correct and enforced.

## Consequences

### Positive

- Forester can bulk-populate cache entries as soon as a massif is updated.
- `canopy-api` can implement `resolve-receipt` via a single cache read.
- Cache rebuild is possible from the committed log without re-reading `R2_LEAVES`.

### Negative / Trade-offs

- A transient id is not globally unique over time (by design).
- “Latest wins” can surprise clients if they reuse stale ids; SCRAPI permits
  expiry and reuse, so this is acceptable, but must be documented.

## Implementation Plan

### Phase 1: Ingress: content-hash path + create-only writes (canopy-api)

- Change leaf storage path to `logs/{logId}/leaves/{contentHash}`.
- Implement create-only R2 puts (idempotent until object expiry).
- Document the reliance on ingress lifecycle/expiry to define the duplicate
  submission window.

### Phase 2: Forester cache writer

- Subscribe Forester to `R2_MMRS` notifications (massif object puts).
- For each massif notification:
  - Fetch the massif blob
  - Read `UrkleLeafTableRegion`
  - For each appended leaf:
    - `idtimestamp := LeafKey(...)`
    - `contentHash := LeafValue(...)`
    - Write KV/Redis entry: `receipts/v1/{logId}/{contentHashHex}`
      → `idtimestamp`
- Bulk write:
  - Cloudflare KV: use the `/bulk` endpoint (chunked to Cloudflare limits).
  - Redis: use pipelined `MSET` or batched `SET` operations.

### Phase 3: canopy-api resolve-receipt

- Use the content-hash itself as the transient SCRAPI identifier.
- `resolve-receipt` behavior:
  - If cache hit: return a permanent URL (303) for the sequenced entry
    (keyed by `idtimestamp`).
  - If cache miss: return 303 retry-after (pending).

## Notes on Idempotency / Duplicates

The transient id is `contentHash`. Because ingress writes are create-only,
re-registering the same content hash is idempotent until the ingress object
expires and is deleted. After expiry, a new registration of the same content
hash may sequence again; the receipt cache is intentionally “latest wins”.


