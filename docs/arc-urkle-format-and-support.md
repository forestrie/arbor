# ARC: Urkle Format and Support (in-place, span-encoded postorder)

## Status

Draft.

## Parent ARC

This ARC is a child of `arbor/docs/arc-massif-exclusion-trie.md`.

The parent ARC motivates *why* we want an Urkle-style exclusion trie in the massif index budget.
This ARC records the **concrete encoding and primitive API choices** used by the `go-merklelog/urkle` module.

## Abstract

We standardize a **bounded, in-place, append-only** Urkle-style radix trie suitable for storing inside a preallocated massif index region.

Key properties:

- Keys are 64-bit monotone `idtimestamp` (Snowflake64), encoded big-endian and traversed MSB-first.
- Writes are **append-only** into a **preallocated, zero-filled** node store. No rewrites of previously-emitted node records.
- The on-disk representation is a **postorder** stream with **subtree span** metadata (B′):
  branch nodes store `rightSpan` (node count of right subtree) and `subtreeSize`,
  enabling pointer-free navigation without storing explicit child references.
- Leaves commit to an application-defined `valueBytes[32]` plus a chunk-local `leafOrdinal`,
  enabling authenticated recovery of `mmrIndex` given the massif start context.

This ARC also defines the proof structures and the “natural side effects” returned by verification:
`leafOrdinal` and `valueBytes`, from which `mmrIndex` is efficiently derived.

## Terms (additive to `term-cheatsheet.md`)

This ARC introduces / clarifies the following terms (see the cheat-sheet updates in follow-up work):

- **Urkle trie**: here, a binary radix trie over fixed-width 64-bit keys, hashed with domain separation.
- **crit-bit**: the first differing bit between two keys (MSB-first index in `[0..63]`).
- **common prefix bits (LCP)**: the number of shared prefix bits between two keys (MSB-first).
  For distinct keys, `critBit == LCP`.
- **leafOrdinal**: the chunk-local ordinal of a leaf (0..N-1) where `N` is the chunk leaf capacity.
- **postorder node store**: node records written in postorder (children first, left-to-right), enabling append-only emission.
- **rightSpan**: the number of node records in the right subtree of a branch node in the postorder node store.
- **frontier**: the bounded builder state needed to resume append-only construction across batches without scanning.

## Key invariants (non-negotiable)

The implementation and any writer using it MUST enforce:

1. **Monotone keys**: `newKey > lastKey` (strictly increasing).
2. **Key encoding**: `key` is interpreted as `uint64` and traversed MSB-first.
3. **Bit numbering**: bit index `0` is the MSB (`bit 63` in the `uint64`), bit index `63` is the LSB.
4. **Preallocation**: the node store and leaf table are fully allocated and zero-filled before use; building writes in-place.

If (1) is violated, the append-only postorder construction is unsound (it would need rewrites).

## High-level layout

This ARC does **not** decide the exact massif blob offsets (that remains in the parent ARC / format work).
It does standardize the **internal encoding** of the Urkle data structures that will live inside the index budget.

We use two fixed regions:

```text
UrkleIndexRegion (within a preallocated massif index budget)

  +----------------------+  fixed-size header (versioned)
  | urkle header         |  params, counters, root ref/hash, etc.
  +----------------------+  fixed-size frontier snapshot (versioned)
  | frontier snapshot    |  builder-only mutable state
  +----------------------+  fixed per-leaf record size
  | leaf table           |  N * LeafRecordBytes
  +----------------------+  bounded by N
  | node store           |  <= (2N-1) * NodeRecordBytes
  +----------------------+
```

The `leaf table` is required because node records do not store full leaf payloads.

## Leaf table encoding (fixed-size records)

Each `leafOrdinal` maps to `(key, valueBytes[32])`:

```text
LeafRecord (LeafRecordBytes = 40), big-endian integers

offset  size  meaning
0       8     key_be8 (uint64 idtimestamp)
8       32    valueBytes (content-hash, 32 bytes)
```

**Semantics of valueBytes**: The `valueBytes` field stores the **content-hash**
directly (not the MMR leaf hash `H(idtimestamp || content-hash)`). This enables
direct verification of `(idtimestamp, content)` pair exclusion without needing
to check the MMR structure. The MMR tree stores `H(idtimestamp || content-hash)`
as its leaf values, while the trie commits to content hashes directly.

Rationale:

- Keeps node records small and fixed-size.
- Allows proof generation and verification to recover leaf payload by ordinal.
- Storing content-hash directly enables efficient exclusion proofs for specific
  content under a given idtimestamp.

## Node store encoding (B′: postorder + spans, no child refs)

Node records are written in **postorder** and stored in a fixed-size record array.
Each node has an implicit **ref** (record index) allocated monotonically:

```text
ref = 0, 1, 2, ... (monotone)
offset = nodeStoreBase + uint64(ref)*NodeRecordBytes
```

### Node navigation using `rightSpan`

For any **branch** node at record index `i`:

```text
rightRoot = i - 1
leftRoot  = i - 1 - rightSpan
```

This is the trie analogue of MMR “index arithmetic navigation”:
MMR can derive structure from indices alone because its shape is append-driven;
tries are key-driven, so we persist minimal structure (`rightSpan`) to make index navigation possible.

### Record layout

We standardize `NodeRecordBytes = 64` bytes to keep alignment simple and leave room for future fields.
All integers are big-endian.

```text
NodeRecord (64 bytes)

offset  size  meaning
0       1     kind: 1=leaf, 2=branch
1       1     bit (branch only): crit-bit index in [0..63] (MSB-first)
2       2     reserved (0)
4       4     rightSpan (branch only): node count of right subtree
8       4     subtreeSize: total node count of this subtree (incl this node)
12      4     leafOrdinal (leaf only); otherwise 0
16      16    reserved (0) (room for future counters/flags)
32      32    nodeHash (32 bytes)
```

Notes:

- `rightSpan` MUST equal `subtreeSize(rightRoot)` for well-formed branch nodes.
- `subtreeSize` for leaves is `1`.
- `subtreeSize` for branches is `leftSize + rightSize + 1`.
- `nodeHash` is the committed hash for this node (defined below).

## Hashing (domain separated)

Hash algorithm is provided by the caller as a `hash.Hash`, but the preimage format is fixed.

### Leaf hash

Leaves commit to `key`, `leafOrdinal`, and `valueBytes`:

```text
H( 0x00 || key_be8 || leafOrdinal_be4 || valueBytes[32] )
```

### Branch hash

Branches commit to the crit-bit index and ordered child hashes:

```text
H( 0x01 || bit_u8 || leftHash[32] || rightHash[32] )
```

This makes the root a deterministic function of the set of `(key,valueBytes)` pairs
under the canonical encoding rules. The builder requires monotone keys for append-only emission;
order-independence is achieved by canonicalizing input (sorting) before building.

## Builder: append-only from monotone keys

The builder maintains:

- `lastKey` (for strict ordering checks)
- `pendingRef` (root of the current rightmost subtree)
- a stack of frames: `(bit, leftRef)`
- `nextRef` (monotone cursor in the preallocated node store)

### Intuition (ASCII)

As keys arrive strictly increasing in trie order, the builder only ever needs to “close”
subtrees that will never be extended by future keys.

```text
sorted keys => future keys are always to the “right”

so once we move past a divergence level, the left side is final forever
and can be emitted (postorder) without rewrites.
```

### `FrontierStateV1` snapshot (bounded, builder-only)

To resume after persisting an open massif, the builder stores a fixed-size frontier snapshot.

```text
FrontierStateV1 (fixed size)

offset  size  field
0       4     magic "FNT1"
4       1     version = 1
5       1     key_bits = 64
6       2     reserved
8       8     last_key_be8
16      4     pending_ref_be4 (0xffffffff = none)
20      4     next_ref_be4    (next node record index to write)
24      1     depth (0..64)
25      3     reserved
28      4     next_leaf_ordinal_be4
32      8*64  frames[64]

frame (8 bytes)
0       1     bit index (0..63)
1       3     reserved
4       4     left_ref_be4
```

The verifier does not need frontier state; it is not an authenticated commitment unless explicitly anchored.

## Proof formats

Proof wire formats are module-internal Go structs. External CBOR/COSE formats are out of scope here
(see the parent ARC’s checkpoint anchoring discussion).

### Inclusion proof

An inclusion proof must allow a verifier to recompute the root and recover `(valueBytes, leafOrdinal)`.

```text
InclusionProof

- targetKey (uint64)
- leafOrdinal (uint32)
- valueBytes [32]byte
- steps[] where each step includes:
  - bit (uint8)          // the crit-bit index for this branch
  - siblingHash [32]byte // hash of the sibling subtree root
  - dir (uint8)          // 0=went left, 1=went right (may be derived from targetKey and bit)
```

Verification recomputes:

1. `leafHash = H(0x00||key||ordinal||value)`
2. For each step, compute parent hash using `(bit, leftHash, rightHash)`
3. The result must equal the expected root hash.

The verifier should return `leafOrdinal` and `valueBytes` as the “natural side effects”.

### Exclusion proof

For absence, we return a proof of membership for the **encountered leaf** reached by trie traversal
and show it is not the target key.

```text
ExclusionProof

- targetKey (uint64)
- encounteredKey (uint64)
- leafOrdinal (uint32)
- valueBytes [32]byte
- steps[] (same shape as inclusion proof, for encounteredKey)
```

Verification checks:

- recomputed root matches expected root
- `encounteredKey != targetKey`
- the encountered leaf is the correct terminal leaf for the traversal (i.e. divergence occurs at some crit-bit)

## Preallocation sizing

Given `leafCount = N`:

```text
maxNodes = 2*N - 1

leafTableBytes = N * LeafRecordBytes
nodeStoreBytes = maxNodes * NodeRecordBytes
frontierBytes  = FrontierStateV1Bytes
```

Implementations MUST check that:

- `N` fits into `uint32` for `leafOrdinal`
- `maxNodes` fits into `uint32` for `subtreeSize/rightSpan`
- chosen `massifHeight` implies a `leafCount` compatible with the ordinal width

## Derived `mmrIndex` from `leafOrdinal`

Given a massif/chunk context providing `firstLeafMMRIndex` (the MMR index of the first leaf in the chunk),
derive:

```go
firstLeafIndex := mmr.LeafCount(firstLeafMMRIndex)
mmrIndex := mmr.MMRIndex(firstLeafIndex + uint64(leafOrdinal))
```

This yields an authenticated mapping:

```text
key -> (leafOrdinal -> mmrIndex) -> valueBytes
```

## Testing guidance

Unit tests for the primitive module must include:

- strict monotone insert rejection (`newKey <= lastKey`)
- inclusion proof round-trips for random inserted keys
- exclusion proofs for missing keys (below min, between, above max)
- frontier snapshot encode/decode and “resume produces same root”
- order-independence at the *set* level: sort/canonicalize input pairs and assert root equivalence

## References

- Parent ARC: `arbor/docs/arc-massif-exclusion-trie.md`
- Existing MMR functional style: `arbor/services/_deps/go-merklelog/mmr/`

