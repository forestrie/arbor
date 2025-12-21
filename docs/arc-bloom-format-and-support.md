# ARC: Bloom Format and Support (4-way, fixed 32-byte elements)

## Status

Draft.

## Parent ARC

This ARC is a child of `arbor/docs/arc-massif-exclusion-trie.md`.

The parent ARC discusses Bloom filters as an optional **prefilter optimization** (not a proof mechanism).
This ARC records the concrete, bounded encoding and primitive API choices used by the `go-merklelog/bloom` module.

## Abstract

We standardize a bounded Bloom filter encoding intended for preallocated massif index regions.

Key properties:

- Exactly **4 parallel filters**, stored side-by-side.
- Each element is exactly **32 bytes** (Forestrie `ValueBytes`).
- Parameterized by `leafCount` and a fixed `bitsPerElement` budget (and derived `mBits`).
- Deterministic double-hashing with an explicit bit numbering convention.

This ARC covers:

- the in-memory / in-place layout of the 4 filters,
- how to compute preallocation sizes from `leafCount`,
- and the update/query algorithms.

## Non-goals

- Bloom filters are **not** cryptographic commitments and do not provide exclusion proofs.
- This ARC does not decide checkpoint anchoring of bloom data (see parent ARC for anchoring discussions).
- This ARC does not mandate *which* elements each filter indexes; it only standardizes the format.

## Terms (additive to `term-cheatsheet.md`)

- **Bloom filter**: fixed-size bitset supporting probabilistic membership queries (false positives possible).
- **mBits**: number of bits in the filter bitset.
- **bitsPerElement**: `b`, the fixed sizing knob used to derive `mBits = b * leafCount`.
- **k**: number of hash-derived bit positions set per inserted element.
- **bit order**: mapping from `(byteIndex, bitIndex)` to an integer bit position.

## Layout

The Bloom structure is designed to live inside a preallocated index budget region.

```text
BloomRegion (within a preallocated massif index budget)

  +----------------------+  fixed-size header (versioned)
  | bloom header         |  params, counters, etc.
  +----------------------+  filter 0 bitset bytes
  | filter0 bitset       |
  +----------------------+  filter 1 bitset bytes
  | filter1 bitset       |
  +----------------------+  filter 2 bitset bytes
  | filter2 bitset       |
  +----------------------+  filter 3 bitset bytes
  | filter3 bitset       |
  +----------------------+
```

All bitsets have identical size `bitsetBytes = ceil(mBits/8)`.

## Header: `BloomHeaderV1` (fixed size)

We standardize a 32-byte header to keep parsing simple and compatible with other fixed-size index headers.

```text
BloomHeaderV1 (32 bytes)

offset  size  meaning
0       4     magic "BLM1"
4       1     version = 1
5       1     bitOrder = 0  (0 = LSB0 within byte)
6       1     k (number of hash functions)
7       1     filters = 4
8       4     mBits (uint32, bits per filter)
12      4     nInserted (uint32, optional counter)
16      16    reserved (0)
```

Notes:

- `bitOrder` is explicit so verifiers and writers agree on bit numbering.
- `nInserted` is optional operational metadata. It is not an authenticated commitment unless explicitly anchored.

## Bit numbering (explicit)

We choose **LSB0** numbering within each byte:

```text
bitset bytes: b[0], b[1], ...

bit index j:
  byte = j / 8
  bit  = j % 8

LSB0 convention:
  bit 0 is (b[0] & 0x01)
  bit 7 is (b[0] & 0x80)
```

This convention is simple and fast on common CPUs. Any alternative MUST change `bitOrder`.

## Hashing and double-hashing

Each filter uses deterministic **double hashing** to derive `k` indices in `[0..mBits)`.

For element bytes `x[32]` and filter index `f in {0,1,2,3}`:

```text
sum = SHA-256( 0xB0 || f || x )
h1  = u64be(sum[0:8])
h2  = u64be(sum[8:16])

idx_i = (h1 + i*h2) mod mBits   for i=0..k-1
```

If `h2 == 0`, implementations MUST set `h2 = 1` to avoid generating identical indices.

Rationale for including `f`:

- makes the 4 parallel filters independent even when indexing the same element values
- avoids correlated bit patterns across filters

## Update algorithm

Insert sets `k` bits in the chosen filter:

```text
for i = 0..k-1:
  j = (h1 + i*h2) % mBits
  byte = j / 8
  bit  = j % 8
  bitset[byte] |= (1 << bit)   // LSB0
```

Query checks all `k` bits:

```text
for i = 0..k-1:
  j = (h1 + i*h2) % mBits
  if (bitset[byte] & (1 << bit)) == 0:
    return definitely_not_present
return maybe_present
```

## Preallocation sizing

Given `leafCount = N` and `bitsPerElement = b`:

```text
mBits       = b * N
bitsetBytes = ceil(mBits/8)

totalBytes  = BloomHeaderBytes + 4*bitsetBytes
```

Implementations MUST check overflow when computing `mBits` and `totalBytes`.

## Testing guidance

Unit tests must include:

- inserting elements yields `MaybeContains == true` for those elements
- empty filter yields `MaybeContains == false` for random elements
- invalid filter index and invalid element sizes are rejected
- preallocation sizing (byte rounding and offsets for 4 filters)

## References

- Parent ARC: `arbor/docs/arc-massif-exclusion-trie.md`
- Bloom filter background: Bloom, 1970 (see parent ARC references)

