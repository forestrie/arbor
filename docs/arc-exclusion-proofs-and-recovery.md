# ARC: Exclusion Proofs and Recovery

## Executive Summary

This document assesses the cryptographic properties of the combined MMR + Urkle
trie system for proving exclusion from the log, identifies subtleties for
verifiers/auditors/log users, and summarizes the benefits of maintaining the
trie structure.

## Assessment of Core Statements

### Statement 1: "Urkle-based proof of exclusion allows a log user to prove that
an idtimestamp is not in the urkle index."

**✅ ACCURATE** - This is correct. An Urkle exclusion proof demonstrates that
a given `idtimestamp` key is absent from the trie by:
1. Traversing the trie to find the terminal leaf
2. Showing that the encountered leaf's key differs from the target
   `idtimestamp`
3. Providing a Merkle path that reconstructs the authenticated trie root
4. Verifying the crit-bit relationship confirms the target key would have been
   at a different position

### Statement 2: "Proving the idtimestamp is not in the urkle index does not
prove that the corresponding mmr leaf H(idtimestamp || content-hash) is not in
the tree."

**✅ ACCURATE** - This is a critical observation. The trie exclusion proof
alone does **not** directly prove absence from the MMR tree because:

- The trie maps `idtimestamp → (valueBytes, leafOrdinal)`
- The MMR tree stores leaves as `H(idtimestamp || content-hash)` at specific
  positions
- **These are different data structures with different commitments**

A malicious or buggy log builder could theoretically:
- Add an MMR leaf `H(id_t || content)` at some position
- Fail to add the corresponding trie entry for `id_t`
- The trie exclusion proof would show `id_t` is absent from the trie
- But the MMR leaf would still exist in the tree

### Statement 3: "A proof of exclusion, which yields the leaf index, can then
directly check O(1) the corresponding leaf value in the tree. Therefore the
combination of those two actions is proof of exclusion from the entire log."

**⚠️ MOSTLY ACCURATE, WITH IMPORTANT SUBTLETIES** - The logic is sound, but
requires careful implementation:

**The Correct Verification Procedure:**

1. **Obtain Urkle exclusion proof** for target `id_t`:
   - Proof shows `id_t` is not in the trie
   - Proof yields `encounteredKey`, `encounteredLeafOrdinal`, and `valueBytes`
     of the encountered leaf
   - Verify the proof reconstructs the authenticated trie root

2. **Derive MMR index from encountered leaf** (if applicable):
   - From `encounteredLeafOrdinal`, compute `encounteredMMRIndex` using massif
     context
   - This gives you a position to check, but **not** the position where
     `id_t`'s leaf would be

3. **Critical gap**: The exclusion proof doesn't directly tell you which MMR
   position to check for `id_t`'s leaf, because `id_t` isn't in the trie.

**The Actual Verification Strategy:**

The correct approach depends on what you're trying to prove:

**Case A: Proving `id_t` is not in the log (complete exclusion)**
- Urkle exclusion proof shows `id_t` is not in the trie
- **But you still need to verify**: Could `H(id_t || content)` exist at any
  MMR position?
- **Solution**: The trie is the **authoritative index**. If `id_t` is not in
  the trie, then by the log's construction rules, there should be no
  corresponding MMR leaf. However, this requires trusting that the log builder
  correctly maintains the trie-MMR correspondence.

**Case B: Proving a specific `(id_t, content)` pair is not in the log**
- Urkle exclusion proof for `id_t`
- **Additional check needed**: Verify that no MMR leaf equals `H(id_t ||
  content)` at any position
- This requires either:
  - Scanning relevant massifs (inefficient)
  - Using a Bloom filter to rule out presence (probabilistic)
  - Trusting the trie as authoritative (requires integrity guarantee)

**The O(1) Claim:**

The statement about "O(1) check" is **not quite accurate** in the exclusion
case. Here's why:

- **Inclusion case**: If `id_t` is in the trie, you get `leafOrdinal →
  mmrIndex → O(1) MMR leaf access` ✅
- **Exclusion case**: If `id_t` is NOT in the trie, you get an
  `encounteredLeafOrdinal` for a **different** key. This doesn't give you the
  MMR position to check for `id_t`'s leaf.

**What the exclusion proof actually enables:**

The exclusion proof is most powerful when combined with the **monotone key
ordering guarantee**:

1. Urkle exclusion proof shows `id_t` is not in the trie
2. The encountered leaf provides a neighboring key in the sorted order
3. You can use range queries to identify which massif(s) could contain `id_t`
   (if it existed)
4. For those massifs, you'd need to verify the trie root matches the
   authenticated checkpoint
5. The trie exclusion proof for that massif then proves absence

This is **not O(1)** - it's O(log N) for the trie proof + potentially
multiple massif checks.

## Cryptographic Subtleties for Verifiers, Auditors, and Log Users

### 1. **Trie-MMR Correspondence Integrity**

**Risk**: The trie and MMR are separate authenticated structures. A verifier
must trust that:
- Every MMR leaf has a corresponding trie entry
- Every trie entry corresponds to a valid MMR leaf
- The `valueBytes` in the trie correctly represents the committed content

**Mitigation**:
- Checkpoint signatures should commit to both trie roots and MMR peaks
- Auditors should verify consistency between trie entries and MMR leaves
- Consider adding a "correspondence proof" that demonstrates trie-MMR
  alignment

### 2. **State-Relative Proofs**

**Critical**: Exclusion proofs are **state-relative**, not absolute:
- An exclusion proof for checkpoint `C_i` only proves absence as of that
  checkpoint
- Future appends may add the excluded `idtimestamp`
- Verifiers must check the proof's checkpoint timestamp/version

**Best Practice**: Always verify:
- The trie root in the exclusion proof matches an authenticated checkpoint
- The checkpoint is recent enough for the use case
- The proof includes checkpoint metadata (massif index, commitment epoch,
  etc.)

### 3. **Leaf Ordinal to MMR Index Derivation**

**Subtlety**: Converting `leafOrdinal` to `mmrIndex` requires authenticated
context:
- Massif's `FirstIndex` (MMR index of first leaf in massif)
- Massif height (to compute leaf capacity)
- Correct interpretation of MMR indexing arithmetic

**Risk**: If the derivation is incorrect, you check the wrong MMR position.

**Mitigation**:
- Verify the massif header is authenticated
- Use well-tested, audited MMR index conversion functions
- Consider including `mmrIndex` directly in trie leaves (Option A from ARC)
  for simplicity

### 4. **Content Hash Commitment**

**Question**: What does `valueBytes` in the trie actually store?

From the code analysis:
- `IndexLeaf` is called with `parsed.Hash` which is the content-hash
- The MMR stores `H(idtimestamp || content-hash)` via `AddIndexedEntry(leafHash)`
- The trie stores `content-hash` directly via `IndexLeaf(idTimestamp, parsed.Hash)`

**Implementation**: The system uses a **hybrid commitment strategy**:

- **MMR tree**: Stores `H(idtimestamp || content-hash)` as leaf values (Case 1)
- **Urkle trie**: Stores `content-hash` directly as `valueBytes` (Case 2)

This is the intended design and what the code implements. The MMR commits to the
combined hash, while the trie commits to content hashes directly.

**What This Proves (Case 2: `valueBytes = content-hash`):**

Since the trie stores content-hash directly, an exclusion proof proves:
- The target `id_t` is not present in the trie
- The encountered leaf's `valueBytes` is a content hash (but for a different
  key)
- **Advantage**: If you have a candidate `content` and want to prove the
  `(id_t, content)` pair is absent:
  - Compute `content_hash = H(content)`
  - The exclusion proof shows `id_t` is not in the trie
  - Since the trie maps `idtimestamp → content-hash`, absence means no
    content-hash is associated with `id_t`
  - This directly proves the `(id_t, content)` pair is absent (assuming
    content-hash collision resistance)
- **What it enables**: Direct verification that a specific content was not
  logged under a given `idtimestamp`, without needing to check the MMR
  structure. The trie exclusion proof is sufficient for this claim.

**Why This Hybrid Design**: The combination of MMR storing `H(idtimestamp ||
content-hash)` and trie storing `content-hash` directly provides complementary
benefits. See the "Design Analysis" section below for a detailed pros/cons
analysis.

## Design Analysis: Hybrid Commitment Strategy

### Current Implementation

The system uses a **hybrid commitment strategy**:

- **MMR tree**: Commits `H(idtimestamp || content-hash)` as leaf values
- **Urkle trie**: Commits `content-hash` directly as `valueBytes`

### Pros of This Design

#### 1. **MMR: Binding idtimestamp to Content**

**Pro**: Committing `H(idtimestamp || content-hash)` in the MMR ensures:
- **Uniqueness**: Each MMR leaf is unique even if the same content is logged
  multiple times with different idtimestamps
- **Binding**: The MMR structure cryptographically binds each idtimestamp to its
  specific content at that position
- **Position integrity**: The MMR leaf hash commits to both the key (idtimestamp)
  and value (content), preventing substitution attacks where someone tries to
  claim different content was logged at a given position

#### 2. **Trie: Direct Content Queries**

**Pro**: Committing `content-hash` directly in the trie enables:
- **Efficient exclusion proofs**: Can directly prove a specific `(idtimestamp,
  content)` pair is absent without MMR verification
- **Content-based lookups**: Can query "was this content logged under any
  idtimestamp?" by checking the trie
- **Simpler verification**: For content exclusion queries, verifiers don't need
  to reconstruct MMR leaf hashes

#### 3. **Separation of Concerns**

**Pro**: The two structures serve different purposes:
- **MMR**: Provides append-only log integrity and position-based commitments
- **Trie**: Provides efficient key-based lookups and exclusion proofs

#### 4. **Collision Resistance**

**Pro**: Using `H(idtimestamp || content-hash)` in MMR provides strong collision
resistance:
- Even if two different `(idtimestamp, content)` pairs hash to the same
  content-hash, their MMR leaf hashes will differ
- Prevents accidental collisions in the MMR structure

### Cons of This Design

#### 1. **Storage Overhead**

**Con**: Storing both representations requires:
- MMR stores 32 bytes per leaf: `H(idtimestamp || content-hash)`
- Trie stores 32 bytes per leaf: `content-hash`
- Total: 64 bytes of hash data per entry (plus structure overhead)

**Mitigation**: This is acceptable given the benefits, and the trie storage is
bounded by massif capacity.

#### 2. **Verification Complexity**

**Con**: Verifiers must understand two different commitment schemes:
- MMR inclusion proofs verify `H(idtimestamp || content-hash)`
- Trie exclusion proofs verify `content-hash` directly
- Need to ensure both structures are checked when appropriate

**Mitigation**: Clear documentation and APIs can abstract this complexity.

#### 3. **Correspondence Verification**

**Con**: The two structures commit to different values, so:
- Verifiers must trust that the trie-MMR correspondence is maintained correctly
- A buggy or malicious log builder could add an MMR leaf without the
  corresponding trie entry (or vice versa)
- Requires additional verification to ensure consistency

**Mitigation**: 
- Checkpoint signatures should commit to both trie roots and MMR peaks
- Auditors should verify correspondence periodically
- Consider adding correspondence proofs

#### 4. **Content Hash Collisions**

**Con**: If two different contents hash to the same `content-hash`:
- The trie can only store one mapping per content-hash
- This is a fundamental limitation of content-addressed storage
- However, the MMR still distinguishes them via `H(idtimestamp ||
  content-hash)`

**Mitigation**: This is a general property of content-addressed systems, not
specific to this design. SHA-256 collision resistance makes this extremely
unlikely in practice.

### Alternative Designs Considered

#### Alternative 1: Both Store MMR Leaf Hash

**If both MMR and trie stored `H(idtimestamp || content-hash)`:**

Pros:
- Single commitment scheme (simpler)
- Perfect correspondence (trie and MMR commit to same value)
- No ambiguity about what's being committed

Cons:
- **Cannot directly prove content exclusion**: To prove `(id_t, content)` is
  absent, you'd need to compute `H(id_t || content)` and check if it exists,
  but the trie is keyed by `idtimestamp`, not by the hash
- **Less efficient content queries**: Can't query "was this content logged?"
  without knowing the idtimestamp
- **Weaker exclusion proofs**: Exclusion proof for `id_t` doesn't directly tell
  you about specific content

#### Alternative 2: Both Store Content Hash

**If both MMR and trie stored `content-hash`:**

Pros:
- Single commitment scheme (simpler)
- Direct content-based queries in both structures
- Simpler verification

Cons:
- **Weaker binding**: MMR doesn't bind idtimestamp to content - same content
  logged twice would have identical MMR leaves
- **Position ambiguity**: If the same content is logged at multiple positions,
  the MMR leaves are identical, making it harder to prove which position
  contains which entry
- **Substitution attacks**: Without idtimestamp in the MMR leaf hash, an
  attacker could potentially claim different content was logged at a position
  (though this is mitigated by the trie and other mechanisms)

### Conclusion

The **hybrid design** (MMR stores `H(idtimestamp || content-hash)`, trie stores
`content-hash`) is optimal because:

1. **MMR integrity**: The MMR maintains strong cryptographic binding between
   idtimestamp and content at each position
2. **Trie efficiency**: The trie enables efficient content-based exclusion
   proofs and queries
3. **Complementary strengths**: Each structure serves its purpose optimally
4. **Practical trade-offs**: The storage overhead and verification complexity
   are acceptable given the benefits

The design correctly balances the needs of:
- **Log integrity** (MMR with position-based commitments)
- **Efficient queries** (Trie with content-based commitments)
- **Exclusion proofs** (Trie enables direct content verification)

### 5. **Trie Root Authentication**

**Critical**: The exclusion proof is only valid if the trie root is
authenticated:
- Trie root must be in a signed checkpoint
- Or the trie root must be derivable from authenticated MMR state
- Unauthenticated trie roots provide no security guarantees

**Verification Requirement**: Always verify the trie root against a signed
checkpoint before accepting an exclusion proof.

### 6. **Massif Range Queries**

**For Whole-Log Exclusion**:
- Use monotone `idtimestamp` ordering to identify candidate massifs
- Each massif has a `last_id` (max key) in its header
- Range: `(prev_massif.last_id, current_massif.last_id]`
- If `id_t` is outside all massif ranges, it's definitely absent
- If `id_t` is within a range, use that massif's trie exclusion proof

### 7. **Bloom Filter False Positives**

**Note**: Bloom filters are used as prefilters, not proof mechanisms:
- A Bloom "maybe present" result requires a trie check
- A Bloom "definitely absent" result is probabilistic (false positive rate)
- Only the trie provides cryptographic exclusion proofs

## Benefits of Maintaining the Trie

### 1. **Efficient Exclusion Proofs**

**Without Trie**:
- To prove `id_t` is absent, you'd need to scan all leaves in relevant
  massifs: O(N) where N is leaves per massif
- Or maintain a separate authenticated index structure

**With Trie**:
- Exclusion proof is O(log N) in trie size (typically ~64 steps for 64-bit
  keys)
- Proof size is O(log N) hashes
- Verification is O(log N) hash operations

### 2. **Deterministic Root (Order Independence)**

**Key Property**: "Any order of addition produces the same trie root"

This property is **crucial** for backup recovery and verification:

#### Backup Recovery Benefits:

1. **Incremental Backup Verification**:
   - Backup system can receive massifs in any order
   - Can verify each massif's trie root independently
   - Final reconstructed log has the same trie root regardless of backup
     order
   - Enables parallel backup/restore operations

2. **Partial Recovery**:
   - Can verify individual massifs without full log context
   - Each massif's trie root is self-contained
   - Enables selective recovery of specific massif ranges

3. **Consistency Checking**:
   - Can compare trie roots across backup copies
   - Identical trie roots guarantee identical key sets (for the same
     massif)
   - Enables efficient deduplication and integrity verification

4. **Distributed Storage**:
   - Massifs can be stored across multiple locations
   - Trie roots enable verification without reassembling full massifs
   - Enables erasure coding and distributed backup strategies

#### Verification Benefits:

1. **Independent Massif Verification**:
   - Each massif's trie can be verified independently
   - No need to reconstruct full log to verify a single massif
   - Enables parallel verification across multiple massifs

2. **Checkpoint Consistency**:
   - Trie roots in checkpoints can be verified against massif trie roots
   - Enables detection of checkpoint-massif mismatches
   - Supports incremental checkpoint verification

3. **Audit Trail**:
   - Trie roots provide compact commitments to key sets
   - Auditors can verify trie roots without accessing full massif data
   - Enables efficient audit of log integrity over time

4. **Proof Generation**:
   - Exclusion proofs can be generated from a single massif
   - No need to access other massifs or full log state
   - Enables efficient proof generation for distributed systems

### 3. **Bounded Storage**

- Trie size is bounded by massif leaf capacity: O(N) nodes for N leaves
- Preallocated storage enables efficient append-only construction
- Fixed index budget per massif simplifies resource planning

### 4. **Incremental Construction**

- Trie can be built incrementally as leaves are added
- Supports efficient batch appends
- Enables real-time index maintenance during log construction

### 5. **Position Recovery**

- Trie inclusion proofs yield `leafOrdinal`
- Enables efficient `idtimestamp → mmrIndex` lookup
- Supports content-addressed storage lookups

### 6. **Range Queries**

- Monotone key ordering enables efficient range queries
- `last_id` chain enables whole-log range identification
- Supports efficient "all entries in time range" queries

## Recommendations

### For Verifiers:

1. **Always verify trie root authentication** before accepting exclusion
   proofs
2. **Check checkpoint timestamps** to ensure proof is current enough
3. **Verify massif context** (FirstIndex, height) when deriving MMR indices
4. **Understand what `valueBytes` represents** in your deployment
5. **Use range queries** to identify candidate massifs for whole-log exclusion

### For Auditors:

1. **Verify trie-MMR correspondence** periodically
2. **Check that trie roots match checkpoints** consistently
3. **Audit the order-independence property** by verifying trie roots match
   across different construction orders
4. **Monitor for trie root mismatches** that could indicate integrity issues

### For Log Users:

1. **Understand exclusion proofs are state-relative** - check checkpoint
   versions
2. **Use inclusion proofs when possible** - they're simpler and more
   efficient
3. **Cache authenticated trie roots** to reduce verification overhead
4. **Use Bloom filters as prefilters** but rely on trie for cryptographic
   proofs

### For System Designers:

1. **Document explicitly** what `valueBytes` contains (MMR leaf hash vs
   content hash)
2. **Consider including `mmrIndex` directly** in trie leaves for simpler
   verification
3. **Provide clear APIs** for trie root authentication and checkpoint
   binding
4. **Design checkpoint formats** that clearly bind trie roots to MMR state
5. **Consider adding correspondence proofs** that demonstrate trie-MMR
   alignment

## Conclusion

The Urkle-based exclusion proof system is cryptographically sound when properly
implemented and verified. The key insight is that **trie exclusion + MMR
verification** together provide complete exclusion proofs, but this requires:

1. Authenticated trie roots (via checkpoints)
2. Correct MMR index derivation
3. Understanding of what the trie actually commits to
4. Awareness that exclusion proofs are state-relative

The "order independence" property of the trie is particularly valuable for
backup/recovery scenarios, enabling efficient verification, parallel
operations, and distributed storage strategies.

The main subtlety is that trie exclusion alone doesn't prove MMR exclusion -
you need the combination, and the verification procedure must be carefully
implemented to ensure both structures are checked correctly.
