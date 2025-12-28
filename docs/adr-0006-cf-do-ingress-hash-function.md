# ADR-0006: Non-Cryptographic Hash for Poller Assignment

## Status
Accepted

## Context
The SequencingQueue DO uses consistent hashing to assign logs to pollers. When
multiple ranger instances poll the queue, each log is deterministically
assigned to one poller based on its logId. This ensures:

1. Each log is processed by exactly one poller at a time
2. Log assignment is stable across pulls (same poller handles a log until it
   leaves or a new poller joins)
3. Logs are distributed roughly evenly across pollers

The hash function choice warrants discussion because "write your own crypto"
is generally ill-advised. We must clearly establish whether this is a
cryptographically sensitive context.

## Decision
Use djb2, a simple non-cryptographic hash function, for poller assignment.

```typescript
function djb2Hash(data: Uint8Array): number {
  let hash = 5381;
  for (let i = 0; i < data.length; i++) {
    hash = ((hash << 5) + hash + data[i]) >>> 0;
  }
  return hash >>> 0;
}
```

Assignment is computed as: `sortedPollerIds[djb2Hash(logId) % pollerCount]`

## Rationale

### This is NOT cryptographically sensitive

The hash function is used solely for load distribution. Consider what an
adversary could achieve by manipulating hash inputs or predicting outputs:

1. **Craft logIds to target a specific poller**: An attacker controlling
   statement content could theoretically craft logIds that hash to a particular
   poller. However, logIds are derived from log creation, not arbitrary user
   input, and targeting a specific poller provides no security advantage — the
   poller will process the entry identically regardless.

2. **Predict which poller handles a log**: This information is not sensitive.
   Rangers are interchangeable and the assignment is deterministic by design.

3. **Cause uneven distribution**: With adversarial input, an attacker could
   skew load toward one poller. However, logIds are not user-controlled, and
   even if they were, this is a denial-of-service vector at most, not a
   security breach. Rate limiting at the API layer is the appropriate defense.

### Why not use a cryptographic hash?

1. **SHA-256 via Web Crypto API**:
   - Async API adds complexity (`await crypto.subtle.digest(...)`)
   - Significantly slower (10-100x for small inputs)
   - Returns 256 bits when we need ~32 bits for modulo operation
   - Overkill for non-security-sensitive load balancing

2. **Pre-existing cryptographic dependencies**:
   - The codebase uses `cose-js` which includes cryptographic functions, but
     these are optimized for COSE operations, not general hashing
   - Adding a dependency for this simple use case is unnecessary

### Why djb2 specifically?

1. **Simplicity**: 5 lines of code, no dependencies, easy to audit
2. **Speed**: Operates directly on bytes, no memory allocation
3. **Adequate distribution**: djb2 has good avalanche properties for
   non-adversarial inputs. Small input changes produce well-distributed
   output changes.
4. **Proven track record**: Created by Daniel J. Bernstein, widely used in
   hash tables (glibc, Python 2, etc.)

### Alternatives considered

| Option | Pros | Cons |
|--------|------|------|
| FNV-1a | Similar simplicity, slightly better distribution | More code |
| MurmurHash | Excellent distribution | Requires library or 50+ lines |
| SHA-256 | Cryptographic strength | Async, slow, overkill |
| xxHash | Very fast, good distribution | Requires library |

For assigning among 1-10 pollers, djb2's distribution is more than adequate.

## Consequences

### Positive
- Zero dependencies for hash function
- Synchronous, fast execution
- Simple code that's easy to understand and audit

### Negative
- Custom hash function may raise eyebrows in code review (hence this ADR)
- Distribution may not be perfectly uniform (acceptable for this use case)

### Neutral
- If we later need cryptographic hashing elsewhere, this doesn't preclude it
- If load balancing requirements become more sophisticated, we can swap
  implementations (the interface is just `logId → pollerIndex`)

## References
- [djb2 hash function](http://www.cse.yorku.ca/~oz/hash.html)
- [Hash function comparison](https://softwareengineering.stackexchange.com/q/49550)
- adr-0002-cf-do-ingress-consistent-hashing.md (discusses why consistent
  hashing is used, not which hash function)
