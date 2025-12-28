# ADR-0004: Fixed Visibility Timeout per Pull

## Status
Accepted

## Context
When a consumer pulls entries from the queue, it needs a lease period during
which those entries are invisible to other consumers. Three options:

1. **Fixed timeout per pull**: consumer specifies timeout; all entries in the
   batch share it.
2. **Per-entry timeout**: each entry can have a different timeout.
3. **Heartbeat extension**: consumer can extend the lease before expiry.

## Decision
We will use **fixed timeout per pull**. The consumer specifies `visibilityMs`
in the pull request; all returned entries become invisible until
`now + visibilityMs`.

## Rationale
- Simple to implement and reason about.
- Ranger processes batches atomically—no need for per-entry flexibility.
- Heartbeat adds round-trip overhead and complexity for marginal benefit.
- If processing takes longer than expected, entries simply redeliver.

## Consequences
- Consumer must choose a timeout that covers expected processing time.
- Long-running batches may cause spurious redelivery (acceptable; ranger
  handles duplicates via optimistic concurrency).

## References
- [arc-cloudflare-do-ingress.md](arc-cloudflare-do-ingress.md): Section 1.4
