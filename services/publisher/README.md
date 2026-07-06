# publisher

Anchors sealed v3 checkpoints on-chain. It reads each checkpoint object from
public R2, resolves the forest's `(chainId, contract)` from public genesis
(ADR-0047), builds the `publishCheckpoint` calldata with `publishproof`, and
submits it from a **gas-only EOA** — authority stays with the grant/signature
chain ("postmark, not gatekeeper"). Multi-forest, multi-chain (plan-2607-02).

- **Daemon** (default): Cloudflare-queue consumer on the `v2/merklelog/checkpoints/`
  prefix → batched per-chain submitter → per-message ack.
- **CLI**: `publisher publish --key <checkpoint object key> [--json]` — one-shot,
  for system-testing before GitOps rollout.

## ⚠️ Load-bearing invariant: the publisher EOA is single-writer

**Exactly one process may ever send transactions from a given publisher wallet.**
Under horizontal scaling this MUST be preserved by giving each replica its own
wallet — never point two replicas at one EOA.

The per-chain nonce counter (`chainNonce`, `src/batchsubmit.go`) is only correct
because nothing else advances the account nonce: while transactions are in flight
it hands out nonces from memory (no RPC); when drained it re-seeds from
`PendingNonceAt`. Two processes sharing one wallet would silently corrupt the
counter (`nonce too low` / dropped replacements). Enforce with `replicas: 1`
(GitOps) until a wallet-per-replica partition exists.

## Submission model (sequential admission, gap-free)

Per chain, under a send lock held only across the sends: read the next nonce
once, then admit `N, N+1, …` in order awaiting only mempool admission, **stopping
on the first admission failure** and rolling back the unsent nonces. Nothing
above a failed nonce is ever sent, so the sequence is gap-free by construction —
no stuffer, no reseed policy. Receipts are confirmed asynchronously by a
persistent per-chain collector that acks each message the instant its receipt
resolves. Reverts are classified transient (retry) vs terminal (ack + alert).

Safety (no lost checkpoint) is deterministic regardless: publish is idempotent
(skip-if-anchored), messages are acked only on a terminal outcome, and the queue
redelivers anything else.

## Key configuration

| Env | Meaning | Default |
|-----|---------|---------|
| `UNIVOCITY_RPC_URLS` | JSON `{chainId: rpcUrl}` map | required |
| `PUBLISHER_EOA_KEY` | gas-only EOA private key (hex; Doppler) | required |
| `GRANT_STORE_URL` | anonymous public-read grant/genesis bucket domain (≠ `R2_URL`) | required |
| `R2_URL` / `AWS_*` | SigV4 S3 endpoint + creds for massif reads | required |
| `PUBLISHER_GAS_LIMIT` | fixed gas limit (no `EstimateGas`) | `3000000` |
| `PUBLISHER_MAX_FEE_PER_GAS` / `PUBLISHER_MAX_PRIORITY_FEE` | EIP-1559 caps (wei); else derived from base fee | derive |
| `PUBLISHER_RECEIPT_TIMEOUT` / `PUBLISHER_RECEIPT_POLL_INTERVAL` | receipt wait | `60s` / `200ms` |
| `VISIBILITY_TIMEOUT` | queue lease — must exceed the receipt timeout | `90s` |
| `QUEUE_URL` / `QUEUE_TOKEN` / `QUEUE_BATCH_SIZE` | Cloudflare queue (daemon only) | — / — / `31` |

## Build & test

```bash
cd services/publisher && go test ./...   # via the generated go.work
```
