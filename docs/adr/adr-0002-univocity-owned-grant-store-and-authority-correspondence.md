# Univocity-owned grant store and authority correspondence

Sealing a log's **first** checkpoint must be possible before the log exists
on-chain (publishing the checkpoint is what establishes it). The previous design
([ADR-0001](adr-0001-genesis-driven-logid-resolution.md)) could only resolve a
log's authority after an on-chain checkpoint existed, forcing a Custodian /
coordinator central-trust fallback for the pre-chain window.

**Decision:** Univocity **owns** the off-chain genesis + grant store and verifies
the grant **signature chain** off-chain, anchored to the immutable on-chain
**bootstrap key** (`bootstrapConfig()`):

- genesis: `forest/{hex64(R)}/genesis.cbor`
- grants: `forest/{hex64(R)}/grants/{hex64(subject)}.cbor` (raw transparent
  statement bytes)
- A non-root grant's COSE **envelope** verifies against its **owner's** root key
  `grantData_O` (resolved on-chain via `logRootKey(O)` or by recursing the grant
  store), not against its own `grantData`. The recursion bottoms out at the root,
  whose self-referential bootstrap grant must verify against `bootstrapConfig()`.

**Authority correspondence:** on-chain authority is grant **inclusion in the owner
MMR** plus a **checkpoint/delegation signature** that verifies against the log
root key. The off-chain grant **COSE envelope** is the *same* authority expressed
at ingress. The contract never inspects the grant envelope — the leaf preimage
carries no signature and `publishCheckpoint` is permissionless (`_msgSender()` is
event-only) — so tightening "who must sign the envelope" requires **no contract
change**.

**Why:** This makes grant publishing permissionless and secure (checkpoints are
only possible when COSE envelopes are signed by the keys grants actually
authorize), decouples attested-append throughput from on-chain transaction
throughput, and removes the central-trust fallback. Grant storage is ephemeral —
it need only persist until a log's first checkpoint — so there is no long-term
backup/recovery requirement.

**Consequences:** Univocity needs write/authorize token auth and grants-bucket
credentials; canopy delegates creation-grant validation to univocity and stops
owning genesis storage (R2 becomes a transitional compat shim). GC is explicit
(admin delete), not automatic.
