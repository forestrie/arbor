# Global logId → R uniqueness

A subject `logId` could, in principle, be presented under more than one forest
root `R` (cross-forest reuse), which would make `logId → authority` ambiguous and
let a grant valid in one forest be replayed to seal a log in another.

**Decision:** A subject `logId` maps to **exactly one** forest `R` globally.
Univocity maintains an atomic index
`forests/index/forest/{uuid-subject}` (body: ASCII UUID of `R`) created with a
conditional write (`If-None-Match: *`). See
[ADR-0004](adr-0004-forests-storage-and-uuid-log-ids.md). `POST /api/grants` performs an idempotent
index create:

- **new** → `201` (first time this `logId` is seen)
- **match** (existing `R` equals the request's `R`) → `200`
- **conflict** (existing `R` differs) → `409`

Canopy enforces this at the **edge**: register-grant forwards creation grants to
univocity and surfaces `409` to the caller. The root self-indexes `R → R` at
genesis POST.

**Why:** O(1) per-grant uniqueness with no scan; closes cross-forest `logId`
reuse; gives the resolver a single authoritative `logId → R` lookup that both the
public-root read and the authority resolution share. Ranger still simply appends to
(or creates) the log it is told to; the sealer may later be hardened to refuse a
log whose authoritative `R` disagrees with a known binding (follow-up).

**Consequences:** Uniqueness is per global index namespace (one grants bucket).
Deleting a forest/subject must also delete its index entry (admin delete does).
