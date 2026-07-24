package merklelog

import (
	"github.com/forestrie/go-merklelog/massifs"
	massifstorage "github.com/forestrie/go-merklelog/massifs/storage"
)

// Cache policy for published log objects (FOR-302, ADR-0057).
//
// Log objects are served to verifiers from a CDN-fronted object store, so they
// are cached. Which of them may be cached is not a matter of taste: a massif is
// overwritten in place on every commit until it is full, and frozen forever
// once it is. Publishing both states without cache directives leaves the edge
// to guess, and the guess is wrong in both directions:
//
//   - a cached 404 outlives the write that would have satisfied it, so a
//     just-written massif reads as absent long after it exists (the FOR-302
//     lane-B `massifs tile not yet available: HTTP 404` failures);
//   - a cached *partial* massif is worse because it is silent — a verifier
//     receives a short tile that does not cover its entry and concludes the
//     entry is not yet sealed.
//
// Completeness is decidable at write time and needs no checkpoint, no registry
// and no coordination: the massif height is fixed for a log (and carried in the
// object path), so a massif is complete exactly when it holds TreeCount(height)
// log entries. The write that fills it is therefore the write that may declare
// it immutable — there is no rollover restamping pass.
//
// Checkpoints are deliberately never cached. Sealing runs continuously at the
// head, so a checkpoint attests only up to its own tree size; its existence
// says nothing about whether the massif it names is frozen, and a checkpoint
// object is superseded repeatedly while its massif stays open. Deciding when a
// `.sth` has become terminal requires reading the massif it refers to, and the
// objects are a few hundred bytes against multi-megabyte massifs — there is no
// caching benefit worth that correctness risk.
const (
	// CacheControlImmutable is applied to a massif that can never legitimately
	// change again. The long max-age is the point: independently retained
	// copies of the original bytes make a retroactive rewrite at origin harder
	// to hide, which complements rather than competes with the on-chain
	// checkpoint. The accepted cost is that a published complete massif cannot
	// be corrected — that is the intended semantics of an append-only log.
	CacheControlImmutable = "public, max-age=31536000, immutable"

	// CacheControlNoStore is applied to every object that may still change:
	// the head massif and all checkpoints.
	CacheControlNoStore = "no-store"
)

// MassifDataComplete reports whether a massif payload holds a full tree for its
// height, i.e. no further entry can be appended to it.
//
// A short or malformed payload reports false: an object we cannot prove is
// complete must not be published as immutable.
func MassifDataComplete(data []byte, massifHeight uint8) bool {
	entries, err := massifs.MassifLogEntries(len(data), massifHeight)
	if err != nil {
		return false
	}
	return entries >= massifs.TreeCount(massifHeight)
}

// CacheControlForObject returns the Cache-Control directive to publish an
// object with. Anything not provably immutable is no-store.
//
// ObjectMassifStart resolves to the SAME object key as ObjectMassifData
// (massifs/storage.ObjectPath falls through), and is always no-store here
// because a start-header payload is shorter than the peak-stack end, so
// completeness cannot be proven from it. Writing a start header over a
// completed massif would therefore downgrade it from immutable — the safe
// direction (coverage is lost, stale bytes are never served), and such a write
// would be a larger problem than its cache policy in any case.
func CacheControlForObject(ty massifstorage.ObjectType, data []byte, massifHeight uint8) string {
	if ty == massifstorage.ObjectMassifData && MassifDataComplete(data, massifHeight) {
		return CacheControlImmutable
	}
	return CacheControlNoStore
}
