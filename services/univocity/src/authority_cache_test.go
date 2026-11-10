package univocity

import (
	"testing"
	"time"
)

// The cache evicts its oldest answer when full. A log whose answer was
// dropped and cached again is new, not old.
func TestAuthorityCache_EvictsTheOldestAnswer(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := NewAuthorityCache(2, 5*time.Minute)
	A, B, C := testLogID(1), testLogID(2), testLogID(3)
	anchored := func(id [16]byte) Authority { return Authority{LogID: id, State: stateAnchored} }

	c.put(anchored(A), now)
	c.evict(A)
	c.put(anchored(B), now)
	c.put(anchored(A), now)
	c.put(anchored(C), now) // full: B is the oldest

	if _, ok := c.get(A, now); !ok {
		t.Fatal("A, cached after B, was evicted before it")
	}
	if _, ok := c.get(B, now); ok {
		t.Fatal("B, the oldest answer, was kept")
	}
}

// A final answer never changes, so an answer computed alongside it that is
// not yet final (a read that saw the chain a moment earlier) must not
// replace it.
func TestAuthorityCache_KeepsAFinalAnswer(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := NewAuthorityCache(10, 5*time.Minute)
	R := testLogID(1)

	c.put(Authority{LogID: R, RootLogID: R, State: stateAnchored, Final: true}, now)
	c.put(Authority{LogID: R, RootLogID: R, State: stateAnchored}, now)

	x, ok := c.get(R, now.Add(time.Hour))
	if !ok || !x.Final {
		t.Fatalf("final answer was replaced: %+v, cached %v", x, ok)
	}
}
