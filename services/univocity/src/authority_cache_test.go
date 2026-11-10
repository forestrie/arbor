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
