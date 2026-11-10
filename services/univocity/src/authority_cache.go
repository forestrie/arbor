package univocity

import (
	"sync"
	"time"

	"github.com/forestrie/arbor/services/pkgs/logid"
)

// AuthorityCache holds authority answers that do not need recomputing. A
// final answer is kept for good (protocol ADR-0070 decision 3). An anchored
// answer that is not yet final is kept until recheck: anchoring is
// permanent, so only the log's first checkpoint can still change it, and
// the LogRegistered watcher evicts it as soon as that happens. Anything
// else is recomputed on every read.
type AuthorityCache struct {
	mu      sync.Mutex
	entries map[logid.UUID]authorityEntry
	leaves  map[logid.UUID]struct{}
	order   []logid.UUID
	maxSize int
	recheck time.Duration
}

type authorityEntry struct {
	x     Authority
	until time.Time // zero: kept for good
}

// NewAuthorityCache bounds the cache at maxSize answers and re-checks an
// anchored answer that is not final after recheck.
func NewAuthorityCache(maxSize int, recheck time.Duration) *AuthorityCache {
	if maxSize < 1 {
		maxSize = 1
	}
	return &AuthorityCache{
		entries: map[logid.UUID]authorityEntry{},
		leaves:  map[logid.UUID]struct{}{},
		maxSize: maxSize,
		recheck: recheck,
	}
}

func (c *AuthorityCache) get(id logid.UUID, now time.Time) (Authority, bool) {
	if c == nil {
		return Authority{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	if !ok || (!e.until.IsZero() && !now.Before(e.until)) {
		return Authority{}, false
	}
	return e.x, true
}

func (c *AuthorityCache) put(x Authority, now time.Time) {
	if c == nil {
		return
	}
	var until time.Time
	switch {
	case x.Final:
	case x.State == stateAnchored:
		until = now.Add(c.recheck)
	default:
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[x.LogID]; !exists {
		c.order = append(c.order, x.LogID)
	}
	c.entries[x.LogID] = authorityEntry{x: x, until: until}
	for len(c.entries) > c.maxSize && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
}

// evict drops a log's answer so the next read recomputes it.
func (c *AuthorityCache) evict(id logid.UUID) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, id)
}

// leafAnchored reports whether a published checkpoint of the owner has been
// proved to cover the log's create grant. That never changes.
func (c *AuthorityCache) leafAnchored(id logid.UUID) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.leaves[id]
	return ok
}

func (c *AuthorityCache) markLeafAnchored(id logid.UUID) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.leaves[id] = struct{}{}
}
