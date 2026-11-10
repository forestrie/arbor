package univocity

import (
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/forestrie/arbor/services/pkgs/logid"
)

// AuthorityCache holds authority answers that do not need recomputing. A
// final answer is kept for good (protocol ADR-0070 decision 3), unless an
// ancestor that is only pending blocks it: that ancestor can still anchor.
// A conflicted answer is kept outside the size bound, so it is detected and
// alarmed once. An anchored answer that is not yet final is kept until
// recheck. Only a registration on chain can still change it, and the
// LogRegistered watcher evicts it as soon as one is seen: a child's own
// first checkpoint, or for a forest root the first root checkpoint on its
// contract, whichever root that is. Anything else is recomputed on every
// read.
type AuthorityCache struct {
	mu        sync.Mutex
	entries   map[logid.UUID]authorityEntry
	conflicts map[logid.UUID]Authority
	leaves    map[logid.UUID]struct{}
	order     []logid.UUID
	maxSize   int
	recheck   time.Duration
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
		entries:   map[logid.UUID]authorityEntry{},
		conflicts: map[logid.UUID]Authority{},
		leaves:    map[logid.UUID]struct{}{},
		maxSize:   maxSize,
		recheck:   recheck,
	}
}

func (c *AuthorityCache) get(id logid.UUID, now time.Time) (Authority, bool) {
	if c == nil {
		return Authority{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if x, ok := c.conflicts[id]; ok {
		return x, true
	}
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
	if x.State == stateConflicted {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.conflicts[x.LogID] = x
		// Answers that are not final may rest on this log's earlier answer;
		// drop them so its descendants report the conflict at once.
		c.dropLocked(func(_ logid.UUID, e authorityEntry) bool { return !e.x.Final })
		return
	}
	var until time.Time
	switch {
	case !x.BlockedBy.IsZero() && !x.blockedByConflict:
		return
	case x.Final:
	case x.State == stateAnchored:
		until = now.Add(c.recheck)
	default:
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	old, exists := c.entries[x.LogID]
	if exists && old.x.Final && !x.Final {
		// A read that saw the chain a moment before the final answer must
		// not replace it: a final answer never changes.
		return
	}
	if !exists {
		c.order = append(c.order, x.LogID)
	}
	c.entries[x.LogID] = authorityEntry{x: x, until: until}
	for len(c.entries) > c.maxSize && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
}

// evict drops a log's answer that is not final, so the next read
// recomputes it. A final answer never changes.
func (c *AuthorityCache) evict(id logid.UUID) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dropLocked(func(k logid.UUID, e authorityEntry) bool { return k == id && !e.x.Final })
}

// evictPendingRoots drops the answers, not yet final, of the forest roots
// bound to a contract. A contract takes one root, the first to publish
// there, so a root registration on it settles every such root: the one
// registered turns final, and any other turns conflicted.
func (c *AuthorityCache) evictPendingRoots(chainID uint64, contract common.Address) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dropLocked(func(k logid.UUID, e authorityEntry) bool {
		return !e.x.Final && k == e.x.RootLogID &&
			e.x.ChainID == chainID && e.x.Contract == contract
	})
}

// dropLocked removes the answers drop selects, from the entries and from
// the eviction order alike, so that order holds each cached log once.
func (c *AuthorityCache) dropLocked(drop func(logid.UUID, authorityEntry) bool) {
	kept := c.order[:0]
	for _, id := range c.order {
		if e, ok := c.entries[id]; ok && drop(id, e) {
			delete(c.entries, id)
			continue
		}
		kept = append(kept, id)
	}
	c.order = kept
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
