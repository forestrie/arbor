package univocity

import (
	"sync"
	"time"
)

type forestCacheEntry struct {
	entry   ForestEntry
	expires time.Time
}

// forestLRUCache maps logId hex -> forest with optional negative TTL.
type forestLRUCache struct {
	mu       sync.Mutex
	positive map[string]ForestEntry
	negative map[string]time.Time
	maxSize  int
	negTTL   time.Duration
	order    []string
}

func newForestLRUCache(maxSize int, negTTL time.Duration) *forestLRUCache {
	if maxSize < 1 {
		maxSize = 1
	}
	return &forestLRUCache{
		positive: make(map[string]ForestEntry),
		negative: make(map[string]time.Time),
		maxSize:  maxSize,
		negTTL:   negTTL,
	}
}

func (c *forestLRUCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.positive = make(map[string]ForestEntry)
	c.order = nil
}

func (c *forestLRUCache) Get(logID [32]byte) (ForestEntry, bool, bool) {
	key := logIDHexKey(logID)
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.negative[key]; ok {
		if time.Now().Before(exp) {
			return ForestEntry{}, false, true
		}
		delete(c.negative, key)
	}
	e, ok := c.positive[key]
	return e, ok, false
}

func (c *forestLRUCache) PutPositive(logID [32]byte, e ForestEntry) {
	key := logIDHexKey(logID)
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.negative, key)
	if _, exists := c.positive[key]; !exists {
		c.order = append(c.order, key)
	}
	c.positive[key] = e
	for len(c.order) > c.maxSize {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.positive, oldest)
	}
}

func (c *forestLRUCache) PutNegative(logID [32]byte) {
	key := logIDHexKey(logID)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.negative[key] = time.Now().Add(c.negTTL)
}
