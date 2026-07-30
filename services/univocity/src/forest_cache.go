package univocity

import (
	"sync"
	"time"

	"github.com/forestrie/arbor/services/pkgs/logid"
)

// ForestCache maps logId uuid string -> forest with optional negative TTL.
// Positive entries are written only after an existence check has passed
// (index+genesis, R-case genesis, or hint+grant — plan-2607-10 slice 02);
// negative entries bound repeated lookups of unknown logIds.
type ForestCache struct {
	mu       sync.Mutex
	positive map[string]ForestEntry
	negative map[string]time.Time
	maxSize  int
	negTTL   time.Duration
	order    []string
}

// NewForestCache builds a bounded resolution cache with a negative-entry TTL.
func NewForestCache(maxSize int, negTTL time.Duration) *ForestCache {
	if maxSize < 1 {
		maxSize = 1
	}
	return &ForestCache{
		positive: make(map[string]ForestEntry),
		negative: make(map[string]time.Time),
		maxSize:  maxSize,
		negTTL:   negTTL,
	}
}

func (c *ForestCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.positive = make(map[string]ForestEntry)
	c.order = nil
}

func (c *ForestCache) Get(logID logid.UUID) (ForestEntry, bool, bool) {
	key := logID.String()
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

func (c *ForestCache) PutPositive(logID logid.UUID, e ForestEntry) {
	key := logID.String()
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

func (c *ForestCache) PutNegative(logID logid.UUID) {
	key := logID.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.negative[key] = time.Now().Add(c.negTTL)
}
