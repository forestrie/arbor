package custodian

import (
	"container/list"
	"sync"
)

// logIDKeyLRU is a bounded LRU of logId -> custodian keyId (in-memory).
type logIDKeyLRU struct {
	mu       sync.Mutex
	capacity int
	byKey    map[string]*list.Element
	order    *list.List
}

type logIDLRUEntry struct {
	logID string
	keyID string
}

func newLogIDKeyLRU(capacity int) *logIDKeyLRU {
	if capacity <= 0 {
		return nil
	}
	return &logIDKeyLRU{
		capacity: capacity,
		byKey:    make(map[string]*list.Element),
		order:    list.New(),
	}
}

func (c *logIDKeyLRU) Get(logID string) (keyID string, hit bool) {
	if c == nil || logID == "" {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.byKey[logID]; ok {
		c.order.MoveToFront(el)
		return el.Value.(*logIDLRUEntry).keyID, true
	}
	return "", false
}

func (c *logIDKeyLRU) Put(logID, keyID string) {
	if c == nil || logID == "" || keyID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.byKey[logID]; ok {
		el.Value.(*logIDLRUEntry).keyID = keyID
		c.order.MoveToFront(el)
		return
	}
	ent := &logIDLRUEntry{logID: logID, keyID: keyID}
	el := c.order.PushFront(ent)
	c.byKey[logID] = el
	for c.capacity > 0 && c.order.Len() > c.capacity {
		back := c.order.Back()
		old := back.Value.(*logIDLRUEntry)
		delete(c.byKey, old.logID)
		c.order.Remove(back)
	}
}
