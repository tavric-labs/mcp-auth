package mcpauth

import (
	"container/list"
	"sync"
	"time"
)

// SessionKey identifies a cache entry. Entries are never shared across
// different values of any field.
type SessionKey struct {
	// Issuer is the verified token issuer.
	Issuer string
	// Subject is the verified token subject.
	Subject string
	// Service is the downstream service the value is for.
	Service string
	// Version is the version of the mapping or configuration the value was
	// derived from; changing it invalidates earlier entries.
	Version string
}

type sessionEntry[V any] struct {
	key     SessionKey
	value   V
	expires time.Time
}

// SessionBoundCache is a bounded LRU cache whose entries are keyed by
// SessionKey and never outlive the login session that produced them.
//
// It should be consulted only after the request has been authorised, so a hit
// cannot bypass a revocation check. Expired entries are never returned. A
// SessionBoundCache is safe for concurrent use.
type SessionBoundCache[V any] struct {
	mu     sync.Mutex
	max    int
	maxTTL time.Duration
	now    func() time.Time
	items  map[SessionKey]*list.Element
	order  *list.List
}

// NewSessionBoundCache returns a cache holding at most maxEntries entries
// (minimum 1). When maxTTL is positive it also caps the lifetime of every
// entry, measured from the time of Put.
func NewSessionBoundCache[V any](maxEntries int, maxTTL time.Duration) *SessionBoundCache[V] {
	if maxEntries < 1 {
		maxEntries = 1
	}
	return &SessionBoundCache[V]{
		max:    maxEntries,
		maxTTL: maxTTL,
		now:    time.Now,
		items:  map[SessionKey]*list.Element{},
		order:  list.New(),
	}
}

// Get returns the value stored for key if it has not expired at now. An entry
// whose expiry is not after now is removed and not returned.
func (c *SessionBoundCache[V]) Get(key SessionKey, now time.Time) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var zero V
	element, ok := c.items[key]
	if !ok {
		return zero, false
	}
	e := element.Value.(*sessionEntry[V])
	if !e.expires.After(now) {
		c.remove(element)
		return zero, false
	}
	c.order.MoveToFront(element)
	return e.value, true
}

// Put stores v for key until expires, which should be the login session
// expiry. The lifetime is further capped by the cache's maxTTL. A value that
// would already be expired is not stored, and any older entry for key is
// removed. When the cache is full the least recently used entry is evicted.
func (c *SessionBoundCache[V]) Put(key SessionKey, v V, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.maxTTL > 0 {
		if limit := now.Add(c.maxTTL); limit.Before(expires) {
			expires = limit
		}
	}
	element, exists := c.items[key]
	if !expires.After(now) {
		if exists {
			c.remove(element)
		}
		return
	}
	entry := &sessionEntry[V]{key: key, value: v, expires: expires}
	if exists {
		element.Value = entry
		c.order.MoveToFront(element)
	} else {
		c.items[key] = c.order.PushFront(entry)
	}
	for len(c.items) > c.max {
		c.remove(c.order.Back())
	}
}

// Len reports the number of entries currently held, including any that have
// expired but not yet been read.
func (c *SessionBoundCache[V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

func (c *SessionBoundCache[V]) remove(element *list.Element) {
	delete(c.items, element.Value.(*sessionEntry[V]).key)
	c.order.Remove(element)
}
