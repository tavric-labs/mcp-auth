package mcpauth

import (
	"sync"
	"testing"
	"time"
)

var cacheT0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func newTestCache(max int, ttl time.Duration, now time.Time) *SessionBoundCache[string] {
	c := NewSessionBoundCache[string](max, ttl)
	c.now = func() time.Time { return now }
	return c
}

func TestSessionBoundCacheExpiry(t *testing.T) {
	key := SessionKey{"iss", "alice", "svc", "v1"}
	expires := cacheT0.Add(time.Minute)
	tests := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"before expiry", expires.Add(-time.Nanosecond), true},
		{"at expiry", expires, false},
		{"after expiry", expires.Add(time.Second), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestCache(4, time.Hour, cacheT0)
			c.Put(key, "secret", expires)
			v, ok := c.Get(key, tc.at)
			if ok != tc.want || (ok && v != "secret") || (!ok && v != "") {
				t.Fatalf("got (%q, %v), want ok=%v", v, ok, tc.want)
			}
			if !tc.want && c.Len() != 0 {
				t.Fatal("expired entry not removed")
			}
		})
	}
}

func TestSessionBoundCacheLifetimeBounds(t *testing.T) {
	key := SessionKey{"iss", "alice", "svc", "v1"}
	tests := []struct {
		name    string
		maxTTL  time.Duration
		expires time.Time
		at      time.Time
		want    bool
	}{
		{"session expiry shorter than ttl", time.Hour, cacheT0.Add(time.Minute), cacheT0.Add(2 * time.Minute), false},
		{"ttl shorter than session expiry", time.Minute, cacheT0.Add(time.Hour), cacheT0.Add(2 * time.Minute), false},
		{"ttl shorter, still fresh", time.Minute, cacheT0.Add(time.Hour), cacheT0.Add(30 * time.Second), true},
		{"no ttl cap uses session expiry", 0, cacheT0.Add(time.Hour), cacheT0.Add(30 * time.Minute), true},
		{"already expired session not stored", time.Hour, cacheT0, cacheT0.Add(-time.Second), false},
		{"past session not stored", time.Hour, cacheT0.Add(-time.Minute), cacheT0.Add(-time.Second), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestCache(4, tc.maxTTL, cacheT0)
			c.Put(key, "v", tc.expires)
			if _, ok := c.Get(key, tc.at); ok != tc.want {
				t.Fatalf("got %v want %v", ok, tc.want)
			}
		})
	}
}

func TestSessionBoundCachePutExpiredRemovesOlderEntry(t *testing.T) {
	key := SessionKey{"iss", "alice", "svc", "v1"}
	c := newTestCache(4, time.Hour, cacheT0)
	c.Put(key, "old", cacheT0.Add(time.Hour))
	c.Put(key, "new", cacheT0)
	if _, ok := c.Get(key, cacheT0.Add(-time.Hour)); ok || c.Len() != 0 {
		t.Fatal("stale entry survived an expired Put")
	}
}

func TestSessionBoundCacheIsolation(t *testing.T) {
	base := SessionKey{"iss", "alice", "svc", "v1"}
	c := newTestCache(16, time.Hour, cacheT0)
	c.Put(base, "alice-v1", cacheT0.Add(time.Hour))
	tests := []struct {
		name string
		key  SessionKey
	}{
		{"other version", SessionKey{"iss", "alice", "svc", "v2"}},
		{"other user", SessionKey{"iss", "bob", "svc", "v1"}},
		{"other service", SessionKey{"iss", "alice", "other", "v1"}},
		{"other issuer", SessionKey{"other", "alice", "svc", "v1"}},
		{"shifted fields", SessionKey{"iss", "alic", "esvc", "v1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if v, ok := c.Get(tc.key, cacheT0); ok {
				t.Fatalf("shared entry %q", v)
			}
		})
	}
	v2 := SessionKey{"iss", "alice", "svc", "v2"}
	c.Put(v2, "alice-v2", cacheT0.Add(time.Hour))
	if v, _ := c.Get(base, cacheT0); v != "alice-v1" {
		t.Fatalf("v1 overwritten: %q", v)
	}
	if v, _ := c.Get(v2, cacheT0); v != "alice-v2" {
		t.Fatalf("v2 missing: %q", v)
	}
}

func TestSessionBoundCacheSizeCapEvictsLRU(t *testing.T) {
	k := func(s string) SessionKey { return SessionKey{"iss", s, "svc", "v1"} }
	exp := cacheT0.Add(time.Hour)
	tests := []struct {
		name    string
		max     int
		wantLen int
	}{
		{"cap 2", 2, 2},
		{"cap below one is one", 0, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestCache(tc.max, time.Hour, cacheT0)
			c.Put(k("a"), "a", exp)
			c.Put(k("b"), "b", exp)
			if tc.max == 2 {
				c.Get(k("a"), cacheT0) // a becomes most recent
			}
			c.Put(k("c"), "c", exp)
			if c.Len() != tc.wantLen {
				t.Fatalf("len %d want %d", c.Len(), tc.wantLen)
			}
			if _, ok := c.Get(k("c"), cacheT0); !ok {
				t.Fatal("newest entry evicted")
			}
			if tc.max == 2 {
				if _, ok := c.Get(k("b"), cacheT0); ok {
					t.Fatal("least recently used entry kept")
				}
				if _, ok := c.Get(k("a"), cacheT0); !ok {
					t.Fatal("recently used entry evicted")
				}
			}
		})
	}
}

func TestSessionBoundCacheOverwriteAndConcurrency(t *testing.T) {
	key := SessionKey{"iss", "alice", "svc", "v1"}
	c := newTestCache(2, time.Hour, cacheT0)
	c.Put(key, "one", cacheT0.Add(time.Hour))
	c.Put(key, "two", cacheT0.Add(time.Hour))
	if v, _ := c.Get(key, cacheT0); v != "two" || c.Len() != 1 {
		t.Fatalf("overwrite failed: %q len %d", v, c.Len())
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k := SessionKey{"iss", string(rune('a' + i)), "svc", "v1"}
			for j := 0; j < 100; j++ {
				c.Put(k, "x", cacheT0.Add(time.Hour))
				c.Get(k, cacheT0)
			}
		}(i)
	}
	wg.Wait()
	if c.Len() > 2 {
		t.Fatalf("cap exceeded: %d", c.Len())
	}
}
