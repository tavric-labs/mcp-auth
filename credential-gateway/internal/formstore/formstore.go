// Package formstore keeps header values that a person submitted at sign-in.
//
// Values live only in process memory, are bounded in count and lifetime, and
// are never logged. The store plays both roles the credential service expects
// of a vault, a mapping store and a resolver, so the per-request path that
// injects headers is the same for submitted values and for vault values.
package formstore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"sync"
	"time"

	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/mappings"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/secrets"
)

// RefPrefix marks a reference that this store resolves.
const RefPrefix = "form:"

type key struct{ issuer, subject, service string }

type item struct {
	key     key
	handle  string
	values  map[string]string
	expires time.Time
	created time.Time
}

// Store holds submitted values by (issuer, subject, service).
type Store struct {
	TTL time.Duration
	Max int
	Now func() time.Time

	mu       sync.Mutex
	items    map[key]*item
	byHandle map[string]*item
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// NewSubject returns an unguessable subject suffix for one sign-in.
func NewSubject() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Put stores a copy of values, replacing any earlier entry for the identity.
func (s *Store) Put(issuer, subject, service string, values map[string]string) error {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	copied := make(map[string]string, len(values))
	for name, value := range values {
		copied[name] = value
	}
	now := s.now()
	k := key{issuer, subject, service}
	entry := &item{key: k, handle: base64.RawURLEncoding.EncodeToString(raw), values: copied, expires: now.Add(s.TTL), created: now}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items == nil {
		s.items, s.byHandle = map[key]*item{}, map[string]*item{}
	}
	s.sweepLocked(now)
	if old, ok := s.items[k]; ok {
		delete(s.byHandle, old.handle)
	}
	s.items[k], s.byHandle[entry.handle] = entry, entry
	limit := s.Max
	if limit < 1 {
		limit = 1
	}
	for len(s.items) > limit {
		var oldest *item
		for _, candidate := range s.items {
			if oldest == nil || candidate.created.Before(oldest.created) {
				oldest = candidate
			}
		}
		s.removeLocked(oldest)
	}
	return nil
}

// Delete forgets the values for an identity and service.
func (s *Store) Delete(issuer, subject, service string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.items[key{issuer, subject, service}]; ok {
		s.removeLocked(entry)
	}
}

// Len reports the number of stored entries, expired ones included until swept.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

func (s *Store) removeLocked(entry *item) {
	delete(s.items, entry.key)
	delete(s.byHandle, entry.handle)
}

func (s *Store) sweepLocked(now time.Time) {
	for _, entry := range s.items {
		if !entry.expires.After(now) {
			s.removeLocked(entry)
		}
	}
}

// Lookup implements mappings.Store. It returns (nil, nil) when nothing live is
// stored. The mapping version is the entry's handle, so a new sign-in never
// reuses a cached result from an earlier one.
func (s *Store) Lookup(issuer, subject, service string) (*mappings.Mapping, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.items[key{issuer, subject, service}]
	if !ok {
		return nil, nil
	}
	if !entry.expires.After(s.now()) {
		s.removeLocked(entry)
		return nil, nil
	}
	refs := make(map[string]string, len(entry.values))
	for field := range entry.values {
		refs[field] = RefPrefix + entry.handle + "/" + field
	}
	return &mappings.Mapping{Issuer: issuer, Subject: subject, Service: service, Refs: refs, Version: entry.handle}, nil
}

// Resolve implements the read half of secrets.Resolver for form references.
func (s *Store) Resolve(_ context.Context, refs map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(refs))
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for field, ref := range refs {
		rest, ok := strings.CutPrefix(ref, RefPrefix)
		if !ok {
			return nil, secrets.ErrFieldUnavailable
		}
		handle, name, ok := strings.Cut(rest, "/")
		entry := s.byHandle[handle]
		if !ok || entry == nil || name != field || !entry.expires.After(now) {
			return nil, secrets.ErrFieldUnavailable
		}
		value, present := entry.values[name]
		if !present {
			return nil, secrets.ErrFieldUnavailable
		}
		out[field] = value
	}
	return out, nil
}

// Ready reports that the store is usable.
func (s *Store) Ready() bool { return true }
