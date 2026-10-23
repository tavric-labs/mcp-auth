package formstore

import (
	"context"
	"strings"
	"testing"
	"time"
)

func newStore(now *time.Time) *Store {
	return &Store{TTL: time.Minute, Max: 2, Now: func() time.Time { return *now }}
}

func TestLookupAndResolveReturnSubmittedValues(t *testing.T) {
	now := time.Now()
	s := newStore(&now)
	if err := s.Put("iss", "form-a:u1", "svc", map[string]string{"username": "alice", "token": "glpat-x"}); err != nil {
		t.Fatal(err)
	}
	m, err := s.Lookup("iss", "form-a:u1", "svc")
	if err != nil || m == nil {
		t.Fatalf("lookup = %v, %v", m, err)
	}
	got, err := s.Resolve(context.Background(), m.Refs)
	if err != nil || got["username"] != "alice" || got["token"] != "glpat-x" {
		t.Fatalf("resolve = %v, %v", got, err)
	}
	for _, ref := range m.Refs {
		if strings.Contains(ref, "alice") || strings.Contains(ref, "glpat-x") {
			t.Fatal("a reference exposes a value")
		}
	}
}

func TestEntriesAreScopedToIdentityAndService(t *testing.T) {
	now := time.Now()
	s := newStore(&now)
	s.Put("iss", "u1", "svc", map[string]string{"token": "one"})
	for name, args := range map[string][3]string{
		"other subject": {"iss", "u2", "svc"}, "other service": {"iss", "u1", "other"}, "other issuer": {"x", "u1", "svc"},
	} {
		if m, _ := s.Lookup(args[0], args[1], args[2]); m != nil {
			t.Errorf("%s found the entry", name)
		}
	}
}

func TestResolveRejectsForeignAndMismatchedReferences(t *testing.T) {
	now := time.Now()
	s := newStore(&now)
	s.Put("iss", "u1", "svc", map[string]string{"token": "one"})
	m, _ := s.Lookup("iss", "u1", "svc")
	handleRef := m.Refs["token"]
	for name, refs := range map[string]map[string]string{
		"vault ref":       {"token": "op://vault/item/token"},
		"wrong field":     {"username": handleRef},
		"unknown handle":  {"token": RefPrefix + "nope/token"},
		"no field in ref": {"token": RefPrefix + strings.Split(strings.TrimPrefix(handleRef, RefPrefix), "/")[0]},
	} {
		if _, err := s.Resolve(context.Background(), refs); err == nil {
			t.Errorf("resolved %s", name)
		}
	}
}

func TestExpiryDeleteAndReplacementInvalidateReferences(t *testing.T) {
	now := time.Now()
	s := newStore(&now)
	s.Put("iss", "u1", "svc", map[string]string{"token": "one"})
	old, _ := s.Lookup("iss", "u1", "svc")
	s.Put("iss", "u1", "svc", map[string]string{"token": "two"})
	if _, err := s.Resolve(context.Background(), old.Refs); err == nil {
		t.Fatal("a replaced entry's old reference still resolves")
	}
	fresh, _ := s.Lookup("iss", "u1", "svc")
	if fresh.Version == old.Version {
		t.Fatal("a new sign-in reused the cache version")
	}
	s.Delete("iss", "u1", "svc")
	if m, _ := s.Lookup("iss", "u1", "svc"); m != nil {
		t.Fatal("deleted entry still found")
	}
	s.Put("iss", "u1", "svc", map[string]string{"token": "three"})
	live, _ := s.Lookup("iss", "u1", "svc")
	now = now.Add(2 * time.Minute)
	if m, _ := s.Lookup("iss", "u1", "svc"); m != nil {
		t.Fatal("expired entry still found")
	}
	if _, err := s.Resolve(context.Background(), live.Refs); err == nil {
		t.Fatal("expired reference still resolves")
	}
}

func TestCapEvictsTheOldestEntry(t *testing.T) {
	now := time.Now()
	s := newStore(&now)
	for i, subject := range []string{"u1", "u2", "u3"} {
		now = now.Add(time.Second)
		s.Put("iss", subject, "svc", map[string]string{"token": string(rune('a' + i))})
	}
	if s.Len() != 2 {
		t.Fatalf("len = %d, want the cap of 2", s.Len())
	}
	if m, _ := s.Lookup("iss", "u1", "svc"); m != nil {
		t.Fatal("the oldest entry was kept")
	}
}

func TestStoredValuesAreCopied(t *testing.T) {
	now := time.Now()
	s := newStore(&now)
	values := map[string]string{"token": "one"}
	s.Put("iss", "u1", "svc", values)
	values["token"] = "changed"
	m, _ := s.Lookup("iss", "u1", "svc")
	got, _ := s.Resolve(context.Background(), m.Refs)
	if got["token"] != "one" {
		t.Fatal("the store aliases the caller's map")
	}
}

func TestNewSubjectIsUnique(t *testing.T) {
	a, _ := NewSubject()
	b, _ := NewSubject()
	if a == "" || a == b || len(a) < 32 {
		t.Fatalf("subjects %q %q are not unguessable and unique", a, b)
	}
}
