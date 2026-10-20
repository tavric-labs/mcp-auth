package mcpauth

import (
	"strings"
	"testing"
)

var testBinderKey = []byte("0123456789abcdef0123456789abcdef")

func newTestBinder(t *testing.T, key []byte) *SessionBinder {
	t.Helper()
	b, err := NewSessionBinder(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNewSessionBinderRejectsEmptyKey(t *testing.T) {
	for _, key := range [][]byte{nil, {}} {
		if b, err := NewSessionBinder(key); err == nil || b != nil {
			t.Fatalf("empty key accepted: %v %v", b, err)
		}
	}
}

func TestSessionBinderCopiesKey(t *testing.T) {
	key := []byte("0123456789abcdef")
	b := newTestBinder(t, key)
	wrapped := b.Wrap("iss", "alice", "svc", "up")
	for i := range key {
		key[i] = 0
	}
	if _, ok := b.Unwrap("iss", "alice", "svc", wrapped); !ok {
		t.Fatal("mutating caller key changed the binder")
	}
}

func TestSessionBinderUnwrap(t *testing.T) {
	b := newTestBinder(t, testBinderKey)
	wrapped := b.Wrap("iss", "alice", "gitlab", "up.stream-1")
	if wrapped == "" {
		t.Fatal("wrap failed")
	}
	tampered := wrapped[:len(wrapped)-1] + "A"
	if wrapped[len(wrapped)-1] == 'A' {
		tampered = wrapped[:len(wrapped)-1] + "B"
	}
	other := newTestBinder(t, []byte("another-key-another-key-another-k"))
	tests := []struct {
		name                     string
		binder                   *SessionBinder
		iss, sub, svc, presented string
		wantID                   string
		wantOK                   bool
	}{
		{"round trip", b, "iss", "alice", "gitlab", wrapped, "up.stream-1", true},
		{"wrong user", b, "iss", "bob", "gitlab", wrapped, "", false},
		{"wrong service", b, "iss", "alice", "gerrit", wrapped, "", false},
		{"wrong issuer", b, "other", "alice", "gitlab", wrapped, "", false},
		{"tampered tag", b, "iss", "alice", "gitlab", tampered, "", false},
		{"tampered id", b, "iss", "alice", "gitlab", "x" + wrapped, "", false},
		{"different key", other, "iss", "alice", "gitlab", wrapped, "", false},
		{"empty", b, "iss", "alice", "gitlab", "", "", false},
		{"no separator", b, "iss", "alice", "gitlab", "plain", "", false},
		{"empty tag", b, "iss", "alice", "gitlab", "x.", "", false},
		{"empty id", b, "iss", "alice", "gitlab", ".tag", "", false},
		{"extra suffix", b, "iss", "alice", "gitlab", wrapped + "x", "", false},
		{"forged tag", b, "iss", "alice", "gitlab", "up.stream-1.AAAA", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := tc.binder.Unwrap(tc.iss, tc.sub, tc.svc, tc.presented)
			if ok != tc.wantOK || id != tc.wantID {
				t.Fatalf("got (%q, %v), want (%q, %v)", id, ok, tc.wantID, tc.wantOK)
			}
		})
	}
}

func TestSessionBinderWrapRejectsUnusableIDs(t *testing.T) {
	b := newTestBinder(t, testBinderKey)
	tests := map[string]string{
		"empty":     "",
		"space":     "has space",
		"newline":   "bad\nid",
		"nul":       "a\x00b",
		"non-ascii": "café",
		"too long":  strings.Repeat("a", maxUpstreamSessionID+1),
	}
	for name, id := range tests {
		if got := b.Wrap("iss", "a", "s", id); got != "" {
			t.Errorf("%s: wrapped to %q", name, got)
		}
	}
	if b.Wrap("iss", "a", "s", strings.Repeat("a", maxUpstreamSessionID)) == "" {
		t.Error("max length id rejected")
	}
}

// The plugin joined fields with a NUL byte, so identities containing NUL could
// collide. Length-prefixed encoding must keep every split distinct.
func TestSessionBinderTagIsUnambiguous(t *testing.T) {
	b := newTestBinder(t, testBinderKey)
	tests := []struct {
		name string
		a, b [3]string
	}{
		{"adjacent boundary", [3]string{"a", "bc", "svc"}, [3]string{"ab", "c", "svc"}},
		{"subject service boundary", [3]string{"iss", "a", "bc"}, [3]string{"iss", "ab", "c"}},
		{"nul in fields", [3]string{"a\x00b", "c", "svc"}, [3]string{"a", "b\x00c", "svc"}},
		{"empty field shift", [3]string{"", "ab", "svc"}, [3]string{"ab", "", "svc"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if b.tag(tc.a[0], tc.a[1], tc.a[2], "id") == b.tag(tc.b[0], tc.b[1], tc.b[2], "id") {
				t.Fatal("tags collide")
			}
			wrapped := b.Wrap(tc.a[0], tc.a[1], tc.a[2], "id")
			if _, ok := b.Unwrap(tc.b[0], tc.b[1], tc.b[2], wrapped); ok {
				t.Fatal("session id accepted for colliding identity")
			}
		})
	}
	// Moving bytes between the service and the upstream id must not collide.
	if b.tag("i", "s", "ab", "c") == b.tag("i", "s", "a", "bc") {
		t.Fatal("service/id boundary collides")
	}
}
