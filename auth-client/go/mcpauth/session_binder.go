package mcpauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

const (
	maxUpstreamSessionID = 512
	sessionTagBytes      = 24
	sessionTagDomain     = "mcpauth.session-binder.v1"
)

// SessionBinder ties an upstream MCP session id to the verified identity
// (issuer, subject) and the service it was issued for.
//
// Wrap returns "<upstream-id>.<tag>", where tag is an HMAC-SHA256 over the
// issuer, subject, service and upstream id under a deployment secret. Unwrap
// accepts a presented id only when its tag verifies for the caller's own
// identity and service, so a session id cannot be replayed by another user or
// against another service. The binding is stateless: it survives restarts and
// works across replicas that share the key. A SessionBinder is safe for
// concurrent use.
type SessionBinder struct{ key []byte }

// NewSessionBinder returns a SessionBinder that authenticates with key. It
// returns an error when key is empty. The key is copied.
func NewSessionBinder(key []byte) (*SessionBinder, error) {
	if len(key) == 0 {
		return nil, errors.New("mcpauth: session binder key must not be empty")
	}
	return &SessionBinder{key: append([]byte(nil), key...)}, nil
}

// tag computes the HMAC tag. Every field is length-prefixed so the encoding is
// unambiguous: ("a","bc") and ("ab","c") produce different MAC inputs, as do
// fields that themselves contain any separator byte.
func (b *SessionBinder) tag(issuer, subject, service, id string) string {
	mac := hmac.New(sha256.New, b.key)
	mac.Write([]byte(sessionTagDomain))
	var n [8]byte
	for _, field := range [...]string{issuer, subject, service, id} {
		binary.BigEndian.PutUint64(n[:], uint64(len(field)))
		mac.Write(n[:])
		mac.Write([]byte(field))
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:sessionTagBytes])
}

// Wrap returns the session id to give the client, or "" when upstreamID is
// unusable (empty, longer than 512 bytes, or containing anything other than
// printable ASCII without spaces).
func (b *SessionBinder) Wrap(issuer, subject, service, upstreamID string) string {
	if upstreamID == "" || len(upstreamID) > maxUpstreamSessionID {
		return ""
	}
	for i := 0; i < len(upstreamID); i++ {
		if upstreamID[i] < 0x21 || upstreamID[i] > 0x7E {
			return ""
		}
	}
	return upstreamID + "." + b.tag(issuer, subject, service, upstreamID)
}

// Unwrap returns the upstream session id when presented was issued by Wrap for
// exactly this issuer, subject and service, and reports whether it did. The tag
// is compared in constant time.
func (b *SessionBinder) Unwrap(issuer, subject, service, presented string) (string, bool) {
	i := strings.LastIndexByte(presented, '.')
	if i <= 0 || i == len(presented)-1 {
		return "", false
	}
	id, tag := presented[:i], presented[i+1:]
	if hmac.Equal([]byte(tag), []byte(b.tag(issuer, subject, service, id))) {
		return id, true
	}
	return "", false
}
