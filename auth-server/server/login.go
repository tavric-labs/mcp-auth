package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// A login method is one way a person proves who they are before mcp-auth
// issues an MCP token. A deployment enables several at once; the person picks
// one on the login page. Methods come in two shapes:
//
//   - RedirectLoginMethod: the browser leaves for an upstream provider (OIDC,
//     Google, GitHub) and returns to /identity/callback with a code.
//   - CredentialLoginMethod: the person types credentials into a page this
//     server renders (LDAP), and the method checks them directly.
//
// mcp-auth stays a broker. A method establishes who the person is; it never
// hands upstream credentials to the MCP client, and the core server never
// imports a provider-specific SDK outside the method's own file.

// LoginMethod is the part every login method shares.
type LoginMethod interface {
	// ID is the stable, URL-safe name used in the login form action and in the
	// upstream state. It must match loginMethodIDPattern.
	ID() string
	// Label is the button or heading text shown to the person.
	Label() string
}

// RedirectLoginMethod signs a person in through an upstream provider's own
// login page. It mirrors InteractiveIdentityProvider so an existing provider
// adapts without change.
type RedirectLoginMethod interface {
	LoginMethod
	Begin(ctx context.Context, request IdentityRequest, state string) (location, codeVerifier string, err error)
	Complete(ctx context.Context, callback IdentityCallback) (Identity, error)
}

// LoginField describes one input of a credential login form.
type LoginField struct {
	Name   string
	Label  string
	Secret bool
}

// LoginAttempt carries the submitted form values to a CredentialLoginMethod.
type LoginAttempt struct {
	// Values holds one entry per LoginField, keyed by field name.
	Values map[string]string
	// RemoteAddr is the host of the connecting peer, for the method's own
	// diagnostics. It is not a trusted client address behind a proxy.
	RemoteAddr string
}

// CredentialLoginMethod signs a person in by checking credentials typed into
// the login page.
type CredentialLoginMethod interface {
	LoginMethod
	// Fields lists the form inputs. The first non-secret field is the account
	// name that failed-attempt throttling is keyed on.
	Fields() []LoginField
	// Authenticate verifies the attempt. It returns ErrInvalidCredentials
	// (possibly wrapped) when the credentials are wrong or the account is
	// unknown, so the response never distinguishes the two. Any other error
	// means the method itself failed, such as an unreachable directory.
	Authenticate(ctx context.Context, request IdentityRequest, attempt LoginAttempt) (Identity, error)
}

// ErrInvalidCredentials is the one answer a CredentialLoginMethod gives for a
// wrong password or an unknown account.
var ErrInvalidCredentials = errors.New("invalid credentials")

// loginMethodIDPattern keeps ids safe in a URL path segment and free of the
// "." that separates the id from the random part of the upstream state.
var loginMethodIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// LoginEntry registers one method.
type LoginEntry struct {
	Method LoginMethod
	// SubjectPrefix is prepended to the subject the method returns. Methods
	// have independent identifier spaces (a Google sub, a GitHub id and an LDAP
	// uid can be equal strings), so without a prefix two people could share an
	// access-token subject. The loader defaults it to "<id>:".
	SubjectPrefix string
}

// LoginRegistry is the set of enabled login methods. It also implements
// IdentityProvider so it can be passed to NewServer; the server then runs the
// login page flow instead of a single upstream redirect.
type LoginRegistry struct {
	entries []LoginEntry
	byID    map[string]LoginEntry
	limiter *loginLimiter
}

// NewLoginRegistry validates and registers the methods in order. The order is
// the order shown on the login page.
func NewLoginRegistry(entries ...LoginEntry) (*LoginRegistry, error) {
	if len(entries) == 0 {
		return nil, errors.New("at least one login method is required")
	}
	registry := &LoginRegistry{byID: make(map[string]LoginEntry, len(entries)), limiter: newLoginLimiter()}
	for _, entry := range entries {
		if entry.Method == nil {
			return nil, errors.New("login method is nil")
		}
		id := entry.Method.ID()
		if !loginMethodIDPattern.MatchString(id) {
			return nil, fmt.Errorf("login method id %q must be 1-32 lowercase letters, digits or hyphens", id)
		}
		if _, dup := registry.byID[id]; dup {
			return nil, fmt.Errorf("login method id %q is used twice", id)
		}
		if strings.TrimSpace(entry.Method.Label()) == "" {
			return nil, fmt.Errorf("login method %q needs a label", id)
		}
		_, redirect := entry.Method.(RedirectLoginMethod)
		credential, isCredential := entry.Method.(CredentialLoginMethod)
		switch {
		case redirect && isCredential:
			return nil, fmt.Errorf("login method %q cannot be both redirect and credential", id)
		case !redirect && !isCredential:
			return nil, fmt.Errorf("login method %q is neither a redirect nor a credential method", id)
		case isCredential && len(credential.Fields()) == 0:
			return nil, fmt.Errorf("login method %q has no form fields", id)
		}
		registry.byID[id] = entry
		registry.entries = append(registry.entries, entry)
	}
	return registry, nil
}

// Authenticate satisfies IdentityProvider. Registry sign-in always goes
// through the login page, so a direct call is a wiring mistake.
func (r *LoginRegistry) Authenticate(context.Context, IdentityRequest) (Identity, error) {
	return Identity{}, errors.New("login registry requires interactive sign-in")
}

func (r *LoginRegistry) lookup(id string) (LoginEntry, bool) {
	entry, ok := r.byID[id]
	return entry, ok
}

// single returns the only method when exactly one is registered.
func (r *LoginRegistry) single() (LoginEntry, bool) {
	if len(r.entries) != 1 {
		return LoginEntry{}, false
	}
	return r.entries[0], true
}

// qualify namespaces the identity a method returned. Upstream tokens are not
// kept: registry mode has no downstream strategy that would use them, so
// storing them would only widen what a database leak exposes.
func (e LoginEntry) qualify(identity Identity) (Identity, error) {
	if strings.TrimSpace(identity.Subject) == "" {
		return Identity{}, errors.New("login method returned an empty subject")
	}
	identity.Subject = e.SubjectPrefix + identity.Subject
	identity.UpstreamSession = nil
	return identity, nil
}

const (
	// loginMaxFailures failed attempts on one account within loginWindow lock
	// that account out of the method until the window passes.
	loginMaxFailures = 5
	loginWindow      = 5 * time.Minute
	// loginLimiterCapacity bounds the memory a flood of distinct account
	// names can use.
	loginLimiterCapacity = 50000
)

// loginLimiter throttles failed credential attempts per (method, account).
// It is deliberately in-memory and per replica: it blunts online guessing
// against one account and is not a substitute for rate limiting at the proxy.
// It does not key on client address, because behind a proxy every person
// shares one and the limiter would lock everyone out together.
type loginLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{failures: map[string][]time.Time{}}
}

// loginLimiterKey hashes the account so the map holds fixed-size keys and no
// account names.
func loginLimiterKey(method, account string) string {
	sum := sha256.Sum256([]byte(method + "\x00" + strings.ToLower(account)))
	return hex.EncodeToString(sum[:16])
}

func (l *loginLimiter) recent(key string, now time.Time) []time.Time {
	kept := l.failures[key][:0]
	for _, at := range l.failures[key] {
		if now.Sub(at) < loginWindow {
			kept = append(kept, at)
		}
	}
	if len(kept) == 0 {
		delete(l.failures, key)
		return nil
	}
	l.failures[key] = kept
	return kept
}

// allow reports whether another attempt may be made for the account.
func (l *loginLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(key, now)) < loginMaxFailures
}

func (l *loginLimiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, known := l.failures[key]; !known && len(l.failures) >= loginLimiterCapacity {
		for other := range l.failures {
			if len(l.recent(other, now)) == 0 {
				continue
			}
			delete(l.failures, other)
			break
		}
	}
	l.failures[key] = append(l.recent(key, now), now)
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}
