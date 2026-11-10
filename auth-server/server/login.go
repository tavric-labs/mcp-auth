package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"
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

// ErrMethodUnavailable marks a failure that happened before the person's
// password was tested: the directory could not be reached, the service account
// was refused, the lookup failed. Such an attempt is not counted against the
// account and is reported as an outage.
//
// A method must return it only for failures that cannot depend on whether the
// password was right. Any other error from Authenticate is treated as a failed
// attempt, counted and shown exactly like a wrong password, because it may have
// come after the password was checked, and an answer that differs from "wrong
// password" would tell an attacker the guess was correct while leaving them
// unthrottled.
var ErrMethodUnavailable = errors.New("login method unavailable")

// loginMethodIDPattern keeps ids safe in a URL path segment and free of the
// "." that separates the id from the random part of the upstream state.
var loginMethodIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// LoginEntry registers one method.
type LoginEntry struct {
	Method LoginMethod
	// Resources scopes this method to exact MCP resource URLs. Explicitly
	// scoped methods replace the unscoped defaults for their resources.
	Resources []string
	// SubjectPrefix is prepended to the subject the method returns. Methods
	// have independent identifier spaces (a Google sub, a GitHub id and an LDAP
	// uid can be equal strings), so without a prefix two people could share an
	// access-token subject. The loader defaults it to "<id>:".
	SubjectPrefix string
	// KeepUpstreamSession keeps the token set the method's upstream provider
	// issued at login, so a resource exchanger can hand it to that resource's
	// server and refresh it. It is off by default: a database leak then exposes
	// only the methods that need a downstream credential. It is meant for a
	// method scoped to Resources, which is also what the exchanger is routed by.
	KeepUpstreamSession bool
	// UpstreamConnector is the provider the kept session came from; its token
	// endpoint and client refresh that session. Required with
	// KeepUpstreamSession.
	UpstreamConnector *ConnectorConfig
	// ConnectorName names the connectors-file entry an oidc method was built
	// from. It lets the process report which connectors are in use.
	ConnectorName string
}

// LoginRegistry is the set of enabled login methods. It also implements
// IdentityProvider so it can be passed to NewServer; the server then runs the
// login page flow instead of a single upstream redirect.
type LoginRegistry struct {
	entries []LoginEntry
	byID    map[string]LoginEntry
	limiter *loginLimiter
	// disabled lists methods the loader refused to enable (see
	// LoginMethodsOptions.SkipInvalidMethods). They cannot authenticate anyone.
	disabled []DisabledLoginMethod
}

// DisabledLoginMethod records a configured method that was not enabled because
// its own configuration is invalid, for example it names a connector that is not
// in the connectors file.
type DisabledLoginMethod struct {
	ID string
	// Resources are the resources the method was scoped to. A resource whose
	// scoped login is disabled stays closed; it never falls back to a default.
	Resources []string
	// Reason is the validation error. It is for logs, not for public output.
	Reason string
}

// NewLoginRegistry validates and registers the methods in order. The order is
// the order shown on the login page.
func NewLoginRegistry(entries ...LoginEntry) (*LoginRegistry, error) {
	return newLoginRegistry(entries, nil)
}

// newLoginRegistry also records disabled methods. With disabled methods the
// enabled list may be empty: the caller decides whether that is acceptable.
func newLoginRegistry(entries []LoginEntry, disabled []DisabledLoginMethod) (*LoginRegistry, error) {
	if len(entries) == 0 && len(disabled) == 0 {
		return nil, errors.New("at least one login method is required")
	}
	registry := &LoginRegistry{byID: make(map[string]LoginEntry, len(entries)), limiter: newLoginLimiter(), disabled: disabled}
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
		if err := validateLoginResources(id, entry.Resources); err != nil {
			return nil, err
		}
		entry.Resources = append([]string(nil), entry.Resources...)
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
		if entry.KeepUpstreamSession && (len(entry.Resources) == 0 || entry.UpstreamConnector == nil) {
			return nil, fmt.Errorf("login method %q keeps its upstream session, which needs resources and a connector", id)
		}
		registry.byID[id] = entry
		registry.entries = append(registry.entries, entry)
	}
	if err := registry.checkSubjectPrefixes(); err != nil {
		return nil, err
	}
	if err := registry.checkUpstreamSessionResources(); err != nil {
		return nil, err
	}
	return registry, nil
}

// validateLoginResources requires a method's resources to be unique absolute
// HTTP(S) URLs, so scoping is unambiguous.
func validateLoginResources(id string, resources []string) error {
	seen := map[string]bool{}
	for _, resource := range resources {
		u, err := url.Parse(resource)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || strings.TrimSpace(resource) != resource || seen[resource] {
			return fmt.Errorf("login method %q resources must be unique absolute HTTP(S) URLs without userinfo, query or fragment", id)
		}
		seen[resource] = true
	}
	return nil
}

// DisabledMethods lists the configured methods that were not enabled. It is
// nil-safe.
func (r *LoginRegistry) DisabledMethods() []DisabledLoginMethod {
	if r == nil {
		return nil
	}
	return append([]DisabledLoginMethod(nil), r.disabled...)
}

// EnabledCount is the number of methods that can authenticate someone.
func (r *LoginRegistry) EnabledCount() int {
	if r == nil {
		return 0
	}
	return len(r.entries)
}

// disabledServes reports whether a disabled method was scoped to resource.
func (r *LoginRegistry) disabledServes(resource string) bool {
	for _, method := range r.disabled {
		for _, scoped := range method.Resources {
			if scoped == resource {
				return true
			}
		}
	}
	return false
}

// checkUpstreamSessionResources allows one session-keeping method per
// resource. The exchanger for a resource is chosen by the resource alone, so
// two such methods could not tell which provider refreshes a given subject.
func (r *LoginRegistry) checkUpstreamSessionResources() error {
	owner := map[string]string{}
	for _, entry := range r.entries {
		if !entry.KeepUpstreamSession {
			continue
		}
		for _, resource := range entry.Resources {
			if other, taken := owner[resource]; taken {
				return fmt.Errorf("login methods %q and %q both keep upstream sessions for %s; one resource can have only one", other, entry.Method.ID(), resource)
			}
			owner[resource] = entry.Method.ID()
		}
	}
	return nil
}

// ConnectorNames returns the connectors-file entries the registry's oidc methods
// use, so a connector a login depends on is never reported as unused.
func (r *LoginRegistry) ConnectorNames() []string {
	var names []string
	for _, entry := range r.entries {
		if entry.ConnectorName != "" {
			names = append(names, entry.ConnectorName)
		}
	}
	return names
}

// UpstreamSessionConnectors maps each resource whose login keeps its upstream
// session to the connector that refreshes it.
func (r *LoginRegistry) UpstreamSessionConnectors() map[string]ConnectorConfig {
	connectors := map[string]ConnectorConfig{}
	for _, entry := range r.entries {
		if !entry.KeepUpstreamSession {
			continue
		}
		for _, resource := range entry.Resources {
			connectors[resource] = *entry.UpstreamConnector
		}
	}
	return connectors
}

// checkSubjectPrefixes refuses prefixes under which two methods could mint
// the same subject. Subjects are what a resource server keys a person on, so
// a collision lets one person's account stand in for another's. Two methods
// cannot share a prefix, and one non-empty prefix cannot begin another (with
// "a-" and "a-b-", the id "b-1" from the first equals "1" from the second).
// A single empty prefix is allowed, for keeping an existing connector's
// subjects; its subjects must not themselves start with another method's
// prefix, which this cannot check.
func (r *LoginRegistry) checkSubjectPrefixes() error {
	for i, a := range r.entries {
		for _, b := range r.entries[i+1:] {
			pa, pb := a.SubjectPrefix, b.SubjectPrefix
			switch {
			case pa == pb:
				return fmt.Errorf("login methods %q and %q use the same subject prefix %q, so they could issue the same subject", a.Method.ID(), b.Method.ID(), pa)
			case pa != "" && pb != "" && (strings.HasPrefix(pa, pb) || strings.HasPrefix(pb, pa)):
				return fmt.Errorf("subject prefixes %q (%s) and %q (%s) overlap, so they could issue the same subject", pa, a.Method.ID(), pb, b.Method.ID())
			}
		}
	}
	return nil
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

// entriesForResource makes an explicit resource assignment an authentication
// requirement: a user cannot select a weaker default method instead. Methods
// without resource assignments remain defaults for other resources.
func (r *LoginRegistry) entriesForResource(resource string) []LoginEntry {
	var scoped, defaults []LoginEntry
	for _, entry := range r.entries {
		if len(entry.Resources) == 0 {
			defaults = append(defaults, entry)
			continue
		}
		for _, allowed := range entry.Resources {
			if allowed == resource {
				scoped = append(scoped, entry)
				break
			}
		}
	}
	if len(scoped) > 0 {
		return scoped
	}
	if r.disabledServes(resource) {
		// The resource requires a login that is disabled. Falling back to a
		// default method would let a weaker sign-in stand in for it.
		return nil
	}
	return defaults
}

// ResourceURLs lists every resource some method is assigned to.
func (r *LoginRegistry) ResourceURLs() []string {
	var out []string
	for _, entry := range r.entries {
		out = append(out, entry.Resources...)
	}
	return out
}

// servesResource reports whether a method is explicitly assigned to resource.
// It is nil-safe, so a server with no resource logins answers false.
func (r *LoginRegistry) servesResource(resource string) bool {
	if r == nil {
		return false
	}
	for _, entry := range r.entries {
		for _, allowed := range entry.Resources {
			if allowed == resource {
				return true
			}
		}
	}
	// A disabled method still claims its resources, so they stay closed
	// instead of being signed in through another flow.
	return r.disabledServes(resource)
}

func (r *LoginRegistry) lookupForResource(id, resource string) (LoginEntry, bool) {
	for _, entry := range r.entriesForResource(resource) {
		if entry.Method.ID() == id {
			return entry, true
		}
	}
	return LoginEntry{}, false
}

func (r *LoginRegistry) singleForResource(resource string) (LoginEntry, bool) {
	entries := r.entriesForResource(resource)
	if len(entries) != 1 {
		return LoginEntry{}, false
	}
	return entries[0], true
}

// qualify namespaces the identity a method returned. Upstream tokens are
// dropped unless the entry opts in with KeepUpstreamSession: without a
// downstream strategy that uses them, storing them would only widen what a
// database leak exposes.
func (e LoginEntry) qualify(identity Identity) (Identity, error) {
	if strings.TrimSpace(identity.Subject) == "" {
		return Identity{}, errors.New("login method returned an empty subject")
	}
	identity.Subject = e.SubjectPrefix + identity.Subject
	if !e.KeepUpstreamSession {
		identity.UpstreamSession = nil
	}
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

// normalizeLoginAccount reduces an account name to the form the throttle keys
// on, so spellings a directory treats as one account share one lockout:
// surrounding and repeated whitespace, letter case, and Unicode compatibility
// forms (RFC 4518 matching applies NFKC, so a fullwidth name is the same
// account). It is for keying only; what is sent to a directory is separate.
// Aliases a directory defines itself, such as DOMAIN\name and name@domain,
// cannot be unified here, which is why this is not the only defence.
func normalizeLoginAccount(account string) string {
	folded := strings.ToLower(norm.NFKC.String(account))
	return strings.Join(strings.FieldsFunc(folded, unicode.IsSpace), " ")
}

// loginLimiterKey hashes the account so the map holds fixed-size keys and no
// account names.
func loginLimiterKey(method, account string) string {
	sum := sha256.Sum256([]byte(method + "\x00" + normalizeLoginAccount(account)))
	return hex.EncodeToString(sum[:16])
}

type loginAttemptRecord struct {
	at  time.Time
	seq uint64
}

// loginLimiter throttles failed credential attempts per (method, account).
// It is deliberately in-memory and per replica: it blunts online guessing
// against one account and is not a substitute for rate limiting at the proxy.
// It does not key on client address, because behind a proxy every person
// shares one and the limiter would lock everyone out together.
//
// An attempt is counted when it starts, not when it fails. Counting only
// failures would let any number of requests pass the check while the first is
// still waiting on the directory.
type loginLimiter struct {
	mu       sync.Mutex
	seq      uint64
	attempts map[string][]loginAttemptRecord
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{attempts: map[string][]loginAttemptRecord{}}
}

func (l *loginLimiter) prune(key string, now time.Time) []loginAttemptRecord {
	kept := l.attempts[key][:0]
	for _, record := range l.attempts[key] {
		if now.Sub(record.at) < loginWindow {
			kept = append(kept, record)
		}
	}
	if len(kept) == 0 {
		delete(l.attempts, key)
		return nil
	}
	l.attempts[key] = kept
	return kept
}

// reserve counts an attempt against the account and reports whether it may
// proceed. The returned ticket is released with success (the account is
// cleared) or abandon (the attempt did not test the password, for example
// because the directory was down); a wrong password just leaves the count.
func (l *loginLimiter) reserve(key string, now time.Time) (loginTicket, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.prune(key, now)) >= loginMaxFailures {
		return loginTicket{}, false
	}
	if _, known := l.attempts[key]; !known && len(l.attempts) >= loginLimiterCapacity && !l.makeRoom(now) {
		// Every tracked account is locked. Refusing the newcomer is the only
		// way to keep those locks, so an unknown account waits for one to expire.
		return loginTicket{}, false
	}
	l.seq++
	l.attempts[key] = append(l.attempts[key], loginAttemptRecord{at: now, seq: l.seq})
	return loginTicket{limiter: l, key: key, seq: l.seq}, true
}

// makeRoom frees one slot and reports whether it could. An account that has
// expired goes first; otherwise the unlocked account whose latest attempt is
// oldest. A locked account is never dropped: otherwise filling the limiter
// with other names would unlock it.
func (l *loginLimiter) makeRoom(now time.Time) bool {
	var victim string
	var victimLatest time.Time
	for key := range l.attempts {
		records := l.prune(key, now)
		if len(records) == 0 {
			return true
		}
		if len(records) >= loginMaxFailures {
			continue
		}
		if latest := records[len(records)-1].at; victim == "" || latest.Before(victimLatest) {
			victim, victimLatest = key, latest
		}
	}
	if victim == "" {
		return false
	}
	delete(l.attempts, victim)
	return true
}

type loginTicket struct {
	limiter *loginLimiter
	key     string
	seq     uint64
}

// success clears the account's count.
func (t loginTicket) success() {
	t.limiter.mu.Lock()
	defer t.limiter.mu.Unlock()
	delete(t.limiter.attempts, t.key)
}

// abandon removes this attempt's count: it never tested the password.
func (t loginTicket) abandon() {
	t.limiter.mu.Lock()
	defer t.limiter.mu.Unlock()
	records := t.limiter.attempts[t.key]
	for index, record := range records {
		if record.seq == t.seq {
			t.limiter.attempts[t.key] = append(records[:index], records[index+1:]...)
			break
		}
	}
	if len(t.limiter.attempts[t.key]) == 0 {
		delete(t.limiter.attempts, t.key)
	}
}
