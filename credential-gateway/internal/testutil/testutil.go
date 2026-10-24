// Package testutil provides fakes for tests only: a stand-in mcp-auth, a fake
// upstream MCP server, and a fake secret resolver. All credentials are fake.
package testutil

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/config"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/credentials"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/gateway"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/mappings"
)

const (
	GitLabResource = "https://mcp.example.test/gitlab/mcp"
	GerritResource = "https://mcp.example.test/gerrit/mcp"
	Sentinel       = "SENTINEL-SECRET-VALUE"
)

// NewKey returns a fresh RSA key.
func NewKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func b64(v any) string {
	data, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(data)
}

// SignJWT signs claims with RS256.
func SignJWT(t testing.TB, key *rsa.PrivateKey, kid, typ string, claims map[string]any) string {
	t.Helper()
	msg := b64(map[string]any{"alg": "RS256", "kid": kid, "typ": typ}) + "." + b64(claims)
	digest := sha256.Sum256([]byte(msg))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return msg + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// FakeAS stands in for mcp-auth: JWKS, access tokens and the credential exchange.
type FakeAS struct {
	Server *httptest.Server
	Key    *rsa.PrivateKey
	t      testing.TB

	mu         sync.Mutex
	revoked    map[string]bool
	failStatus int
	lastForm   url.Values
	Exchanges  atomic.Int64
}

func NewFakeAS(t testing.TB) *FakeAS {
	a := &FakeAS{Key: NewKey(t), t: t, revoked: map[string]bool{}}
	a.Server = httptest.NewServer(http.HandlerFunc(a.handle))
	t.Cleanup(a.Server.Close)
	return a
}

func (a *FakeAS) Issuer() string { return a.Server.URL }

func (a *FakeAS) Revoke(sid string) { a.mu.Lock(); a.revoked[sid] = true; a.mu.Unlock() }

// FailExchange makes the token endpoint answer with status (0 restores it).
func (a *FakeAS) FailExchange(status int) { a.mu.Lock(); a.failStatus = status; a.mu.Unlock() }

func (a *FakeAS) LastForm() url.Values { a.mu.Lock(); defer a.mu.Unlock(); return a.lastForm }

// TokenOpts customises an access token. Zero values mean "valid default".
type TokenOpts struct {
	Subject, Resource, Scope, SessionID, Issuer string
	NoSession                                   bool
	ExpiresIn                                   time.Duration
	Key                                         *rsa.PrivateKey
}

// Token mints an access token the way mcp-auth would.
func (a *FakeAS) Token(o TokenOpts) string {
	def := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	def(&o.Subject, "alice")
	def(&o.Resource, GitLabResource)
	def(&o.Scope, "gitlab:use")
	def(&o.SessionID, "session-1")
	def(&o.Issuer, a.Issuer())
	if o.ExpiresIn == 0 {
		o.ExpiresIn = time.Minute
	}
	key := o.Key
	if key == nil {
		key = a.Key
	}
	now := time.Now()
	claims := map[string]any{"iss": o.Issuer, "sub": o.Subject, "aud": o.Resource, "scope": o.Scope,
		"iat": now.Unix(), "exp": now.Add(o.ExpiresIn).Unix(), "jti": fmt.Sprint(now.UnixNano())}
	if !o.NoSession {
		claims["sid"] = o.SessionID
	}
	return SignJWT(a.t, key, "as-key", "at+jwt", claims)
}

func (a *FakeAS) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/jwks.json":
		pub := a.Key.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "as-key",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	case "/token":
		a.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (a *FakeAS) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	a.mu.Lock()
	a.lastForm = r.PostForm
	fail := a.failStatus
	a.mu.Unlock()
	a.Exchanges.Add(1)
	if fail != 0 {
		w.WriteHeader(fail)
		return
	}
	form := r.PostForm
	parts := strings.Split(form.Get("subject_token"), ".")
	var subject map[string]any
	if len(parts) != 3 {
		w.WriteHeader(400)
		return
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(raw, &subject)
	sid, _ := subject["sid"].(string)
	a.mu.Lock()
	revoked := a.revoked[sid]
	a.mu.Unlock()
	if revoked || form.Get("requested_token_type") != "urn:mcp-auth:token-type:credential-access-assertion" {
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
		return
	}
	clientID := form.Get("client_id")
	now := time.Now()
	assertion := SignJWT(a.t, a.Key, "as-key", "credential-access+jwt", map[string]any{
		"iss": a.Issuer(), "sub": subject["sub"], "aud": clientID, "azp": clientID,
		"resource": form.Get("audience"), "sid": sid, "scope": subject["scope"], "token_use": "credential_access",
		"jti": fmt.Sprint(now.UnixNano()), "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": assertion, "token_type": "N_A", "expires_in": 60,
		"issued_token_type": "urn:mcp-auth:token-type:credential-access-assertion"})
}

// Record is one request seen by the fake upstream.
type Record struct {
	Method string
	URL    string
	Header http.Header
	Body   string
}

// FakeUpstream is a fake upstream MCP server that records exactly what it receives.
type FakeUpstream struct {
	Server *httptest.Server
	mu     sync.Mutex
	recs   []Record
	// Behavior overrides the default responder when set.
	Behavior func(w http.ResponseWriter, r *http.Request)
}

func NewFakeUpstream(t testing.TB) *FakeUpstream {
	u := &FakeUpstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.recs = append(u.recs, Record{r.Method, r.URL.RequestURI(), r.Header.Clone(), string(body)})
		n, behavior := len(u.recs), u.Behavior
		u.mu.Unlock()
		if behavior != nil {
			behavior(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && strings.Contains(string(body), "initialize") {
			w.Header().Set("Mcp-Session-Id", fmt.Sprintf("upstream-session-%d", n))
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	t.Cleanup(u.Server.Close)
	return u
}

func (u *FakeUpstream) Records() []Record {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]Record(nil), u.recs...)
}

// FakeResolver resolves references from a map and records every call.
type FakeResolver struct {
	mu     sync.Mutex
	Values map[string]string
	calls  []map[string]string
	Err    error
}

func (f *FakeResolver) Resolve(_ context.Context, refs map[string]string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := map[string]string{}
	for k, v := range refs {
		cp[k] = v
	}
	f.calls = append(f.calls, cp)
	if f.Err != nil {
		return nil, f.Err
	}
	out := map[string]string{}
	for name, ref := range refs {
		out[name] = f.Values[ref]
	}
	return out, nil
}
func (f *FakeResolver) Ready() bool { return true }
func (f *FakeResolver) Calls() int  { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }
func (f *FakeResolver) SetErr(err error) {
	f.mu.Lock()
	f.Err = err
	f.mu.Unlock()
}

// Ref builds the op:// reference used by the default mappings.
func Ref(user, service, field string) string {
	return fmt.Sprintf("op://Org-MCP/%s-%s/%s", service, user, field)
}

// MapStore is an in-memory mappings.Store for tests. The shipped store is the
// form store; this one lets a test choose exactly which identities have values.
type MapStore struct {
	mu      sync.Mutex
	m       map[[3]string]*mappings.Mapping
	err     error
	version int
}

// SetErr makes every lookup fail with err, as an unavailable store would.
func (s *MapStore) SetErr(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

// Replace sets the whole mapping table from entries shaped like DefaultMappings.
// Every call gets a new version, so a gateway cache never serves an older table.
func (s *MapStore) Replace(entries []map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.version++
	table := map[[3]string]*mappings.Mapping{}
	for _, e := range entries {
		refs, _ := e["fields"].(map[string]string)
		issuer, subject, service := e["issuer"].(string), e["subject"].(string), e["service"].(string)
		table[[3]string{issuer, subject, service}] = &mappings.Mapping{
			Issuer: issuer, Subject: subject, Service: service, Refs: refs, Version: fmt.Sprint(s.version),
		}
	}
	s.m = table
}

// Lookup implements mappings.Store.
func (s *MapStore) Lookup(issuer, subject, service string) (*mappings.Mapping, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return s.m[[3]string{issuer, subject, service}], nil
}

// Env is a complete wired plugin with fakes.
type Env struct {
	T        testing.TB
	AS       *FakeAS
	Upstream *FakeUpstream
	Resolver *FakeResolver
	Creds    *credentials.Service
	Config   *config.Config
	Gateway  *httptest.Server
	Store    *MapStore
	Clock    *Clock
}

// Clock is a settable clock for cache-expiry tests.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *Clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func writeKey(t testing.TB, path string, key *rsa.PrivateKey) {
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// DefaultMappings: alice and bob on GitLab, alice also on Gerrit.
func DefaultMappings(issuer string) []map[string]any {
	entry := func(user, service string, fields ...string) map[string]any {
		refs := map[string]string{}
		for _, f := range fields {
			refs[f] = Ref(user, service, f)
		}
		return map[string]any{"issuer": issuer, "subject": user, "service": service, "fields": refs}
	}
	return []map[string]any{
		entry("alice", "gitlab", "username", "api_token"),
		entry("bob", "gitlab", "username", "api_token"),
		entry("alice", "gerrit", "username", "http_password"),
	}
}

// WriteMappings replaces the table the gateway looks identities up in.
func (e *Env) WriteMappings(m []map[string]any) { e.Store.Replace(m) }

func formFields(names ...string) []any {
	out := make([]any, 0, len(names))
	for _, n := range names {
		out = append(out, map[string]any{"name": n, "secret": n != "username"})
	}
	return out
}

// ConfigMutator edits the raw configuration before it is parsed.
type ConfigMutator func(raw map[string]any)

// NewEnv wires fakes, the credential service and the gateway.
func NewEnv(t testing.TB, mutate ...ConfigMutator) *Env {
	t.Helper()
	dir := t.TempDir()
	as, up := NewFakeAS(t), NewFakeUpstream(t)
	values := map[string]string{}
	for _, u := range []string{"alice", "bob"} {
		values[Ref(u, "gitlab", "username")] = u + "-gl"
		values[Ref(u, "gitlab", "api_token")] = "glpat-" + u + "-token"
	}
	values[Ref("alice", "gerrit", "username")] = "alice-gerrit"
	values[Ref("alice", "gerrit", "http_password")] = "gerrit-pw"

	gitlabKey, gerritKey := filepath.Join(dir, "gitlab.pem"), filepath.Join(dir, "gerrit.pem")
	writeKey(t, gitlabKey, NewKey(t))
	writeKey(t, gerritKey, NewKey(t))
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "session.key"), []byte(strings.Repeat("k", 48)), 0o600))
	env := &Env{T: t, AS: as, Upstream: up, Resolver: &FakeResolver{Values: values}, Store: &MapStore{},
		Clock: &Clock{t: time.Now()}}
	env.WriteMappings(DefaultMappings(as.Issuer()))

	raw := map[string]any{
		"allow_insecure_http":      true,
		"authorization_server":     map[string]any{"issuer": as.Issuer()},
		"session_binding_key_file": filepath.Join(dir, "session.key"),
		"credential_cache":         map[string]any{"ttl_seconds": 300, "max_entries": 16},
		"limits":                   map[string]any{"max_request_bytes": 1 << 20},
		"services": []any{
			map[string]any{"id": "gitlab", "resource_url": GitLabResource, "upstream_url": up.Server.URL + "/api/v4/mcp", "validation_url": up.Server.URL + "/auth/check",
				"required_scopes": []string{"gitlab:use"}, "form_fields": formFields("username", "api_token"),
				"resource_client": map[string]any{"client_id": "gitlab-plugin", "key_id": "k1", "private_key_file": gitlabKey},
				"headers": []any{
					map[string]any{"name": "X-GitLab-Username", "type": "direct", "field": "username"},
					map[string]any{"name": "X-GitLab-PAT-Token", "type": "direct", "field": "api_token"},
				}},
			map[string]any{"id": "gerrit", "resource_url": GerritResource, "upstream_url": up.Server.URL + "/gerrit/mcp", "validation_url": up.Server.URL + "/auth/check",
				"required_scopes": []string{"gitlab:use"}, "form_fields": formFields("username", "http_password"),
				"resource_client": map[string]any{"client_id": "gerrit-plugin", "key_id": "k2", "private_key_file": gerritKey},
				"headers": []any{
					map[string]any{"name": "Authorization", "type": "basic", "username_field": "username", "password_field": "http_password"},
				}},
		},
	}
	for _, m := range mutate {
		m(raw)
	}
	data, _ := json.Marshal(raw)
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	env.Config = cfg
	env.Creds = &credentials.Service{Mappings: env.Store, Resolver: env.Resolver, TTL: cfg.CacheTTL, Max: cfg.CacheMaxEntries, Now: env.Clock.Now}
	env.Gateway = httptest.NewServer(gateway.New(cfg, env.Creds, env.Resolver.Ready, nil))
	t.Cleanup(env.Gateway.Close)
	return env
}

// Do sends a request to the gateway.
func (e *Env) Do(method, path, token, body string, header map[string]string) *http.Response {
	e.T.Helper()
	req, err := http.NewRequest(method, e.Gateway.URL+path, strings.NewReader(body))
	if err != nil {
		e.T.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		e.T.Fatal(err)
	}
	e.T.Cleanup(func() { resp.Body.Close() })
	return resp
}

// ReadBody returns the response body.
func ReadBody(resp *http.Response) string {
	data, _ := io.ReadAll(resp.Body)
	return string(data)
}

// JSONField extracts a top-level string field from a JSON body.
func JSONField(body, field string) string {
	var m map[string]any
	_ = json.Unmarshal([]byte(body), &m)
	s, _ := m[field].(string)
	return s
}

const Initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
