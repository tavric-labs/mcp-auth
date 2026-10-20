package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCredentialMethod accepts one account/password pair.
type fakeCredentialMethod struct {
	id       string
	user     string
	password string
	// failWith, when set, is returned instead of checking the password.
	failWith error
	// delay simulates directory latency.
	delay time.Duration
	mu    sync.Mutex
	calls int
}

func (m *fakeCredentialMethod) ID() string    { return m.id }
func (m *fakeCredentialMethod) Label() string { return "Fake directory" }
func (m *fakeCredentialMethod) Fields() []LoginField {
	return []LoginField{{Name: "username", Label: "Username"}, {Name: "password", Label: "Password", Secret: true}}
}
func (m *fakeCredentialMethod) Authenticate(_ context.Context, _ IdentityRequest, attempt LoginAttempt) (Identity, error) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	time.Sleep(m.delay)
	if m.failWith != nil {
		return Identity{}, m.failWith
	}
	if attempt.Values["username"] != m.user || attempt.Values["password"] != m.password {
		return Identity{}, ErrInvalidCredentials
	}
	return Identity{Subject: m.user, UpstreamSession: &UpstreamSession{AccessToken: "must-be-dropped"}}, nil
}

// fakeRedirectMethod sends the browser to a fake provider and accepts the
// code "good".
type fakeRedirectMethod struct{ id string }

func (m *fakeRedirectMethod) ID() string    { return m.id }
func (m *fakeRedirectMethod) Label() string { return "Fake provider" }
func (m *fakeRedirectMethod) Begin(_ context.Context, _ IdentityRequest, state string) (string, string, error) {
	return "https://idp.example/authorize?state=" + url.QueryEscape(state), "verifier-1", nil
}
func (m *fakeRedirectMethod) Complete(_ context.Context, callback IdentityCallback) (Identity, error) {
	if callback.Code != "good" || callback.CodeVerifier != "verifier-1" {
		return Identity{}, errors.New("bad code")
	}
	return Identity{Subject: "u1"}, nil
}

func loginTestServer(t *testing.T, entries ...LoginEntry) *Server {
	t.Helper()
	registry, err := NewLoginRegistry(entries...)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{
		Issuer: "http://localhost:8080", Resources: []string{"http://localhost:8081/mcp"},
		AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour, AuthorizationCodeTTL: time.Minute,
		AllowedScopes: []string{"tools:read"}, LocalDevelopment: true,
	}
	instance, err := NewServer(config, NewMemoryStore(), registry, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Store.SaveClient(Client{ID: "client", RedirectURIs: []string{"http://localhost:9999/callback"}, TokenEndpointAuth: "none"}); err != nil {
		t.Fatal(err)
	}
	return instance
}

// browser holds cookies the way a real one does: it sends back what it was
// given and drops what the server expires.
type browser struct {
	mu      sync.Mutex
	cookies map[string]*http.Cookie
}

func newBrowser() *browser { return &browser{cookies: map[string]*http.Cookie{}} }

func (b *browser) do(instance *Server, request *http.Request) *httptest.ResponseRecorder {
	b.mu.Lock()
	for _, cookie := range b.cookies {
		request.AddCookie(cookie)
	}
	b.mu.Unlock()
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	b.mu.Lock()
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.MaxAge < 0 {
			delete(b.cookies, cookie.Name)
		} else {
			b.cookies[cookie.Name] = cookie
		}
	}
	b.mu.Unlock()
	return recorder
}

// defaultBrowsers gives each test server one browser, so most tests read as
// one person signing in. Attack tests use a second browser explicitly.
var defaultBrowsers sync.Map

func defaultBrowser(instance *Server) *browser {
	loaded, _ := defaultBrowsers.LoadOrStore(instance, newBrowser())
	return loaded.(*browser)
}

func serve(instance *Server, request *http.Request) *httptest.ResponseRecorder {
	return defaultBrowser(instance).do(instance, request)
}

func postForm(path string, values url.Values) *http.Request {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

var (
	consentIDPattern = regexp.MustCompile(`name="consent_id" value="([^"]+)"`)
	loginIDPattern   = regexp.MustCompile(`name="login_id" value="([^"]+)"`)
)

// approveConsent runs /authorize and the consent approval, returning the
// response that follows approval.
func approveConsent(t *testing.T, instance *Server) *httptest.ResponseRecorder {
	t.Helper()
	digest := sha256.Sum256([]byte("verifier-1234567890"))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	authorize := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=client&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&code_challenge="+url.QueryEscape(challenge)+"&code_challenge_method=S256&resource=http%3A%2F%2Flocalhost%3A8081%2Fmcp&scope=tools%3Aread&state=client-state", nil)
	page := serve(instance, authorize)
	match := consentIDPattern.FindStringSubmatch(page.Body.String())
	if page.Code != http.StatusOK || match == nil {
		t.Fatalf("authorize did not render consent: %d %s", page.Code, page.Body.String())
	}
	return serve(instance, postForm("/authorize/consent", url.Values{"consent_id": {match[1]}, "decision": {"approve"}}))
}

// loginPageID approves consent and returns the login id from the login page.
func loginPageID(t *testing.T, instance *Server) string {
	t.Helper()
	approved := approveConsent(t, instance)
	location := approved.Header().Get("Location")
	if approved.Code != http.StatusSeeOther || !strings.HasPrefix(location, "http://localhost:8080/login?login_id=") {
		t.Fatalf("expected a redirect to the login page, got %d %q", approved.Code, location)
	}
	parsed, _ := url.Parse(location)
	page := serve(instance, httptest.NewRequest(http.MethodGet, "/login?"+parsed.RawQuery, nil))
	match := loginIDPattern.FindStringSubmatch(page.Body.String())
	if page.Code != http.StatusOK || match == nil {
		t.Fatalf("login page did not render: %d %s", page.Code, page.Body.String())
	}
	return match[1]
}

func credentialEntry() (*fakeCredentialMethod, LoginEntry) {
	method := &fakeCredentialMethod{id: "corp", user: "alice", password: "correct horse"}
	return method, LoginEntry{Method: method, SubjectPrefix: "corp:"}
}

func TestNewLoginRegistryValidation(t *testing.T) {
	_, valid := credentialEntry()
	cases := map[string][]LoginEntry{
		"no methods":     nil,
		"nil method":     {{}},
		"duplicate id":   {valid, valid},
		"uppercase id":   {{Method: &fakeRedirectMethod{id: "Google"}}},
		"dot in id":      {{Method: &fakeRedirectMethod{id: "a.b"}}},
		"empty id":       {{Method: &fakeRedirectMethod{id: ""}}},
		"overlong id":    {{Method: &fakeRedirectMethod{id: strings.Repeat("a", 33)}}},
		"neither shape":  {{Method: bareMethod{}}},
		"both shapes":    {{Method: &bothMethod{}}},
		"no form fields": {{Method: &noFieldsMethod{}}},
	}
	for name, entries := range cases {
		if _, err := NewLoginRegistry(entries...); err == nil {
			t.Errorf("NewLoginRegistry accepted %s", name)
		}
	}
	if _, err := NewLoginRegistry(valid, LoginEntry{Method: &fakeRedirectMethod{id: "github"}}); err != nil {
		t.Fatalf("rejected a valid registry: %v", err)
	}
}

type bareMethod struct{}

func (bareMethod) ID() string    { return "bare" }
func (bareMethod) Label() string { return "Bare" }

type bothMethod struct {
	fakeRedirectMethod
	fakeCredentialMethod
}

func (*bothMethod) ID() string    { return "both" }
func (*bothMethod) Label() string { return "Both" }

type noFieldsMethod struct{ fakeCredentialMethod }

func (*noFieldsMethod) ID() string           { return "nofields" }
func (*noFieldsMethod) Fields() []LoginField { return nil }

func TestLoginRoutesAre404WithoutRegistry(t *testing.T) {
	instance := testServer(t)
	if got := serve(instance, httptest.NewRequest(http.MethodGet, "/login?login_id=x", nil)).Code; got != http.StatusNotFound {
		t.Fatalf("GET /login = %d, want 404", got)
	}
	if got := serve(instance, postForm("/login/corp", url.Values{"login_id": {"x"}})).Code; got != http.StatusNotFound {
		t.Fatalf("POST /login/corp = %d, want 404", got)
	}
}

func TestCredentialLoginIssuesNamespacedSubject(t *testing.T) {
	method, entry := credentialEntry()
	instance := loginTestServer(t, entry)
	loginID := loginPageID(t, instance)
	response := serve(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {"alice"}, "password": {"correct horse"}}))
	location, _ := url.Parse(response.Header().Get("Location"))
	if response.Code != http.StatusFound && response.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d body=%s", response.Code, response.Body.String())
	}
	if location.Host != "localhost:9999" || location.Query().Get("state") != "client-state" {
		t.Fatalf("did not return to the MCP client: %s", location)
	}
	code, err := instance.Store.ConsumeAuthorizationCode(location.Query().Get("code"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code.Subject != "corp:alice" {
		t.Fatalf("subject = %q, want the method-namespaced corp:alice", code.Subject)
	}
	if method.calls != 1 {
		t.Fatalf("method called %d times", method.calls)
	}
	if _, err := instance.Store.GetUpstreamSession("corp:alice"); err == nil {
		t.Fatal("registry mode stored an upstream session it cannot use")
	}
}

func TestCredentialLoginFailureRotatesIDAndKeepsExpiry(t *testing.T) {
	_, entry := credentialEntry()
	instance := loginTestServer(t, entry)
	loginID := loginPageID(t, instance)

	bad := serve(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {"alice"}, "password": {"wrong"}}))
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d, want 401", bad.Code)
	}
	body := bad.Body.String()
	if !strings.Contains(body, "Sign-in failed") {
		t.Fatalf("no failure message: %s", body)
	}
	if strings.Contains(body, "wrong") || strings.Contains(body, "correct horse") {
		t.Fatal("the form echoed a password")
	}
	if !strings.Contains(body, `value="alice"`) {
		t.Fatal("the account name was not kept for retry")
	}
	next := loginIDPattern.FindStringSubmatch(body)
	if next == nil || next[1] == loginID {
		t.Fatalf("expected a fresh login id, got %v", next)
	}
	// The old id was consumed by the failed attempt.
	replay := serve(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {"alice"}, "password": {"correct horse"}}))
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("a used login id was accepted again: %d", replay.Code)
	}
	good := serve(instance, postForm("/login/corp", url.Values{"login_id": {next[1]}, "username": {"alice"}, "password": {"correct horse"}}))
	if !strings.HasPrefix(good.Header().Get("Location"), "http://localhost:9999/callback?code=") {
		t.Fatalf("retry with the fresh id did not complete: %d %s", good.Code, good.Header().Get("Location"))
	}
}

func TestCredentialLoginThrottlesFailedAttemptsPerAccount(t *testing.T) {
	method, entry := credentialEntry()
	instance := loginTestServer(t, entry)
	loginID := loginPageID(t, instance)
	for attempt := 1; attempt <= loginMaxFailures; attempt++ {
		response := serve(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {"Alice"}, "password": {"wrong"}}))
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", attempt, response.Code)
		}
		loginID = loginIDPattern.FindStringSubmatch(response.Body.String())[1]
	}
	before := method.calls
	locked := serve(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {"alice"}, "password": {"correct horse"}}))
	if locked.Code != http.StatusTooManyRequests {
		t.Fatalf("locked account status = %d, want 429", locked.Code)
	}
	if method.calls != before {
		t.Fatal("a throttled attempt still reached the method")
	}
	loginID = loginIDPattern.FindStringSubmatch(locked.Body.String())[1]
	other := serve(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {"bob"}, "password": {"wrong"}}))
	if other.Code != http.StatusUnauthorized {
		t.Fatalf("a different account was throttled: %d", other.Code)
	}
}

func TestCredentialLoginMethodFailureIsNotAWrongPassword(t *testing.T) {
	method, entry := credentialEntry()
	method.failWith = errors.New("directory unreachable at ldap.internal:636")
	instance := loginTestServer(t, entry)
	loginID := loginPageID(t, instance)
	for i := 0; i < loginMaxFailures+1; i++ {
		response := serve(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {"alice"}, "password": {"x"}}))
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("outage status = %d, want 503", response.Code)
		}
		if strings.Contains(response.Body.String(), "ldap.internal") {
			t.Fatal("the response leaked the method's internal error")
		}
		loginID = loginIDPattern.FindStringSubmatch(response.Body.String())[1]
	}
}

func TestLoginRejectsMissingOrUnknownLoginID(t *testing.T) {
	_, entry := credentialEntry()
	instance := loginTestServer(t, entry)
	for name, values := range map[string]url.Values{
		"missing":  {"username": {"alice"}, "password": {"correct horse"}},
		"unknown":  {"login_id": {"nope"}, "username": {"alice"}, "password": {"correct horse"}},
		"overlong": {"login_id": {strings.Repeat("a", maxLoginIDBytes+1)}},
	} {
		if got := serve(instance, postForm("/login/corp", values)).Code; got != http.StatusBadRequest {
			t.Errorf("%s login id: status %d, want 400", name, got)
		}
	}
	if got := serve(instance, httptest.NewRequest(http.MethodGet, "/login", nil)).Code; got != http.StatusBadRequest {
		t.Errorf("GET /login without an id: %d, want 400", got)
	}
	if got := serve(instance, postForm("/login/unknown", url.Values{"login_id": {"x"}})).Code; got != http.StatusNotFound {
		t.Errorf("unknown method: %d, want 404", got)
	}
}

func TestLoginPageHeadersAndFields(t *testing.T) {
	_, entry := credentialEntry()
	instance := loginTestServer(t, entry, LoginEntry{Method: &fakeRedirectMethod{id: "github"}, SubjectPrefix: "github:"})
	loginID := loginPageID(t, instance)
	page := serve(instance, httptest.NewRequest(http.MethodGet, "/login?login_id="+loginID, nil))
	for header, want := range map[string]string{
		"Cache-Control":           "no-store",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "frame-ancestors 'none'",
	} {
		if !strings.Contains(page.Header().Get(header), want) {
			t.Errorf("%s = %q, want it to contain %q", header, page.Header().Get(header), want)
		}
	}
	body := page.Body.String()
	for _, want := range []string{`action="http://localhost:8080/login/corp"`, `action="http://localhost:8080/login/github"`, `type="password"`, "Fake provider"} {
		if !strings.Contains(body, want) {
			t.Errorf("login page is missing %q", want)
		}
	}
}

func TestSingleRedirectMethodSkipsThePickerAndCompletes(t *testing.T) {
	instance := loginTestServer(t, LoginEntry{Method: &fakeRedirectMethod{id: "github"}, SubjectPrefix: "github:"})
	approved := approveConsent(t, instance)
	location, _ := url.Parse(approved.Header().Get("Location"))
	if location.Host != "idp.example" {
		t.Fatalf("expected a direct redirect to the provider, got %s", location)
	}
	state := location.Query().Get("state")
	if !strings.HasPrefix(state, "github.") {
		t.Fatalf("state %q does not name its method", state)
	}
	callback := serve(instance, httptest.NewRequest(http.MethodGet, "/identity/callback?code=good&state="+url.QueryEscape(state), nil))
	final, _ := url.Parse(callback.Header().Get("Location"))
	if final.Host != "localhost:9999" || final.Query().Get("code") == "" {
		t.Fatalf("callback did not finish authorization: %d %s", callback.Code, callback.Header().Get("Location"))
	}
	code, err := instance.Store.ConsumeAuthorizationCode(final.Query().Get("code"), time.Now())
	if err != nil || code.Subject != "github:u1" {
		t.Fatalf("subject = %q (err %v), want github:u1", code.Subject, err)
	}
	// The state is one time.
	replay := serve(instance, httptest.NewRequest(http.MethodGet, "/identity/callback?code=good&state="+url.QueryEscape(state), nil))
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("a replayed state was accepted: %d", replay.Code)
	}
}

func TestSubjectPrefixCanBeEmptyToKeepProviderSubjects(t *testing.T) {
	instance := loginTestServer(t, LoginEntry{Method: &fakeRedirectMethod{id: "okta"}, SubjectPrefix: ""})
	state := mustRedirectState(t, instance)
	callback := serve(instance, httptest.NewRequest(http.MethodGet, "/identity/callback?code=good&state="+url.QueryEscape(state), nil))
	final, _ := url.Parse(callback.Header().Get("Location"))
	code, err := instance.Store.ConsumeAuthorizationCode(final.Query().Get("code"), time.Now())
	if err != nil || code.Subject != "u1" {
		t.Fatalf("subject = %q (err %v), want the provider's own u1", code.Subject, err)
	}
}

func mustRedirectState(t *testing.T, instance *Server) string {
	t.Helper()
	location, _ := url.Parse(approveConsent(t, instance).Header().Get("Location"))
	return location.Query().Get("state")
}

func TestCallbackRejectsStateForAnotherOrWrongKindOfMethod(t *testing.T) {
	_, credential := credentialEntry()
	instance := loginTestServer(t, credential, LoginEntry{Method: &fakeRedirectMethod{id: "github"}, SubjectPrefix: "github:"})
	loginID := loginPageID(t, instance)
	started := serve(instance, postForm("/login/github", url.Values{"login_id": {loginID}}))
	location, _ := url.Parse(started.Header().Get("Location"))
	if started.Code != http.StatusSeeOther || location.Host != "idp.example" {
		t.Fatalf("choosing a redirect method did not leave for the provider: %d %s", started.Code, location)
	}
	state := location.Query().Get("state")
	random := strings.TrimPrefix(state, "github.")
	for name, forged := range map[string]string{
		"prefix of an unknown method":     "other." + random,
		"prefix of a credential method":   "corp." + random,
		"prefix removed":                  random,
		"empty":                           "",
		"prefix of a different real kind": "corp.",
	} {
		response := serve(instance, httptest.NewRequest(http.MethodGet, "/identity/callback?code=good&state="+url.QueryEscape(forged), nil))
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, response.Code)
		}
	}
	// None of the forged states consumed the real one.
	ok := serve(instance, httptest.NewRequest(http.MethodGet, "/identity/callback?code=good&state="+url.QueryEscape(state), nil))
	if ok.Code != http.StatusFound && ok.Code != http.StatusSeeOther {
		t.Fatalf("the genuine state no longer works: %d", ok.Code)
	}
}

func TestCallbackReportsUpstreamErrorToTheClient(t *testing.T) {
	instance := loginTestServer(t, LoginEntry{Method: &fakeRedirectMethod{id: "github"}, SubjectPrefix: "github:"})
	state := mustRedirectState(t, instance)
	response := serve(instance, httptest.NewRequest(http.MethodGet, "/identity/callback?error=access_denied&state="+url.QueryEscape(state), nil))
	location, _ := url.Parse(response.Header().Get("Location"))
	if location.Query().Get("error") != "access_denied" {
		t.Fatalf("client was not told access was denied: %s", location)
	}
}

func TestCallbackFailureDeniesAndDoesNotIssueCode(t *testing.T) {
	instance := loginTestServer(t, LoginEntry{Method: &fakeRedirectMethod{id: "github"}, SubjectPrefix: "github:"})
	state := mustRedirectState(t, instance)
	response := serve(instance, httptest.NewRequest(http.MethodGet, "/identity/callback?code=bad&state="+url.QueryEscape(state), nil))
	location, _ := url.Parse(response.Header().Get("Location"))
	if location.Query().Get("error") != "access_denied" || location.Query().Get("code") != "" {
		t.Fatalf("a failed provider login must deny without a code: %s", location)
	}
}

func TestOverlongFieldsAreRejectedBeforeTheMethodSeesThem(t *testing.T) {
	method, entry := credentialEntry()
	instance := loginTestServer(t, entry)
	loginID := loginPageID(t, instance)
	response := serve(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {"alice"}, "password": {strings.Repeat("a", maxLoginFieldBytes+1)}}))
	if response.Code != http.StatusUnauthorized || method.calls != 0 {
		t.Fatalf("overlong password: status %d, method calls %d", response.Code, method.calls)
	}
}

func TestLoginLimiterBoundsMemory(t *testing.T) {
	limiter := newLoginLimiter()
	now := time.Now()
	for i := 0; i < loginLimiterCapacity+500; i++ {
		if _, ok := limiter.reserve(loginLimiterKey("corp", fmt.Sprintf("user-%d", i)), now); !ok {
			t.Fatalf("a first attempt on a new account was refused (account %d)", i)
		}
	}
	if got := len(limiter.attempts); got > loginLimiterCapacity {
		t.Fatalf("limiter holds %d keys, capacity is %d", got, loginLimiterCapacity)
	}
	// Attempts age out of the window.
	key := loginLimiterKey("corp", "old")
	for i := 0; i < loginMaxFailures; i++ {
		limiter.reserve(key, now.Add(-2*loginWindow))
	}
	if _, ok := limiter.reserve(key, now); !ok {
		t.Fatal("expired attempts still count")
	}
}

// When the limiter is full it drops the account whose latest attempt is
// oldest, so a lock that was just earned is the last to go.
func TestLoginLimiterEvictsTheOldestAccountNotAFreshLock(t *testing.T) {
	limiter := newLoginLimiter()
	now := time.Now()
	locked := loginLimiterKey("corp", "victim")
	for i := 0; i < loginMaxFailures; i++ {
		limiter.reserve(locked, now)
	}
	for i := 0; i < loginLimiterCapacity+100; i++ {
		limiter.reserve(loginLimiterKey("corp", fmt.Sprintf("filler-%d", i)), now.Add(-time.Duration(1+i%100)*time.Second))
	}
	if _, ok := limiter.reserve(locked, now); ok {
		t.Fatal("filling the limiter evicted a fresh lock")
	}
}

func TestLoginLimiterReservationsAreAtomic(t *testing.T) {
	limiter := newLoginLimiter()
	now := time.Now()
	key := loginLimiterKey("corp", "alice")
	var wg sync.WaitGroup
	var mu sync.Mutex
	granted := 0
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := limiter.reserve(key, now); ok {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if granted != loginMaxFailures {
		t.Fatalf("%d concurrent attempts were granted, want exactly %d", granted, loginMaxFailures)
	}
}

func TestLoginLimiterAbandonAndSuccess(t *testing.T) {
	limiter := newLoginLimiter()
	now := time.Now()
	key := loginLimiterKey("corp", "alice")
	var tickets []loginTicket
	for i := 0; i < loginMaxFailures; i++ {
		ticket, ok := limiter.reserve(key, now)
		if !ok {
			t.Fatal("refused under the limit")
		}
		tickets = append(tickets, ticket)
	}
	if _, ok := limiter.reserve(key, now); ok {
		t.Fatal("limit not enforced")
	}
	tickets[0].abandon()
	ticket, ok := limiter.reserve(key, now)
	if !ok {
		t.Fatal("an abandoned attempt still counted")
	}
	ticket.success()
	if _, ok := limiter.reserve(key, now); !ok || len(limiter.attempts[key]) != 1 {
		t.Fatal("success did not clear the account")
	}
}

func TestLoginAccountNormalization(t *testing.T) {
	base := loginLimiterKey("corp", "alice")
	for _, alias := range []string{"alice", "Alice", "ALICE", " alice", "alice ", "\talice\n", " alice ", "ａｌｉｃｅ", "ＡＬＩＣＥ"} {
		if got := loginLimiterKey("corp", alias); got != base {
			t.Errorf("%q is a different account to the limiter", alias)
		}
	}
	if loginLimiterKey("corp", "bob") == base || loginLimiterKey("other", "alice") == base {
		t.Error("distinct accounts or methods share a key")
	}
	if normalizeLoginAccount("a   b	c") != "a b c" {
		t.Errorf("inner whitespace not collapsed: %q", normalizeLoginAccount("a   b	c"))
	}
}

// A failed attempt must not buy more time: otherwise someone could keep a
// login window open indefinitely by failing every few minutes.
func TestFailedAttemptDoesNotExtendTheLoginWindow(t *testing.T) {
	_, entry := credentialEntry()
	instance := loginTestServer(t, entry)
	clock := time.Now()
	instance.now = func() time.Time { return clock }
	loginID := loginPageID(t, instance)

	clock = clock.Add(9 * time.Minute)
	failed := serve(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {"alice"}, "password": {"wrong"}}))
	if failed.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", failed.Code)
	}
	next := loginIDPattern.FindStringSubmatch(failed.Body.String())[1]

	clock = clock.Add(2 * time.Minute) // 11 minutes after the page was issued
	late := serve(instance, postForm("/login/corp", url.Values{"login_id": {next}, "username": {"alice"}, "password": {"correct horse"}}))
	if late.Code != http.StatusBadRequest {
		t.Fatalf("the rotated login id outlived the original window: status %d", late.Code)
	}
}

func TestSuccessfulLoginClearsTheFailureCount(t *testing.T) {
	_, entry := credentialEntry()
	instance := loginTestServer(t, entry)
	failTimes := func(count int) {
		t.Helper()
		loginID := loginPageID(t, instance)
		for i := 0; i < count; i++ {
			response := serve(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {"alice"}, "password": {"wrong"}}))
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("failure %d: status %d, want 401", i+1, response.Code)
			}
			loginID = loginIDPattern.FindStringSubmatch(response.Body.String())[1]
		}
	}
	failTimes(loginMaxFailures - 1)
	loginID := loginPageID(t, instance)
	if got := serve(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {"alice"}, "password": {"correct horse"}})); got.Code != http.StatusFound && got.Code != http.StatusSeeOther {
		t.Fatalf("a correct password under the limit was refused: %d", got.Code)
	}
	// Without the reset, these would sit on top of the earlier failures and lock the account.
	failTimes(loginMaxFailures - 1)
}

// authorizeAndApprove runs /authorize and the consent approval in the given
// browser and returns the response to the approval.
func authorizeAndApprove(t *testing.T, instance *Server, b *browser) *httptest.ResponseRecorder {
	t.Helper()
	digest := sha256.Sum256([]byte("verifier-1234567890"))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	page := b.do(instance, httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=client&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&code_challenge="+url.QueryEscape(challenge)+"&code_challenge_method=S256&resource=http%3A%2F%2Flocalhost%3A8081%2Fmcp&scope=tools%3Aread&state=client-state", nil))
	match := consentIDPattern.FindStringSubmatch(page.Body.String())
	if match == nil {
		t.Fatalf("no consent page: %d", page.Code)
	}
	return b.do(instance, postForm("/authorize/consent", url.Values{"consent_id": {match[1]}, "decision": {"approve"}}))
}

func loginIDFromRedirect(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("login_id") == "" {
		t.Fatalf("no login id in redirect %q (status %d)", response.Header().Get("Location"), response.Code)
	}
	return location.Query().Get("login_id")
}

// Consent ids, login ids and upstream states share one table. A consent id from
// /authorize, never approved, must not be accepted as a login id.
func TestConsentIDIsNotAcceptedAsALoginID(t *testing.T) {
	method, entry := credentialEntry()
	instance := loginTestServer(t, entry)
	attacker := newBrowser()
	digest := sha256.Sum256([]byte("verifier-1234567890"))
	page := attacker.do(instance, httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=client&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&code_challenge="+url.QueryEscape(base64.RawURLEncoding.EncodeToString(digest[:]))+"&code_challenge_method=S256&resource=http%3A%2F%2Flocalhost%3A8081%2Fmcp&scope=tools%3Aread", nil))
	consentID := consentIDPattern.FindStringSubmatch(page.Body.String())[1]

	victim := newBrowser()
	response := victim.do(instance, postForm("/login/corp", url.Values{"login_id": {consentID}, "username": {"alice"}, "password": {"correct horse"}}))
	if response.Code != http.StatusBadRequest || method.calls != 0 {
		t.Fatalf("a consent id worked as a login id: status %d, method calls %d, location %q", response.Code, method.calls, response.Header().Get("Location"))
	}
	// The same, from the browser that holds the consent page.
	response = attacker.do(instance, postForm("/login/corp", url.Values{"login_id": {consentID}, "username": {"alice"}, "password": {"correct horse"}}))
	if response.Code != http.StatusBadRequest || method.calls != 0 {
		t.Fatalf("consent was skipped: status %d, method calls %d", response.Code, method.calls)
	}
}

// Someone who approved consent for their own client must not be able to hand
// the login link to a victim and collect the victim's authorization code.
func TestLoginRequiresTheBrowserThatApprovedConsent(t *testing.T) {
	method, entry := credentialEntry()
	instance := loginTestServer(t, entry)
	attacker, victim := newBrowser(), newBrowser()
	loginID := loginIDFromRedirect(t, authorizeAndApprove(t, instance, attacker))

	page := victim.do(instance, httptest.NewRequest(http.MethodGet, "/login?login_id="+loginID, nil))
	if page.Code != http.StatusOK {
		t.Fatalf("login page status %d", page.Code)
	}
	response := victim.do(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {"alice"}, "password": {"correct horse"}}))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("a different browser signed in: %d %s", response.Code, response.Header().Get("Location"))
	}
	if method.calls != 0 {
		t.Fatal("the victim's password was tried against the directory")
	}
	// The wrong browser did not use up the right browser's sign-in.
	response = attacker.do(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {"alice"}, "password": {"correct horse"}}))
	if !strings.HasPrefix(response.Header().Get("Location"), "http://localhost:9999/callback?code=") {
		t.Fatalf("the original browser could no longer sign in: %d", response.Code)
	}
}

func TestLoginRejectsAForgedOrStaleBindingCookie(t *testing.T) {
	_, entry := credentialEntry()
	instance := loginTestServer(t, entry)
	b := newBrowser()
	loginID := loginIDFromRedirect(t, authorizeAndApprove(t, instance, b))
	name := instance.loginCookieName(loginID)
	genuine := b.cookies[name]
	if genuine == nil {
		t.Fatalf("no binding cookie set; have %v", b.cookies)
	}
	for label, value := range map[string]string{"garbage": "not-the-value", "empty": "", "the id itself": loginID, "its hash": HashSecret(genuine.Value)} {
		forged := newBrowser()
		forged.cookies[name] = &http.Cookie{Name: name, Value: value}
		if got := forged.do(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {"alice"}, "password": {"correct horse"}})); got.Code != http.StatusBadRequest {
			t.Errorf("%s binding accepted: %d", label, got.Code)
		}
	}
	// A cookie for a different sign-in does not carry over.
	other := newBrowser()
	otherID := loginIDFromRedirect(t, authorizeAndApprove(t, instance, other))
	mixed := newBrowser()
	mixed.cookies[name] = &http.Cookie{Name: name, Value: other.cookies[instance.loginCookieName(otherID)].Value}
	if got := mixed.do(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {"alice"}, "password": {"correct horse"}})); got.Code != http.StatusBadRequest {
		t.Errorf("another sign-in's binding was accepted: %d", got.Code)
	}
}

func TestProviderCallbackRequiresTheBrowserThatStartedTheLogin(t *testing.T) {
	instance := loginTestServer(t, LoginEntry{Method: &fakeRedirectMethod{id: "github"}, SubjectPrefix: "github:"})
	attacker, victim := newBrowser(), newBrowser()
	location, _ := url.Parse(authorizeAndApprove(t, instance, attacker).Header().Get("Location"))
	state := location.Query().Get("state")
	callback := "/identity/callback?code=good&state=" + url.QueryEscape(state)

	if got := victim.do(instance, httptest.NewRequest(http.MethodGet, callback, nil)); got.Code != http.StatusBadRequest {
		t.Fatalf("a different browser completed the provider login: %d %s", got.Code, got.Header().Get("Location"))
	}
	got := attacker.do(instance, httptest.NewRequest(http.MethodGet, callback, nil))
	if !strings.HasPrefix(got.Header().Get("Location"), "http://localhost:9999/callback?code=") {
		t.Fatalf("the original browser could no longer finish: %d", got.Code)
	}
}

func TestBindingCookieAttributesAndCleanup(t *testing.T) {
	_, entry := credentialEntry()
	for _, tc := range []struct {
		issuer     string
		secure     bool
		hostPrefix bool
	}{{"http://localhost:8080", false, false}, {"https://auth.example.com", true, true}} {
		instance := loginTestServer(t, entry)
		instance.Config.Issuer = tc.issuer
		b := newBrowser()
		response := authorizeAndApprove(t, instance, b)
		cookies := response.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("%s: %d cookies set, want 1", tc.issuer, len(cookies))
		}
		cookie := cookies[0]
		if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Secure != tc.secure || cookie.MaxAge <= 0 {
			t.Errorf("%s: cookie attributes = %+v", tc.issuer, cookie)
		}
		if strings.HasPrefix(cookie.Name, "__Host-") != tc.hostPrefix {
			t.Errorf("%s: cookie name %q", tc.issuer, cookie.Name)
		}
		if cookie.Value == "" || strings.Contains(response.Header().Get("Location"), cookie.Value) {
			t.Errorf("%s: the binding must be random and must not appear in the URL", tc.issuer)
		}
	}
	// The cookie is removed once the sign-in completes.
	instance := loginTestServer(t, entry)
	b := newBrowser()
	loginID := loginIDFromRedirect(t, authorizeAndApprove(t, instance, b))
	b.do(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {"alice"}, "password": {"correct horse"}}))
	if len(b.cookies) != 0 {
		t.Fatalf("binding cookies left behind after sign-in: %v", b.cookies)
	}
}

// Spellings a directory treats as one account must share one lockout.
func TestThrottleCannotBeSidesteppedWithAccountAliases(t *testing.T) {
	method, entry := credentialEntry()
	instance := loginTestServer(t, entry)
	loginID := loginPageID(t, instance)
	aliases := []string{"alice", "alice ", " alice", "ALICE", " Alice", "ａlice", "alice\t"}
	for attempt, alias := range aliases[:loginMaxFailures] {
		response := serve(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {alias}, "password": {"wrong"}}))
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d (%q): status %d", attempt+1, alias, response.Code)
		}
		loginID = loginIDPattern.FindStringSubmatch(response.Body.String())[1]
	}
	before := method.calls
	for _, alias := range aliases[loginMaxFailures:] {
		response := serve(instance, postForm("/login/corp", url.Values{"login_id": {loginID}, "username": {alias}, "password": {"wrong"}}))
		if response.Code != http.StatusTooManyRequests {
			t.Fatalf("alias %q got through the lockout: %d", alias, response.Code)
		}
		loginID = loginIDPattern.FindStringSubmatch(response.Body.String())[1]
	}
	if method.calls != before {
		t.Fatal("a locked-out alias still reached the directory")
	}
}

// Many sign-in ids can be minted cheaply, so guesses can be sent in parallel.
// The count must be taken before the slow directory answers, not after.
func TestThrottleHoldsUnderParallelGuesses(t *testing.T) {
	method, entry := credentialEntry()
	method.delay = 60 * time.Millisecond
	instance := loginTestServer(t, entry)
	const guesses = 25
	ids := make([]string, guesses)
	for i := range ids {
		ids[i] = loginPageID(t, instance)
	}
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			serve(instance, postForm("/login/corp", url.Values{"login_id": {id}, "username": {"alice"}, "password": {"wrong"}}))
		}(id)
	}
	wg.Wait()
	if method.calls != loginMaxFailures {
		t.Fatalf("%d parallel guesses reached the directory, want %d", method.calls, loginMaxFailures)
	}
}

func TestSubjectPrefixesMustNotCollide(t *testing.T) {
	methods := func(prefixes ...string) []LoginEntry {
		var entries []LoginEntry
		for index, prefix := range prefixes {
			entries = append(entries, LoginEntry{Method: &fakeRedirectMethod{id: fmt.Sprintf("m%d", index)}, SubjectPrefix: prefix})
		}
		return entries
	}
	rejected := map[string][]string{
		"same prefix":          {"a:", "a:"},
		"two empty prefixes":   {"", ""},
		"one begins another":   {"a-", "a-b-"},
		"reversed":             {"a-b-", "a-"},
		"duplicate among many": {"x:", "y:", "x:"},
	}
	for name, prefixes := range rejected {
		if _, err := NewLoginRegistry(methods(prefixes...)...); err == nil {
			t.Errorf("accepted: %s %q", name, prefixes)
		}
	}
	for name, prefixes := range map[string][]string{
		"distinct":                   {"google:", "github:", "corp:"},
		"one empty to keep subjects": {"", "github:"},
		"a single empty":             {""},
	} {
		if _, err := NewLoginRegistry(methods(prefixes...)...); err != nil {
			t.Errorf("rejected %s: %v", name, err)
		}
	}
}

// The sign-in window is set once, when consent is approved. Choosing a
// provider later does not start a fresh window.
func TestProviderRedirectKeepsTheOriginalWindow(t *testing.T) {
	_, credential := credentialEntry()
	instance := loginTestServer(t, credential, LoginEntry{Method: &fakeRedirectMethod{id: "github"}, SubjectPrefix: "github:"})
	clock := time.Now()
	instance.now = func() time.Time { return clock }
	loginID := loginIDFromRedirect(t, authorizeAndApprove(t, instance, defaultBrowser(instance)))
	clock = clock.Add(9 * time.Minute)
	started := serve(instance, postForm("/login/github", url.Values{"login_id": {loginID}}))
	location, _ := url.Parse(started.Header().Get("Location"))
	if location.Host != "idp.example" {
		t.Fatalf("did not leave for the provider: %d", started.Code)
	}
	clock = clock.Add(2 * time.Minute) // 11 minutes after approval
	late := serve(instance, httptest.NewRequest(http.MethodGet, "/identity/callback?code=good&state="+url.QueryEscape(location.Query().Get("state")), nil))
	if late.Code != http.StatusBadRequest {
		t.Fatalf("choosing a provider restarted the window: %d", late.Code)
	}
}

// The record-kind namespace is one layer and the browser binding is another;
// each is checked on its own, because either alone would hide the other's
// removal from a test of the whole flow.
func TestLoginRecordsLiveInTheirOwnNamespace(t *testing.T) {
	_, entry := credentialEntry()
	instance := loginTestServer(t, entry)
	b := newBrowser()
	loginID := loginIDFromRedirect(t, authorizeAndApprove(t, instance, b))
	if loginRecordKey(loginID) == loginID {
		t.Fatal("login record keys are not namespaced")
	}
	// A pending consent request is reachable only by its own id, never through
	// the login key space, and a login record never through the raw id.
	page := b.do(instance, httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=client&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&code_challenge=x&code_challenge_method=S256&resource=http%3A%2F%2Flocalhost%3A8081%2Fmcp", nil))
	if match := consentIDPattern.FindStringSubmatch(page.Body.String()); match != nil {
		if _, err := instance.Store.ConsumeConsentRequest(loginRecordKey(match[1]), time.Now()); err == nil {
			t.Fatal("a consent request was reachable as a login record")
		}
	}
	if _, err := instance.Store.ConsumeConsentRequest(loginID, time.Now()); err == nil {
		t.Fatal("a login record was reachable by its raw id")
	}
	if _, err := instance.Store.ConsumeConsentRequest(loginRecordKey(loginID), time.Now()); err != nil {
		t.Fatalf("the login record is not stored under its namespaced key: %v", err)
	}
}

func TestBindingNeverMatchesWhenEitherSideIsEmpty(t *testing.T) {
	stored := ConsentRequest{Request: AuthorizationRequest{LoginBinding: HashSecret("value")}}
	if !bindingMatches("value", stored) {
		t.Fatal("the genuine value was refused")
	}
	for name, tc := range map[string]struct {
		presented string
		pending   ConsentRequest
	}{
		"wrong value":              {"other", stored},
		"no cookie":                {"", stored},
		"no stored binding":        {"value", ConsentRequest{}},
		"neither side has a value": {"", ConsentRequest{}},
		"the stored hash itself":   {HashSecret("value"), stored},
	} {
		if bindingMatches(tc.presented, tc.pending) {
			t.Errorf("%s: matched", name)
		}
	}
}
