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
	mu       sync.Mutex
	calls    int
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

func serve(instance *Server, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	return recorder
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
		limiter.fail(loginLimiterKey("corp", fmt.Sprintf("user-%d", i)), now)
	}
	if got := len(limiter.failures); got > loginLimiterCapacity {
		t.Fatalf("limiter holds %d keys, capacity is %d", got, loginLimiterCapacity)
	}
	// Failures age out of the window.
	key := loginLimiterKey("corp", "old")
	limiter.fail(key, now.Add(-2*loginWindow))
	if !limiter.allow(key, now) {
		t.Fatal("an expired failure still counts")
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
