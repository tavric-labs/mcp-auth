package server

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	gatewayResource = "https://mcp.example/headers/mcp"
	otherResource   = "https://mcp.example/other/mcp"
)

// connectorServer is a server whose identity provider is a single connector
// (a fixed-subject local one here) with a redirect login assigned to one resource.
func connectorServer(t *testing.T) *Server {
	t.Helper()
	logins, err := NewLoginRegistry(LoginEntry{Method: &fakeRedirectMethod{id: "gateway"}, SubjectPrefix: "gateway:", Resources: []string{gatewayResource}})
	if err != nil {
		t.Fatal(err)
	}
	config := Config{
		Issuer: "http://localhost:8080", Resources: []string{gatewayResource, otherResource},
		AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour, AuthorizationCodeTTL: time.Minute,
		AllowedScopes: []string{"tools:read"}, LocalDevelopment: true,
	}
	instance, err := NewServer(config, NewMemoryStore(), LocalIdentityProvider{Subject: "connector-user"}, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	instance.ResourceLogins = logins
	if err := instance.Store.SaveClient(Client{ID: "client", RedirectURIs: []string{"http://localhost:9999/callback"}, TokenEndpointAuth: "none"}); err != nil {
		t.Fatal(err)
	}
	return instance
}

// consentFor runs /authorize and the consent approval for a resource.
func consentFor(t *testing.T, instance *Server, resource string) *httptest.ResponseRecorder {
	t.Helper()
	digest := sha256.Sum256([]byte("verifier-1234567890"))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	authorize := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=client&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&code_challenge="+url.QueryEscape(challenge)+"&code_challenge_method=S256&resource="+url.QueryEscape(resource)+"&scope=tools%3Aread&state=client-state", nil)
	page := serve(instance, authorize)
	match := consentIDPattern.FindStringSubmatch(page.Body.String())
	if page.Code != http.StatusOK || match == nil {
		t.Fatalf("authorize did not render consent: %d %s", page.Code, page.Body.String())
	}
	return serve(instance, postForm("/authorize/consent", url.Values{"consent_id": {match[1]}, "decision": {"approve"}}))
}

func TestResourceLoginRedirectsOnlyItsResourceAndCompletesThroughTheCallback(t *testing.T) {
	instance := connectorServer(t)
	approved := consentFor(t, instance, gatewayResource)
	location := approved.Header().Get("Location")
	if !strings.HasPrefix(location, "https://idp.example/authorize?state=gateway.") {
		t.Fatalf("the resource login did not take over: %d %q", approved.Code, location)
	}
	state, _ := url.Parse(location)
	callback := serve(instance, httptest.NewRequest(http.MethodGet, "/identity/callback?code=good&state="+url.QueryEscape(state.Query().Get("state")), nil))
	redirect, _ := url.Parse(callback.Header().Get("Location"))
	if redirect.Host != "localhost:9999" || redirect.Query().Get("code") == "" {
		t.Fatalf("callback did not issue a code: %d %s", callback.Code, callback.Header().Get("Location"))
	}
	code, err := instance.Store.ConsumeAuthorizationCode(redirect.Query().Get("code"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code.Subject != "gateway:u1" {
		t.Fatalf("subject = %q, want the prefixed gateway:u1", code.Subject)
	}
}

func TestOtherResourcesKeepTheConnectorFlow(t *testing.T) {
	instance := connectorServer(t)
	approved := consentFor(t, instance, otherResource)
	redirect, _ := url.Parse(approved.Header().Get("Location"))
	if redirect.Host != "localhost:9999" || redirect.Query().Get("code") == "" {
		t.Fatalf("another resource left the connector flow: %d %s", approved.Code, approved.Header().Get("Location"))
	}
	code, err := instance.Store.ConsumeAuthorizationCode(redirect.Query().Get("code"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code.Subject != "connector-user" {
		t.Fatalf("subject = %q, want the connector's own subject", code.Subject)
	}
}

func TestResourceLoginCallbackRejectsUnknownMethodStates(t *testing.T) {
	instance := connectorServer(t)
	for _, state := range []string{"unknown.abc", "gateway", "gateway.never-issued", ""} {
		callback := serve(instance, httptest.NewRequest(http.MethodGet, "/identity/callback?code=good&state="+url.QueryEscape(state), nil))
		if callback.Code == http.StatusSeeOther || callback.Code == http.StatusFound {
			t.Errorf("state %q was accepted: %d %s", state, callback.Code, callback.Header().Get("Location"))
		}
	}
}

func TestLoadResourceLoginsRequiresScopeAndPrefix(t *testing.T) {
	loginTestEnv(t)
	write := func(method string) string {
		path := filepath.Join(t.TempDir(), "logins.json")
		if err := os.WriteFile(path, []byte(`{"methods":[`+method+`]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	base := `{"id":"google","type":"google","client_id":"x","client_secret_env":"TEST_GOOGLE_CLIENT_SECRET"`
	options := LoginMethodsOptions{CallbackURL: "https://auth.example.com/identity/callback"}
	if _, err := LoadResourceLogins(write(base+`,"resources":["`+gatewayResource+`"]}`), options); err != nil {
		t.Fatalf("a scoped method with the default prefix was rejected: %v", err)
	}
	for name, method := range map[string]string{
		"unscoped":     base + `}`,
		"empty prefix": base + `,"resources":["` + gatewayResource + `"],"subject_prefix":""}`,
	} {
		if _, err := LoadResourceLogins(write(method), options); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}
