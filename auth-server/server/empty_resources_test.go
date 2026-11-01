package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestResourceEnvironmentDistinguishesUnsetAndExplicitEmpty(t *testing.T) {
	t.Setenv("MCP_AUTH_RESOURCES", "")
	t.Setenv("MCP_AUTH_RESOURCE", "https://ignored.example.test/mcp")
	if err := os.Unsetenv("MCP_AUTH_RESOURCES"); err != nil {
		t.Fatal(err)
	}
	if got := ConfigFromEnv().Resources; len(got) != 1 || got[0] != "http://localhost:8081/mcp" {
		t.Fatalf("unset resources lost the development default: %v", got)
	}
	for _, value := range []string{"", " ", ","} {
		t.Setenv("MCP_AUTH_RESOURCES", value)
		if got := ConfigFromEnv().Resources; got == nil || len(got) != 0 {
			t.Fatalf("explicit resources %q must be an empty allowlist, got %v", value, got)
		}
	}
}

func TestExplicitEmptyResourcesPreserveDeploymentValidation(t *testing.T) {
	config := Config{
		Issuer: "https://auth.example.test/mcp-auth", Resources: []string{},
		RequireHTTPS: true, PrivateKeyFile: "/keys/signing.pem",
		StoreBackend: "sqlite", DatabaseURL: "/data/auth.db",
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("explicit empty allowlist must support strict startup: %v", err)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.Resources = nil },
		func(c *Config) { c.Issuer = "http://auth.example.test" },
		func(c *Config) { c.Resources = []string{"http://mcp.example.test/mcp"} },
		func(c *Config) { c.PrivateKeyFile = "" },
		func(c *Config) { c.StoreBackend = "memory" },
	} {
		invalid := config
		change(&invalid)
		if err := invalid.Validate(); err == nil {
			t.Fatalf("accepted invalid deployment: %+v", invalid)
		}
	}
}

func TestEmptyResourcesServeDiscoveryAndDenyRemovedGrants(t *testing.T) {
	seed := testServer(t)
	config := seed.Config
	config.Issuer = "https://auth.example.test/mcp-auth"
	config.RequireHTTPS = true
	config.LocalDevelopment = false
	config.Resources = []string{}
	instance, err := NewServerWithKeyProvider(config, seed.Store, seed.IdentityProvider, nil, seed.KeyProvider, io.Discard)
	if err != nil {
		t.Fatalf("empty allowlist must start: %v", err)
	}
	serve := func(method, path string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		request := httptest.NewRequest(method, "https://auth.example.test"+path, body)
		if form != nil {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		recorder := httptest.NewRecorder()
		instance.Handler().ServeHTTP(recorder, request)
		return recorder
	}
	checkDiscovery := func() {
		t.Helper()
		for _, path := range []string{"/.well-known/oauth-authorization-server/mcp-auth", "/.well-known/openid-configuration/mcp-auth", "/.well-known/jwks.json", "/readyz"} {
			if got := serve(http.MethodGet, path, nil); got.Code != http.StatusOK {
				t.Fatalf("empty resources %s: %d %s", path, got.Code, got.Body.String())
			}
		}
		if got := serve(http.MethodGet, "/.well-known/oauth-protected-resource", nil); got.Code != http.StatusNotFound {
			t.Fatalf("empty resources advertised a resource: %d %s", got.Code, got.Body.String())
		}
	}
	checkDiscovery()
	const resource = "https://mcp.example.test/mcp"
	const verifier = "empty-allowlist-lifecycle-verifier"
	digest := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"response_type": {"code"}, "client_id": {"client"},
		"redirect_uri":   {"http://localhost:9999/callback"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
		"resource": {resource}, "scope": {"tools:read"},
	}
	authorize := func() *httptest.ResponseRecorder { return serve(http.MethodGet, "/authorize?"+query.Encode(), nil) }
	if got := authorize(); got.Code != http.StatusBadRequest || got.Header().Get("Location") != "" {
		t.Fatalf("empty allowlist authorized a resource: %d %s", got.Code, got.Body.String())
	}
	instance.Config.Resources = []string{resource}
	codeForm := func() url.Values {
		t.Helper()
		got := authorize()
		if got.Code != http.StatusOK {
			t.Fatalf("configured resource did not offer consent: %d", got.Code)
		}
		_, field, found := strings.Cut(got.Body.String(), `name="consent_id" value="`)
		consentID, _, closed := strings.Cut(field, `"`)
		if !found || !closed || consentID == "" {
			t.Fatal("consent form has no request identifier")
		}
		got = serve(http.MethodPost, "/authorize/consent", url.Values{"consent_id": {consentID}, "decision": {"approve"}})
		if got.Code != http.StatusFound {
			t.Fatalf("configured resource could not authorize: %d %s", got.Code, got.Body.String())
		}
		redirect, err := url.Parse(got.Header().Get("Location"))
		if err != nil || redirect.Query().Get("code") == "" {
			t.Fatalf("missing authorization code: %v", err)
		}
		return url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "code": {redirect.Query().Get("code")},
			"redirect_uri": {"http://localhost:9999/callback"}, "code_verifier": {verifier}, "resource": {resource}}
	}
	tokens := serve(http.MethodPost, "/token", codeForm())
	var grant struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(tokens.Body.Bytes(), &grant); err != nil || tokens.Code != http.StatusOK || grant.AccessToken == "" || grant.RefreshToken == "" {
		t.Fatalf("configured resource token issuance: %d %s", tokens.Code, tokens.Body.String())
	}
	pendingCode := codeForm()
	config = instance.Config
	config.Resources = []string{}
	instance, err = NewServerWithKeyProvider(config, seed.Store, seed.IdentityProvider, nil, seed.KeyProvider, io.Discard)
	if err != nil {
		t.Fatalf("removing the last resource must permit restart: %v", err)
	}
	checkDiscovery()
	if got := authorize(); got.Code != http.StatusBadRequest {
		t.Fatalf("removed resource authorized: %d %s", got.Code, got.Body.String())
	}
	for _, form := range []url.Values{pendingCode, {"grant_type": {"refresh_token"}, "client_id": {"client"}, "refresh_token": {grant.RefreshToken}}} {
		got := serve(http.MethodPost, "/token", form)
		var denied struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &denied); err != nil || got.Code != http.StatusBadRequest || denied.Error != "invalid_target" {
			t.Fatalf("removed resource issued tokens: %d %s", got.Code, got.Body.String())
		}
	}
}
