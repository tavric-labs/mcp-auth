package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const disabledTestCallback = "https://auth.example.com/identity/callback"

// connectorsFileWithOkta writes a connectors file that defines only "okta".
func connectorsFileWithOkta(t *testing.T) string {
	t.Helper()
	connectors := `{"okta": {
  "issuer": "https://id.example.com", "authorization_endpoint": "https://id.example.com/authorize",
  "token_endpoint": "https://id.example.com/token", "jwks_uri": "https://id.example.com/keys",
  "client_id": "mcp-auth", "client_secret_env": "TEST_OKTA_SECRET", "token_endpoint_auth_method": "client_secret_basic",
  "exchange_client_id": "mcp-auth", "scopes": ["openid", "profile"]}}`
	path := filepath.Join(t.TempDir(), "connectors.json")
	if err := os.WriteFile(path, []byte(connectors), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func parseTolerant(t *testing.T, methods string) (*LoginRegistry, error) {
	t.Helper()
	loginTestEnv(t)
	return ParseLoginMethods([]byte(`{"methods": [`+methods+`]}`), LoginMethodsOptions{
		CallbackURL: disabledTestCallback, ConnectorsFile: connectorsFileWithOkta(t), SkipInvalidMethods: true,
	})
}

const (
	disabledGoogle   = `{"id": "google", "type": "google", "client_id": "x", "client_secret_env": "TEST_GOOGLE_CLIENT_SECRET"}`
	disabledDangling = `{"id": "form-credential-form-demo", "type": "oidc", "connector": "gateway-login-credential-form-demo"}`
)

func TestDanglingLoginMethodIsDisabledNotFatal(t *testing.T) {
	registry, err := parseTolerant(t, disabledGoogle+","+disabledDangling)
	if err != nil {
		t.Fatalf("a dangling method must not stop startup: %v", err)
	}
	if len(registry.entries) != 1 || registry.entries[0].Method.ID() != "google" {
		t.Fatalf("valid methods were not kept: %#v", registry.entries)
	}
	disabled := registry.DisabledMethods()
	if len(disabled) != 1 || disabled[0].ID != "form-credential-form-demo" {
		t.Fatalf("disabled = %#v", disabled)
	}
	if !strings.Contains(disabled[0].Reason, "gateway-login-credential-form-demo") {
		t.Fatalf("reason must name the missing connector: %q", disabled[0].Reason)
	}
	if _, ok := registry.lookup("form-credential-form-demo"); ok {
		t.Fatal("a disabled method can still be looked up")
	}
}

func TestInvalidLoginMethodsStayFatalByDefault(t *testing.T) {
	loginTestEnv(t)
	_, err := ParseLoginMethods([]byte(`{"methods": [`+disabledGoogle+","+disabledDangling+`]}`), LoginMethodsOptions{
		CallbackURL: disabledTestCallback, ConnectorsFile: connectorsFileWithOkta(t),
	})
	if err == nil || !strings.Contains(err.Error(), "gateway-login-credential-form-demo") {
		t.Fatalf("library default must stay strict, got %v", err)
	}
}

func TestOtherInvalidOptionalMethodsAreDisabledToo(t *testing.T) {
	for name, method := range map[string]string{
		"unknown type":            `{"id": "x", "type": "saml"}`,
		"missing type":            `{"id": "x"}`,
		"misspelled field":        `{"id": "x", "type": "google", "client_id": "a", "client_secret_env": "TEST_GOOGLE_CLIENT_SECRET", "allowed_domain": ["example.com"]}`,
		"unset secret env":        `{"id": "x", "type": "google", "client_id": "a", "client_secret_env": "TEST_UNSET_SECRET"}`,
		"oidc without connector":  `{"id": "x", "type": "oidc"}`,
		"downstream no resources": `{"id": "x", "type": "oidc", "connector": "okta", "downstream_token": "upstream_session"}`,
	} {
		registry, err := parseTolerant(t, disabledGoogle+","+method)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(registry.entries) != 1 || len(registry.DisabledMethods()) != 1 || registry.DisabledMethods()[0].ID != "x" {
			t.Errorf("%s: entries=%d disabled=%#v", name, len(registry.entries), registry.DisabledMethods())
		}
	}
}

func TestStartupStillFailsWhereItMustFailClosed(t *testing.T) {
	const resource = `"resources": ["https://mcp.example.com/a/mcp"]`
	for name, document := range map[string]string{
		"not json":                  `{`,
		"unknown top-level key":     `{"methods": [` + disabledGoogle + `], "extra": 1}`,
		"missing id":                `{"methods": [{"type": "google"}]}`,
		"invalid id":                `{"methods": [{"id": "Bad_ID", "type": "saml"}]}`,
		"duplicate id":              `{"methods": [` + disabledGoogle + `,` + disabledGoogle + `]}`,
		"duplicate with disabled":   `{"methods": [{"id": "google", "type": "saml"},` + disabledGoogle + `]}`,
		"bad resources":             `{"methods": [{"id": "x", "type": "saml", "resources": ["not a url"]}]}`,
		"duplicate resources":       `{"methods": [{"id": "x", "type": "saml", "resources": ["https://a.example/mcp", "https://a.example/mcp"]}]}`,
		"subject prefix wrong type": `{"methods": [{"id": "x", "type": "saml", "subject_prefix": 5}]}`,
		"overlapping prefixes":      `{"methods": [` + disabledGoogle + `, {"id": "other", "type": "google", "client_id": "x", "client_secret_env": "TEST_GOOGLE_CLIENT_SECRET", "subject_prefix": "google:x:"}]}`,
		"unreadable connectors":     `{"methods": [{"id": "okta", "type": "oidc", "connector": "okta", ` + resource + `}]}`,
	} {
		loginTestEnv(t)
		options := LoginMethodsOptions{CallbackURL: disabledTestCallback, ConnectorsFile: connectorsFileWithOkta(t), SkipInvalidMethods: true}
		if name == "unreadable connectors" {
			path := filepath.Join(t.TempDir(), "broken.json")
			if err := os.WriteFile(path, []byte(`{"okta": {"issuer": "https://id.example.com"}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			options.ConnectorsFile = path
		}
		if _, err := ParseLoginMethods([]byte(document), options); err == nil {
			t.Errorf("startup accepted %s", name)
		}
	}
}

func TestResourceLoginsStayFatalWithoutResourcesOrPrefix(t *testing.T) {
	loginTestEnv(t)
	path := filepath.Join(t.TempDir(), "logins.json")
	options := LoginMethodsOptions{CallbackURL: disabledTestCallback, ConnectorsFile: connectorsFileWithOkta(t), SkipInvalidMethods: true}
	for name, document := range map[string]string{
		"no resources": `{"methods": [{"id": "okta", "type": "oidc", "connector": "okta"}]}`,
		"empty prefix": `{"methods": [{"id": "okta", "type": "oidc", "connector": "okta", "subject_prefix": "", "resources": ["https://mcp.example.com/a/mcp"]}]}`,
	} {
		if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadResourceLogins(path, options); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}

func TestDisabledResourceLoginDoesNotFallBackToDefaults(t *testing.T) {
	const scoped = "https://mcp.example.com/a/mcp"
	registry, err := parseTolerant(t, disabledGoogle+`,{"id": "gone", "type": "oidc", "connector": "missing", "resources": ["`+scoped+`"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := registry.entriesForResource(scoped); len(got) != 0 {
		t.Fatalf("a resource whose required login is disabled fell back to %d default method(s)", len(got))
	}
	if !registry.servesResource(scoped) {
		t.Fatal("the resource must still count as served by resource logins, so the connector flow cannot take it")
	}
	if len(registry.entriesForResource("https://mcp.example.com/other/mcp")) != 1 {
		t.Fatal("other resources lost their default method")
	}
}

func disabledTestServer(t *testing.T, registry *LoginRegistry) *Server {
	t.Helper()
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

func TestDisabledMethodIsNotOfferedOnTheLoginPage(t *testing.T) {
	registry, err := parseTolerant(t, `{"id": "github", "type": "github", "client_id": "a", "client_secret_env": "TEST_GITHUB_CLIENT_SECRET"},`+
		`{"id": "corp", "type": "ldap", "url": "ldaps://ldap.example.com", "user_dn_template": "uid={username},dc=x", "subject_attribute": "dn"},`+disabledDangling)
	if err != nil {
		t.Fatal(err)
	}
	instance := disabledTestServer(t, registry)
	approved := approveConsent(t, instance)
	location := approved.Header().Get("Location")
	if !strings.Contains(location, "/login?login_id=") {
		t.Fatalf("no login page redirect: %d %q", approved.Code, location)
	}
	page := serve(instance, httptest.NewRequest(http.MethodGet, location, nil))
	body := page.Body.String()
	if !strings.Contains(body, "/login/github") || !strings.Contains(body, "/login/corp") {
		t.Fatalf("valid methods missing from the page: %s", body)
	}
	if strings.Contains(body, "form-credential-form-demo") {
		t.Fatalf("a disabled method is offered: %s", body)
	}
	direct := serve(instance, postForm("/login/form-credential-form-demo", map[string][]string{"login_id": {loginIDPattern.FindStringSubmatch(body)[1]}}))
	if direct.Code < 400 || direct.Header().Get("Location") != "" {
		t.Fatalf("a disabled method can be used directly: %d %s", direct.Code, direct.Header().Get("Location"))
	}
}

func TestResourceWithOnlyADisabledLoginIsDenied(t *testing.T) {
	registry, err := parseTolerant(t, disabledGoogle+`,{"id": "gone", "type": "oidc", "connector": "missing", "resources": ["http://localhost:8081/mcp"]}`)
	if err != nil {
		t.Fatal(err)
	}
	approved := approveConsent(t, disabledTestServer(t, registry))
	location := approved.Header().Get("Location")
	if !strings.Contains(location, "error=access_denied") || strings.Contains(location, "/login") {
		t.Fatalf("expected access_denied, got %d %q", approved.Code, location)
	}
}

func TestReadyzReportsDisabledLoginMethods(t *testing.T) {
	registry, err := parseTolerant(t, disabledGoogle+","+disabledDangling)
	if err != nil {
		t.Fatal(err)
	}
	instance := disabledTestServer(t, registry)
	response := httptest.NewRecorder()
	instance.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("readyz status = %d", response.Code)
	}
	var body struct {
		Status   string   `json:"status"`
		Disabled []string `json:"login_methods_disabled"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "ready" || len(body.Disabled) != 1 || body.Disabled[0] != "form-credential-form-demo" {
		t.Fatalf("readyz = %s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "gateway-login") {
		t.Fatal("readyz must not expose connector names or error details")
	}

	healthy := disabledTestServer(t, mustRegistry(t, disabledGoogle))
	response = httptest.NewRecorder()
	healthy.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if strings.TrimSpace(response.Body.String()) != `{"status":"ready"}` {
		t.Fatalf("a healthy server's readyz changed: %s", response.Body.String())
	}
}

func mustRegistry(t *testing.T, methods string) *LoginRegistry {
	t.Helper()
	registry, err := parseTolerant(t, methods)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestDisabledResourceLoginDoesNotFallBackToTheConnectorFlow(t *testing.T) {
	registry, err := parseTolerant(t, `{"id": "gone", "type": "oidc", "connector": "missing", "resources": ["http://localhost:8081/mcp"]}`)
	if err != nil {
		t.Fatal(err)
	}
	instance := disabledTestServer(t, mustRegistry(t, disabledGoogle))
	instance.IdentityProvider = LocalIdentityProvider{Subject: "connector-user"}
	instance.ResourceLogins = registry
	approved := approveConsent(t, instance)
	location := approved.Header().Get("Location")
	if !strings.Contains(location, "error=access_denied") || strings.Contains(location, "code=") {
		t.Fatalf("the resource was signed in through the connector flow: %d %q", approved.Code, location)
	}
}
