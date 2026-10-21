package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func loginTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("TEST_GOOGLE_CLIENT_SECRET", "g-secret")
	t.Setenv("TEST_GITHUB_CLIENT_SECRET", "gh-secret")
	t.Setenv("TEST_LDAP_BIND_PASSWORD", "service-secret")
	t.Setenv("TEST_OKTA_SECRET", "okta-secret")
}

const allMethodsDocument = `{"methods": [
  {"id": "google", "type": "google", "client_id": "123.apps.googleusercontent.com", "client_secret_env": "TEST_GOOGLE_CLIENT_SECRET", "allowed_domains": ["example.com"]},
  {"id": "github", "type": "github", "label": "Use GitHub", "client_id": "Iv1.abc", "client_secret_env": "TEST_GITHUB_CLIENT_SECRET", "allowed_orgs": ["acme"]},
  {"id": "corp", "type": "ldap", "url": "ldaps://ldap.example.com", "bind_dn": "cn=svc,dc=example,dc=com", "bind_password_env": "TEST_LDAP_BIND_PASSWORD",
   "user_search_base": "ou=people,dc=example,dc=com", "user_filter": "(uid={username})", "subject_attribute": "entryUUID", "claims": {"email": "mail"}}
]}`

func TestParseLoginMethodsBuildsEveryType(t *testing.T) {
	loginTestEnv(t)
	registry, err := ParseLoginMethods([]byte(allMethodsDocument), LoginMethodsOptions{CallbackURL: "https://auth.example.com/identity/callback"})
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.entries) != 3 {
		t.Fatalf("entries = %d", len(registry.entries))
	}
	want := []struct{ id, label, prefix string }{
		{"google", "Sign in with Google", "google:"},
		{"github", "Use GitHub", "github:"},
		{"corp", "Sign in with your directory account", "corp:"},
	}
	for index, entry := range registry.entries {
		if entry.Method.ID() != want[index].id || entry.Method.Label() != want[index].label || entry.SubjectPrefix != want[index].prefix {
			t.Errorf("entry %d = %s %q %q, want %+v", index, entry.Method.ID(), entry.Method.Label(), entry.SubjectPrefix, want[index])
		}
	}
	if _, ok := registry.entries[2].Method.(CredentialLoginMethod); !ok {
		t.Error("ldap must be a credential method")
	}
	if _, ok := registry.entries[0].Method.(RedirectLoginMethod); !ok {
		t.Error("google must be a redirect method")
	}
}

func TestParseLoginMethodsSubjectPrefixOverride(t *testing.T) {
	loginTestEnv(t)
	document := `{"methods": [{"id": "github", "type": "github", "client_id": "x", "client_secret_env": "TEST_GITHUB_CLIENT_SECRET", "subject_prefix": ""}]}`
	registry, err := ParseLoginMethods([]byte(document), LoginMethodsOptions{CallbackURL: "https://auth.example.com/identity/callback"})
	if err != nil {
		t.Fatal(err)
	}
	if registry.entries[0].SubjectPrefix != "" {
		t.Fatalf("an explicit empty subject_prefix must be kept, got %q", registry.entries[0].SubjectPrefix)
	}
	document = strings.Replace(document, `"subject_prefix": ""`, `"subject_prefix": "gh|"`, 1)
	registry, err = ParseLoginMethods([]byte(document), LoginMethodsOptions{CallbackURL: "https://auth.example.com/identity/callback"})
	if err != nil || registry.entries[0].SubjectPrefix != "gh|" {
		t.Fatalf("custom prefix = %q err %v", registry.entries[0].SubjectPrefix, err)
	}
}

func TestParseLoginMethodsRejectsBadDocuments(t *testing.T) {
	loginTestEnv(t)
	google := `{"id": "google", "type": "google", "client_id": "x", "client_secret_env": "TEST_GOOGLE_CLIENT_SECRET"`
	rejected := map[string]string{
		"not json":                  `{`,
		"trailing content":          `{"methods": [` + google + `}]} {}`,
		"unknown top-level key":     `{"methods": [` + google + `}], "extra": 1}`,
		"no methods":                `{"methods": []}`,
		"missing id":                `{"methods": [{"type": "google"}]}`,
		"missing type":              `{"methods": [{"id": "x"}]}`,
		"unknown type":              `{"methods": [{"id": "x", "type": "saml"}]}`,
		"duplicate id":              `{"methods": [` + google + `}, ` + google + `}]}`,
		"uppercase id":              `{"methods": [{"id": "Google", "type": "google", "client_id": "x", "client_secret_env": "TEST_GOOGLE_CLIENT_SECRET"}]}`,
		"misspelled google field":   `{"methods": [` + google + `, "allowed_domain": ["example.com"]}]}`,
		"ldap field on google":      `{"methods": [` + google + `, "url": "ldaps://x"}]}`,
		"google field on ldap":      `{"methods": [{"id": "corp", "type": "ldap", "client_id": "x"}]}`,
		"secret env empty":          `{"methods": [{"id": "google", "type": "google", "client_id": "x", "client_secret_env": "TEST_UNSET_SECRET"}]}`,
		"oidc without connector":    `{"methods": [{"id": "okta", "type": "oidc"}]}`,
		"oidc without a file":       `{"methods": [{"id": "okta", "type": "oidc", "connector": "okta"}]}`,
		"ldap without subject":      `{"methods": [{"id": "corp", "type": "ldap", "url": "ldaps://x", "user_dn_template": "uid={username},dc=x"}]}`,
		"bad allowed domain":        `{"methods": [{"id": "google", "type": "google", "client_id": "x", "client_secret_env": "TEST_GOOGLE_CLIENT_SECRET", "allowed_domains": ["@example.com"]}]}`,
		"subject prefix wrong type": `{"methods": [` + google + `, "subject_prefix": 5}]}`,
	}
	for name, document := range rejected {
		if _, err := ParseLoginMethods([]byte(document), LoginMethodsOptions{CallbackURL: "https://auth.example.com/identity/callback"}); err == nil {
			t.Errorf("accepted: %s", name)
		}
	}
}

func TestParseLoginMethodsErrorNamesTheMethod(t *testing.T) {
	loginTestEnv(t)
	_, err := ParseLoginMethods([]byte(`{"methods": [{"id": "corp", "type": "ldap", "url": "ldap://ldap.example.com", "user_dn_template": "uid={username},dc=x", "subject_attribute": "dn"}]}`),
		LoginMethodsOptions{CallbackURL: "https://auth.example.com/identity/callback"})
	if err == nil || !strings.Contains(err.Error(), `"corp"`) || !strings.Contains(err.Error(), "start_tls") {
		t.Fatalf("error should name the method and the problem, got: %v", err)
	}
}

func TestParseLoginMethodsAnonymousLDAPSearch(t *testing.T) {
	document := `{"methods":[{"id":"directory","type":"ldap","url":"ldaps://ldap.example.com","anonymous_search":true,"user_search_base":"ou=people,dc=example,dc=com","user_filter":"(uid={username})","subject_attribute":"entryUUID"}]}`
	registry, err := ParseLoginMethods([]byte(document), LoginMethodsOptions{})
	if err != nil {
		t.Fatal(err)
	}
	method, ok := registry.entries[0].Method.(*LDAPLoginMethod)
	if !ok || !method.config.AnonymousSearch || method.config.BindDN != "" || method.bindPassword != "" {
		t.Fatal("anonymous search was not loaded independently of service credentials")
	}
	// Omitting the flag must never silently downgrade a missing service bind.
	document = strings.Replace(document, `"anonymous_search":true,`, "", 1)
	if _, err := ParseLoginMethods([]byte(document), LoginMethodsOptions{}); err == nil {
		t.Fatal("missing service credentials implicitly enabled anonymous search")
	}
}

func TestLoadAnonymousLDAPExample(t *testing.T) {
	registry, err := LoadLoginMethods("../../examples/login-methods.ldap.example.json", LoginMethodsOptions{})
	if err != nil {
		t.Fatal(err)
	}
	method, ok := registry.entries[0].Method.(*LDAPLoginMethod)
	if !ok || !method.config.AnonymousSearch || method.config.SubjectAttribute != "entryUUID" {
		t.Fatal("LDAP example must use explicit anonymous search and a stable subject")
	}
}

func TestParseLoginMethodsOIDCUsesAConnectorsFile(t *testing.T) {
	loginTestEnv(t)
	connectors := `{"okta": {
  "issuer": "https://id.example.com", "authorization_endpoint": "https://id.example.com/authorize",
  "token_endpoint": "https://id.example.com/token", "jwks_uri": "https://id.example.com/keys",
  "client_id": "mcp-auth", "client_secret_env": "TEST_OKTA_SECRET", "token_endpoint_auth_method": "client_secret_basic",
  "exchange_client_id": "mcp-auth", "scopes": ["openid", "profile"]}}`
	path := filepath.Join(t.TempDir(), "connectors.json")
	if err := os.WriteFile(path, []byte(connectors), 0o600); err != nil {
		t.Fatal(err)
	}
	document := `{"methods": [{"id": "okta", "type": "oidc", "connector": "okta"}]}`
	registry, err := ParseLoginMethods([]byte(document), LoginMethodsOptions{CallbackURL: "https://auth.example.com/identity/callback", ConnectorsFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if registry.entries[0].Method.Label() != "Sign in with okta" {
		t.Fatalf("label = %q", registry.entries[0].Method.Label())
	}
	redirect := registry.entries[0].Method.(RedirectLoginMethod)
	location, _, err := redirect.Begin(context.Background(), IdentityRequest{Nonce: "n"}, "okta.s")
	if err != nil || !strings.HasPrefix(location, "https://id.example.com/authorize?") {
		t.Fatalf("Begin = %q, %v", location, err)
	}
	missing := `{"methods": [{"id": "okta", "type": "oidc", "connector": "nope"}]}`
	if _, err := ParseLoginMethods([]byte(missing), LoginMethodsOptions{CallbackURL: "https://auth.example.com/identity/callback", ConnectorsFile: path}); err == nil {
		t.Fatal("an unknown connector name was accepted")
	}
}

func TestLoadLoginMethodsMissingFile(t *testing.T) {
	if _, err := LoadLoginMethods(filepath.Join(t.TempDir(), "absent.json"), LoginMethodsOptions{}); err == nil {
		t.Fatal("a missing file was accepted")
	}
}

func TestConfigRejectsLoginMethodsWithASingleConnector(t *testing.T) {
	base := func() Config {
		return Config{
			Issuer: "https://auth.example.com", Resources: []string{"https://mcp.example.com/mcp"},
			RequireHTTPS: true, PrivateKeyFile: "key.pem", StoreBackend: "sqlite",
			DatabaseURL: "/tmp/x.db", AllowedScopes: []string{"tools:read"},
		}
	}
	both := base()
	both.LoginMethodsFile, both.ConnectorsFile, both.ConnectorName = "methods.json", "connectors.json", "okta"
	if err := both.Validate(); err == nil {
		t.Error("login methods and a single connector were both accepted")
	}
	// A connectors file alone is fine when login methods reference it by name.
	referenced := base()
	referenced.LoginMethodsFile, referenced.ConnectorsFile = "methods.json", "connectors.json"
	if err := referenced.Validate(); err != nil {
		t.Errorf("a connectors file referenced by login methods was rejected: %v", err)
	}
	// The old requirement still holds without login methods.
	legacy := base()
	legacy.ConnectorsFile = "connectors.json"
	if err := legacy.Validate(); err == nil {
		t.Error("a connectors file without MCP_AUTH_CONNECTOR was accepted outside login-methods mode")
	}
}

func TestLoginEndpointAndTTL(t *testing.T) {
	for issuer, want := range map[string]string{
		"https://auth.example.com":       "https://auth.example.com/login",
		"https://auth.example.com/":      "https://auth.example.com/login",
		"https://auth.example.com/oauth": "https://auth.example.com/oauth/login",
	} {
		if got := (Config{Issuer: issuer}).LoginEndpoint(); got != want {
			t.Errorf("LoginEndpoint(%q) = %q, want %q", issuer, got, want)
		}
	}
	if got := (Config{}).loginTTL(); got != defaultLoginTTL {
		t.Errorf("default login TTL = %s", got)
	}
	if got := (Config{LoginTTL: 3 * time.Minute}).loginTTL(); got.Minutes() != 3 {
		t.Errorf("configured login TTL = %s", got)
	}
}
