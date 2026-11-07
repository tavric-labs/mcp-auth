package application

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Agent-Hellboy/mcp-auth/auth-server/server"
)

func TestCopyConsentDoesNotAliasConnectorConfig(t *testing.T) {
	in := &server.ConsentConfig{
		DisplayName:     "Inventory",
		WebsiteURL:      "https://inventory.example.com",
		IntroParagraphs: []string{"Review this request."},
		Permissions:     []string{"Read inventory records"},
		ScopeLabels:     map[string]string{"tools:read": "Read data through tools"},
	}
	out := copyConsent(in)
	in.ScopeLabels["tools:read"] = "changed"
	in.IntroParagraphs[0] = "changed"
	in.Permissions[0] = "changed"
	in.DisplayName = "changed"
	if out.DisplayName != "Inventory" || out.IntroParagraphs[0] != "Review this request." || out.Permissions[0] != "Read inventory records" {
		t.Fatalf("consent copy aliased the connector: %+v", out)
	}
	if out.ScopeLabels["tools:read"] != "Read data through tools" {
		t.Fatalf("scope_labels were aliased: %+v", out.ScopeLabels)
	}
	if copyConsent(nil) != nil {
		t.Fatal("nil consent config was copied")
	}
}

func TestRegisterResourceExchangersServesOnlyResourcesThatKeepASession(t *testing.T) {
	t.Setenv("TEST_LINKEDIN_SECRET", "secret")
	connectors := filepath.Join(t.TempDir(), "connectors.json")
	if err := os.WriteFile(connectors, []byte(`{"linkedin": {
  "issuer": "https://www.linkedin.com/oauth", "authorization_endpoint": "https://www.linkedin.com/oauth/v2/authorization",
  "token_endpoint": "https://www.linkedin.com/oauth/v2/accessToken", "jwks_uri": "https://www.linkedin.com/oauth/openid/jwks",
  "client_id": "linkedin-client", "client_secret_env": "TEST_LINKEDIN_SECRET", "token_endpoint_auth_method": "client_secret_post",
  "exchange_client_id": "linkedin-client", "scopes": ["openid", "profile"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	const kept, plain = "https://mcp.example.com/linkedin/mcp", "https://mcp.example.com/other/mcp"
	logins, err := server.ParseLoginMethods([]byte(`{"methods": [
  {"id":"linkedin","type":"oidc","connector":"linkedin","resources":["`+kept+`"],"downstream_token":"upstream_session"},
  {"id":"other","type":"oidc","connector":"linkedin","resources":["`+plain+`"]}]}`),
		server.LoginMethodsOptions{CallbackURL: "https://auth.example.com/identity/callback", ConnectorsFile: connectors})
	if err != nil {
		t.Fatal(err)
	}
	auth := &server.Server{}
	if err := registerResourceExchangers(auth, server.NewMemoryStore(), logins); err != nil {
		t.Fatal(err)
	}
	if _, ok := auth.ResourceExchangers[kept].(*server.UpstreamSessionExchanger); !ok {
		t.Fatalf("no upstream session exchanger for the resource that keeps its session: %#v", auth.ResourceExchangers)
	}
	if _, ok := auth.ResourceExchangers[plain]; ok {
		t.Fatal("a resource whose login keeps nothing got an exchanger")
	}
}
