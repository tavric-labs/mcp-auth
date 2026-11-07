package server

import (
	"os"
	"path/filepath"
	"testing"
)

const downstreamResource = "https://mcp.example.com/linkedin/mcp"

// downstreamConnectors writes a connectors file with one OIDC provider and
// returns its path.
func downstreamConnectors(t *testing.T) string {
	t.Helper()
	loginTestEnv(t)
	connectors := `{"linkedin": {
  "issuer": "https://www.linkedin.com/oauth", "authorization_endpoint": "https://www.linkedin.com/oauth/v2/authorization",
  "token_endpoint": "https://www.linkedin.com/oauth/v2/accessToken", "jwks_uri": "https://www.linkedin.com/oauth/openid/jwks",
  "client_id": "linkedin-client", "client_secret_env": "TEST_OKTA_SECRET", "token_endpoint_auth_method": "client_secret_post",
  "exchange_client_id": "linkedin-client", "scopes": ["openid", "profile", "w_member_social"]}}`
	path := filepath.Join(t.TempDir(), "connectors.json")
	if err := os.WriteFile(path, []byte(connectors), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func parseDownstream(t *testing.T, methods string) (*LoginRegistry, error) {
	t.Helper()
	path := downstreamConnectors(t)
	return ParseLoginMethods([]byte(`{"methods": [`+methods+`]}`), LoginMethodsOptions{
		CallbackURL: "https://auth.example.com/identity/callback", ConnectorsFile: path,
	})
}

func TestOIDCLoginMethodCanKeepItsUpstreamSession(t *testing.T) {
	registry, err := parseDownstream(t, `{"id":"linkedin","type":"oidc","connector":"linkedin","resources":["`+downstreamResource+`"],"downstream_token":"upstream_session"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !registry.entries[0].KeepUpstreamSession {
		t.Fatal("the entry did not opt in to keeping the upstream session")
	}
	connector, ok := registry.UpstreamSessionConnectors()[downstreamResource]
	if !ok || connector.ClientID != "linkedin-client" {
		t.Fatalf("connector for the resource = %+v, %v", connector, ok)
	}
}

func TestOIDCLoginMethodKeepsNothingByDefault(t *testing.T) {
	registry, err := parseDownstream(t, `{"id":"linkedin","type":"oidc","connector":"linkedin","resources":["`+downstreamResource+`"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if registry.entries[0].KeepUpstreamSession || len(registry.UpstreamSessionConnectors()) != 0 {
		t.Fatal("a login without downstream_token must not keep the upstream session")
	}
}

func TestDownstreamTokenIsRejectedWhenItCannotWork(t *testing.T) {
	resource := `"resources":["` + downstreamResource + `"]`
	oidc := `{"id":"linkedin","type":"oidc","connector":"linkedin",`
	for name, methods := range map[string]string{
		"unknown strategy": oidc + resource + `,"downstream_token":"rfc8693"}`,
		"no resources":     oidc + `"downstream_token":"upstream_session"}`,
		"unsupported type": `{"id":"google","type":"google","client_id":"x","client_secret_env":"TEST_GOOGLE_CLIENT_SECRET",` + resource + `,"downstream_token":"upstream_session"}`,
		"two methods, one resource": oidc + resource + `,"downstream_token":"upstream_session"},` +
			`{"id":"linkedin2","type":"oidc","connector":"linkedin",` + resource + `,"downstream_token":"upstream_session"}`,
	} {
		if _, err := parseDownstream(t, methods); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}
