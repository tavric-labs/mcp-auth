package server

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
)

// The examples in docs/connectors.md must keep loading.
func TestOAuth2OnlyConnectorExampleLoads(t *testing.T) {
	t.Setenv("EXAMPLE_OAUTH2_CLIENT_ID", "client")
	t.Setenv("EXAMPLE_OAUTH2_CLIENT_SECRET", "secret")
	connectors, err := LoadConnectors("../../examples/connectors.oauth2-only.example.json")
	if err != nil {
		t.Fatal(err)
	}
	connector := connectors["example-oauth2"]
	if connector.usesPKCE() || connector.requiresIDToken() || connector.requiresIDTokenNonce() {
		t.Fatalf("example must be OAuth 2.0 only, without PKCE or a nonce: %+v", connector)
	}
	registry, err := LoadLoginMethods("../../examples/login-methods.oauth2-only.example.json", LoginMethodsOptions{
		CallbackURL: "https://auth.example.com/identity/callback", ConnectorsFile: "../../examples/connectors.oauth2-only.example.json",
	})
	if err != nil || registry.EnabledCount() != 1 {
		t.Fatalf("methods example: %v", err)
	}
}

// minimalRedirectMethod is the complete example in docs/connectors.md.
type minimalRedirectMethod struct{ id string }

func (m minimalRedirectMethod) ID() string    { return m.id }
func (m minimalRedirectMethod) Label() string { return "Sign in with Example" }
func (m minimalRedirectMethod) Begin(_ context.Context, _ IdentityRequest, state string) (string, string, error) {
	return "https://provider.example.com/authorize?" + url.Values{"state": {state}}.Encode(), "verifier", nil
}
func (m minimalRedirectMethod) Complete(_ context.Context, callback IdentityCallback) (Identity, error) {
	if callback.Code != "good" {
		return Identity{}, errors.New("provider refused the code")
	}
	return Identity{Subject: "user-123"}, nil
}

func TestMinimalCustomMethodRegisters(t *testing.T) {
	registry, err := NewLoginRegistry(LoginEntry{Method: minimalRedirectMethod{id: "example"}, SubjectPrefix: "example:"})
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := registry.lookup("example")
	if !ok {
		t.Fatal("method not registered")
	}
	identity, err := entry.qualify(Identity{Subject: "user-123"})
	if err != nil || !strings.HasPrefix(identity.Subject, "example:") {
		t.Fatalf("subject = %q, %v", identity.Subject, err)
	}
}
