package application

import (
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
