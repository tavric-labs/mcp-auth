package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStartupErrorsDoNotExposeConfigurationContents(t *testing.T) {
	for _, name := range []string{"MCP_AUTH_CONNECTOR", "MCP_AUTH_CONNECTORS_FILE", "MCP_AUTH_LOGIN_METHODS_FILE", "MCP_AUTH_PRIVATE_KEY_FILE", "MCP_AUTH_EXTERNAL_CREDENTIALS_FILE", "MCP_AUTH_RESOURCE_CLIENTS_FILE"} {
		t.Setenv(name, "")
	}
	t.Setenv("MCP_AUTH_ISSUER", "http://127.0.0.1:8080")
	t.Setenv("MCP_AUTH_RESOURCES", "http://127.0.0.1:8090/demo/mcp")
	t.Setenv("MCP_AUTH_LOCAL_DEVELOPMENT", "true")
	t.Setenv("MCP_AUTH_REQUIRE_HTTPS", "false")
	t.Setenv("MCP_AUTH_STORE", "memory")
	path := filepath.Join(t.TempDir(), "sensitive-config-content.json")
	if err := os.WriteFile(path, []byte(`{"provider":{"password":"fixture-sensitive-value"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCP_AUTH_CREDENTIAL_GATEWAY_CONFIG", path)
	err := run()
	if err == nil || !strings.Contains(err.Error(), "credential gateway initialization failed") {
		t.Fatal("missing startup phase")
	}
	if strings.Contains(err.Error(), "fixture-sensitive") || strings.Contains(err.Error(), path) {
		t.Fatal("startup error exposes private configuration")
	}
}
