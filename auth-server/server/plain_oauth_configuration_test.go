package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestPlainOAuthConnectorDoesNotRequireOIDCDiscovery(t *testing.T) {
	var discoveryCalls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { discoveryCalls.Add(1); http.NotFound(w, r) }))
	defer provider.Close()
	connector := map[string]any{"gateway": map[string]any{"issuer": provider.URL + "/login", "authorization_endpoint": provider.URL + "/authorize", "token_endpoint": provider.URL + "/token", "userinfo_endpoint": provider.URL + "/userinfo", "client_id": "broker", "exchange_client_id": "unused", "token_endpoint_auth_method": "none", "scopes": []string{"profile"}}}
	data, _ := json.Marshal(connector)
	path := filepath.Join(t.TempDir(), "connectors.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConnectorsWithOptions(path, true)
	if err != nil {
		t.Fatalf("explicit plain OAuth endpoints unexpectedly require OIDC metadata: %v", err)
	}
	if discoveryCalls.Load() != 0 || loaded["gateway"].JWKSURI != "" {
		t.Fatal("plain OAuth connector unexpectedly used OIDC discovery or keys")
	}
}
