package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, mutate func(map[string]any)) ([]byte, string) {
	t.Helper()
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	files := map[string][]byte{
		"rc.pem":      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		"session.key": []byte(strings.Repeat("s", 40)),
		"op.token":    []byte("ops_fake_token_value"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw := map[string]any{
		"authorization_server":     map[string]any{"issuer": "https://auth.example.com"},
		"session_binding_key_file": filepath.Join(dir, "session.key"),
		"mappings_file":            filepath.Join(dir, "mappings.json"),
		"provider":                 map[string]any{"type": "onepassword", "options": map[string]any{"service_account_token_file": filepath.Join(dir, "op.token")}},
		"services": []any{map[string]any{
			"id": "gitlab", "resource_url": "https://mcp.example.com/gitlab/mcp",
			"upstream_url": "https://gitlab.example.com/api/v4/mcp_server", "validation_url": "https://gitlab.example.com/auth/check", "required_scopes": []string{"gitlab:use"},
			"resource_client": map[string]any{"client_id": "gitlab-plugin", "key_id": "k1", "private_key_file": filepath.Join(dir, "rc.pem")},
			"headers": []any{
				map[string]any{"name": "X-GitLab-Username", "type": "direct", "field": "username"},
				map[string]any{"name": "X-GitLab-PAT-Token", "type": "direct", "field": "api_token"},
			},
		}},
	}
	if mutate != nil {
		mutate(raw)
	}
	data, _ := json.Marshal(raw)
	return data, dir
}

func service(raw map[string]any) map[string]any { return raw["services"].([]any)[0].(map[string]any) }

func TestValidConfigAndDefaults(t *testing.T) {
	data, _ := fixture(t, nil)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TokenEndpoint != "https://auth.example.com/token" || cfg.JWKSURI != "https://auth.example.com/.well-known/jwks.json" ||
		cfg.CacheTTL.Seconds() != 300 || cfg.Listen != "0.0.0.0:8090" || cfg.Services[0].ResourcePath != "/gitlab/mcp" {
		t.Fatalf("defaults: %+v", cfg)
	}
	if got := strings.Join(cfg.RequiredFields()["gitlab"], ","); got != "api_token,username" {
		t.Fatal(got)
	}
}

func TestInvalidConfigurationFailsStartup(t *testing.T) {
	cases := map[string]func(map[string]any){
		"http issuer": func(r map[string]any) {
			r["authorization_server"] = map[string]any{"issuer": "http://auth.example.com"}
		},
		"http upstream":       func(r map[string]any) { service(r)["upstream_url"] = "http://gitlab.example.com/mcp" },
		"upstream with query": func(r map[string]any) { service(r)["upstream_url"] = "https://gitlab.example.com/mcp?x=1" },
		"upstream creds":      func(r map[string]any) { service(r)["upstream_url"] = "https://u:p@gitlab.example.com/mcp" },
		"unknown key":         func(r map[string]any) { r["vault_token"] = "ops_x" },
		"unknown service key": func(r map[string]any) { service(r)["backend_override"] = "x" },
		"no services":         func(r map[string]any) { r["services"] = []any{} },
		"bad service id":      func(r map[string]any) { service(r)["id"] = "Git Lab" },
		"missing provider":    func(r map[string]any) { delete(r, "provider") },
		"bad prefix":          func(r map[string]any) { r["public_path_prefix"] = "proxy/" },
		"bad header": func(r map[string]any) {
			service(r)["headers"] = []any{map[string]any{"name": "Host", "type": "direct", "field": "f"}}
		},
		"no headers":        func(r map[string]any) { service(r)["headers"] = []any{} },
		"bad ttl":           func(r map[string]any) { r["credential_cache"] = map[string]any{"ttl_seconds": 99999} },
		"validation origin": func(r map[string]any) { service(r)["validation_url"] = "https://other.example.com/check" },
		"duplicate service": func(r map[string]any) {
			r["services"] = []any{service(r), service(r)}
		},
		"missing client id": func(r map[string]any) { service(r)["resource_client"].(map[string]any)["client_id"] = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			data, _ := fixture(t, mutate)
			if _, err := Parse(data); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
	t.Run("short session key", func(t *testing.T) {
		data, dir := fixture(t, nil)
		_ = os.WriteFile(filepath.Join(dir, "session.key"), []byte("short"), 0o600)
		if _, err := Parse(data); err == nil {
			t.Fatal("accepted a short session binding key")
		}
	})
	t.Run("not json", func(t *testing.T) {
		if _, err := Parse([]byte("{")); err == nil {
			t.Fatal("accepted")
		}
	})
}

func TestErrorsNeverEchoSecretValues(t *testing.T) {
	data, dir := fixture(t, nil)
	_ = os.WriteFile(filepath.Join(dir, "rc.pem"), []byte("-----BEGIN "+"PRIVATE KEY-----\nSECRETBYTES\n-----END "+"PRIVATE KEY-----"), 0o600)
	_, err := Parse(data)
	if err == nil || strings.Contains(err.Error(), "SECRETBYTES") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("accepted")
	}
}

func TestConflictingGatewayPathsFailStartup(t *testing.T) {
	data, _ := fixture(t, func(raw map[string]any) {
		first := service(raw)
		second := map[string]any{}
		for k, v := range first {
			second[k] = v
		}
		second["id"] = "other"
		second["resource_url"] = "https://other.example.com/gitlab/mcp"
		old := first["resource_client"].(map[string]any)
		second["resource_client"] = map[string]any{"client_id": "other-client", "key_id": old["key_id"], "private_key_file": old["private_key_file"]}
		raw["services"] = []any{first, second}
	})
	if _, err := Parse(data); err == nil {
		t.Fatal("ambiguous path accepted")
	}
}
