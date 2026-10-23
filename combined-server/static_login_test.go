package combinedserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Agent-Hellboy/mcp-auth/auth-server/server"
	credentialgateway "github.com/Agent-Hellboy/mcp-auth/credential-gateway"
)

// headerVault returns two header values, as a GitLab-style upstream expects.
type headerVault struct{ token atomic.Value }

func (v *headerVault) Resolve(context.Context, map[string]string) (map[string]string, error) {
	return map[string]string{"username": "alice", "token": v.token.Load().(string)}, nil
}
func (*headerVault) Ready() bool { return true }

// TestStaticLoginNeedsNoIdentityProvider drives the real sign-in page: the
// client does standard MCP OAuth and holds only a bearer token. The gateway
// reads both header values from the vault, validates them at the upstream
// before any code is issued, and sends them on every later request.
func TestStaticLoginNeedsNoIdentityProvider(t *testing.T) {
	vault := &headerVault{}
	vault.token.Store("wrong")
	var operations atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-GitLab-Username") != "alice" || r.Header.Get("X-GitLab-PAT-Token") != "glpat-fixture" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/check" {
			w.WriteHeader(204)
			return
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("the client's bearer token reached the upstream")
		}
		operations.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	authHTTP := httptest.NewUnstartedServer(nil)
	issuer := "http://" + authHTTP.Listener.Addr().String()
	resource := "https://mcp.example.test/gitlab/mcp"
	method, err := server.NewStaticLoginMethod("vault", "Continue with the vault credential", "gitlab-shared")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := server.NewLoginRegistry(server.LoginEntry{Method: method, SubjectPrefix: "vault:", Resources: []string{resource}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := server.Config{Issuer: issuer, Resources: []string{resource}, AllowedScopes: []string{"tools:read"}, LocalDevelopment: true, AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour, AuthorizationCodeTTL: time.Minute, LogLevel: "silent"}
	auth, err := server.NewServer(cfg, server.NewMemoryStore(), registry, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	write := func(name string, value any) string {
		p := filepath.Join(dir, name)
		b, _ := json.Marshal(value)
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	keyFile := filepath.Join(dir, "client.pem")
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600)
	sessionFile := filepath.Join(dir, "session.key")
	os.WriteFile(sessionFile, []byte(strings.Repeat("s", 40)), 0600)
	mapFile := write("mappings.json", map[string]any{"mappings": []any{map[string]any{
		"issuer": issuer, "subject": "vault:gitlab-shared", "service": "gitlab",
		"fields": map[string]string{"username": "test://vault/item/username", "token": "test://vault/item/token"},
	}}})
	configFile := write("gateway.json", map[string]any{
		"allow_insecure_http": true, "authorization_server": map[string]string{"issuer": issuer},
		"session_binding_key_file": sessionFile, "mappings_file": mapFile,
		"provider": map[string]any{"type": "test", "options": map[string]any{}},
		"services": []any{map[string]any{
			"id": "gitlab", "resource_url": resource, "upstream_url": upstream.URL + "/mcp", "validation_url": upstream.URL + "/check",
			"required_scopes": []string{"tools:read"},
			"resource_client": map[string]string{"client_id": "gitlab-gateway", "key_id": "k1", "private_key_file": keyFile},
			"headers": []any{
				map[string]string{"name": "X-GitLab-Username", "type": "direct", "field": "username"},
				map[string]string{"name": "X-GitLab-PAT-Token", "type": "direct", "field": "token"},
			},
		}},
	})
	gate, err := credentialgateway.OpenWithProviders(configFile, "test", map[string]credentialgateway.ProviderFactory{"test": {
		New:            func(json.RawMessage, string) (credentialgateway.Resolver, error) { return vault, nil },
		ValidReference: func(s string) bool { return strings.HasPrefix(s, "test://") },
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := Attach(auth, gate); err != nil {
		t.Fatal(err)
	}
	authHTTP.Config.Handler = auth.Handler()
	authHTTP.Start()
	defer authHTTP.Close()
	gateHTTP := httptest.NewServer(gate.Handler())
	defer gateHTTP.Close()
	auth.Store.SaveClient(server.Client{ID: "client", RedirectURIs: []string{"http://127.0.0.1:39001/callback"}, TokenEndpointAuth: "none"})

	verifier := strings.Repeat("v", 64)
	digest := sha256.Sum256([]byte(verifier))
	idPattern := regexp.MustCompile(`name="login_id" value="([^"]+)"`)
	consentPattern := regexp.MustCompile(`name="consent_id" value="([^"]+)"`)

	// signIn plays one browser: authorize, approve consent, press the button.
	signIn := func() url.Values {
		jar, _ := cookiejar.New(nil)
		browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		q := url.Values{"response_type": {"code"}, "client_id": {"client"}, "redirect_uri": {"http://127.0.0.1:39001/callback"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}, "resource": {resource}, "scope": {"tools:read"}, "state": {"st"}}
		body := func(resp *http.Response) string {
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return string(b)
		}
		resp, err := browser.Get(issuer + "/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		page := body(resp)
		match := consentPattern.FindStringSubmatch(page)
		if match == nil {
			t.Fatalf("no consent page: %d %s", resp.StatusCode, page)
		}
		resp, err = browser.PostForm(issuer+"/authorize/consent", url.Values{"consent_id": {match[1]}, "decision": {"approve"}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		location, err := resp.Location()
		if err != nil {
			t.Fatalf("consent did not redirect: %d", resp.StatusCode)
		}
		resp, err = browser.Get(location.String())
		if err != nil {
			t.Fatal(err)
		}
		page = body(resp)
		if strings.Contains(page, `type="password"`) || !strings.Contains(page, "Continue with the vault credential") {
			t.Fatalf("expected a no-input confirm page: %s", page)
		}
		match = idPattern.FindStringSubmatch(page)
		if match == nil {
			t.Fatalf("no login id: %s", page)
		}
		resp, err = browser.PostForm(issuer+"/login/vault", url.Values{"login_id": {match[1]}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		final, err := resp.Location()
		if err != nil {
			t.Fatalf("sign-in did not redirect: %d", resp.StatusCode)
		}
		return final.Query()
	}

	if q := signIn(); q.Get("code") != "" || q.Get("error") != "access_denied" {
		t.Fatalf("a wrong vault credential issued a grant: %v", q)
	}
	vault.token.Store("glpat-fixture")
	q := signIn()
	if q.Get("code") == "" {
		t.Fatalf("the vault credential did not issue a grant: %v", q)
	}
	resp, err := http.PostForm(issuer+"/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "redirect_uri": {"http://127.0.0.1:39001/callback"}, "code": {q.Get("code")}, "code_verifier": {verifier}, "resource": {resource}})
	if err != nil {
		t.Fatal(err)
	}
	var tokens map[string]any
	json.NewDecoder(resp.Body).Decode(&tokens)
	resp.Body.Close()
	raw, _ := json.Marshal(tokens)
	if resp.StatusCode != 200 || strings.Contains(string(raw), "glpat-fixture") {
		t.Fatalf("token exchange failed or leaked the credential: %d", resp.StatusCode)
	}

	req, _ := http.NewRequest("POST", gateHTTP.URL+"/gitlab/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	req.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))
	req.Header.Set("X-GitLab-PAT-Token", "spoofed")
	call, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	call.Body.Close()
	if call.StatusCode != 200 || operations.Load() != 1 {
		t.Fatalf("bearer was not exchanged for the vault headers: status %d, upstream calls %d", call.StatusCode, operations.Load())
	}
	anon, _ := http.Post(gateHTTP.URL+"/gitlab/mcp", "application/json", strings.NewReader(`{}`))
	anon.Body.Close()
	if anon.StatusCode != 401 {
		t.Fatalf("an anonymous request reached the gateway: %d", anon.StatusCode)
	}
}
