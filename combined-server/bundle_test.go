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
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Agent-Hellboy/mcp-auth/auth-server/server"
	credentialgateway "github.com/Agent-Hellboy/mcp-auth/credential-gateway"
)

type fakeVault struct {
	value atomic.Value
	reads atomic.Int64
}

func (v *fakeVault) Resolve(context.Context, map[string]string) (map[string]string, error) {
	v.reads.Add(1)
	return map[string]string{"password": v.value.Load().(string)}, nil
}
func (*fakeVault) Ready() bool { return true }

func TestCombinedLoginInjectionRefreshAndRevocation(t *testing.T) {
	// Real OAuth core and gateway, with an explicitly substituted fake vault.
	vault := &fakeVault{}
	vault.value.Store("wrong")
	var validations, operations atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Upstream-Password") != "fixture-upstream-secret" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/check" {
			validations.Add(1)
			w.WriteHeader(204)
			return
		}
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("caller credentials leaked upstream")
		}
		operations.Add(1)
		w.Header().Set("Mcp-Session-Id", "upstream-session")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	authHTTP := httptest.NewUnstartedServer(nil)
	issuer := "http://" + authHTTP.Listener.Addr().String()
	resource := "https://mcp.example.test/demo/mcp"
	cfg := server.Config{Issuer: issuer, Resources: []string{resource}, AllowedScopes: []string{"demo:use"}, LocalDevelopment: true, AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour, AuthorizationCodeTTL: time.Minute, LogLevel: "silent"}
	auth, err := server.NewServer(cfg, server.NewMemoryStore(), server.LocalIdentityProvider{Subject: "alice"}, nil, io.Discard)
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
	mapFile := write("mappings.json", map[string]any{"mappings": []any{map[string]any{"issuer": issuer, "subject": "alice", "service": "demo", "fields": map[string]string{"password": "test://vault/item/password"}}}})
	configFile := write("gateway.json", map[string]any{
		"allow_insecure_http": true, "authorization_server": map[string]string{"issuer": issuer}, "session_binding_key_file": sessionFile, "mappings_file": mapFile,
		"provider": map[string]any{"type": "test", "options": map[string]any{}},
		"services": []any{map[string]any{"id": "demo", "resource_url": resource, "upstream_url": upstream.URL + "/mcp", "validation_url": upstream.URL + "/check", "required_scopes": []string{"demo:use"}, "resource_client": map[string]string{"client_id": "demo-gateway", "key_id": "k1", "private_key_file": keyFile}, "headers": []any{map[string]string{"name": "X-Upstream-Password", "type": "direct", "field": "password"}}}},
	})
	open := func() *credentialgateway.Runtime {
		g, err := credentialgateway.OpenWithProviders(configFile, "test", map[string]credentialgateway.ProviderFactory{"test": {New: func(json.RawMessage, string) (credentialgateway.Resolver, error) { return vault, nil }, ValidReference: func(s string) bool { return strings.HasPrefix(s, "test://") }}})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	gate := open()
	if err := Attach(auth, gate); err != nil {
		t.Fatal(err)
	}
	// Restart with the same store must accept the gateway's provisioned client.
	auth.ResourceAuthorizationCheck = nil
	auth.ExternalCredentials = nil
	if err := Attach(auth, open()); err != nil {
		t.Fatal("restart failed", err)
	}
	authHTTP.Config.Handler = auth.Handler()
	authHTTP.Start()
	defer authHTTP.Close()
	gateHTTP := httptest.NewServer(gate.Handler())
	defer gateHTTP.Close()
	for _, client := range []string{"client-1", "client-2"} {
		auth.Store.SaveClient(server.Client{ID: client, RedirectURIs: []string{"http://127.0.0.1:39001/callback"}, TokenEndpointAuth: "none"})
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	verifier := strings.Repeat("v", 64)
	digest := sha256.Sum256([]byte(verifier))
	login := func(client string) url.Values {
		q := url.Values{"response_type": {"code"}, "client_id": {client}, "redirect_uri": {"http://127.0.0.1:39001/callback"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}, "resource": {resource}, "scope": {"demo:use"}, "state": {"st"}, "approve": {"true"}}
		resp, err := noRedirect.Get(issuer + "/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		loc, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		return loc.Query()
	}
	if q := login("client-1"); q.Get("code") != "" || q.Get("error") != "access_denied" {
		t.Fatal("bad saved credentials issued a grant")
	}
	vault.value.Store("fixture-upstream-secret")
	q := login("client-1")
	if q.Get("code") == "" {
		t.Fatal("good credentials did not issue a grant")
	}
	token := func(form url.Values) map[string]any {
		resp, err := http.PostForm(issuer+"/token", form)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatal("token request failed", resp.StatusCode)
		}
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(out)
		if strings.Contains(string(b), "fixture-upstream-secret") {
			t.Fatal("credential leaked into OAuth")
		}
		return out
	}
	tokens := token(url.Values{"grant_type": {"authorization_code"}, "client_id": {"client-1"}, "redirect_uri": {"http://127.0.0.1:39001/callback"}, "code": {q.Get("code")}, "code_verifier": {verifier}, "resource": {resource}})
	call := func(method, access, session string) *http.Response {
		req, _ := http.NewRequest(method, gateHTTP.URL+"/demo/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
		req.Header.Set("Authorization", "Bearer "+access)
		req.Header.Set("Cookie", "bad-cookie")
		req.Header.Set("X-Upstream-Password", "spoof")
		if session != "" {
			req.Header.Set("Mcp-Session-Id", session)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}
	access := tokens["access_token"].(string)
	first := call("POST", access, "")
	if first.StatusCode != 200 {
		t.Fatal("initialize failed", first.StatusCode)
	}
	session := first.Header.Get("Mcp-Session-Id")
	if session == "" || session == "upstream-session" {
		t.Fatal("session was not bound")
	}
	for _, method := range []string{"POST", "GET", "DELETE"} {
		if resp := call(method, access, session); resp.StatusCode != 200 {
			t.Fatal("header injection failed", method, resp.StatusCode)
		}
	}
	refresh := tokens["refresh_token"].(string)
	tokens = token(url.Values{"grant_type": {"refresh_token"}, "client_id": {"client-1"}, "refresh_token": {refresh}, "resource": {resource}})
	if resp := call("POST", tokens["access_token"].(string), ""); resp.StatusCode != 200 {
		t.Fatal("refresh lost credentials")
	}
	before := vault.reads.Load()
	if q := login("client-2"); q.Get("code") == "" {
		t.Fatal("new client login failed")
	}
	if vault.reads.Load() <= before {
		t.Fatal("new client skipped vault preflight")
	}
	resp, err := http.PostForm(issuer+"/revoke", url.Values{"client_id": {"client-1"}, "token": {tokens["refresh_token"].(string)}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	before = vault.reads.Load()
	if resp := call("POST", tokens["access_token"].(string), ""); resp.StatusCode != 401 {
		t.Fatal("revocation accepted cached credential", resp.StatusCode)
	}
	if vault.reads.Load() != before {
		t.Fatal("revoked session reached vault")
	}
	if validations.Load() != 2 || operations.Load() != 5 {
		t.Fatal("unexpected upstream call counts", validations.Load(), operations.Load())
	}
}
