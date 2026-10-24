// Package e2e runs the real mcp-auth authorization server (built from source and
// executed as a separate process), the plugin gateway, a fake secret resolver and
// a fake upstream MCP server. The upstream asserts the exact headers it receives.
//
// The plugin never imports authorization-server code: the binary is built and
// started as a process, exactly as in a deployment.
package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/config"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/credentials"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/gateway"
	. "github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/testutil"
)

const (
	resource    = "https://mcp.example.test/gitlab/mcp"
	clientID    = "e2e-client"
	redirectURI = "http://127.0.0.1:39001/callback"
)

type stack struct {
	t        *testing.T
	dir      string
	binary   string
	port     int
	signKey  string
	issuer   string
	asCmd    *exec.Cmd
	upstream *FakeUpstream
	resolver *FakeResolver
	gateway  *httptest.Server
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// buildAuthServer returns an authorization server binary. It uses
// MCP_AUTH_SERVER_BINARY if set, otherwise builds the checkout named by
// MCP_AUTH_SRC. The plugin never imports authorization-server code: the binary is
// started as a process, as in a deployment.
func buildAuthServer(t *testing.T, dir string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("end-to-end test runs the authorization server")
	}
	if binary := os.Getenv("MCP_AUTH_SERVER_BINARY"); binary != "" {
		return binary
	}
	src := os.Getenv("MCP_AUTH_SRC")
	if src == "" {
		t.Skip("set MCP_AUTH_SERVER_BINARY or MCP_AUTH_SRC (a mcp-auth checkout with external credential support) to run")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	binary := filepath.Join(dir, "auth-server")
	cmd := exec.Command("go", "build", "-o", binary, "./cmd/auth-server")
	cmd.Dir = filepath.Join(src, "auth-server")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build auth-server: %v\n%s", err, out)
	}
	return binary
}

func newStack(t *testing.T) *stack {
	t.Helper()
	dir := t.TempDir()
	s := &stack{t: t, dir: dir, binary: buildAuthServer(t, dir), port: freePort(t)}
	s.issuer = fmt.Sprintf("http://127.0.0.1:%d", s.port)

	// AS signing key (shared across the two "users" below) and the plugin's resource-client key.
	asKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(asKey)
	s.signKey = filepath.Join(dir, "as-signing.pem")
	writePEM(t, s.signKey, "PRIVATE KEY", der)
	rcKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rcPriv, _ := x509.MarshalPKCS8PrivateKey(rcKey)
	rcPub, _ := x509.MarshalPKIXPublicKey(&rcKey.PublicKey)
	writePEM(t, filepath.Join(dir, "rc-private.pem"), "PRIVATE KEY", rcPriv)
	writePEM(t, filepath.Join(dir, "rc-public.pem"), "PUBLIC KEY", rcPub)

	ext, _ := json.Marshal([]map[string]any{{
		"id": "gitlab-vault", "resource": resource, "required_scopes": []string{"gitlab:use"},
		"resource_client": map[string]any{"client_id": "gitlab-plugin", "public_key_file": filepath.Join(dir, "rc-public.pem")},
	}})
	if err := os.WriteFile(filepath.Join(dir, "external.json"), ext, 0o600); err != nil {
		t.Fatal(err)
	}

	// Plugin side.
	s.upstream, s.resolver = NewFakeUpstream(t), &FakeResolver{Values: map[string]string{}}
	for _, u := range []string{"alice", "bob"} {
		s.resolver.Values[Ref(u, "gitlab", "username")] = u + "-gitlab"
		s.resolver.Values[Ref(u, "gitlab", "api_token")] = "glpat-" + u + "-fake"
	}
	store := &MapStore{}
	store.Replace(DefaultMappings(s.issuer)[:2])
	_ = os.WriteFile(filepath.Join(dir, "session.key"), []byte(strings.Repeat("k", 48)), 0o600)
	raw, _ := json.Marshal(map[string]any{
		"allow_insecure_http":      true,
		"authorization_server":     map[string]any{"issuer": s.issuer},
		"session_binding_key_file": filepath.Join(dir, "session.key"),
		"services": []any{map[string]any{
			"id": "gitlab", "resource_url": resource, "upstream_url": s.upstream.Server.URL + "/api/v4/mcp_server", "validation_url": s.upstream.Server.URL + "/auth/check",
			"required_scopes": []string{"gitlab:use"},
			"form_fields":     []any{map[string]any{"name": "username"}, map[string]any{"name": "api_token", "secret": true}},
			"resource_client": map[string]any{"client_id": "gitlab-plugin", "key_id": "rc-1", "private_key_file": filepath.Join(dir, "rc-private.pem")},
			"headers": []any{
				map[string]any{"name": "X-GitLab-Username", "type": "direct", "field": "username"},
				map[string]any{"name": "X-GitLab-PAT-Token", "type": "direct", "field": "api_token"},
			},
		}},
	})
	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	creds := &credentials.Service{Mappings: store, Resolver: s.resolver, TTL: cfg.CacheTTL, Max: cfg.CacheMaxEntries}
	s.gateway = httptest.NewServer(gateway.New(cfg, creds, s.resolver.Ready, nil))
	t.Cleanup(s.gateway.Close)
	t.Cleanup(s.stopAS)
	return s
}

// startAS starts the real authorization server whose local-development login
// authenticates the fixed subject given. Restarting it with another subject (same
// issuer URL and signing key) models a second user.
func (s *stack) startAS(subject string) {
	s.t.Helper()
	s.stopAS()
	cmd := exec.Command(s.binary)
	cmd.Env = append(os.Environ(),
		"MCP_AUTH_ISSUER="+s.issuer,
		fmt.Sprintf("MCP_AUTH_LISTEN_ADDR=127.0.0.1:%d", s.port),
		"MCP_AUTH_RESOURCES="+resource,
		`MCP_AUTH_RESOURCE_SCOPES={"`+resource+`":["gitlab:use"]}`,
		"MCP_AUTH_EXTERNAL_CREDENTIALS_FILE="+filepath.Join(s.dir, "external.json"),
		"MCP_AUTH_PRIVATE_KEY_FILE="+s.signKey,
		"MCP_AUTH_LOCAL_DEVELOPMENT=true", "MCP_AUTH_REQUIRE_HTTPS=false",
		"MCP_AUTH_LOCAL_SUBJECT="+subject, "MCP_AUTH_LOCAL_CLIENT_ID="+clientID,
		"MCP_AUTH_LOG_LEVEL=silent",
	)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	s.asCmd = cmd
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(s.issuer + "/healthz"); err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.t.Fatal("authorization server did not start")
}

func (s *stack) stopAS() {
	if s.asCmd != nil && s.asCmd.Process != nil {
		_ = s.asCmd.Process.Kill()
		_, _ = s.asCmd.Process.Wait()
		s.asCmd = nil
	}
}

type tokens struct{ Access, Refresh string }

// login performs the OAuth flow the way an MCP client does: discover the
// authorization server from the plugin, then authorization-code + PKCE (S256).
func (s *stack) login() tokens {
	t := s.t
	t.Helper()
	// 1-2. Unauthenticated request: challenge pointing to protected-resource metadata.
	resp, err := http.Post(s.gateway.URL+"/gitlab/mcp", "application/json", strings.NewReader(Initialize))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	challenge := resp.Header.Get("WWW-Authenticate")
	if resp.StatusCode != 401 || !strings.Contains(challenge, "resource_metadata=") {
		t.Fatalf("challenge: %d %q", resp.StatusCode, challenge)
	}
	// 3. Metadata names mcp-auth as the authorization server.
	meta := getJSON(t, s.gateway.URL+"/.well-known/oauth-protected-resource/gitlab/mcp")
	servers, _ := meta["authorization_servers"].([]any)
	if len(servers) != 1 || servers[0] != s.issuer || meta["resource"] != resource {
		t.Fatalf("metadata = %v", meta)
	}
	asMeta := getJSON(t, s.issuer+"/.well-known/oauth-authorization-server")
	if asMeta["token_endpoint"] == nil || asMeta["authorization_endpoint"] == nil {
		t.Fatalf("AS metadata = %v", asMeta)
	}
	// 4. Authorization code + PKCE bound to the resource.
	verifier := "e2e-verifier-" + strings.Repeat("x", 40)
	digest := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
		"resource": {resource}, "scope": {"gitlab:use"}, "state": {"st"}, "approve": {"true"}}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authResp, err := noRedirect.Get(asMeta["authorization_endpoint"].(string) + "?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	authResp.Body.Close()
	loc, _ := url.Parse(authResp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no authorization code: %d %s", authResp.StatusCode, authResp.Header.Get("Location"))
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier}, "resource": {resource}}
	tokenResp, err := http.PostForm(asMeta["token_endpoint"].(string), form)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(tokenResp.Body)
	tokenResp.Body.Close()
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	if tokenResp.StatusCode != 200 || out["access_token"] == nil {
		t.Fatalf("token response: %d %s", tokenResp.StatusCode, body)
	}
	// The public OAuth response never contains upstream credentials.
	if strings.Contains(string(body), "glpat") || strings.Contains(string(body), "-gitlab") {
		t.Fatal("upstream credential leaked into the OAuth response")
	}
	return tokens{out["access_token"].(string), out["refresh_token"].(string)}
}

func getJSON(t *testing.T, u string) map[string]any {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func (s *stack) call(method, token, body string, h map[string]string) *http.Response {
	req, _ := http.NewRequestWithContext(context.Background(), method, s.gateway.URL+"/gitlab/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	return resp
}

func TestRealAuthorizationServerTwoUsersAndRevocation(t *testing.T) {
	s := newStack(t)

	// ---- Alice ----
	s.startAS("alice")
	alice := s.login()
	resp := s.call("POST", alice.Access, Initialize, nil)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("alice initialize: %d %s", resp.StatusCode, b)
	}
	resp.Body.Close()
	session := resp.Header.Get("Mcp-Session-Id")
	// Later requests on every operation are authorised and injected independently.
	for _, op := range []string{"POST", "GET", "DELETE"} {
		body := ""
		if op == "POST" {
			body = `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
		}
		r := s.call(op, alice.Access, body, map[string]string{"Mcp-Session-Id": session, "X-GitLab-PAT-Token": "spoofed"})
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatalf("alice %s: %d", op, r.StatusCode)
		}
	}
	recs := s.upstream.Records()
	if len(recs) != 4 {
		t.Fatalf("upstream saw %d requests", len(recs))
	}
	for _, r := range recs {
		if r.Header.Get("X-Gitlab-Username") != "alice-gitlab" || r.Header.Get("X-Gitlab-Pat-Token") != "glpat-alice-fake" {
			t.Fatalf("alice headers = %v", r.Header)
		}
		// The client's mcp-auth bearer token is never forwarded as the upstream credential.
		if strings.Contains(strings.Join(r.Header.Values("Authorization"), ","), alice.Access) || r.Header.Get("Authorization") != "" {
			t.Fatalf("Authorization reached upstream: %v", r.Header)
		}
	}

	// Revocation: the session ends at mcp-auth, and the very next request is refused
	// before any vault access, even though credentials are cached.
	callsBefore := s.resolver.Calls()
	rev, err := http.PostForm(s.issuer+"/revoke", url.Values{"token": {alice.Refresh}, "client_id": {clientID}})
	if err != nil {
		t.Fatal(err)
	}
	rev.Body.Close()
	r := s.call("POST", alice.Access, `{"id":3}`, map[string]string{"Mcp-Session-Id": session})
	r.Body.Close()
	if r.StatusCode != 401 || !strings.Contains(r.Header.Get("WWW-Authenticate"), "invalid_token") {
		t.Fatalf("revoked session: %d %q", r.StatusCode, r.Header.Get("WWW-Authenticate"))
	}
	if s.resolver.Calls() != callsBefore || len(s.upstream.Records()) != 4 {
		t.Fatal("revoked session reached the vault or upstream")
	}

	// ---- Bob (same plugin, same GitLab backend, different credentials) ----
	s.startAS("bob")
	bob := s.login()
	b := s.call("POST", bob.Access, Initialize, nil)
	b.Body.Close()
	if b.StatusCode != 200 {
		t.Fatalf("bob initialize: %d", b.StatusCode)
	}
	last := s.upstream.Records()[len(s.upstream.Records())-1]
	if last.Header.Get("X-Gitlab-Username") != "bob-gitlab" || last.Header.Get("X-Gitlab-Pat-Token") != "glpat-bob-fake" {
		t.Fatalf("bob headers = %v", last.Header)
	}
	// Alice's upstream session cannot be used by Bob.
	x := s.call("POST", bob.Access, `{"id":9}`, map[string]string{"Mcp-Session-Id": session})
	x.Body.Close()
	if x.StatusCode != 403 {
		t.Fatalf("cross-user session reuse: %d", x.StatusCode)
	}
	// Both users reached the same backend URL.
	if recs[0].URL != last.URL {
		t.Fatalf("backends differ: %s vs %s", recs[0].URL, last.URL)
	}
}

// A token minted for another resource, or by the wrong key, never reaches the vault.
func TestRealAuthorizationServerRejectsForeignTokens(t *testing.T) {
	s := newStack(t)
	s.startAS("alice")
	tok := s.login()
	parts := strings.Split(tok.Access, ".")
	forged := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString([]byte("bad-signature"))
	r := s.call("POST", forged, Initialize, nil)
	r.Body.Close()
	if r.StatusCode != 401 || s.resolver.Calls() != 0 {
		t.Fatalf("forged token: %d, vault calls %d", r.StatusCode, s.resolver.Calls())
	}
}
