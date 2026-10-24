package e2e

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	credentialgateway "github.com/Agent-Hellboy/mcp-auth/credential-gateway"
	. "github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/testutil"
)

// TestSignInAcrossTheRealAuthServerAndTheSeparateGateway runs the two services
// as separate HTTP servers, as deployed: mcp-auth sends the browser to the
// gateway's sign-in page through a resource login, the gateway validates the
// person's values and keeps them, and every later request carries only a bearer
// token that the gateway turns into the stored headers.
func TestSignInAcrossTheRealAuthServerAndTheSeparateGateway(t *testing.T) {
	dir := t.TempDir()
	binary := buildAuthServer(t, dir)
	asPort := freePort(t)
	issuer := fmt.Sprintf("http://127.0.0.1:%d", asPort)

	upstream := NewFakeUpstream(t)
	upstream.Behavior = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/check" {
			if r.Header.Get("X-GitLab-PAT-Token") == "glpat-good" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}

	gatewayServer := httptest.NewUnstartedServer(nil)
	gatewayOrigin := "http://" + gatewayServer.Listener.Addr().String()
	resourceURL := gatewayOrigin + "/gitlab/mcp"

	// Keys: mcp-auth's signing key, and the gateway's resource-client key whose
	// public half mcp-auth is told about.
	signKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(signKey)
	signPath := filepath.Join(dir, "as-signing.pem")
	writePEM(t, signPath, "PRIVATE KEY", der)
	rcKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rcPriv, _ := x509.MarshalPKCS8PrivateKey(rcKey)
	rcPub, _ := x509.MarshalPKIXPublicKey(&rcKey.PublicKey)
	writePEM(t, filepath.Join(dir, "rc-private.pem"), "PRIVATE KEY", rcPriv)
	writePEM(t, filepath.Join(dir, "rc-public.pem"), "PUBLIC KEY", rcPub)
	writeFile := func(name string, value any) string {
		path := filepath.Join(dir, name)
		data, _ := json.Marshal(value)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if err := os.WriteFile(filepath.Join(dir, "session.key"), []byte(strings.Repeat("k", 48)), 0o600); err != nil {
		t.Fatal(err)
	}

	gatewayConfig := writeFile("gateway.json", map[string]any{
		"allow_insecure_http": true, "authorization_server": map[string]any{"issuer": issuer},
		"session_binding_key_file": filepath.Join(dir, "session.key"),
		"services": []any{map[string]any{
			"id": "gitlab", "resource_url": resourceURL, "upstream_url": upstream.Server.URL + "/api/v4/mcp", "validation_url": upstream.Server.URL + "/auth/check",
			"required_scopes": []string{"gitlab:use"},
			"resource_client": map[string]any{"client_id": "gitlab-plugin", "key_id": "rc-1", "private_key_file": filepath.Join(dir, "rc-private.pem")},
			"form_fields":     []any{map[string]any{"name": "username", "label": "Username"}, map[string]any{"name": "api_token", "label": "Token", "secret": true}},
			"headers": []any{
				map[string]any{"name": "X-GitLab-Username", "type": "direct", "field": "username"},
				map[string]any{"name": "X-GitLab-PAT-Token", "type": "direct", "field": "api_token"},
			},
		}},
	})
	loginBase := resourceURL + "/login"
	connectors := writeFile("connectors.json", map[string]any{
		"gitlab-login": map[string]any{
			"issuer": loginBase, "authorization_endpoint": loginBase + "/authorize", "token_endpoint": loginBase + "/token", "userinfo_endpoint": loginBase + "/userinfo",
			"client_id": credentialgateway.LoginClientID("gitlab"), "exchange_client_id": "unused-in-login-registry-mode", "token_endpoint_auth_method": "none",
			"scopes": []string{"profile"}, "identity_claims": []string{"sub"}, "allowed_upstream_callback_uris": []string{issuer + "/identity/callback"},
		},
	})
	logins := writeFile("logins.json", map[string]any{"methods": []any{map[string]any{
		"id": "form-gitlab", "type": "oidc", "connector": "gitlab-login", "subject_prefix": credentialgateway.SubjectPrefix("gitlab"), "resources": []string{resourceURL},
	}}})
	external := writeFile("external.json", []map[string]any{{
		"id": "gitlab", "resource": resourceURL, "required_scopes": []string{"gitlab:use"},
		"resource_client": map[string]any{"client_id": "gitlab-plugin", "public_key_file": filepath.Join(dir, "rc-public.pem")},
	}})

	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(),
		"MCP_AUTH_ISSUER="+issuer, fmt.Sprintf("MCP_AUTH_LISTEN_ADDR=127.0.0.1:%d", asPort),
		"MCP_AUTH_RESOURCES="+resourceURL, `MCP_AUTH_RESOURCE_SCOPES={"`+resourceURL+`":["gitlab:use"]}`,
		"MCP_AUTH_EXTERNAL_CREDENTIALS_FILE="+external,
		"MCP_AUTH_CONNECTORS_FILE="+connectors, "MCP_AUTH_RESOURCE_LOGINS_FILE="+logins,
		"MCP_AUTH_PRIVATE_KEY_FILE="+signPath,
		"MCP_AUTH_LOCAL_DEVELOPMENT=true", "MCP_AUTH_REQUIRE_HTTPS=false",
		"MCP_AUTH_LOCAL_SUBJECT=connector-user", "MCP_AUTH_LOCAL_CLIENT_ID="+clientID,
		"MCP_AUTH_LOG_LEVEL=silent",
	)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	gw, err := credentialgateway.Open(gatewayConfig, "test")
	if err != nil {
		t.Fatal(err)
	}
	gatewayServer.Config.Handler = gw.Handler()
	gatewayServer.Start()
	t.Cleanup(gatewayServer.Close)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if resp, err := http.Get(issuer + "/healthz"); err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("authorization server did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}

	hidden := regexp.MustCompile(`name="(request|csrf)" value="([^"]+)"`)
	// person signs in once: returns the access and refresh tokens.
	signIn := func(username, token string) (access, refresh string) {
		t.Helper()
		jar, _ := cookiejar.New(nil)
		browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		get := func(target string) (*http.Response, string) {
			resp, err := browser.Get(target)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return resp, string(body)
		}
		verifier := strings.Repeat("v", 64) + username
		sum := sha256.Sum256([]byte(verifier))
		q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI}, "state": {"st"}, "resource": {resourceURL},
			"scope": {"gitlab:use"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "approve": {"true"}}

		// mcp-auth hands the browser to the gateway's sign-in page.
		resp, _ := get(issuer + "/authorize?" + q.Encode())
		signInURL := resp.Header.Get("Location")
		if !strings.HasPrefix(signInURL, loginBase+"/authorize?") {
			t.Fatalf("mcp-auth did not send the browser to the gateway: %d %q", resp.StatusCode, signInURL)
		}
		resp, page := get(signInURL)
		fields := map[string]string{}
		for _, m := range hidden.FindAllStringSubmatch(page, -1) {
			fields[m[1]] = m[2]
		}
		if resp.StatusCode != 200 || fields["request"] == "" || !strings.Contains(page, `type="password"`) {
			t.Fatalf("gateway sign-in page: %d %s", resp.StatusCode, page)
		}
		approve := func(values map[string]string) (*http.Response, string) {
			form := url.Values{"request": {fields["request"]}, "csrf": {fields["csrf"]}}
			for k, v := range values {
				form.Set(k, v)
			}
			req, _ := http.NewRequest(http.MethodPost, loginBase+"/approve", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", gatewayOrigin)
			resp, err := browser.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return resp, string(body)
		}
		if resp, body := approve(map[string]string{"username": username, "api_token": "glpat-wrong"}); resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("Location") != "" || !strings.Contains(body, "Sign-in failed") {
			t.Fatalf("wrong values were not refused on the gateway's form: %d %s", resp.StatusCode, body)
		}
		resp, body := approve(map[string]string{"username": username, "api_token": token})
		callback := resp.Header.Get("Location")
		if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(callback, issuer+"/identity/callback?") {
			t.Fatalf("right values did not return to mcp-auth: %d %q %s", resp.StatusCode, callback, body)
		}
		// mcp-auth finishes with the gateway behind the scenes and returns a code.
		resp, _ = get(callback)
		final, _ := url.Parse(resp.Header.Get("Location"))
		code := final.Query().Get("code")
		if final.Host != "127.0.0.1:39001" || code == "" {
			t.Fatalf("mcp-auth did not issue a code: %d %q", resp.StatusCode, resp.Header.Get("Location"))
		}
		exchange, err := http.PostForm(issuer+"/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "redirect_uri": {redirectURI}, "code": {code}, "code_verifier": {verifier}, "resource": {resourceURL}})
		if err != nil {
			t.Fatal(err)
		}
		defer exchange.Body.Close()
		raw, _ := io.ReadAll(exchange.Body)
		var tokens struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if exchange.StatusCode != 200 || json.Unmarshal(raw, &tokens) != nil || tokens.AccessToken == "" {
			t.Fatalf("token exchange: %d %s", exchange.StatusCode, raw)
		}
		if strings.Contains(string(raw), token) {
			t.Fatal("the submitted value reached mcp-auth's token response")
		}
		return tokens.AccessToken, tokens.RefreshToken
	}
	call := func(access string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, resourceURL, strings.NewReader(Initialize))
		req.Header.Set("Content-Type", "application/json")
		if access != "" {
			req.Header.Set("Authorization", "Bearer "+access)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	lastUsername := func() string {
		records := upstream.Records()
		return records[len(records)-1].Header.Get("X-Gitlab-Username")
	}

	if call("") != http.StatusUnauthorized {
		t.Fatal("a request with no bearer token reached the gateway's upstream")
	}
	accessAlice, refreshAlice := signIn("alice", "glpat-good")
	accessBob, _ := signIn("bob", "glpat-good")

	for name, want := range map[string]string{accessAlice: "alice", accessBob: "bob"} {
		if call(name) != 200 || lastUsername() != want {
			t.Fatalf("a bearer token did not map to its own sign-in's headers (want %q, upstream saw %q)", want, lastUsername())
		}
	}
	if got := upstream.Records()[len(upstream.Records())-1].Header.Get("X-Gitlab-Pat-Token"); got != "glpat-good" {
		t.Fatalf("the token header was not injected: %q", got)
	}

	revoke, err := http.PostForm(issuer+"/revoke", url.Values{"client_id": {clientID}, "token": {refreshAlice}})
	if err != nil {
		t.Fatal(err)
	}
	revoke.Body.Close()
	if call(accessAlice) != http.StatusUnauthorized {
		t.Fatal("a revoked sign-in still reached the upstream")
	}
	if call(accessBob) != 200 {
		t.Fatal("revoking one person's session ended another's")
	}
}
