package credentialgateway

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// openGateway writes a one-service configuration and opens it for real.
func openGateway(t *testing.T, upstream string) *Runtime {
	t.Helper()
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	keyFile := filepath.Join(dir, "client.pem")
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	sessionFile := filepath.Join(dir, "session.key")
	os.WriteFile(sessionFile, []byte(strings.Repeat("s", 40)), 0o600)
	raw, _ := json.Marshal(map[string]any{
		"allow_insecure_http": true, "authorization_server": map[string]any{"issuer": "https://auth.example.test/mcp-auth"},
		"session_binding_key_file": sessionFile,
		"services": []any{map[string]any{
			"id": "demo", "resource_url": "https://auth.example.test/demo/mcp", "upstream_url": upstream + "/mcp", "validation_url": upstream + "/check",
			"required_scopes": []string{"tools:read"},
			"resource_client": map[string]any{"client_id": "demo-gateway", "key_id": "k1", "private_key_file": keyFile},
			"form_fields":     []any{map[string]any{"name": "password", "secret": true}},
			"headers":         []any{map[string]any{"name": "X-Password", "type": "direct", "field": "password"}},
		}},
	})
	path := filepath.Join(dir, "gateway.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	run, err := Open(path, "test")
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func newUpstream(t *testing.T) (*httptest.Server, *int) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/check" || r.Header.Get("X-Password") != "correct" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(204)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestAuthenticateFormValidatesBeforeStoringAnything(t *testing.T) {
	upstream, calls := newUpstream(t)
	run := openGateway(t, upstream.URL)
	ctx := context.Background()

	if _, err := run.authenticateForm(ctx, "demo", SubjectPrefix("demo"), map[string]string{"password": "wrong"}); err != ErrRejected {
		t.Fatalf("wrong value: %v, want ErrRejected", err)
	}
	if run.forms.Len() != 0 {
		t.Fatal("rejected values were stored")
	}
	subject, err := run.authenticateForm(ctx, "demo", SubjectPrefix("demo"), map[string]string{"password": "correct", "extra": "ignored"})
	if err != nil || subject == "" {
		t.Fatalf("right value: %q %v", subject, err)
	}
	mapping, err := run.forms.Lookup(run.cfg.Issuer, SubjectPrefix("demo")+subject, "demo")
	if err != nil || mapping == nil {
		t.Fatalf("values were not stored under the prefixed subject: %v %v", mapping, err)
	}
	if _, ok := mapping.Refs["extra"]; ok {
		t.Fatal("a field outside form_fields was stored")
	}
	if got, _ := run.forms.Lookup(run.cfg.Issuer, subject, "demo"); got != nil {
		t.Fatal("values are reachable without the prefix mcp-auth adds")
	}
	if _, err := run.authenticateForm(ctx, "missing", SubjectPrefix("missing"), nil); err != ErrUnavailable {
		t.Fatalf("unknown service: %v", err)
	}
	before := *calls
	upstream.Close()
	if _, err := run.authenticateForm(ctx, "demo", SubjectPrefix("demo"), map[string]string{"password": "correct"}); err != ErrUnavailable {
		t.Fatalf("unreachable upstream: %v", err)
	}
	if *calls != before || run.forms.Len() != 1 {
		t.Fatal("an unreachable upstream stored values")
	}
}

func TestHandlerServesTheSignInEndpointsAndStoresValuesForTheIssuedSubject(t *testing.T) {
	upstream, _ := newUpstream(t)
	run := openGateway(t, upstream.URL)
	h := run.Handler()

	if w := httptest.NewRecorder(); true {
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if w.Code != 200 {
			t.Fatalf("the proxy routes are gone: %d", w.Code)
		}
	}
	verifier := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	callback := "https://auth.example.test/mcp-auth/identity/callback"
	q := url.Values{"client_id": {LoginClientID("demo")}, "redirect_uri": {callback}, "response_type": {"code"}, "state": {"form-demo.xyz"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/demo/mcp/login/authorize?"+q.Encode(), nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `action="/demo/mcp/login/approve"`) {
		t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	field := func(name string) string {
		i := strings.Index(body, `name="`+name+`" value="`)
		rest := body[i+len(`name="`+name+`" value="`):]
		return rest[:strings.Index(rest, `"`)]
	}
	cookie := w.Result().Cookies()[0]

	form := url.Values{"request": {field("request")}, "csrf": {field("csrf")}, "password": {"correct"}}
	r := httptest.NewRequest(http.MethodPost, "/demo/mcp/login/approve", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://auth.example.test")
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	loc, _ := url.Parse(w.Header().Get("Location"))
	code := loc.Query().Get("code")
	if w.Code != http.StatusSeeOther || code == "" {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}

	tokenForm := url.Values{"grant_type": {"authorization_code"}, "client_id": {LoginClientID("demo")}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {callback}}
	r = httptest.NewRequest(http.MethodPost, "/demo/mcp/login/token", strings.NewReader(tokenForm.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &tok)
	r = httptest.NewRequest(http.MethodGet, "/demo/mcp/login/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var info struct {
		Sub string `json:"sub"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &info)
	if w.Code != 200 || info.Sub == "" {
		t.Fatalf("userinfo: %d %s", w.Code, w.Body.String())
	}
	// mcp-auth will present this prefixed subject on every later request.
	if m, _ := run.forms.Lookup(run.cfg.Issuer, SubjectPrefix("demo")+info.Sub, "demo"); m == nil {
		t.Fatal("no values are stored for the subject mcp-auth will issue")
	}
	if pem, ok := run.PublicKeyPEM("demo"); !ok || !strings.Contains(pem, "PUBLIC KEY") {
		t.Fatal("no public key for the service's resource client")
	}
}
