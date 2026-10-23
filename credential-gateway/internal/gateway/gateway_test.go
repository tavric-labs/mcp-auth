package gateway_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/secrets"
	. "github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/testutil"
)

const mcp = "/gitlab/mcp"

func init() { slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil))) }

func status(t *testing.T, resp *http.Response, want int) string {
	t.Helper()
	body := ReadBody(resp)
	if resp.StatusCode != want {
		t.Fatalf("status = %d, want %d: %s", resp.StatusCode, want, body)
	}
	return body
}

func TestChallengeAndMetadataDiscovery(t *testing.T) {
	env := NewEnv(t)
	resp := env.Do("POST", mcp, "", Initialize, nil)
	status(t, resp, 401)
	challenge := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(challenge, `resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/gitlab/mcp"`) {
		t.Fatalf("challenge = %q", challenge)
	}
	var meta map[string]any
	body := status(t, env.Do("GET", "/.well-known/oauth-protected-resource/gitlab/mcp", "", "", nil), 200)
	_ = json.Unmarshal([]byte(body), &meta)
	servers, _ := meta["authorization_servers"].([]any)
	if meta["resource"] != GitLabResource || len(servers) != 1 || servers[0] != env.AS.Issuer() {
		t.Fatalf("metadata = %v", meta)
	}
	if env.Resolver.Calls() != 0 || len(env.Upstream.Records()) != 0 {
		t.Fatal("unauthenticated request reached the vault or upstream")
	}
}

func TestMethodsAndRoutes(t *testing.T) {
	env := NewEnv(t)
	status(t, env.Do("PUT", mcp, env.AS.Token(TokenOpts{}), "", nil), 405)
	status(t, env.Do("POST", "/nope", "", Initialize, nil), 404)
}

func TestTokenChecksRejectBeforeExchangeOrVault(t *testing.T) {
	env := NewEnv(t)
	cases := map[string]struct {
		opts TokenOpts
		want int
	}{
		"wrong audience": {TokenOpts{Resource: GerritResource}, 401},
		"foreign issuer": {TokenOpts{Issuer: "https://evil.example"}, 401},
		"expired":        {TokenOpts{ExpiresIn: -10 * time.Minute}, 401},
		"missing scope":  {TokenOpts{Scope: "other"}, 403},
		"no session id":  {TokenOpts{NoSession: true}, 401},
		"bad signature":  {TokenOpts{Key: NewKey(t)}, 401},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			resp := env.Do("POST", mcp, env.AS.Token(tc.opts), Initialize, nil)
			status(t, resp, tc.want)
			if tc.want == 403 && !strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="insufficient_scope"`) {
				t.Fatalf("challenge = %q", resp.Header.Get("WWW-Authenticate"))
			}
		})
	}
	if env.AS.Exchanges.Load() != 0 || env.Resolver.Calls() != 0 || len(env.Upstream.Records()) != 0 {
		t.Fatal("a rejected token reached the exchange, vault or upstream")
	}
	status(t, env.Do("POST", mcp, "not-a-jwt", Initialize, nil), 401)
}

func TestExchangeIsAuthenticatedAndRequestsAssertion(t *testing.T) {
	env := NewEnv(t)
	status(t, env.Do("POST", mcp, env.AS.Token(TokenOpts{}), Initialize, nil), 200)
	form := env.AS.LastForm()
	if !strings.HasSuffix(form.Get("grant_type"), "token-exchange") || form.Get("audience") != GitLabResource ||
		form.Get("client_id") != "gitlab-plugin" || form.Get("client_assertion") == "" ||
		form.Get("requested_token_type") != "urn:mcp-auth:token-type:credential-access-assertion" {
		t.Fatalf("form = %v", form)
	}
}

func TestRevokedSessionRejectedBeforeVaultAccess(t *testing.T) {
	env := NewEnv(t)
	token := env.AS.Token(TokenOpts{})
	env.AS.Revoke("session-1")
	resp := env.Do("POST", mcp, token, Initialize, nil)
	status(t, resp, 401)
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatal("revoked session should produce an invalid_token challenge")
	}
	if env.Resolver.Calls() != 0 || len(env.Upstream.Records()) != 0 {
		t.Fatal("revoked session reached the vault or upstream")
	}
}

func TestInitializeDoesNotAuthoriseLaterRequests(t *testing.T) {
	env := NewEnv(t)
	token := env.AS.Token(TokenOpts{})
	session := env.Do("POST", mcp, token, Initialize, nil).Header.Get("Mcp-Session-Id")
	if session == "" {
		t.Fatal("no session id returned")
	}
	env.AS.Revoke("session-1")
	h := map[string]string{"Mcp-Session-Id": session}
	status(t, env.Do("POST", mcp, token, `{"id":2}`, h), 401)
	status(t, env.Do("GET", mcp, token, "", h), 401)
	status(t, env.Do("DELETE", mcp, token, "", h), 401)
	if n := len(env.Upstream.Records()); n != 1 {
		t.Fatalf("upstream saw %d requests, want only the initialize", n)
	}
}

func TestCacheHitDoesNotBypassRevocation(t *testing.T) {
	env := NewEnv(t)
	token := env.AS.Token(TokenOpts{})
	status(t, env.Do("POST", mcp, token, Initialize, nil), 200)
	status(t, env.Do("POST", mcp, token, Initialize, nil), 200)
	if env.Resolver.Calls() != 1 {
		t.Fatalf("resolver calls = %d, want 1 (second request served from cache)", env.Resolver.Calls())
	}
	if env.AS.Exchanges.Load() != 2 {
		t.Fatalf("exchanges = %d, want 2 (every request authorised)", env.AS.Exchanges.Load())
	}
	env.AS.Revoke("session-1")
	status(t, env.Do("POST", mcp, token, Initialize, nil), 401)
	if len(env.Upstream.Records()) != 2 {
		t.Fatal("cached credentials were used after revocation")
	}
}

func TestAuthorizationServerOutageIs503(t *testing.T) {
	env := NewEnv(t)
	env.AS.FailExchange(500)
	body := status(t, env.Do("POST", mcp, env.AS.Token(TokenOpts{}), Initialize, nil), 503)
	if JSONField(body, "error") != "authorization_unavailable" || env.Resolver.Calls() != 0 {
		t.Fatalf("body = %s", body)
	}
	env.AS.FailExchange(401) // our own client rejected: operator error, not a user error
	status(t, env.Do("POST", mcp, env.AS.Token(TokenOpts{}), Initialize, nil), 503)
}

func TestTwoUsersGetOnlyTheirOwnCredentials(t *testing.T) {
	env := NewEnv(t)
	status(t, env.Do("POST", mcp, env.AS.Token(TokenOpts{Subject: "alice"}), Initialize, nil), 200)
	status(t, env.Do("POST", mcp, env.AS.Token(TokenOpts{Subject: "bob", SessionID: "session-2"}), Initialize, nil), 200)
	recs := env.Upstream.Records()
	alice, bob := recs[0].Header, recs[1].Header
	if alice.Get("X-Gitlab-Username") != "alice-gl" || alice.Get("X-Gitlab-Pat-Token") != "glpat-alice-token" ||
		bob.Get("X-Gitlab-Username") != "bob-gl" || bob.Get("X-Gitlab-Pat-Token") != "glpat-bob-token" {
		t.Fatalf("alice=%v bob=%v", alice, bob)
	}
	if recs[0].URL != "/api/v4/mcp" || recs[1].URL != "/api/v4/mcp" {
		t.Fatal("requests did not go to the configured upstream")
	}
}

func TestOneUserDifferentCredentialsPerService(t *testing.T) {
	env := NewEnv(t)
	status(t, env.Do("POST", mcp, env.AS.Token(TokenOpts{}), Initialize, nil), 200)
	status(t, env.Do("POST", "/gerrit/mcp", env.AS.Token(TokenOpts{Resource: GerritResource}), Initialize, nil), 200)
	recs := env.Upstream.Records()
	gl, ge := recs[0].Header, recs[1].Header
	if gl.Get("X-Gitlab-Pat-Token") != "glpat-alice-token" || gl.Get("Authorization") != "" {
		t.Fatalf("gitlab headers = %v", gl)
	}
	// Basic base64("alice-gerrit:gerrit-pw")
	if ge.Get("Authorization") != "Basic YWxpY2UtZ2Vycml0OmdlcnJpdC1wdw==" || ge.Get("X-Gitlab-Pat-Token") != "" {
		t.Fatalf("gerrit headers = %v", ge)
	}
	if recs[1].URL != "/gerrit/mcp" {
		t.Fatalf("gerrit upstream url = %s", recs[1].URL)
	}
}

func TestUnmappedIdentityGetsNothing(t *testing.T) {
	env := NewEnv(t)
	body := status(t, env.Do("POST", mcp, env.AS.Token(TokenOpts{Subject: "mallory"}), Initialize, nil), 403)
	if JSONField(body, "error") != "no_credential_mapping" {
		t.Fatal(body)
	}
	// bob has GitLab but no Gerrit mapping
	status(t, env.Do("POST", "/gerrit/mcp", env.AS.Token(TokenOpts{Subject: "bob", Resource: GerritResource}), Initialize, nil), 403)
	if env.Resolver.Calls() != 0 || len(env.Upstream.Records()) != 0 {
		t.Fatal("unmapped identity reached the vault or upstream")
	}
}

func TestMappingKeyIncludesIssuer(t *testing.T) {
	env := NewEnv(t)
	// A mapping approved for a different issuer must not match this issuer's "alice".
	env.WriteMappings([]map[string]any{{"issuer": "https://other-issuer.example", "subject": "alice", "service": "gitlab",
		"fields": map[string]string{"username": Ref("alice", "gitlab", "username"), "api_token": Ref("alice", "gitlab", "api_token")}}})
	status(t, env.Do("POST", mcp, env.AS.Token(TokenOpts{}), Initialize, nil), 403)
}

func TestCrossUserAndCrossServiceSessionRejected(t *testing.T) {
	env := NewEnv(t)
	alice := env.AS.Token(TokenOpts{})
	bob := env.AS.Token(TokenOpts{Subject: "bob", SessionID: "session-2"})
	session := env.Do("POST", mcp, alice, Initialize, nil).Header.Get("Mcp-Session-Id")

	status(t, env.Do("POST", mcp, alice, `{"id":2}`, map[string]string{"Mcp-Session-Id": session}), 200)
	last := env.Upstream.Records()[1].Header.Get("Mcp-Session-Id")
	if last != "upstream-session-1" {
		t.Fatalf("upstream got session %q; the gateway tag must be stripped", last)
	}
	body := status(t, env.Do("POST", mcp, bob, `{"id":3}`, map[string]string{"Mcp-Session-Id": session}), 403)
	if JSONField(body, "error") != "session_binding_mismatch" {
		t.Fatal(body)
	}
	gerrit := env.AS.Token(TokenOpts{Resource: GerritResource})
	status(t, env.Do("POST", "/gerrit/mcp", gerrit, `{"id":4}`, map[string]string{"Mcp-Session-Id": session}), 403)
	status(t, env.Do("POST", mcp, alice, `{"id":5}`, map[string]string{"Mcp-Session-Id": "upstream-session-1"}), 403)
	if len(env.Upstream.Records()) != 2 {
		t.Fatal("a rejected session reached the upstream")
	}
}

func TestInjectionOnEveryOperationAndSpoofRemoval(t *testing.T) {
	env := NewEnv(t)
	token := env.AS.Token(TokenOpts{})
	spoof := map[string]string{
		"X-GitLab-Username": "attacker", "X-GitLab-PAT-Token": "stolen", "Cookie": "sid=1",
		"X-Forwarded-Host": "evil.example", "X-Forwarded-For": "6.6.6.6", "X-Original-URL": "/admin",
		"Forwarded": "host=evil", "Proxy-Authorization": "x", "X-HTTP-Method-Override": "DELETE",
		"X-Remote-User": "root", "X-Foo": "bar", "Private-Token": "evil", "Origin": "https://evil.example",
		"Connection": "keep-alive, X-Foo", "X-Gitlab-Host": "evil.example",
	}
	merge := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range spoof {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	init := env.Do("POST", mcp+"?target=https://evil.example", token, Initialize, merge(nil))
	status(t, init, 200)
	h := merge(map[string]string{"Mcp-Session-Id": init.Header.Get("Mcp-Session-Id"), "Accept": "text/event-stream"})
	status(t, env.Do("POST", mcp, token, `{"id":2}`, h), 200)
	status(t, env.Do("GET", mcp, token, "", h), 200)
	status(t, env.Do("DELETE", mcp, token, "", h), 200)

	recs := env.Upstream.Records()
	var methods []string
	for _, r := range recs {
		methods = append(methods, r.Method)
		if r.URL != "/api/v4/mcp" {
			t.Fatalf("destination changed: %s", r.URL)
		}
		if r.Header.Get("X-Gitlab-Username") != "alice-gl" || r.Header.Get("X-Gitlab-Pat-Token") != "glpat-alice-token" {
			t.Fatalf("credentials not injected on %s: %v", r.Method, r.Header)
		}
		for _, name := range []string{"Authorization", "Cookie", "X-Forwarded-Host", "X-Forwarded-For", "X-Original-Url",
			"Forwarded", "Proxy-Authorization", "X-Http-Method-Override", "X-Remote-User", "X-Foo", "Private-Token", "Origin", "X-Gitlab-Host"} {
			if r.Header.Get(name) != "" {
				t.Fatalf("%s survived on %s", name, r.Method)
			}
		}
		for _, values := range r.Header {
			for _, v := range values {
				if strings.Contains(v, "evil") || v == "attacker" || v == "stolen" {
					t.Fatalf("spoofed value reached upstream: %q", v)
				}
			}
		}
	}
	if strings.Join(methods, ",") != "POST,POST,GET,DELETE" {
		t.Fatalf("methods = %v", methods)
	}
}

func TestDeleteRequiresSession(t *testing.T) {
	env := NewEnv(t)
	status(t, env.Do("DELETE", mcp, env.AS.Token(TokenOpts{}), "", nil), 400)
	if len(env.Upstream.Records()) != 0 {
		t.Fatal("DELETE without session reached upstream")
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	env := NewEnv(t)
	evil := NewFakeUpstream(t)
	env.Upstream.Behavior = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.Server.URL+"/steal", http.StatusTemporaryRedirect)
	}
	resp := env.Do("POST", mcp, env.AS.Token(TokenOpts{}), Initialize, nil)
	body := status(t, resp, 502)
	if JSONField(body, "error") != "upstream_redirect" || resp.Header.Get("Location") != "" {
		t.Fatal(body)
	}
	if n := len(evil.Records()); n != 0 {
		t.Fatalf("redirect target received %d requests (credentials leaked)", n)
	}
}

func TestUpstreamStatusHandling(t *testing.T) {
	env := NewEnv(t)
	token := env.AS.Token(TokenOpts{})
	env.Upstream.Behavior = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="gl"`)
		w.WriteHeader(401)
	}
	resp := env.Do("POST", mcp, token, Initialize, nil)
	status(t, resp, 502)
	if resp.Header.Get("WWW-Authenticate") != "" {
		t.Fatal("an upstream OAuth challenge must not reach the MCP client")
	}
	env.Upstream.Behavior = func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Mcp-Protocol-Version", "2025-06-18")
			_, _ = io.WriteString(w, "event: message\ndata: {}\n\n")
		default:
			if strings.Contains(r.Header.Get("Content-Type"), "json") {
				w.WriteHeader(202)
				return
			}
			w.WriteHeader(404)
		}
	}
	sse := env.Do("GET", mcp, token, "", nil)
	if sse.StatusCode != 200 || sse.Header.Get("Content-Type") != "text/event-stream" ||
		sse.Header.Get("Mcp-Protocol-Version") != "2025-06-18" || !strings.HasPrefix(ReadBody(sse), "event: message") {
		t.Fatalf("sse passthrough failed: %v", sse.Header)
	}
	status(t, env.Do("POST", mcp, token, `{"method":"notifications/initialized"}`, nil), 202)
	status(t, env.Do("POST", mcp, token, `{"id":1}`, map[string]string{"Content-Type": "text/plain"}), 404)
}

func TestStreamingFlushesEventsAndCancelsUpstream(t *testing.T) {
	env := NewEnv(t)
	release, cancelled := make(chan struct{}), make(chan struct{})
	env.Upstream.Behavior = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
			_, _ = io.WriteString(w, "data: second\n\n")
		case <-r.Context().Done():
			close(cancelled)
		}
	}
	req, _ := http.NewRequest("GET", env.Gateway.URL+mcp, nil)
	req.Header.Set("Authorization", "Bearer "+env.AS.Token(TokenOpts{}))
	ctx, cancel := contextWithCancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := resp.Body.Read(buf) // arrives while the upstream is still holding the stream open
	if err != nil || !strings.Contains(string(buf[:n]), "first") {
		t.Fatalf("first event not delivered incrementally: %q %v", buf[:n], err)
	}
	cancel() // the MCP client disconnects
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("client disconnect did not cancel the upstream request")
	}
	close(release)
}

func TestUpstreamUnreachableIsRedacted(t *testing.T) {
	env := NewEnv(t)
	env.Upstream.Server.Close()
	body := status(t, env.Do("POST", mcp, env.AS.Token(TokenOpts{}), Initialize, nil), 502)
	if JSONField(body, "error") != "upstream_unreachable" || strings.Contains(body, "glpat") || strings.Contains(body, "127.0.0.1") {
		t.Fatal(body)
	}
}

func TestRequestBodyLimit(t *testing.T) {
	env := NewEnv(t)
	status(t, env.Do("POST", mcp, env.AS.Token(TokenOpts{}), strings.Repeat("x", 2<<20), nil), 413)
	if env.Resolver.Calls() != 0 {
		t.Fatal("oversize request reached the vault")
	}
}

func TestProviderFailuresAreExplicitAndRedacted(t *testing.T) {
	cases := map[string]struct {
		err  error
		want int
		code string
	}{
		"outage":        {secrets.ErrProviderUnavailable, 503, "credential_provider_unavailable"},
		"missing field": {secrets.ErrFieldUnavailable, 502, "credential_unavailable"},
		"raw error":     {io.ErrUnexpectedEOF, 502, "credential_unavailable"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			env := NewEnv(t)
			var logs bytes.Buffer
			old := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
			defer slog.SetDefault(old)
			env.Resolver.SetErr(tc.err)
			body := status(t, env.Do("POST", mcp, env.AS.Token(TokenOpts{}), Initialize, nil), tc.want)
			if JSONField(body, "error") != tc.code || strings.Contains(body+logs.String(), Sentinel) || strings.Contains(body, "op://") {
				t.Fatalf("body=%s logs=%s", body, logs.String())
			}
			if len(env.Upstream.Records()) != 0 {
				t.Fatal("upstream reached despite credential failure")
			}
		})
	}
}

func TestRotationVisibleAfterTTLAndNoExpiredFallback(t *testing.T) {
	env := NewEnv(t)
	token := func() string { return env.AS.Token(TokenOpts{ExpiresIn: time.Hour}) }
	status(t, env.Do("POST", mcp, token(), Initialize, nil), 200)
	// rotate the secret in the vault; same reference
	env.Resolver.Values[Ref("alice", "gitlab", "api_token")] = "glpat-alice-ROTATED"
	status(t, env.Do("POST", mcp, token(), Initialize, nil), 200)
	if got := env.Upstream.Records()[1].Header.Get("X-Gitlab-Pat-Token"); got != "glpat-alice-token" {
		t.Fatalf("cache should still serve the old value inside the TTL, got %s", got)
	}
	env.Clock.Advance(301 * time.Second)
	status(t, env.Do("POST", mcp, token(), Initialize, nil), 200)
	if got := env.Upstream.Records()[2].Header.Get("X-Gitlab-Pat-Token"); got != "glpat-alice-ROTATED" {
		t.Fatalf("rotation not visible after TTL, got %s", got)
	}
	// provider outage after the cache expired: the expired entry must not be served
	env.Clock.Advance(301 * time.Second)
	env.Resolver.SetErr(secrets.ErrProviderUnavailable)
	status(t, env.Do("POST", mcp, token(), Initialize, nil), 503)
	if len(env.Upstream.Records()) != 3 {
		t.Fatal("expired credentials were served during an outage")
	}
}

func TestCacheBoundedBySessionExpiryAndIsolatedAcrossUsers(t *testing.T) {
	env := NewEnv(t)
	// token expires in 5s: cache lifetime is bounded by it, not the 300s TTL
	status(t, env.Do("POST", mcp, env.AS.Token(TokenOpts{ExpiresIn: 5 * time.Second}), Initialize, nil), 200)
	env.Clock.Advance(10 * time.Second)
	status(t, env.Do("POST", mcp, env.AS.Token(TokenOpts{ExpiresIn: time.Hour}), Initialize, nil), 200)
	if env.Resolver.Calls() != 2 {
		t.Fatalf("calls = %d; entry must not outlive the session", env.Resolver.Calls())
	}
	// bob must never get alice's cached entry
	status(t, env.Do("POST", mcp, env.AS.Token(TokenOpts{Subject: "bob", SessionID: "s2", ExpiresIn: time.Hour}), Initialize, nil), 200)
	if got := env.Upstream.Records()[2].Header.Get("X-Gitlab-Username"); got != "bob-gl" {
		t.Fatalf("bob received %q", got)
	}
}

func TestMappingRemovalAndFailClosed(t *testing.T) {
	env := NewEnv(t)
	token := env.AS.Token(TokenOpts{ExpiresIn: time.Hour})
	status(t, env.Do("POST", mcp, token, Initialize, nil), 200)
	// administrator removes alice's GitLab access: effective immediately, cache notwithstanding
	env.WriteMappings(DefaultMappings(env.AS.Issuer())[1:2])
	time.Sleep(10 * time.Millisecond)
	status(t, env.Do("POST", mcp, token, Initialize, nil), 403)
	// invalid file after startup: fail closed
	env.WriteMappings([]map[string]any{{"issuer": "x", "subject": "y", "service": "gitlab", "fields": map[string]string{"username": "not-a-ref"}}})
	time.Sleep(10 * time.Millisecond)
	body := status(t, env.Do("POST", mcp, token, Initialize, nil), 503)
	if JSONField(body, "error") != "mapping_unavailable" {
		t.Fatal(body)
	}
}

func TestPublicPathPrefix(t *testing.T) {
	env := NewEnv(t, func(raw map[string]any) {
		raw["public_path_prefix"] = "/mcp-proxy"
		svcs := raw["services"].([]any)
		svcs[0].(map[string]any)["resource_url"] = "https://mcp.example.test/mcp-proxy/gitlab/mcp"
	})
	token := env.AS.Token(TokenOpts{Resource: "https://mcp.example.test/mcp-proxy/gitlab/mcp"})
	status(t, env.Do("POST", "/gitlab/mcp", token, Initialize, nil), 200)           // ingress stripped the prefix
	status(t, env.Do("POST", "/mcp-proxy/gitlab/mcp", token, Initialize, nil), 200) // ingress kept it
	status(t, env.Do("GET", "/.well-known/oauth-protected-resource/mcp-proxy/gitlab/mcp", "", "", nil), 200)
}

func TestHealthAndReadinessExposeNoSecrets(t *testing.T) {
	env := NewEnv(t)
	for _, path := range []string{"/healthz", "/readyz"} {
		body := status(t, env.Do("GET", path, "", "", nil), 200)
		if strings.Contains(body, Sentinel) || strings.Contains(body, "op://") {
			t.Fatal(body)
		}
	}
}
