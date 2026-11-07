package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func jwkFor(key *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func signTestIDToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": kid}
	headEncoded := base64.RawURLEncoding.EncodeToString(mustJSON(header))
	claimEncoded := base64.RawURLEncoding.EncodeToString(mustJSON(claims))
	message := []byte(headEncoded + "." + claimEncoded)
	digest := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return string(message) + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestOIDCCompleteCapturesUpstreamSession(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwkFor(&key.PublicKey, "test-key")}})
	}))
	defer jwksServer.Close()

	const issuer = "https://upstream.example.com"
	const clientID = "test-client"
	now := time.Now().UTC()
	idToken := signTestIDToken(t, key, "test-key", map[string]any{
		"iss": issuer, "sub": "user-1", "aud": clientID, "nonce": "expected-nonce",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})

	var tokenServer *httptest.Server
	tokenServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token": idToken, "access_token": "upstream-access-token", "refresh_token": "upstream-refresh-token",
			"token_type": "Bearer", "expires_in": 300, "scope": "sql unity-catalog",
		})
	}))
	defer func() { tokenServer.Close() }()

	provider := &OIDCIdentityProvider{
		Connector: ConnectorConfig{Issuer: issuer, TokenEndpoint: tokenServer.URL, JWKSURI: jwksServer.URL, TokenEndpointAuthMethod: "none"},
		Client:    http.DefaultClient,
		ClientID:  clientID,
	}
	identity, err := provider.Complete(context.Background(), IdentityCallback{
		Code: "auth-code", RedirectURI: "https://mcp-auth.example.com/identity/callback", State: "state-1",
		Nonce: "expected-nonce", CodeVerifier: "verifier",
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if identity.Subject != "user-1" {
		t.Fatalf("unexpected subject: %q", identity.Subject)
	}
	if identity.UpstreamSession == nil {
		t.Fatal("expected Complete to capture an upstream session")
	}
	session := *identity.UpstreamSession
	if session.AccessToken != "upstream-access-token" || session.RefreshToken != "upstream-refresh-token" {
		t.Fatalf("unexpected upstream session: %+v", session)
	}
	if len(session.Scope) != 2 || session.Scope[0] != "sql" || session.Scope[1] != "unity-catalog" {
		t.Fatalf("unexpected upstream session scope: %+v", session.Scope)
	}
	if session.ExpiresAt.Before(time.Now().Add(4*time.Minute)) || session.ExpiresAt.After(time.Now().Add(6*time.Minute)) {
		t.Fatalf("unexpected upstream session expiry: %v", session.ExpiresAt)
	}
}

func TestJWKSCacheDoesNotRefetchWithinTTL(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwkFor(&key.PublicKey, "kid-1")}})
	}))
	defer server.Close()

	var cache jwksCache
	for range 3 {
		resolved, err := cache.resolve(context.Background(), server.Client(), server.URL, "kid-1")
		rsaKey, ok := resolved.(*rsa.PublicKey)
		if err != nil || !ok || rsaKey.N.Cmp(key.PublicKey.N) != 0 {
			t.Fatalf("resolve: %v", err)
		}
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("expected exactly one JWKS fetch within the cache TTL, got %d", got)
	}
}

func TestJWKSCacheRefreshesOnUnknownKid(t *testing.T) {
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var requests int32
	var rotated atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		keys := []any{jwkFor(&keyA.PublicKey, "kid-a")}
		if rotated.Load() {
			keys = append(keys, jwkFor(&keyB.PublicKey, "kid-b"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	defer server.Close()

	var cache jwksCache
	if _, err := cache.resolve(context.Background(), server.Client(), server.URL, "kid-a"); err != nil {
		t.Fatalf("initial resolve: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("expected one fetch, got %d", got)
	}

	rotated.Store(true)
	resolved, err := cache.resolve(context.Background(), server.Client(), server.URL, "kid-b")
	rsaKey, ok := resolved.(*rsa.PublicKey)
	if err != nil || !ok || rsaKey.N.Cmp(keyB.PublicKey.N) != 0 {
		t.Fatalf("expected an unknown kid to trigger a refresh: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Fatalf("expected a second fetch after an unknown kid, got %d", got)
	}
}

func TestJWKSCacheTTLHonorsCacheControl(t *testing.T) {
	cases := map[string]time.Duration{
		"max-age=120":          120 * time.Second,
		"public, max-age=30":   30 * time.Second,
		"no-cache":             defaultJWKSCacheTTL,
		"":                     defaultJWKSCacheTTL,
		"max-age=not-a-number": defaultJWKSCacheTTL,
		"max-age=0":            defaultJWKSCacheTTL,
		"max-age=-5":           defaultJWKSCacheTTL,
	}
	for header, want := range cases {
		if got := jwksCacheTTL(header); got != want {
			t.Errorf("jwksCacheTTL(%q) = %v, want %v", header, got, want)
		}
	}
}

func TestRSAExponentRejectsOversizedOrInvalidValues(t *testing.T) {
	if _, err := rsaExponent(make([]byte, 5)); err == nil {
		t.Fatal("expected an oversized exponent to be rejected")
	}
	if _, err := rsaExponent(nil); err == nil {
		t.Fatal("expected an empty exponent to be rejected")
	}
	if _, err := rsaExponent([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("expected a zero exponent to be rejected")
	}
	exponent, err := rsaExponent([]byte{0x01, 0x00, 0x01}) // 65537, the common case
	if err != nil || exponent != 65537 {
		t.Fatalf("rsaExponent(65537): got (%d, %v)", exponent, err)
	}
}

func TestValidExpiryAllowsClockSkew(t *testing.T) {
	justExpired := float64(time.Now().Add(-30 * time.Second).Unix())
	if !validExpiry(justExpired) {
		t.Fatal("expected an expiry just past now to be tolerated within clock skew")
	}
	longExpired := float64(time.Now().Add(-10 * time.Minute).Unix())
	if validExpiry(longExpired) {
		t.Fatal("expected an expiry well in the past to be rejected")
	}
}

func TestValidIssuedAtAndNotBefore(t *testing.T) {
	if !validIssuedAt(float64(time.Now().Unix())) {
		t.Fatal("expected an iat of now to be valid")
	}
	if validIssuedAt(float64(time.Now().Add(10 * time.Minute).Unix())) {
		t.Fatal("expected an iat far in the future to be rejected")
	}
	if !validNotBefore(nil) {
		t.Fatal("expected a missing nbf to be treated as valid")
	}
	if validNotBefore(float64(time.Now().Add(10 * time.Minute).Unix())) {
		t.Fatal("expected an nbf far in the future to be rejected")
	}
}

// TestUpstreamExchangeErrorClassifiesInvalidTarget covers the real
// OIDCTokenExchanger path. The non-2xx branch used to discard the OAuth error
// body, so an upstream invalid_target - an unacceptable audience, which is a
// 400 - was reported to the resource server as a 502 server_error.
func TestUpstreamExchangeErrorClassifiesInvalidTarget(t *testing.T) {
	cases := []struct {
		name             string
		status           int
		body             string
		wantUnacceptable bool
	}{
		{"invalid target", http.StatusBadRequest, `{"error":"invalid_target"}`, true},
		{"invalid grant", http.StatusBadRequest, `{"error":"invalid_grant"}`, false},
		{"upstream outage", http.StatusBadGateway, `upstream is down`, false},
		{"empty body", http.StatusInternalServerError, ``, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			response := &http.Response{
				StatusCode: testCase.status,
				Body:       io.NopCloser(strings.NewReader(testCase.body)),
			}
			err := upstreamExchangeError(response)
			if err == nil {
				t.Fatal("upstreamExchangeError returned nil for a non-2xx response")
			}
			if got := errors.Is(err, ErrUnacceptableAudience); got != testCase.wantUnacceptable {
				t.Fatalf("errors.Is(err, ErrUnacceptableAudience) = %v, want %v (err: %v)", got, testCase.wantUnacceptable, err)
			}
		})
	}
}

func TestOIDCNonceCanBeExplicitlyDisabledForProviderWithoutNonceClaim(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwkFor(&key.PublicKey, "test-key")}})
	}))
	defer jwksServer.Close()

	const issuer = "https://provider.example.com"
	const clientID = "test-client"
	now := time.Now().UTC()
	idToken := signTestIDToken(t, key, "test-key", map[string]any{
		"iss": issuer, "sub": "user-1", "aud": clientID,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	provider := &OIDCIdentityProvider{
		Connector: ConnectorConfig{Issuer: issuer, JWKSURI: jwksServer.URL, IDTokenNoncePolicy: "disabled"},
		Client:    http.DefaultClient, ClientID: clientID,
	}
	location, _, err := provider.Begin(context.Background(), IdentityRequest{}, "state-1")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Query().Get("nonce"); got != "" {
		t.Fatalf("nonce = %q, want absent for the explicitly disabled policy", got)
	}
	if _, err := provider.verifyIDToken(context.Background(), idToken, "not-sent"); err != nil {
		t.Fatalf("verify ID token without nonce under disabled policy: %v", err)
	}
}

func TestIDTokenNoncePolicyValidation(t *testing.T) {
	for _, policy := range []string{"", "required", "disabled"} {
		connector := validTestConnector()
		connector.IDTokenNoncePolicy = policy
		if err := connector.validate("test", false); err != nil {
			t.Fatalf("policy %q rejected: %v", policy, err)
		}
	}
	connector := validTestConnector()
	connector.IDTokenNoncePolicy = "optional"
	if err := connector.validate("test", false); err == nil {
		t.Fatal("unsupported nonce policy was accepted")
	}
}

// A provider refusing a token request says why in its OAuth error fields.
// Operators need that text to fix a misconfigured connector, so it is carried
// into the failure reason, bounded and cleaned, while the request's own secrets
// (code, verifier, client secret) never appear in it.
func TestOIDCCompleteReportsTheProvidersOAuthError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "invalid_request", "error_description": "Unable to retrieve access token: authorization code not found\nsecond line",
			"unrelated": "must not be reported",
		})
	}))
	defer tokenServer.Close()
	provider := &OIDCIdentityProvider{
		Connector: ConnectorConfig{Issuer: "https://upstream.example.com", TokenEndpoint: tokenServer.URL, TokenEndpointAuthMethod: "none"},
		Client:    http.DefaultClient, ClientID: "test-client",
	}
	_, err := provider.Complete(context.Background(), IdentityCallback{
		Code: "secret-auth-code", RedirectURI: "https://mcp-auth.example.com/identity/callback", State: "s", Nonce: "n", CodeVerifier: "secret-verifier",
	})
	if err == nil {
		t.Fatal("a refused token request was accepted")
	}
	message := err.Error()
	for _, want := range []string{"HTTP 401", "invalid_request", "authorization code not found"} {
		if !strings.Contains(message, want) {
			t.Errorf("error %q does not mention %q", message, want)
		}
	}
	for _, leak := range []string{"secret-auth-code", "secret-verifier", "must not be reported", "\n"} {
		if strings.Contains(message, leak) {
			t.Errorf("error %q must not contain %q", message, leak)
		}
	}
}

func TestProviderOAuthErrorIsBoundedAndTolerantOfOtherBodies(t *testing.T) {
	long := strings.Repeat("x", 5000)
	for name, body := range map[string]string{
		"not json":   "<html>gateway error</html>",
		"empty":      "",
		"wrong type": `{"error": 5, "error_description": ["a"]}`,
		"huge":       `{"error": "` + long + `", "error_description": "` + long + `"}`,
	} {
		detail := providerOAuthError(strings.NewReader(body))
		if len(detail) > 400 {
			t.Errorf("%s: detail is %d bytes, want it bounded", name, len(detail))
		}
		if strings.ContainsAny(detail, "\n\r\t") {
			t.Errorf("%s: detail contains control characters: %q", name, detail)
		}
	}
	if got := providerOAuthError(strings.NewReader(`{"error":"invalid_grant"}`)); got != "invalid_grant" {
		t.Errorf("error without a description = %q", got)
	}
}

func pkceConnector(auth string, pkce *bool, tokenEndpoint string) ConnectorConfig {
	return ConnectorConfig{
		Issuer: "https://upstream.example.com", AuthorizationEndpoint: "https://upstream.example.com/authorize", TokenEndpoint: tokenEndpoint,
		JWKSURI: "https://upstream.example.com/jwks", ClientID: "client", ClientSecretEnv: "TEST_PKCE_SECRET", ExchangeClientID: "client",
		TokenEndpointAuthMethod: auth, Scopes: []string{"openid"}, PKCE: pkce,
	}
}

func boolPtr(v bool) *bool { return &v }

// Some providers (LinkedIn's standard apps) refuse client-secret authentication
// for a code issued with PKCE. A connector can turn PKCE off; the default keeps
// it on so no existing connector changes.
func TestOIDCBeginSendsPKCEUnlessTheConnectorDisablesIt(t *testing.T) {
	t.Setenv("TEST_PKCE_SECRET", "secret")
	for name, tc := range map[string]struct {
		pkce      *bool
		challenge bool
	}{"default": {nil, true}, "explicitly on": {boolPtr(true), true}, "off": {boolPtr(false), false}} {
		provider, err := NewOIDCIdentityProvider(pkceConnector("client_secret_post", tc.pkce, "https://upstream.example.com/token"), "http://localhost:8080/identity/callback", true)
		if err != nil {
			t.Fatal(err)
		}
		location, verifier, err := provider.Begin(context.Background(), IdentityRequest{Nonce: "n"}, "state-1")
		if err != nil {
			t.Fatal(err)
		}
		query, _ := url.Parse(location)
		got := query.Query().Get("code_challenge") != "" && query.Query().Get("code_challenge_method") == "S256"
		if got != tc.challenge {
			t.Errorf("%s: code_challenge sent = %v, want %v (%s)", name, got, tc.challenge, location)
		}
		if verifier == "" {
			t.Errorf("%s: Begin returned no verifier, which the stored login state relies on", name)
		}
	}
}

func TestOIDCCompleteSendsTheCodeVerifierOnlyWhenPKCEIsOn(t *testing.T) {
	t.Setenv("TEST_PKCE_SECRET", "secret")
	for name, tc := range map[string]struct {
		pkce *bool
		want bool
	}{"default": {nil, true}, "off": {boolPtr(false), false}} {
		var sent url.Values
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			sent = r.PostForm
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"stop_here"}`))
		}))
		provider, err := NewOIDCIdentityProvider(pkceConnector("client_secret_post", tc.pkce, tokenServer.URL), "http://localhost:8080/identity/callback", true)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = provider.Complete(context.Background(), IdentityCallback{Code: "c", RedirectURI: "http://localhost:8080/identity/callback", State: "s", Nonce: "n", CodeVerifier: "stored-verifier"})
		tokenServer.Close()
		if (sent.Get("code_verifier") != "") != tc.want {
			t.Errorf("%s: code_verifier sent = %q, want sent=%v", name, sent.Get("code_verifier"), tc.want)
		}
		if sent.Get("client_secret") != "secret" || sent.Get("client_id") != "client" {
			t.Errorf("%s: client credentials were not sent in the body: %v", name, sent)
		}
	}
}

func TestPKCECanOnlyBeDisabledForAConnectorWithAClientSecret(t *testing.T) {
	t.Setenv("TEST_PKCE_SECRET", "secret")
	if err := pkceConnector("client_secret_post", boolPtr(false), "https://upstream.example.com/token").validate("c", false); err != nil {
		t.Errorf("a confidential connector could not disable PKCE: %v", err)
	}
	public := pkceConnector("none", boolPtr(false), "https://upstream.example.com/token")
	public.ClientSecretEnv = ""
	if err := public.validate("c", false); err == nil {
		t.Error("PKCE was disabled for a public client, which has nothing else to bind the code to")
	}
}
