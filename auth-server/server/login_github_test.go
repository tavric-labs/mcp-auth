package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeGitHub serves the three endpoints the login uses.
type fakeGitHub struct {
	t          *testing.T
	orgs       map[string]string // org -> membership state
	tokenError string
	userID     int64
	sawVerifer string
}

func (g *fakeGitHub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		g.sawVerifer = r.PostFormValue("code_verifier")
		if r.Header.Get("Accept") != "application/json" {
			g.t.Error("token request must ask for JSON")
		}
		w.Header().Set("Content-Type", "application/json")
		if g.tokenError != "" || r.PostFormValue("code") != "good" || r.PostFormValue("client_secret") != "gh-secret" {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "bad_verification_code"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "gho_token", "token_type": "bearer"})
	})
	authorized := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer gho_token" || r.Header.Get("User-Agent") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		if authorized(w, r) {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": g.userID, "login": "octo", "name": "Octo Cat", "email": "octo@example.com"})
		}
	})
	mux.HandleFunc("GET /user/memberships/orgs/{org}", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r) {
			return
		}
		state, ok := g.orgs[r.PathValue("org")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"state": state})
	})
	return mux
}

func newGitHubTestMethod(t *testing.T, orgs []string) (*GitHubLoginMethod, *fakeGitHub) {
	t.Helper()
	fake := &fakeGitHub{t: t, userID: 583231, orgs: map[string]string{}}
	upstream := httptest.NewServer(fake.handler())
	t.Cleanup(upstream.Close)
	t.Setenv("TEST_GITHUB_CLIENT_SECRET", "gh-secret")
	method, err := NewGitHubLoginMethod(GitHubConfig{
		ID: "github", Label: "GitHub", ClientID: "Iv1.abc", ClientSecretEnv: "TEST_GITHUB_CLIENT_SECRET",
		AllowedOrgs: orgs, BaseURL: upstream.URL, APIURL: upstream.URL,
	}, "https://auth.example.com/identity/callback", true)
	if err != nil {
		t.Fatal(err)
	}
	return method, fake
}

func TestGitHubBeginBuildsTheAuthorizeURL(t *testing.T) {
	method, _ := newGitHubTestMethod(t, nil)
	location, verifier, err := method.Begin(context.Background(), IdentityRequest{}, "github.state123")
	if err != nil || verifier == "" {
		t.Fatalf("Begin: %v verifier %q", err, verifier)
	}
	parsed, _ := url.Parse(location)
	query := parsed.Query()
	if parsed.Path != "/login/oauth/authorize" || query.Get("client_id") != "Iv1.abc" || query.Get("state") != "github.state123" ||
		query.Get("redirect_uri") != "https://auth.example.com/identity/callback" || query.Get("scope") != "read:user" ||
		query.Get("allow_signup") != "false" || query.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorize URL = %s", location)
	}
	if _, _, err := method.Begin(context.Background(), IdentityRequest{}, ""); err == nil {
		t.Fatal("an empty state was accepted")
	}
	withOrgs, _ := newGitHubTestMethod(t, []string{"acme"})
	location, _, _ = withOrgs.Begin(context.Background(), IdentityRequest{}, "s")
	if !strings.Contains(location, "read%3Aorg") {
		t.Fatalf("an org restriction must request read:org: %s", location)
	}
}

func TestGitHubCompleteUsesTheNumericAccountID(t *testing.T) {
	method, fake := newGitHubTestMethod(t, nil)
	identity, err := method.Complete(context.Background(), IdentityCallback{Code: "good", CodeVerifier: "v-123", RedirectURI: "https://auth.example.com/identity/callback"})
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "583231" {
		t.Fatalf("subject = %q, want the immutable numeric id, not the renameable login", identity.Subject)
	}
	if identity.Claims["login"] != "octo" || identity.Claims["email"] != "octo@example.com" {
		t.Fatalf("claims = %v", identity.Claims)
	}
	if identity.UpstreamSession != nil {
		t.Fatal("the GitHub token must not be kept")
	}
	if fake.sawVerifer != "v-123" {
		t.Fatalf("PKCE verifier was not sent: %q", fake.sawVerifer)
	}
}

func TestGitHubCompleteFailures(t *testing.T) {
	method, fake := newGitHubTestMethod(t, nil)
	if _, err := method.Complete(context.Background(), IdentityCallback{Code: "bad", CodeVerifier: "v"}); err == nil {
		t.Fatal("a rejected code (HTTP 200 with an error field) was accepted")
	}
	if _, err := method.Complete(context.Background(), IdentityCallback{CodeVerifier: "v"}); err == nil {
		t.Fatal("an empty code was accepted")
	}
	if _, err := method.Complete(context.Background(), IdentityCallback{Code: "good"}); err == nil {
		t.Fatal("a missing verifier was accepted")
	}
	fake.userID = 0
	if _, err := method.Complete(context.Background(), IdentityCallback{Code: "good", CodeVerifier: "v"}); err == nil {
		t.Fatal("a response without an account id was accepted")
	}
}

func TestGitHubOrgRestriction(t *testing.T) {
	method, fake := newGitHubTestMethod(t, []string{"acme", "other"})
	callback := IdentityCallback{Code: "good", CodeVerifier: "v"}
	if _, err := method.Complete(context.Background(), callback); err == nil {
		t.Fatal("a non-member was admitted")
	}
	fake.orgs["acme"] = "pending"
	if _, err := method.Complete(context.Background(), callback); err == nil {
		t.Fatal("a pending invitation counted as membership")
	}
	fake.orgs["other"] = "active"
	if _, err := method.Complete(context.Background(), callback); err != nil {
		t.Fatalf("an active member of an allowed org was refused: %v", err)
	}
}

func TestGitHubConfigValidation(t *testing.T) {
	t.Setenv("TEST_GITHUB_CLIENT_SECRET", "gh-secret")
	base := func() GitHubConfig {
		return GitHubConfig{ID: "github", Label: "GitHub", ClientID: "id", ClientSecretEnv: "TEST_GITHUB_CLIENT_SECRET"}
	}
	rejected := map[string]func(*GitHubConfig){
		"no client id":        func(c *GitHubConfig) { c.ClientID = "" },
		"both client ids":     func(c *GitHubConfig) { c.ClientIDEnv = "X" },
		"no secret env":       func(c *GitHubConfig) { c.ClientSecretEnv = "" },
		"empty secret":        func(c *GitHubConfig) { c.ClientSecretEnv = "TEST_GITHUB_MISSING" },
		"plain http base":     func(c *GitHubConfig) { c.BaseURL = "http://github.example.com" },
		"plain http api":      func(c *GitHubConfig) { c.APIURL = "http://api.github.example.com" },
		"org with a slash":    func(c *GitHubConfig) { c.AllowedOrgs = []string{"acme/repo"} },
		"blank org":           func(c *GitHubConfig) { c.AllowedOrgs = []string{" "} },
		"client id env empty": func(c *GitHubConfig) { c.ClientID = ""; c.ClientIDEnv = "TEST_GITHUB_MISSING" },
	}
	for name, edit := range rejected {
		config := base()
		edit(&config)
		if _, err := NewGitHubLoginMethod(config, "https://auth.example.com/identity/callback", false); err == nil {
			t.Errorf("accepted: %s", name)
		}
	}
	if _, err := NewGitHubLoginMethod(base(), "https://auth.example.com/identity/callback", false); err != nil {
		t.Fatalf("rejected a valid config: %v", err)
	}
}

func TestGoogleAllowedDomains(t *testing.T) {
	check := allowedEmailDomains([]string{"Example.com"})
	cases := map[string]struct {
		claims map[string]any
		ok     bool
	}{
		"verified, allowed":        {map[string]any{"email": "a@example.com", "email_verified": true}, true},
		"verified string true":     {map[string]any{"email": strings.ToUpper("a@example.com"), "email_verified": "true"}, true},
		"unverified":               {map[string]any{"email": "a@example.com", "email_verified": false}, false},
		"verified flag missing":    {map[string]any{"email": "a@example.com"}, false},
		"other domain":             {map[string]any{"email": "a@example.org", "email_verified": true}, false},
		"subdomain is not a match": {map[string]any{"email": "a@mail.example.com", "email_verified": true}, false},
		"no email":                 {map[string]any{"email_verified": true}, false},
		"no local part":            {map[string]any{"email": "@example.com", "email_verified": true}, false},
		"domain in local part":     {map[string]any{"email": "a@example.com@example.org", "email_verified": true}, false},
	}
	for name, tc := range cases {
		if err := check(tc.claims); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", name, err, tc.ok)
		}
	}
	if allowedEmailDomains(nil) != nil {
		t.Error("no domains configured must mean no restriction")
	}
}

func TestGoogleLoginMethodUsesGoogleEndpoints(t *testing.T) {
	t.Setenv("TEST_GOOGLE_CLIENT_SECRET", "g-secret")
	method, err := NewGoogleLoginMethod(GoogleConfig{
		ID: "google", Label: "Google", ClientID: "123.apps.googleusercontent.com", ClientSecretEnv: "TEST_GOOGLE_CLIENT_SECRET",
		AllowedDomains: []string{"example.com"},
	}, "https://auth.example.com/identity/callback", false)
	if err != nil {
		t.Fatal(err)
	}
	location, verifier, err := method.Begin(context.Background(), IdentityRequest{Nonce: "n-1"}, "google.s1")
	if err != nil || verifier == "" {
		t.Fatalf("Begin: %v", err)
	}
	parsed, _ := url.Parse(location)
	query := parsed.Query()
	if parsed.Host != "accounts.google.com" || query.Get("nonce") != "n-1" || query.Get("scope") != "openid email profile" || query.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorize URL = %s", location)
	}
	for _, bad := range []string{"@example.com", "example.com/path", "a b", " "} {
		if _, err := NewGoogleLoginMethod(GoogleConfig{ID: "google", Label: "G", ClientID: "id", ClientSecretEnv: "TEST_GOOGLE_CLIENT_SECRET", AllowedDomains: []string{bad}}, "https://auth.example.com/identity/callback", false); err == nil {
			t.Errorf("allowed_domains %q was accepted", bad)
		}
	}
}
