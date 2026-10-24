package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestResourceLoginOverridesDefaultMethods(t *testing.T) {
	const resource = "https://mcp.example/headers/mcp"
	registry, err := NewLoginRegistry(
		LoginEntry{Method: &fakeRedirectMethod{id: "keycloak"}, SubjectPrefix: ""},
		LoginEntry{Method: &fakeCredentialMethod{id: "headers"}, SubjectPrefix: "headers:", Resources: []string{resource}},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ resource, method string }{{resource, "headers"}, {"https://mcp.example/other/mcp", "keycloak"}} {
		entries := registry.entriesForResource(tc.resource)
		if len(entries) != 1 || entries[0].Method.ID() != tc.method {
			t.Fatalf("resource %s selected %#v", tc.resource, entries)
		}
	}
	if _, ok := registry.lookupForResource("keycloak", resource); ok {
		t.Fatal("default method bypasses mandatory resource login")
	}
	if _, ok := registry.lookupForResource("headers", "https://mcp.example/other/mcp"); ok {
		t.Fatal("resource method usable on another resource")
	}
}

func TestResourceLoginRejectsDirectMethodBypass(t *testing.T) {
	const resource = "http://localhost:8081/mcp"
	s := loginTestServer(t,
		LoginEntry{Method: &fakeRedirectMethod{id: "keycloak"}, SubjectPrefix: ""},
		LoginEntry{Method: &fakeCredentialMethod{id: "headers", user: "alice", password: "right"}, SubjectPrefix: "headers:", Resources: []string{resource}},
	)
	loginID, binding := "pending-login", "browser-binding"
	pending := ConsentRequest{ValueHash: HashSecret(loginRecordKey(loginID)), Request: AuthorizationRequest{ClientID: "client", Resource: resource, LoginBinding: HashSecret(binding)}, ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.Store.SaveConsentRequest(pending); err != nil {
		t.Fatal(err)
	}
	b := newBrowser()
	b.cookies[s.loginCookieName(loginID)] = &http.Cookie{Name: s.loginCookieName(loginID), Value: binding}
	w := b.do(s, postForm("/login/keycloak", url.Values{"login_id": {loginID}}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("direct fallback method status %d; location=%s", w.Code, w.Header().Get("Location"))
	}
	if w.Header().Get("Location") != "" {
		t.Fatal("disallowed method began authentication")
	}
	page := b.do(s, httptest.NewRequest("GET", "/login?login_id="+loginID+"&resource="+url.QueryEscape(resource), nil))
	if strings.Contains(page.Body.String(), "/login/keycloak") || !strings.Contains(page.Body.String(), "/login/headers") {
		t.Fatalf("wrong methods rendered: %s", page.Body.String())
	}
}

func TestLoginResourceConfiguration(t *testing.T) {
	for _, resource := range []string{"*", "/relative", "ftp://example.com/x", "https://user:pass@example.com/mcp", "https://example.com/mcp#fragment"} {
		if _, err := NewLoginRegistry(LoginEntry{Method: &fakeRedirectMethod{id: "test"}, Resources: []string{resource}}); err == nil {
			t.Errorf("accepted resource %q", resource)
		}
	}
}

func TestResourceLoginCallbackCannotUseFallback(t *testing.T) {
	const resource = "http://localhost:8081/mcp"
	s := loginTestServer(t,
		LoginEntry{Method: &fakeRedirectMethod{id: "keycloak"}},
		LoginEntry{Method: &fakeCredentialMethod{id: "headers"}, SubjectPrefix: "headers:", Resources: []string{resource}},
	)
	state, binding := "keycloak.old-state", "browser"
	pending := ConsentRequest{ValueHash: HashSecret(state), Request: AuthorizationRequest{ClientID: "client", Resource: resource, LoginBinding: HashSecret(binding)}, ExpiresAt: time.Now().Add(time.Minute), CodeVerifier: "verifier-1"}
	if err := s.Store.SaveConsentRequest(pending); err != nil {
		t.Fatal(err)
	}
	b := newBrowser()
	b.cookies[s.loginCookieName(state)] = &http.Cookie{Name: s.loginCookieName(state), Value: binding}
	w := b.do(s, httptest.NewRequest("GET", "/identity/callback?state="+state+"&code=good", nil))
	if w.Code != http.StatusForbidden || w.Header().Get("Location") != "" {
		t.Fatalf("disallowed callback: %d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestParseLoginResourceAssignments(t *testing.T) {
	loginTestEnv(t)
	data := strings.Replace(allMethodsDocument, `"id": "google"`, `"id": "google", "resources":["https://mcp.example/headers/mcp"]`, 1)
	registry, err := ParseLoginMethods([]byte(data), LoginMethodsOptions{CallbackURL: "https://auth.example/identity/callback"})
	if err != nil {
		t.Fatal(err)
	}
	entries := registry.entriesForResource("https://mcp.example/headers/mcp")
	if len(entries) != 1 || entries[0].Method.ID() != "google" {
		t.Fatal("resource assignment was not loaded")
	}
	if len(registry.entriesForResource("https://mcp.example/other/mcp")) != 2 {
		t.Fatal("scoped method became a global default")
	}
}
