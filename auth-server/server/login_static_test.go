package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const staticTestResource = "http://localhost:8081/mcp"

func staticEntry(t *testing.T) LoginEntry {
	t.Helper()
	method, err := NewStaticLoginMethod("vault", "Continue with the vault credential", "svc-a")
	if err != nil {
		t.Fatal(err)
	}
	return LoginEntry{Method: method, SubjectPrefix: "vault:", Resources: []string{staticTestResource}}
}

func TestStaticLoginShowsAButtonAndIssuesTheConfiguredSubject(t *testing.T) {
	instance := loginTestServer(t, staticEntry(t))
	approved := approveConsent(t, instance)
	location, _ := url.Parse(approved.Header().Get("Location"))
	page := serve(instance, httptest.NewRequest(http.MethodGet, "/login?"+location.RawQuery, nil))
	body := page.Body.String()
	if page.Code != http.StatusOK || !strings.Contains(body, "Continue with the vault credential") {
		t.Fatalf("login page did not offer the static method: %d %s", page.Code, body)
	}
	if strings.Contains(body, `type="password"`) || strings.Contains(body, `type="text"`) {
		t.Fatal("a static sign-in must not ask for typed values")
	}
	match := loginIDPattern.FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("no login id: %s", body)
	}
	response := serve(instance, postForm("/login/vault", url.Values{"login_id": {match[1]}}))
	redirect, _ := url.Parse(response.Header().Get("Location"))
	if redirect.Host != "localhost:9999" || redirect.Query().Get("code") == "" {
		t.Fatalf("did not return an authorization code to the client: %d %s", response.Code, redirect)
	}
	code, err := instance.Store.ConsumeAuthorizationCode(redirect.Query().Get("code"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code.Subject != "vault:svc-a" {
		t.Fatalf("subject = %q, want vault:svc-a", code.Subject)
	}
}

func TestStaticLoginDeniedWhenResourceCheckFails(t *testing.T) {
	instance := loginTestServer(t, staticEntry(t))
	var gotResource, gotSubject string
	instance.ResourceAuthorizationCheck = func(_ context.Context, resource, subject string) error {
		gotResource, gotSubject = resource, subject
		return errors.New("upstream rejected the vault credential")
	}
	loginID := loginPageID(t, instance)
	response := serve(instance, postForm("/login/vault", url.Values{"login_id": {loginID}}))
	redirect, _ := url.Parse(response.Header().Get("Location"))
	if redirect.Query().Get("error") != "access_denied" || redirect.Query().Get("code") != "" {
		t.Fatalf("a failed upstream check must deny without a code: %s", redirect)
	}
	if gotResource != staticTestResource || gotSubject != "vault:svc-a" {
		t.Fatalf("check saw resource=%q subject=%q", gotResource, gotSubject)
	}
}

func TestStaticLoginRequiresResourceScopeAndAValidSubject(t *testing.T) {
	for name, subject := range map[string]string{"empty": "", "space": "a b", "control": "a\x00b", "too long": strings.Repeat("a", 257)} {
		if _, err := NewStaticLoginMethod("vault", "x", subject); err == nil {
			t.Errorf("accepted %s subject", name)
		}
	}
	document := `{"methods":[{"id":"vault","type":"static","subject":"svc-a"}]}`
	if _, err := ParseLoginMethods([]byte(document), LoginMethodsOptions{}); err == nil {
		t.Fatal("an unscoped static method must be rejected")
	}
	scoped := `{"methods":[{"id":"vault","type":"static","subject":"svc-a","resources":["` + staticTestResource + `"]}]}`
	if _, err := ParseLoginMethods([]byte(scoped), LoginMethodsOptions{}); err != nil {
		t.Fatalf("scoped static method rejected: %v", err)
	}
	misspelled := `{"methods":[{"id":"vault","type":"static","subjet":"svc-a","resources":["` + staticTestResource + `"]}]}`
	if _, err := ParseLoginMethods([]byte(misspelled), LoginMethodsOptions{}); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestStaticLoginCannotServeOtherResources(t *testing.T) {
	company := &fakeCredentialMethod{id: "corp", user: "alice", password: "pw"}
	registry, err := NewLoginRegistry(LoginEntry{Method: company, SubjectPrefix: "corp:"}, staticEntry(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range registry.entriesForResource("http://localhost:8082/other") {
		if entry.Method.ID() == "vault" {
			t.Fatal("the static method leaked to an unassigned resource")
		}
	}
	scoped := registry.entriesForResource(staticTestResource)
	if len(scoped) != 1 || scoped[0].Method.ID() != "vault" {
		t.Fatalf("the assigned resource must use only the static method, got %d entries", len(scoped))
	}
}

// linkedMethod is a credential method that points at a vault page.
type linkedMethod struct {
	fakeCredentialMethod
	label, href string
}

func (m *linkedMethod) HelpLink() (string, string) { return m.label, m.href }

func loginPageFor(t *testing.T, label, href string) string {
	t.Helper()
	method := &linkedMethod{fakeCredentialMethod: fakeCredentialMethod{id: "corp", user: "alice", password: "pw"}, label: label, href: href}
	instance := loginTestServer(t, LoginEntry{Method: method, SubjectPrefix: "corp:"})
	approved := approveConsent(t, instance)
	location, _ := url.Parse(approved.Header().Get("Location"))
	page := serve(instance, httptest.NewRequest(http.MethodGet, "/login?"+location.RawQuery, nil))
	if page.Code != http.StatusOK {
		t.Fatalf("login page status %d", page.Code)
	}
	return page.Body.String()
}

func TestLoginPageShowsTheConfiguredVaultLink(t *testing.T) {
	for name, href := range map[string]string{
		"web vault":   "https://taranawireless.1password.com/app#/vault",
		"desktop app": "onepassword://open/i?a=ACCOUNT&v=VAULT&i=ITEM",
	} {
		body := loginPageFor(t, "Open 1Password", href)
		if !strings.Contains(body, `rel="noopener noreferrer"`) || !strings.Contains(body, `target="_blank"`) || !strings.Contains(body, "Open 1Password") {
			t.Errorf("%s: link missing or not isolated: %s", name, body)
		}
		if !strings.Contains(body, "onepassword://") && !strings.Contains(body, "https://taranawireless.1password.com") {
			t.Errorf("%s: href not rendered", name)
		}
	}
}

func TestLoginPageDropsUnsafeVaultLinks(t *testing.T) {
	for name, href := range map[string]string{
		"javascript": "javascript:alert(1)", "data": "data:text/html,x", "http": "http://vault.example.com/", "no host": "https:///x",
		"userinfo": "https://user:pw@vault.example.com/", "quote": `https://vault.example.com/"onmouseover=x`, "space": "https://vault.example.com/a b",
	} {
		body := loginPageFor(t, "Open", href)
		if strings.Contains(body, "<a ") || strings.Contains(body, "javascript:") {
			t.Errorf("%s: an unsafe link was rendered: %s", name, body)
		}
	}
	if strings.Contains(loginPageFor(t, "Open", ""), "<a ") {
		t.Error("a method with no link rendered one")
	}
}
