package server

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestResourceAuthorizationCheckBeforeCode(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(map[bool]string{false: "allowed", true: "denied"}[denied], func(t *testing.T) {
			s := loginTestServer(t, LoginEntry{Method: &fakeCredentialMethod{id: "directory", user: "alice", password: "test"}})
			calls := 0
			s.ResourceAuthorizationCheck = func(ctx context.Context, resource, subject string) error {
				calls++
				if resource != "http://localhost:8081/mcp" || subject != "directory:alice" {
					t.Fatal("unverified check context")
				}
				if denied {
					return errors.New("sensitive provider detail")
				}
				return nil
			}
			pending := ConsentRequest{Request: AuthorizationRequest{ClientID: "client", RedirectURI: "http://localhost:9999/callback", Resource: "http://localhost:8081/mcp", State: "state"}}
			w := httptest.NewRecorder()
			s.completeAuthorization(w, httptest.NewRequest("GET", "http://localhost:8080/identity/callback", nil), pending, Identity{Subject: "directory:alice"})
			u, err := url.Parse(w.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatal("check was skipped")
			}
			if denied {
				if u.Query().Get("code") != "" || u.Query().Get("error") != "access_denied" {
					t.Fatal("denial issued a code")
				}
				if strings.Contains(w.Body.String()+u.String(), "sensitive") {
					t.Fatal("provider error leaked")
				}
			} else if u.Query().Get("code") == "" {
				t.Fatal("successful check did not issue a code")
			}
		})
	}
}
