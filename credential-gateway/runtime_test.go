package credentialgateway

import (
	"context"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/config"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/credentials"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/headers"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/mappings"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// aliceOnly maps one identity to one service, like a table of approved bindings.
type aliceOnly struct{}

func (aliceOnly) Lookup(issuer, subject, service string) (*mappings.Mapping, error) {
	if issuer != "https://auth" || subject != "alice" || service != "demo" {
		return nil, nil
	}
	return &mappings.Mapping{Issuer: issuer, Subject: subject, Service: service, Version: "v1", Refs: map[string]string{"password": "test://item/password"}}, nil
}

type testProvider struct {
	value string
	calls int
}

func (p *testProvider) Resolve(_ context.Context, _ map[string]string) (map[string]string, error) {
	p.calls++
	return map[string]string{"password": p.value}, nil
}
func (*testProvider) Ready() bool { return true }

func TestPreflightRejectsWrongCredentialsAndAlwaysChecksFresh(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		if r.URL.Path != "/check" || r.Header.Get("X-Password") != "correct" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(204)
	}))
	defer upstream.Close()
	provider := &testProvider{value: "wrong"}
	cfg := &config.Config{Issuer: "https://auth", ConnectTimeout: time.Second, ResponseHeaderTimeout: time.Second, Services: []config.Service{{ID: "demo", ResourceURL: "https://mcp/demo/mcp", UpstreamURL: upstream.URL + "/mcp", ValidationURL: upstream.URL + "/check", Headers: []headers.Spec{{Name: "X-Password", Kind: headers.Direct, Field: "password"}}}}}
	run := newRuntime(cfg, &credentials.Service{Mappings: aliceOnly{}, Resolver: provider, TTL: time.Hour, Max: 5}, provider.Ready)
	if run.CheckAuthorization(context.Background(), "https://mcp/demo/mcp", "alice") == nil {
		t.Fatal("bad credentials authorized")
	}
	provider.value = "correct"
	if err := run.CheckAuthorization(context.Background(), "https://mcp/demo/mcp", "alice"); err != nil {
		t.Fatal(err)
	}
	provider.value = "rotated-invalid"
	if run.CheckAuthorization(context.Background(), "https://mcp/demo/mcp", "alice") == nil {
		t.Fatal("login reused stale credentials")
	}
	if provider.calls != 3 || upstreamCalls != 3 {
		t.Fatal("preflight was cached")
	}
	before := provider.calls
	if run.CheckAuthorization(context.Background(), "https://mcp/demo/mcp", "bob") == nil {
		t.Fatal("unmapped user authorized")
	}
	if provider.calls != before {
		t.Fatal("unmapped user reached provider")
	}
	if err := run.CheckAuthorization(context.Background(), "https://other/mcp", "alice"); err != nil {
		t.Fatal("unrelated OAuth resource changed")
	}
}
