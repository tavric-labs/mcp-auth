package credentials

import (
	"context"
	"testing"
	"time"

	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/headers"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/mappings"
)

type fixedMapping struct{}

func (fixedMapping) Lookup(string, string, string) (*mappings.Mapping, error) {
	return &mappings.Mapping{Version: "v1", Refs: map[string]string{"password": "test://vault/item/password"}}, nil
}

type blockedProvider struct{ started, release chan struct{} }

func (p blockedProvider) Ready() bool { return true }
func (p blockedProvider) Resolve(context.Context, map[string]string) (map[string]string, error) {
	close(p.started)
	<-p.release
	return map[string]string{"password": "old"}, nil
}

func TestFreshLoginInvalidationCannotBeUndoneByInFlightRead(t *testing.T) {
	p := blockedProvider{started: make(chan struct{}), release: make(chan struct{})}
	s := &Service{Mappings: fixedMapping{}, Resolver: p, TTL: time.Hour, Max: 5}
	id := Identity{Issuer: "https://issuer", Subject: "alice"}
	done := make(chan error, 1)
	go func() {
		_, err := s.HeadersFor(context.Background(), id, "demo", []headers.Spec{{Name: "X-Password", Kind: headers.Direct, Field: "password"}}, time.Now().Add(time.Hour))
		done <- err
	}()
	<-p.started
	s.Invalidate(id, "demo")
	close(p.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if s.Len() != 0 {
		t.Fatal("in-flight old read repopulated cache after new login")
	}
}
