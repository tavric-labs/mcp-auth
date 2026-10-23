// Package credentialgateway composes the optional credential-injecting resource
// gateway. The OAuth core depends on none of this module or its providers.
package credentialgateway

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/config"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/credentials"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/gateway"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/mappings"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/secrets"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/providers/onepassword"
)

type Resolver = secrets.Resolver

// ProviderFactory is the extension boundary for another vault implementation.
// Only its factory and reference validator need vendor-specific knowledge.
type ProviderFactory struct {
	New            func(json.RawMessage, string) (Resolver, error)
	ValidReference func(string) bool
}

type Resource struct {
	ID, URL, ClientID, KeyID string
	Scopes                   []string
	PublicKeyPEM             string
}

type Runtime struct {
	cfg    *config.Config
	creds  *credentials.Service
	ready  func() bool
	client *http.Client
}

// Open loads a gateway with the built-in 1Password provider.
func Open(path, version string) (*Runtime, error) {
	return OpenWithProviders(path, version, map[string]ProviderFactory{
		"onepassword": {New: onepassword.New, ValidReference: onepassword.ValidReference},
	})
}

func OpenWithProviders(path, version string, providers map[string]ProviderFactory) (*Runtime, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	factory, ok := providers[cfg.ProviderType]
	if !ok || factory.New == nil || factory.ValidReference == nil {
		return nil, errors.New("credential provider is not registered")
	}
	resolver, err := factory.New(cfg.ProviderOptions, version)
	if err != nil {
		return nil, err
	}
	store, err := mappings.NewValidatedFileStore(cfg.MappingsFile, cfg.RequiredFields(), factory.ValidReference)
	if err != nil {
		return nil, err
	}
	creds := &credentials.Service{Mappings: store, Resolver: resolver, TTL: cfg.CacheTTL, Max: cfg.CacheMaxEntries}
	return newRuntime(cfg, creds, resolver.Ready), nil
}

func newRuntime(cfg *config.Config, creds *credentials.Service, ready func() bool) *Runtime {
	return &Runtime{cfg: cfg, creds: creds, ready: ready, client: &http.Client{
		Timeout:       cfg.ConnectTimeout + cfg.ResponseHeaderTimeout,
		Transport:     &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: cfg.ConnectTimeout}).DialContext, TLSHandshakeTimeout: cfg.ConnectTimeout, ResponseHeaderTimeout: cfg.ResponseHeaderTimeout},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (r *Runtime) ListenAddr() string    { return r.cfg.Listen }
func (r *Runtime) Issuer() string        { return r.cfg.Issuer }
func (r *Runtime) Handler() http.Handler { return gateway.New(r.cfg, r.creds, r.ready, nil) }
func (r *Runtime) Resources() []Resource {
	var out []Resource
	for _, s := range r.cfg.Services {
		key, _ := x509.MarshalPKIXPublicKey(&s.Client.PrivateKey.PublicKey)
		out = append(out, Resource{ID: s.ID, URL: s.ResourceURL, ClientID: s.Client.ClientID, KeyID: s.Client.KeyID, PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: key})), Scopes: append([]string(nil), s.RequiredScopes...)})
	}
	return out
}

// CheckAuthorization runs after verified human login and before code issuance.
// Every new OAuth authorization resolves the approved mapping afresh and sends
// its rendered headers to a fixed same-origin GET validation endpoint. A cache
// hit from an older login cannot skip either check. Unmanaged resources retain
// their normal OAuth behavior.
func (r *Runtime) CheckAuthorization(ctx context.Context, resource, subject string) error {
	for _, s := range r.cfg.Services {
		if s.ResourceURL != resource {
			continue
		}
		fresh := &credentials.Service{Mappings: r.creds.Mappings, Resolver: r.creds.Resolver, TTL: 0, Max: 1}
		values, err := fresh.HeadersFor(ctx, credentials.Identity{Issuer: r.cfg.Issuer, Subject: subject}, s.ID, s.Headers, time.Now())
		if err != nil {
			return errors.New("upstream credential validation failed")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.ValidationURL, nil)
		if err != nil {
			return errors.New("upstream validation unavailable")
		}
		req.Header.Set("Cache-Control", "no-store")
		for name, value := range values.Values() {
			req.Header.Set(name, value)
		}
		resp, err := r.client.Do(req)
		if err != nil {
			return errors.New("upstream validation unavailable")
		}
		// Never log or return validation response bodies. Bound any drain.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return errors.New("upstream credential validation failed")
		}
		r.creds.Invalidate(credentials.Identity{Issuer: r.cfg.Issuer, Subject: subject}, s.ID)
		return nil
	}
	return nil
}
