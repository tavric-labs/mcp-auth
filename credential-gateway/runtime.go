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
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/config"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/credentials"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/formstore"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/gateway"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/headers"
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
	forms  *formstore.Store
}

// ErrRejected means the upstream refused the credentials. ErrUnavailable means
// the upstream could not be asked. Neither carries upstream or credential text.
var (
	ErrRejected    = errors.New("upstream credential validation failed")
	ErrUnavailable = errors.New("upstream validation unavailable")
)

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
	route := &router{
		forms:        &formstore.Store{TTL: cfg.FormTTL, Max: cfg.FormMaxEntries},
		formServices: map[string]bool{},
	}
	for _, s := range cfg.Services {
		if s.Source == config.SourceForm {
			route.formServices[s.ID] = true
		}
	}
	// A provider and a mappings file exist only when some service reads the vault.
	if cfg.HasVaultServices {
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
		route.vault, route.resolver = store, resolver
	}
	creds := &credentials.Service{Mappings: route, Resolver: route, TTL: cfg.CacheTTL, Max: cfg.CacheMaxEntries}
	runtime := newRuntime(cfg, creds, route.Ready)
	runtime.forms = route.forms
	return runtime, nil
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

// CheckAuthorization runs after sign-in and before code issuance. Every new
// OAuth authorization resolves the credentials afresh (the approved vault
// mapping, or the values just submitted at sign-in) and sends their rendered
// headers to a fixed same-origin GET validation endpoint. A cache hit from an
// older login cannot skip either check. Unmanaged resources retain their
// normal OAuth behavior.
func (r *Runtime) CheckAuthorization(ctx context.Context, resource, subject string) error {
	for _, s := range r.cfg.Services {
		if s.ResourceURL != resource {
			continue
		}
		identity := credentials.Identity{Issuer: r.cfg.Issuer, Subject: subject}
		fresh := &credentials.Service{Mappings: r.creds.Mappings, Resolver: r.creds.Resolver, TTL: 0, Max: 1}
		values, err := fresh.HeadersFor(ctx, identity, s.ID, s.Headers, time.Now())
		if err == nil {
			err = r.validateUpstream(ctx, s, values.Values())
		} else {
			err = ErrRejected
		}
		if err != nil {
			if s.Source == config.SourceForm && r.forms != nil {
				// Values that failed the check must not outlive the attempt.
				r.forms.Delete(r.cfg.Issuer, subject, s.ID)
			}
			return err
		}
		r.creds.Invalidate(identity, s.ID)
		return nil
	}
	return nil
}

// validateUpstream sends rendered headers to the service's validation URL.
// Response bodies are never logged or returned.
func (r *Runtime) validateUpstream(ctx context.Context, s config.Service, values map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.ValidationURL, nil)
	if err != nil {
		return ErrUnavailable
	}
	req.Header.Set("Cache-Control", "no-store")
	for name, value := range values {
		req.Header.Set(name, value)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		slog.Warn("credential gateway could not reach the upstream validation endpoint", "service", s.ID, "cause", transportCause(err))
		return ErrUnavailable
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		slog.Warn("credential gateway upstream refused the validation request", "service", s.ID, "status", resp.StatusCode)
		return ErrRejected
	}
	return nil
}

// transportCause names why a request failed without quoting the error, which
// can contain the URL. It is for operators diagnosing an unreachable upstream.
func transportCause(err error) string {
	var dns *net.DNSError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var op *net.OpError
	switch {
	case errors.As(err, &dns):
		return "dns"
	case errors.As(err, &unknownAuthority), errors.As(err, &hostname), errors.As(err, &invalid):
		return "tls-certificate"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &op) && op.Op == "dial":
		if op.Timeout() {
			return "connect-timeout"
		}
		return "connect-refused-or-unroutable"
	case errors.As(err, &op):
		return "network-" + op.Op
	default:
		return "transport"
	}
}

// FormField is one input on a form-source service's sign-in page.
type FormField struct {
	Name, Label string
	Secret      bool
}

// FormService describes a service whose credentials a person submits at sign-in.
type FormService struct {
	ID, ResourceURL string
	Fields          []FormField
	// VaultURL, when set, is shown beside the form as where to find the values.
	VaultURL string
}

// FormServices lists the form-source services, for the OAuth side to offer a
// sign-in method per resource.
func (r *Runtime) FormServices() []FormService {
	var out []FormService
	for _, s := range r.cfg.Services {
		if s.Source != config.SourceForm {
			continue
		}
		service := FormService{ID: s.ID, ResourceURL: s.ResourceURL, VaultURL: s.VaultURL}
		for _, f := range s.FormFields {
			service.Fields = append(service.Fields, FormField{Name: f.Name, Label: f.Label, Secret: f.Secret})
		}
		out = append(out, service)
	}
	return out
}

// AuthenticateForm validates submitted values at the upstream and, only when it
// accepts them, keeps them in memory under a fresh random subject. It returns
// that subject without subjectPrefix, which the caller's login method adds.
// Rejected values yield ErrRejected, an unreachable upstream ErrUnavailable.
func (r *Runtime) AuthenticateForm(ctx context.Context, serviceID, subjectPrefix string, submitted map[string]string) (string, error) {
	var service *config.Service
	for i := range r.cfg.Services {
		if r.cfg.Services[i].ID == serviceID && r.cfg.Services[i].Source == config.SourceForm {
			service = &r.cfg.Services[i]
		}
	}
	if service == nil || r.forms == nil {
		return "", ErrUnavailable
	}
	values := make(map[string]string, len(service.FormFields))
	for _, f := range service.FormFields {
		values[f.Name] = submitted[f.Name]
	}
	rendered, err := headers.RenderAll(service.Headers, values)
	if err != nil {
		return "", ErrRejected
	}
	if err := r.validateUpstream(ctx, *service, rendered); err != nil {
		return "", err
	}
	random, err := formstore.NewSubject()
	if err != nil {
		return "", ErrUnavailable
	}
	if err := r.forms.Put(r.cfg.Issuer, subjectPrefix+random, service.ID, values); err != nil {
		return "", ErrUnavailable
	}
	return random, nil
}
