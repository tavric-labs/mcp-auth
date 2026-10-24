// Package credentialgateway is the credential-injecting resource gateway. It is
// its own service: mcp-auth sends the browser to the gateway's sign-in page for a
// resource, the gateway validates and keeps the person's header values in memory,
// and on later requests it verifies the OAuth bearer against mcp-auth and adds
// those headers before forwarding to the upstream.
package credentialgateway

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/config"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/credentials"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/formstore"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/gateway"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/headers"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/loginprovider"
)

// LoginClientID is the OAuth client id mcp-auth presents to a service's sign-in
// endpoints. The connector entry for the service must use it.
func LoginClientID(serviceID string) string { return "login-" + serviceID }

// SubjectPrefix is what mcp-auth puts before the opaque subject the service's
// sign-in returns. The login method for the service must use it as its
// subject_prefix, because the gateway stores values under the prefixed subject.
func SubjectPrefix(serviceID string) string { return "form-" + serviceID + ":" }

// Runtime is a configured gateway.
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

// Open loads the gateway. Every service collects its header values at sign-in
// and keeps them in memory; there is no vault or mapping file.
func Open(path, version string) (*Runtime, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	forms := &formstore.Store{TTL: cfg.FormTTL, Max: cfg.FormMaxEntries}
	creds := &credentials.Service{Mappings: forms, Resolver: forms, TTL: cfg.CacheTTL, Max: cfg.CacheMaxEntries}
	runtime := newRuntime(cfg, creds, forms.Ready)
	runtime.forms = forms
	return runtime, nil
}

func newRuntime(cfg *config.Config, creds *credentials.Service, ready func() bool) *Runtime {
	return &Runtime{cfg: cfg, creds: creds, ready: ready, client: &http.Client{
		Timeout:       cfg.ConnectTimeout + cfg.ResponseHeaderTimeout,
		Transport:     &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: cfg.ConnectTimeout}).DialContext, TLSHandshakeTimeout: cfg.ConnectTimeout, ResponseHeaderTimeout: cfg.ResponseHeaderTimeout},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// ListenAddr is the address the gateway listens on.
func (r *Runtime) ListenAddr() string { return r.cfg.Listen }

// Issuer is the mcp-auth issuer the gateway trusts.
func (r *Runtime) Issuer() string { return r.cfg.Issuer }

// PublicKeyPEM returns the PEM public key for a service's resource client, which
// mcp-auth needs to verify the assertion requests the gateway signs.
func (r *Runtime) PublicKeyPEM(serviceID string) (string, bool) {
	for _, s := range r.cfg.Services {
		if s.ID == serviceID {
			key, err := x509.MarshalPKIXPublicKey(&s.Client.PrivateKey.PublicKey)
			if err != nil {
				return "", false
			}
			return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: key})), true
		}
	}
	return "", false
}

// Handler serves the proxy and, under each service's path, the sign-in
// endpoints mcp-auth uses: /login/authorize, /login/approve, /login/token and
// /login/userinfo.
func (r *Runtime) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", gateway.New(r.cfg, r.creds, r.ready, nil))
	for _, s := range r.cfg.Services {
		provider := r.loginProvider(s)
		for _, path := range r.servicePaths(s) {
			mux.Handle(path+"/login/", http.StripPrefix(path, provider))
		}
	}
	return mux
}

// servicePaths: the canonical path plus the path left after an ingress strips
// the configured public prefix.
func (r *Runtime) servicePaths(s config.Service) []string {
	paths := []string{s.ResourcePath}
	if p := r.cfg.PublicPathPrefix; p != "" && strings.HasPrefix(s.ResourcePath, p+"/") {
		paths = append(paths, strings.TrimPrefix(s.ResourcePath, p))
	}
	return paths
}

func (r *Runtime) loginProvider(s config.Service) *loginprovider.Provider {
	resource, _ := url.Parse(s.ResourceURL)
	fields := make([]loginprovider.Field, 0, len(s.FormFields))
	for _, f := range s.FormFields {
		fields = append(fields, loginprovider.Field{Name: f.Name, Label: f.Label, Secret: f.Secret})
	}
	return loginprovider.New(loginprovider.Config{
		ClientID:    LoginClientID(s.ID),
		Origin:      resource.Scheme + "://" + resource.Host,
		BasePath:    s.ResourcePath,
		CallbackURL: r.cfg.Issuer + "/identity/callback",
		Fields:      fields,
		Authenticate: func(ctx context.Context, values map[string]string) (string, error) {
			subject, err := r.authenticateForm(ctx, s.ID, SubjectPrefix(s.ID), values)
			switch {
			case err == nil:
				return subject, nil
			case errors.Is(err, ErrRejected):
				return "", loginprovider.ErrRejected
			default:
				return "", loginprovider.ErrUnavailable
			}
		},
	})
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

// authenticateForm validates submitted values at the upstream and, only when it
// accepts them, keeps them in memory under subjectPrefix plus a fresh random
// subject. It returns the random part, which is what the sign-in hands to
// mcp-auth. Rejected values yield ErrRejected, an unreachable upstream
// ErrUnavailable; nothing is stored in either case.
func (r *Runtime) authenticateForm(ctx context.Context, serviceID, subjectPrefix string, submitted map[string]string) (string, error) {
	var service *config.Service
	for i := range r.cfg.Services {
		if r.cfg.Services[i].ID == serviceID {
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
