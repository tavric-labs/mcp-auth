// Package gateway is the Streamable HTTP front end: it authenticates every
// request, injects the calling user's credentials and forwards to the fixed
// upstream backend.
package gateway

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Agent-Hellboy/mcp-auth/auth-client/go/mcpauth"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/authz"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/config"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/credentials"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/headers"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/mappings"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/secrets"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/session"
)

const sessionHeader = "Mcp-Session-Id"

// Gateway implements http.Handler.
type Gateway struct {
	cfg      *config.Config
	creds    *credentials.Service
	authz    *authz.Authorizer
	binder   *session.Binder
	upstream *http.Client
	ready    func() bool
	mux      *http.ServeMux
}

// New builds the gateway. transport may be nil; tests inject one.
func New(cfg *config.Config, creds *credentials.Service, ready func() bool, transport http.RoundTripper) *Gateway {
	if transport == nil {
		transport = &http.Transport{
			Proxy:                 nil, // never route through an environment proxy
			DialContext:           (&net.Dialer{Timeout: cfg.ConnectTimeout}).DialContext,
			TLSHandshakeTimeout:   cfg.ConnectTimeout,
			ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
			DisableCompression:    true, // we ask for identity encoding and stream bytes unchanged
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       90 * time.Second,
		}
	}
	g := &Gateway{
		cfg: cfg, creds: creds, binder: session.NewBinder(cfg.SessionKey), ready: ready, mux: http.NewServeMux(),
		// An upstream redirect must never carry injected credentials elsewhere.
		upstream: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	g.authz = authz.New(cfg, g.metadataURL)
	g.mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	g.mux.HandleFunc("/readyz", g.readyz)
	for i := range cfg.Services {
		svc := cfg.Services[i]
		verifier := &mcpauth.JWTVerifier{Issuer: cfg.Issuer, Audience: svc.ResourceURL, RequiredScopes: toSet(svc.RequiredScopes)}
		meta := mcpauth.NewProtectedResourceMetadata(verifier, svc.ResourceURL, cfg.Issuer)
		seen := map[string]bool{}
		for _, path := range g.localPaths(svc) {
			g.mux.HandleFunc(path, g.mcpHandler(svc))
			wk := "/.well-known/oauth-protected-resource" + strings.TrimRight(path, "/")
			if !seen[wk] {
				seen[wk] = true
				g.mux.HandleFunc(wk, func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Cache-Control", "public, max-age=300")
					writeJSON(w, 200, meta)
				})
			}
		}
	}
	return g
}

func toSet(values []string) map[string]bool {
	m := map[string]bool{}
	for _, v := range values {
		m[v] = true
	}
	return m
}

// ServeHTTP implements http.Handler.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) { g.mux.ServeHTTP(w, r) }

func (g *Gateway) metadataURL(s config.Service) string {
	u, _ := url.Parse(s.ResourceURL)
	u.Path = "/.well-known/oauth-protected-resource" + strings.TrimRight(u.Path, "/")
	return u.String()
}

// localPaths: the canonical path plus the path left after an ingress strips
// the configured public prefix.
func (g *Gateway) localPaths(s config.Service) []string {
	paths := []string{s.ResourcePath}
	if p := g.cfg.PublicPathPrefix; p != "" && strings.HasPrefix(s.ResourcePath, p+"/") {
		paths = append(paths, strings.TrimPrefix(s.ResourcePath, p))
	}
	return paths
}

func (g *Gateway) readyz(w http.ResponseWriter, _ *http.Request) {
	if g.ready != nil && !g.ready() {
		writeJSON(w, 503, map[string]string{"status": "not_ready"})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ready"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = jsonEncode(w, v)
}

func fail(w http.ResponseWriter, status int, code, description string, extra map[string]string) {
	for k, v := range extra {
		w.Header().Set(k, v)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func (g *Gateway) mcpHandler(svc config.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodGet, http.MethodDelete:
		default:
			w.Header().Set("Allow", "POST, GET, DELETE")
			fail(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", nil)
			return
		}
		g.handle(w, r, svc)
	}
}

func (g *Gateway) handle(w http.ResponseWriter, r *http.Request, svc config.Service) {
	// 1. Authenticate this request on its own; initialize never authorises later calls.
	auth, failure := g.authz.Authorize(r.Context(), svc.ID, r.Header.Get("Authorization"))
	if failure != nil {
		fail(w, failure.Status, failure.Code, failure.Message, failure.Headers)
		return
	}
	id := auth.Identity

	// 2. Bound the body before any vault access.
	if r.ContentLength > g.cfg.MaxRequestBytes {
		fail(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large", nil)
		return
	}

	// 3. A session id is valid only for the user and service that opened it.
	var upstreamSession string
	if presented := r.Header.Get(sessionHeader); presented != "" {
		unwrapped, ok := g.binder.Unwrap(id.Issuer, id.Subject, svc.ID, presented)
		if !ok {
			fail(w, http.StatusForbidden, "session_binding_mismatch", "session does not belong to this caller", nil)
			return
		}
		upstreamSession = unwrapped
	} else if r.Method == http.MethodDelete {
		fail(w, http.StatusBadRequest, "missing_session", "Mcp-Session-Id is required", nil)
		return
	}

	var body []byte
	if r.Method == http.MethodPost {
		var err error
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, g.cfg.MaxRequestBytes))
		if err != nil {
			fail(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large", nil)
			return
		}
	}

	// 4. Credentials for the verified identity and this service only.
	injected, err := g.creds.HeadersFor(r.Context(), id, svc.ID, svc.Headers, auth.SessionExpiry)
	if err != nil {
		switch {
		case errors.Is(err, credentials.ErrNoMapping):
			slog.Info("no credential mapping", "service", svc.ID)
			fail(w, 403, "no_credential_mapping", "no credentials are enrolled for this user and service", nil)
		case errors.Is(err, mappings.ErrUnavailable):
			fail(w, 503, "mapping_unavailable", "credential mapping is unavailable", nil)
		case errors.Is(err, secrets.ErrProviderUnavailable):
			fail(w, 503, "credential_provider_unavailable", "credential provider is unavailable", nil)
		default:
			fail(w, 502, "credential_unavailable", "enrolled credentials could not be read", nil)
		}
		return
	}

	// 5. Allowlisted client headers, then the injected credential headers.
	var reader io.Reader
	if len(body) > 0 {
		reader = strings.NewReader(string(body))
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, svc.UpstreamURL, reader)
	if err != nil {
		fail(w, 502, "upstream_invalid", "upstream request could not be built", nil)
		return
	}
	for _, name := range headers.ForwardedRequest {
		if v := r.Header.Get(name); v != "" {
			out.Header.Set(name, v)
		}
	}
	out.Header.Set("Accept-Encoding", "identity")
	if upstreamSession != "" {
		out.Header.Set(sessionHeader, upstreamSession)
	}
	for name, value := range injected.Values() {
		out.Header.Set(name, value)
	}

	resp, err := g.upstream.Do(out)
	if err != nil {
		if r.Context().Err() != nil {
			return // the client went away
		}
		fail(w, 502, "upstream_unreachable", "upstream MCP server is unreachable", nil)
		return
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		fail(w, 502, "upstream_redirect", "upstream redirects are not followed", nil)
		return
	case resp.StatusCode == http.StatusUnauthorized:
		fail(w, 502, "upstream_credentials_rejected", "upstream rejected the enrolled credentials", nil)
		return
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		fail(w, 502, "upstream_invalid", "upstream used an unsupported content encoding", nil)
		return
	}
	for _, name := range headers.ReturnedResponse {
		if v := resp.Header.Get(name); v != "" {
			w.Header().Set(name, v)
		}
	}
	if returned := resp.Header.Get(sessionHeader); returned != "" {
		wrapped := g.binder.Wrap(id.Issuer, id.Subject, svc.ID, returned)
		if wrapped == "" {
			fail(w, 502, "upstream_invalid", "upstream returned an invalid session id", nil)
			return
		}
		w.Header().Set(sessionHeader, wrapped)
	}
	if resp.ContentLength >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	w.WriteHeader(resp.StatusCode)
	g.stream(r.Context(), w, resp.Body)
}

// stream copies the upstream body, flushing after every read so SSE events are
// delivered as they arrive. A client disconnect cancels the request context,
// which closes the upstream connection.
func (g *Gateway) stream(ctx context.Context, w http.ResponseWriter, body io.Reader) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32*1024)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			_ = rc.Flush()
		}
		if err != nil || ctx.Err() != nil {
			return
		}
	}
}
