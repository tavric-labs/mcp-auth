package server

import (
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	// maxLoginFormBytes bounds a login form body.
	maxLoginFormBytes = 16 << 10
	// maxLoginFieldBytes bounds one submitted field, before a method sees it.
	maxLoginFieldBytes = 1024
	// maxLoginIDBytes bounds the opaque pending-request id in a request.
	maxLoginIDBytes = 128
)

func (s *Server) loginRegistry() *LoginRegistry {
	registry, _ := s.IdentityProvider.(*LoginRegistry)
	return registry
}

// startLogin runs after the person approved consent. With one redirect method
// it goes straight to that provider; otherwise it sends the browser to the
// login page, which lets them pick. The pending request is saved again under
// a fresh id because consent consumed the one it arrived with.
func (s *Server) startLogin(w http.ResponseWriter, r *http.Request, registry *LoginRegistry, pending ConsentRequest) {
	if entry, ok := registry.single(); ok {
		if _, redirect := entry.Method.(RedirectLoginMethod); redirect {
			s.beginRedirectLogin(w, r, entry, pending)
			return
		}
	}
	loginID := randomID()
	if err := s.Store.SaveConsentRequest(ConsentRequest{
		ValueHash: HashSecret(loginID), Request: pending.Request, Nonce: pending.Nonce,
		ExpiresAt: s.now().Add(s.Config.loginTTL()),
	}); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	http.Redirect(w, r, s.Config.LoginEndpoint()+"?"+url.Values{"login_id": {loginID}}.Encode(), http.StatusSeeOther)
}

// beginRedirectLogin sends the browser to the method's provider. The upstream
// state carries the method id so the callback can find the method again; the
// whole state is the lookup key, so changing the prefix finds nothing.
func (s *Server) beginRedirectLogin(w http.ResponseWriter, r *http.Request, entry LoginEntry, pending ConsentRequest) {
	method := entry.Method.(RedirectLoginMethod)
	request := pending.Request
	state := method.ID() + "." + randomID()
	location, codeVerifier, err := method.Begin(r.Context(), IdentityRequest{
		ClientID: request.ClientID, Nonce: pending.Nonce, Resource: request.Resource, Scopes: request.Scope,
	}, state)
	if err != nil {
		s.Audit.Event("login", "failure", map[string]any{"method": method.ID(), "reason": err.Error()})
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if err := s.Store.SaveConsentRequest(ConsentRequest{
		ValueHash: HashSecret(state), Request: request, Nonce: pending.Nonce,
		ExpiresAt: s.now().Add(s.Config.loginTTL()), CodeVerifier: codeVerifier,
	}); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	http.Redirect(w, r, location, http.StatusSeeOther)
}

// loginPage renders the method picker. It cannot check the pending request
// without consuming it, so an expired id is only reported when a method is
// chosen.
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	registry := s.loginRegistry()
	if registry == nil {
		http.NotFound(w, r)
		return
	}
	loginID := r.URL.Query().Get("login_id")
	if loginID == "" || len(loginID) > maxLoginIDBytes {
		s.writeExpiredLogin(w)
		return
	}
	s.renderLogin(w, http.StatusOK, registry, loginID, "", "", nil)
}

// loginSubmit handles a chosen method: it starts the provider redirect, or
// checks the submitted credentials.
func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	registry := s.loginRegistry()
	if registry == nil {
		http.NotFound(w, r)
		return
	}
	entry, ok := registry.lookup(r.PathValue("method"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginFormBytes)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid login form")
		return
	}
	loginID := r.PostFormValue("login_id")
	if loginID == "" || len(loginID) > maxLoginIDBytes {
		s.writeExpiredLogin(w)
		return
	}
	pending, err := s.Store.ConsumeConsentRequest(loginID, s.now())
	if err != nil {
		s.writeExpiredLogin(w)
		return
	}
	switch method := entry.Method.(type) {
	case RedirectLoginMethod:
		s.beginRedirectLogin(w, r, entry, pending)
	case CredentialLoginMethod:
		s.attemptCredentialLogin(w, r, registry, entry, method, pending)
	}
}

func (s *Server) attemptCredentialLogin(w http.ResponseWriter, r *http.Request, registry *LoginRegistry, entry LoginEntry, method CredentialLoginMethod, pending ConsentRequest) {
	fields := method.Fields()
	values := make(map[string]string, len(fields))
	account := ""
	for _, field := range fields {
		value := r.PostFormValue(field.Name)
		if len(value) > maxLoginFieldBytes {
			s.retryLogin(w, registry, method, pending, http.StatusUnauthorized, "Sign-in failed. Check your details and try again.", nil)
			return
		}
		values[field.Name] = value
		if account == "" && !field.Secret {
			account = value
		}
	}
	now := s.now()
	key := loginLimiterKey(method.ID(), account)
	if !registry.limiter.allow(key, now) {
		s.Audit.Event("login", "failure", map[string]any{"method": method.ID(), "reason": "throttled"})
		s.retryLogin(w, registry, method, pending, http.StatusTooManyRequests, "Too many failed attempts. Wait a few minutes and try again.", values)
		return
	}
	request := pending.Request
	identity, err := method.Authenticate(r.Context(), IdentityRequest{
		ClientID: request.ClientID, Nonce: pending.Nonce, Resource: request.Resource, Scopes: request.Scope,
	}, LoginAttempt{Values: values, RemoteAddr: remoteHost(r)})
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			registry.limiter.fail(key, now)
			s.Audit.Event("login", "failure", map[string]any{"method": method.ID(), "reason": "invalid_credentials"})
			s.retryLogin(w, registry, method, pending, http.StatusUnauthorized, "Sign-in failed. Check your details and try again.", values)
			return
		}
		s.Audit.Event("login", "failure", map[string]any{"method": method.ID(), "reason": err.Error()})
		s.retryLogin(w, registry, method, pending, http.StatusServiceUnavailable, "Sign-in is temporarily unavailable. Try again shortly.", values)
		return
	}
	identity, err = entry.qualify(identity)
	if err != nil {
		s.Audit.Event("login", "failure", map[string]any{"method": method.ID(), "reason": err.Error()})
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	registry.limiter.reset(key)
	s.Audit.Event("login", "success", map[string]any{"method": method.ID()})
	s.completeAuthorization(w, r, pending, identity)
}

// retryLogin shows the form again after a failed attempt. The pending request
// was consumed to make the attempt, so it is saved under a new id with its
// original expiry: a failure never extends the time allowed to sign in.
func (s *Server) retryLogin(w http.ResponseWriter, registry *LoginRegistry, method CredentialLoginMethod, pending ConsentRequest, status int, message string, values map[string]string) {
	loginID := randomID()
	if err := s.Store.SaveConsentRequest(ConsentRequest{
		ValueHash: HashSecret(loginID), Request: pending.Request, Nonce: pending.Nonce, ExpiresAt: pending.ExpiresAt,
	}); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	s.renderLogin(w, status, registry, loginID, message, method.ID(), values)
}

func (s *Server) writeExpiredLogin(w http.ResponseWriter) {
	setConsentDocumentHeaders(w)
	w.WriteHeader(http.StatusBadRequest)
	_ = loginTemplate.Execute(w, loginView{Expired: true, Title: "Sign-in request expired"})
}

func (s *Server) renderLogin(w http.ResponseWriter, status int, registry *LoginRegistry, loginID, message, failedMethod string, submitted map[string]string) {
	view := loginView{Title: "Sign in", Error: message, LoginID: loginID}
	for _, entry := range registry.entries {
		item := loginMethodView{
			ID: entry.Method.ID(), Label: entry.Method.Label(),
			Action: s.Config.LoginEndpoint() + "/" + entry.Method.ID(),
		}
		if credential, ok := entry.Method.(CredentialLoginMethod); ok {
			for _, field := range credential.Fields() {
				value := ""
				if !field.Secret && entry.Method.ID() == failedMethod {
					value = submitted[field.Name]
				}
				item.Fields = append(item.Fields, loginFieldView{Name: field.Name, Label: field.Label, Secret: field.Secret, Value: value})
			}
		}
		view.Methods = append(view.Methods, item)
	}
	setConsentDocumentHeaders(w)
	w.WriteHeader(status)
	_ = loginTemplate.Execute(w, view)
}

// registryCallback completes a redirect login. The state names the method
// that started it.
func (s *Server) registryCallback(w http.ResponseWriter, r *http.Request, registry *LoginRegistry) {
	state := r.URL.Query().Get("state")
	methodID, _, found := strings.Cut(state, ".")
	entry, known := registry.lookup(methodID)
	method, redirect := entry.Method.(RedirectLoginMethod)
	if !found || !known || !redirect {
		http.Error(w, "identity state is invalid or expired", http.StatusBadRequest)
		return
	}
	pending, err := s.Store.ConsumeConsentRequest(state, s.now())
	if err != nil {
		http.Error(w, "identity state is invalid or expired", http.StatusBadRequest)
		return
	}
	if upstreamError := r.URL.Query().Get("error"); upstreamError != "" {
		s.Audit.Event("login", "failure", map[string]any{"method": methodID, "reason": "upstream_error", "error_type": upstreamError})
		redirectError(w, r, pending.Request, "access_denied", "upstream identity authentication failed", s.Config.Issuer, s.Config.AuthorizationResponseIssuer)
		return
	}
	identity, err := method.Complete(r.Context(), IdentityCallback{
		Code: r.URL.Query().Get("code"), RedirectURI: s.Config.IdentityCallbackURL(), Nonce: pending.Nonce, State: state,
		CodeVerifier: pending.CodeVerifier,
	})
	if err == nil {
		identity, err = entry.qualify(identity)
	}
	if err != nil {
		s.Audit.Event("login", "failure", map[string]any{"method": methodID, "reason": err.Error()})
		redirectError(w, r, pending.Request, "access_denied", "upstream identity authentication failed", s.Config.Issuer, s.Config.AuthorizationResponseIssuer)
		return
	}
	s.Audit.Event("login", "success", map[string]any{"method": methodID})
	s.completeAuthorization(w, r, pending, identity)
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type loginFieldView struct {
	Name   string
	Label  string
	Secret bool
	Value  string
}

type loginMethodView struct {
	ID     string
	Label  string
	Action string
	Fields []loginFieldView
}

type loginView struct {
	Expired bool
	Title   string
	Error   string
	LoginID string
	Methods []loginMethodView
}

var loginTemplate = template.Must(template.New("login").Parse(loginTemplateSource))

const loginTemplateSource = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
:root{color-scheme:light dark}
body{font:16px/1.5 system-ui,sans-serif;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;background:Canvas;color:CanvasText}
main{width:100%;max-width:26rem;padding:1.5rem}
h1{font-size:1.4rem;margin:0 0 1rem}
form{margin:0 0 1.25rem;padding:1rem;border:1px solid GrayText;border-radius:.5rem}
h2{font-size:1rem;margin:0 0 .75rem}
label{display:block;margin:.5rem 0 .25rem;font-size:.9rem}
input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:.5rem;font:inherit;border:1px solid GrayText;border-radius:.25rem;background:Field;color:FieldText}
button{margin-top:.75rem;width:100%;padding:.6rem;font:inherit;cursor:pointer;border:1px solid GrayText;border-radius:.25rem;background:ButtonFace;color:ButtonText}
.error{padding:.6rem .75rem;margin:0 0 1rem;border:1px solid #b00020;border-radius:.25rem;color:#b00020}
p{margin:0}
</style>
</head>
<body>
<main>
{{if .Expired}}
<h1>{{.Title}}</h1>
<p>This sign-in request is no longer valid. Return to your MCP client and start again.</p>
{{else}}
<h1>{{.Title}}</h1>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
{{range .Methods}}
<form method="post" action="{{.Action}}" autocomplete="off">
<input type="hidden" name="login_id" value="{{$.LoginID}}">
{{if .Fields}}
<h2>{{.Label}}</h2>
{{range .Fields}}
<label for="{{$.LoginID}}-{{.Name}}">{{.Label}}</label>
{{if .Secret}}<input type="password" id="{{$.LoginID}}-{{.Name}}" name="{{.Name}}" autocomplete="current-password" required>
{{else}}<input type="text" id="{{$.LoginID}}-{{.Name}}" name="{{.Name}}" value="{{.Value}}" autocomplete="username" autocapitalize="off" spellcheck="false" required>
{{end}}
{{end}}
<button type="submit">Sign in</button>
{{else}}
<button type="submit">{{.Label}}</button>
{{end}}
</form>
{{end}}
{{end}}
</main>
</body>
</html>
`
