package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
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

// loginRecordKey namespaces a login page id in the store. Consent ids, login
// ids and upstream states share one table, and an id from one stage must never
// be accepted at another: a consent id from /authorize, used as a login id,
// would skip consent. Upstream states are separate because they always carry a
// "." and consent and login ids never do.
func loginRecordKey(id string) string { return "login:" + id }

// Browser binding. Whoever approves consent is the person the sign-in is for.
// Without a link between that browser and the sign-in, anyone could approve
// consent for their own client, then send a victim the login link: the victim
// signs in on the real server and the code goes to the attacker. So approving
// consent sets a random value in an HttpOnly cookie, only its hash is stored
// with the pending request, and the login form and the provider callback both
// require the cookie. One cookie per sign-in, named from that sign-in's id, so
// two tabs or two clients do not overwrite each other.

func (s *Server) loginCookieSecure() bool {
	return strings.HasPrefix(strings.ToLower(s.Config.Issuer), "https://")
}

func (s *Server) loginCookieName(id string) string {
	sum := sha256.Sum256([]byte(id))
	name := "mcp_auth_login_" + hex.EncodeToString(sum[:6])
	if s.loginCookieSecure() {
		return "__Host-" + name
	}
	return name
}

func (s *Server) setLoginBinding(w http.ResponseWriter, id, binding string, expires time.Time) {
	maxAge := int(expires.Sub(s.now()).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name: s.loginCookieName(id), Value: binding, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.loginCookieSecure(), SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearLoginBinding(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name: s.loginCookieName(id), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.loginCookieSecure(), SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) presentedBinding(r *http.Request, id string) string {
	cookie, err := r.Cookie(s.loginCookieName(id))
	if err != nil || len(cookie.Value) > maxLoginIDBytes {
		return ""
	}
	return cookie.Value
}

// bindingMatches reports whether the browser's value is the one consent was
// approved with. An empty stored binding never matches.
func bindingMatches(presented string, pending ConsentRequest) bool {
	stored := pending.Request.LoginBinding
	if presented == "" || stored == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(HashSecret(presented)), []byte(stored)) == 1
}

// rejectUnboundLogin puts the request back, so a request from the wrong
// browser cannot use up the right browser's sign-in, and answers as expired.
func (s *Server) rejectUnboundLogin(w http.ResponseWriter, pending ConsentRequest, stage string) {
	_ = s.Store.SaveConsentRequest(pending)
	s.Audit.Event("login", "failure", map[string]any{"reason": "browser_binding_mismatch", "stage": stage})
	s.writeExpiredLogin(w)
}

// startLogin runs after the person approved consent. It starts the sign-in
// window (loginTTL, never restarted afterwards), binds it to this browser, and
// either goes straight to the only provider or shows the login page. The
// pending request is saved again because consent consumed the one it arrived
// with.
func (s *Server) startLogin(w http.ResponseWriter, r *http.Request, registry *LoginRegistry, pending ConsentRequest) {
	if len(registry.entriesForResource(pending.Request.Resource)) == 0 {
		redirectError(w, r, pending.Request, "access_denied", "no login method is configured for this resource", s.Config.Issuer, s.Config.AuthorizationResponseIssuer)
		return
	}
	binding := randomID()
	pending.Request.LoginBinding = HashSecret(binding)
	pending.ExpiresAt = s.now().Add(s.Config.loginTTL())
	if entry, ok := registry.singleForResource(pending.Request.Resource); ok {
		if _, redirect := entry.Method.(RedirectLoginMethod); redirect {
			s.beginRedirectLogin(w, r, entry, pending, binding)
			return
		}
	}
	loginID := randomID()
	pending.ValueHash = HashSecret(loginRecordKey(loginID))
	if err := s.Store.SaveConsentRequest(pending); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	s.setLoginBinding(w, loginID, binding, pending.ExpiresAt)
	http.Redirect(w, r, s.Config.LoginEndpoint()+"?"+url.Values{"login_id": {loginID}, "resource": {pending.Request.Resource}}.Encode(), http.StatusSeeOther)
}

// beginRedirectLogin sends the browser to the method's provider. The upstream
// state carries the method id so the callback can find the method again; the
// whole state is the lookup key, so changing the prefix finds nothing. The
// sign-in keeps the expiry it already had.
func (s *Server) beginRedirectLogin(w http.ResponseWriter, r *http.Request, entry LoginEntry, pending ConsentRequest, binding string) {
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
		ExpiresAt: pending.ExpiresAt, CodeVerifier: codeVerifier,
	}); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	s.setLoginBinding(w, state, binding, pending.ExpiresAt)
	http.Redirect(w, r, location, http.StatusSeeOther)
}

// loginPage renders the method picker. It cannot check the pending request
// without consuming it, so an expired or unbound id is only reported when a
// method is chosen.
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
	// The query controls presentation only. Submission and callbacks select
	// methods using the resource stored with the pending authorization.
	s.renderLogin(w, http.StatusOK, registry, r.URL.Query().Get("resource"), loginID, "", "", nil)
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
	pending, err := s.Store.ConsumeConsentRequest(loginRecordKey(loginID), s.now())
	if err != nil {
		s.writeExpiredLogin(w)
		return
	}
	binding := s.presentedBinding(r, loginID)
	if !bindingMatches(binding, pending) {
		s.rejectUnboundLogin(w, pending, "login")
		return
	}
	if _, allowed := registry.lookupForResource(entry.Method.ID(), pending.Request.Resource); !allowed {
		_ = s.Store.SaveConsentRequest(pending)
		s.Audit.Event("login", "failure", map[string]any{"method": entry.Method.ID(), "reason": "method_not_allowed_for_resource"})
		oauthError(w, http.StatusForbidden, "access_denied")
		return
	}
	switch method := entry.Method.(type) {
	case RedirectLoginMethod:
		s.clearLoginBinding(w, loginID)
		s.beginRedirectLogin(w, r, entry, pending, binding)
	case CredentialLoginMethod:
		s.attemptCredentialLogin(w, r, registry, entry, method, pending, loginID, binding)
	}
}

func (s *Server) attemptCredentialLogin(w http.ResponseWriter, r *http.Request, registry *LoginRegistry, entry LoginEntry, method CredentialLoginMethod, pending ConsentRequest, loginID, binding string) {
	fields := method.Fields()
	values := make(map[string]string, len(fields))
	account := ""
	for _, field := range fields {
		value := r.PostFormValue(field.Name)
		if len(value) > maxLoginFieldBytes {
			s.retryLogin(w, registry, method, pending, loginID, binding, http.StatusUnauthorized, "Sign-in failed. Check your details and try again.", nil)
			return
		}
		values[field.Name] = value
		if account == "" && !field.Secret {
			account = value
		}
	}
	// The attempt is counted before the directory is asked, so requests sent
	// in parallel cannot all pass the check while the first is still waiting.
	ticket, allowed := registry.limiter.reserve(loginLimiterKey(method.ID(), account), s.now())
	if !allowed {
		s.Audit.Event("login", "failure", map[string]any{"method": method.ID(), "reason": "throttled"})
		s.retryLogin(w, registry, method, pending, loginID, binding, http.StatusTooManyRequests, "Too many failed attempts. Wait a few minutes and try again.", values)
		return
	}
	request := pending.Request
	identity, err := method.Authenticate(r.Context(), IdentityRequest{
		ClientID: request.ClientID, Nonce: pending.Nonce, Resource: request.Resource, Scopes: request.Scope,
	}, LoginAttempt{Values: values, RemoteAddr: remoteHost(r)})
	if err == nil {
		identity, err = entry.qualify(identity)
	}
	if err != nil {
		if errors.Is(err, ErrMethodUnavailable) {
			// The password was never tested, so this attempt does not count.
			ticket.abandon()
			s.Audit.Event("login", "failure", map[string]any{"method": method.ID(), "reason": err.Error()})
			s.retryLogin(w, registry, method, pending, loginID, binding, http.StatusServiceUnavailable, "Sign-in is temporarily unavailable. Try again shortly.", values)
			return
		}
		// A wrong password, and any failure that may have come after the
		// password was checked, look the same and count the same. Otherwise a
		// different answer would reveal that the guess was right.
		reason := "invalid_credentials"
		if !errors.Is(err, ErrInvalidCredentials) {
			reason = err.Error()
		}
		s.Audit.Event("login", "failure", map[string]any{"method": method.ID(), "reason": reason})
		s.retryLogin(w, registry, method, pending, loginID, binding, http.StatusUnauthorized, "Sign-in failed. Check your details and try again.", values)
		return
	}
	ticket.success()
	s.Audit.Event("login", "success", map[string]any{"method": method.ID()})
	s.clearLoginBinding(w, loginID)
	s.completeAuthorization(w, r, pending, identity)
}

// retryLogin shows the form again after a failed attempt. The pending request
// was consumed to make the attempt, so it is saved under a new id with its
// original expiry: a failure never extends the time allowed to sign in.
func (s *Server) retryLogin(w http.ResponseWriter, registry *LoginRegistry, method CredentialLoginMethod, pending ConsentRequest, oldID, binding string, status int, message string, values map[string]string) {
	loginID := randomID()
	pending.ValueHash = HashSecret(loginRecordKey(loginID))
	if err := s.Store.SaveConsentRequest(pending); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	s.clearLoginBinding(w, oldID)
	s.setLoginBinding(w, loginID, binding, pending.ExpiresAt)
	s.renderLogin(w, status, registry, pending.Request.Resource, loginID, message, method.ID(), values)
}

func (s *Server) writeExpiredLogin(w http.ResponseWriter) {
	setConsentDocumentHeaders(w)
	w.WriteHeader(http.StatusBadRequest)
	_ = loginTemplate.Execute(w, loginView{Expired: true, Title: "Sign-in request expired"})
}

func (s *Server) renderLogin(w http.ResponseWriter, status int, registry *LoginRegistry, resource, loginID, message, failedMethod string, submitted map[string]string) {
	view := loginView{Title: "Sign in", Error: message, LoginID: loginID}
	for _, entry := range registry.entriesForResource(resource) {
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
// that started it, and the browser must be the one that approved consent.
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
	if !bindingMatches(s.presentedBinding(r, state), pending) {
		_ = s.Store.SaveConsentRequest(pending)
		s.Audit.Event("login", "failure", map[string]any{"method": methodID, "reason": "browser_binding_mismatch", "stage": "callback"})
		http.Error(w, "identity state is invalid or expired", http.StatusBadRequest)
		return
	}
	if _, allowed := registry.lookupForResource(methodID, pending.Request.Resource); !allowed {
		s.Audit.Event("login", "failure", map[string]any{"method": methodID, "reason": "method_not_allowed_for_resource"})
		oauthError(w, http.StatusForbidden, "access_denied")
		return
	}
	s.clearLoginBinding(w, state)
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
