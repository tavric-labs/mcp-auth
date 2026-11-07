package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// capturingMethod is a redirect login that, like an OIDC provider, returns the
// upstream provider's own token set with the identity.
type capturingMethod struct{ fakeRedirectMethod }

func (m *capturingMethod) Complete(ctx context.Context, callback IdentityCallback) (Identity, error) {
	identity, err := m.fakeRedirectMethod.Complete(ctx, callback)
	if err != nil {
		return Identity{}, err
	}
	identity.UpstreamSession = &UpstreamSession{
		AccessToken: "upstream-access-token", TokenType: "Bearer",
		ExpiresAt: time.Now().Add(time.Hour), Scope: []string{"w_member_social"},
	}
	return identity, nil
}

// loginThroughResourceLogin signs in through a resource login on a server
// whose registry holds one capturing method, and returns the server and the
// subject the authorization code was issued for.
func loginThroughResourceLogin(t *testing.T, keep bool) (*Server, string) {
	t.Helper()
	instance := connectorServer(t)
	entry := LoginEntry{
		Method: &capturingMethod{fakeRedirectMethod{id: "gateway"}}, SubjectPrefix: "gateway:",
		Resources: []string{gatewayResource}, KeepUpstreamSession: keep,
	}
	if keep {
		entry.UpstreamConnector = &ConnectorConfig{TokenEndpointAuthMethod: "none"}
	}
	logins, err := NewLoginRegistry(entry)
	if err != nil {
		t.Fatal(err)
	}
	instance.ResourceLogins = logins
	approved := consentFor(t, instance, gatewayResource)
	state, _ := url.Parse(approved.Header().Get("Location"))
	callback := serve(instance, httptest.NewRequest(http.MethodGet, "/identity/callback?code=good&state="+url.QueryEscape(state.Query().Get("state")), nil))
	redirect, _ := url.Parse(callback.Header().Get("Location"))
	code, err := instance.Store.ConsumeAuthorizationCode(redirect.Query().Get("code"), time.Now())
	if err != nil {
		t.Fatalf("callback did not issue a code: %d %s", callback.Code, callback.Header().Get("Location"))
	}
	return instance, code.Subject
}

// Today a login method never keeps the upstream token. This pins that default
// so the opt-in below cannot change deployments that do not ask for it.
func TestResourceLoginDropsTheUpstreamSessionByDefault(t *testing.T) {
	instance, subject := loginThroughResourceLogin(t, false)
	if _, err := instance.Store.GetUpstreamSession(subject); err == nil {
		t.Fatal("a resource login kept the upstream session without opting in")
	}
}

func TestResourceLoginKeepsTheUpstreamSessionWhenOptedIn(t *testing.T) {
	instance, subject := loginThroughResourceLogin(t, true)
	if subject != "gateway:u1" {
		t.Fatalf("subject = %q, want the prefixed gateway:u1", subject)
	}
	session, err := instance.Store.GetUpstreamSession(subject)
	if err != nil {
		t.Fatalf("the opted-in login did not keep its upstream session: %v", err)
	}
	if session.AccessToken != "upstream-access-token" {
		t.Fatalf("stored access token = %q", session.AccessToken)
	}
}

type fixedExchanger struct{ token string }

func (e fixedExchanger) Exchange(context.Context, ExchangeRequest) (ExchangeResponse, error) {
	return ExchangeResponse{AccessToken: e.token, TokenType: "Bearer", ExpiresIn: 60}, nil
}

const (
	pingResource = "https://mcp.example.com/ping/mcp"
	echoResource = "https://mcp.example.com/echo/mcp"
)

// exchangeFor runs a full RFC 8693 exchange as the resource server bound to
// resource and returns the HTTP status and body.
func exchangeFor(t *testing.T, instance *Server, resource string) (int, string) {
	t.Helper()
	key := registerResourceClient(t, instance, "rs-"+resource, resource)
	subjectToken, err := instance.KeyProvider.Sign(context.Background(), instance.Config.Issuer, "user-1", resource, []string{"tools:read"}, time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	assertion := signTestClientAssertion(t, key, "rs-"+resource, instance.Config.Issuer+"/token")
	form := exchangeForm(subjectToken, "rs-"+resource, assertion)
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	return recorder.Code, recorder.Body.String()
}

func TestExchangeUsesTheResourceExchangerOnlyForItsResource(t *testing.T) {
	instance := multiResourceServer(t)
	instance.TokenExchanger = fixedExchanger{token: "connector-token"}
	instance.ResourceExchangers = map[string]TokenExchanger{echoResource: fixedExchanger{token: "resource-token"}}

	if status, body := exchangeFor(t, instance, echoResource); status != http.StatusOK || !strings.Contains(body, "resource-token") {
		t.Fatalf("echo resource: %d %s, want the resource exchanger's token", status, body)
	}
	if status, body := exchangeFor(t, instance, pingResource); status != http.StatusOK || !strings.Contains(body, "connector-token") {
		t.Fatalf("ping resource: %d %s, want the connector exchanger's token", status, body)
	}
}

func TestResourceExchangerWorksWithoutAConnectorExchanger(t *testing.T) {
	instance := multiResourceServer(t)
	instance.ResourceExchangers = map[string]TokenExchanger{echoResource: fixedExchanger{token: "resource-token"}}

	if status, body := exchangeFor(t, instance, echoResource); status != http.StatusOK || !strings.Contains(body, "resource-token") {
		t.Fatalf("echo resource: %d %s, want the resource exchanger's token", status, body)
	}
	if status, _ := exchangeFor(t, instance, pingResource); status != http.StatusBadRequest {
		t.Fatalf("ping resource has no exchanger and must stay unsupported, got %d", status)
	}
}
