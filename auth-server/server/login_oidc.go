package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// OIDCLoginMethod adapts an OIDC or OAuth 2.0 upstream connector (Keycloak,
// Okta, Entra ID, anything with a connector file entry) to a login method.
// An optional check can reject an identity after the provider has verified it.
type OIDCLoginMethod struct {
	id, label string
	provider  *OIDCIdentityProvider
	check     func(claims map[string]any) error
}

// NewOIDCLoginMethod wraps an existing OIDC provider.
func NewOIDCLoginMethod(id, label string, provider *OIDCIdentityProvider, check func(map[string]any) error) *OIDCLoginMethod {
	return &OIDCLoginMethod{id: id, label: label, provider: provider, check: check}
}

// ID implements LoginMethod.
func (m *OIDCLoginMethod) ID() string { return m.id }

// Label implements LoginMethod.
func (m *OIDCLoginMethod) Label() string { return m.label }

// Begin implements RedirectLoginMethod.
func (m *OIDCLoginMethod) Begin(ctx context.Context, request IdentityRequest, state string) (string, string, error) {
	return m.provider.Begin(ctx, request, state)
}

// Complete implements RedirectLoginMethod.
func (m *OIDCLoginMethod) Complete(ctx context.Context, callback IdentityCallback) (Identity, error) {
	identity, err := m.provider.Complete(ctx, callback)
	if err != nil {
		return Identity{}, err
	}
	if m.check != nil {
		if err := m.check(identity.Claims); err != nil {
			return Identity{}, err
		}
	}
	return identity, nil
}

// GoogleConfig configures "Sign in with Google", an OIDC provider with fixed
// endpoints, so only the OAuth client needs configuring.
type GoogleConfig struct {
	ID              string
	Label           string
	ClientID        string
	ClientIDEnv     string
	ClientSecretEnv string
	// AllowedDomains, when set, admits only accounts whose verified email is in
	// one of these domains (for example a Google Workspace domain). Without it,
	// any Google account can sign in.
	AllowedDomains []string
}

// googleEndpoints are Google's published OIDC endpoints. They are a variable
// so tests can point the method at a local server.
var googleEndpoints = struct{ Issuer, Authorization, Token, JWKS, Userinfo string }{
	Issuer:        "https://accounts.google.com",
	Authorization: "https://accounts.google.com/o/oauth2/v2/auth",
	Token:         "https://oauth2.googleapis.com/token",
	JWKS:          "https://www.googleapis.com/oauth2/v3/certs",
	Userinfo:      "https://openidconnect.googleapis.com/v1/userinfo",
}

// NewGoogleLoginMethod builds a Google login on the generic OIDC provider, so
// ID token verification (signature, issuer, audience, expiry, nonce) is the
// same code path as every other OIDC connector.
func NewGoogleLoginMethod(config GoogleConfig, callbackURL string, allowInsecure bool) (*OIDCLoginMethod, error) {
	for _, domain := range config.AllowedDomains {
		if strings.TrimSpace(domain) == "" || strings.ContainsAny(domain, "@ /") {
			return nil, fmt.Errorf("google login method %q: allowed_domains entries must be bare domains such as example.com", config.ID)
		}
	}
	connector := ConnectorConfig{
		Issuer:                  googleEndpoints.Issuer,
		AuthorizationEndpoint:   googleEndpoints.Authorization,
		TokenEndpoint:           googleEndpoints.Token,
		JWKSURI:                 googleEndpoints.JWKS,
		UserinfoEndpoint:        googleEndpoints.Userinfo,
		ClientID:                config.ClientID,
		ClientIDEnv:             config.ClientIDEnv,
		ClientSecretEnv:         config.ClientSecretEnv,
		Scopes:                  []string{"openid", "email", "profile"},
		TokenEndpointAuthMethod: "client_secret_post",
		// validate() requires an exchange client id. This registry never
		// performs a token exchange, so it only needs to be non-empty.
		ExchangeClientID: "unused",
	}
	provider, err := NewOIDCIdentityProvider(connector, callbackURL, allowInsecure)
	if err != nil {
		return nil, fmt.Errorf("google login method %q: %w", config.ID, err)
	}
	return NewOIDCLoginMethod(config.ID, config.Label, provider, allowedEmailDomains(config.AllowedDomains)), nil
}

// allowedEmailDomains returns a claims check that requires a verified email in
// one of the domains, or nil when no restriction is configured.
func allowedEmailDomains(domains []string) func(map[string]any) error {
	if len(domains) == 0 {
		return nil
	}
	allowed := make(map[string]bool, len(domains))
	for _, domain := range domains {
		allowed[strings.ToLower(strings.TrimSpace(domain))] = true
	}
	return func(claims map[string]any) error {
		email, _ := claims["email"].(string)
		at := strings.LastIndex(email, "@")
		if at < 1 || !emailVerified(claims["email_verified"]) {
			return errors.New("account has no verified email address")
		}
		if !allowed[strings.ToLower(email[at+1:])] {
			return errors.New("email domain is not allowed")
		}
		return nil
	}
}

// emailVerified accepts the boolean the spec defines and the string "true"
// some providers send.
func emailVerified(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return typed == "true"
	}
	return false
}
