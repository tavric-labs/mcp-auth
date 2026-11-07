package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// UpstreamSessionExchanger resolves a downstream credential by reusing (and
// refreshing) the token set the upstream provider issued at login, instead
// of requesting a new one via RFC 8693 token-exchange. This is the default
// downstream-token strategy because it works with any OAuth2/OIDC provider,
// not just ones that implement token-exchange federation, and doesn't
// require the upstream provider to trust an mcp-auth-issued subject_token.
//
// It cannot mint a credential scoped for an arbitrary requested audience the
// login session wasn't already scoped for. ExchangeRequest.Audience, Scope,
// and RequestedTokenType are advisory: they are not applied, and the returned
// token is not an RFC 8693 audience-scoped token. The HTTP response still
// carries issued_token_type for an access token because that is what this
// strategy returns. A deployment that needs a token for a specific downstream
// audience the login flow didn't already request should use the "rfc8693"
// strategy against a provider that supports it, or request the needed scopes
// in the connector's own upstream authorization request instead.
type UpstreamSessionExchanger struct {
	Store     Store
	Connector ConnectorConfig
	Secret    string
	Client    *http.Client
}

func NewUpstreamSessionExchanger(store Store, connector ConnectorConfig) (*UpstreamSessionExchanger, error) {
	if store == nil {
		return nil, errors.New("upstream session exchanger requires a store")
	}
	secret, err := connectorSecret(connector)
	if err != nil {
		return nil, err
	}
	return &UpstreamSessionExchanger{Store: store, Connector: connector, Secret: secret, Client: connector.httpClient()}, nil
}

func (e *UpstreamSessionExchanger) Exchange(ctx context.Context, request ExchangeRequest) (ExchangeResponse, error) {
	if request.Subject == "" {
		return ExchangeResponse{}, errors.New("subject is required")
	}
	session, err := e.Store.GetUpstreamSession(request.Subject)
	if err != nil {
		return ExchangeResponse{}, fmt.Errorf("no upstream session for subject: %w", err)
	}
	if time.Now().Before(session.ExpiresAt) {
		return sessionExchangeResponse(session), nil
	}
	if session.RefreshToken == "" {
		return ExchangeResponse{}, errors.New("upstream session expired and has no refresh token")
	}
	refreshed, err := e.refresh(ctx, session)
	if err != nil {
		return ExchangeResponse{}, err
	}
	if err := e.Store.SaveUpstreamSession(request.Subject, refreshed); err != nil {
		return ExchangeResponse{}, fmt.Errorf("persist refreshed upstream session: %w", err)
	}
	return sessionExchangeResponse(refreshed), nil
}

func (e *UpstreamSessionExchanger) refresh(ctx context.Context, session UpstreamSession) (UpstreamSession, error) {
	if e.Client == nil {
		e.Client = http.DefaultClient
	}
	clientID, err := e.Connector.resolveClientID()
	if err != nil {
		return UpstreamSession{}, err
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {session.RefreshToken},
	}
	request, err := newTokenEndpointRequest(ctx, e.Connector, clientID, e.Secret, form)
	if err != nil {
		return UpstreamSession{}, err
	}
	response, err := e.Client.Do(request)
	if err != nil {
		return UpstreamSession{}, fmt.Errorf("refresh upstream session: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return UpstreamSession{}, tokenEndpointError("refresh upstream session", response)
	}
	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil {
		return UpstreamSession{}, fmt.Errorf("decode refresh response: %w", err)
	}
	if token.AccessToken == "" {
		return UpstreamSession{}, errors.New("refresh response has no access_token")
	}
	tokenType := token.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	ttl := time.Duration(token.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	refreshToken := token.RefreshToken
	if refreshToken == "" {
		// Not every provider rotates the refresh token on use; keep the
		// existing one so a future refresh doesn't lose it.
		refreshToken = session.RefreshToken
	}
	scope := session.Scope
	if token.Scope != "" {
		scope = strings.Fields(token.Scope)
	}
	return UpstreamSession{AccessToken: token.AccessToken, RefreshToken: refreshToken, TokenType: tokenType, ExpiresAt: time.Now().Add(ttl), Scope: scope}, nil
}

func sessionExchangeResponse(session UpstreamSession) ExchangeResponse {
	return ExchangeResponse{
		AccessToken: session.AccessToken,
		TokenType:   session.TokenType,
		ExpiresIn:   int(time.Until(session.ExpiresAt).Seconds()),
		Scope:       joinScopes(session.Scope),
	}
}
