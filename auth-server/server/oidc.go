package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// InteractiveIdentityProvider adds the browser redirect/callback seam needed
// by an upstream OAuth/OIDC provider while preserving the small core interface.
// Begin returns the PKCE verifier alongside the redirect location; the caller
// is responsible for persisting it (in the durable ConsentRequest, keyed by
// the same state) and passing it back on IdentityCallback.CodeVerifier. It is
// not kept in the provider itself so it expires with the rest of the pending
// request and works across replicas.
type InteractiveIdentityProvider interface {
	IdentityProvider
	Begin(context.Context, IdentityRequest, string) (location string, codeVerifier string, err error)
	Complete(context.Context, IdentityCallback) (Identity, error)
}

type IdentityCallback struct {
	Code         string
	RedirectURI  string
	Nonce        string
	State        string
	CodeVerifier string
}

// OIDCIdentityProvider performs an upstream Authorization Code + PKCE flow and
// verifies the returned RS256 ID token before exposing subject/claims locally.
type OIDCIdentityProvider struct {
	Connector   ConnectorConfig
	Client      *http.Client
	CallbackURL string
	Secret      string
	// ClientID is the connector's client_id, resolved once at construction
	// time from either the literal client_id or client_id_env.
	ClientID string
	jwks     jwksCache
}

func NewOIDCIdentityProvider(connector ConnectorConfig, callbackURL string, allowInsecure bool) (*OIDCIdentityProvider, error) {
	if err := connector.validate("selected", allowInsecure); err != nil {
		return nil, err
	}
	if len(connector.AllowedUpstreamCallbackURIs) > 0 && !contains(connector.AllowedUpstreamCallbackURIs, callbackURL) {
		return nil, errors.New("OIDC callback URL is not in allowed_upstream_callback_uris")
	}
	secret, err := connectorSecret(connector)
	if err != nil {
		return nil, err
	}
	clientID, err := connector.resolveClientID()
	if err != nil {
		return nil, err
	}
	return &OIDCIdentityProvider{Connector: connector, Client: connector.httpClient(), CallbackURL: callbackURL, Secret: secret, ClientID: clientID}, nil
}

func (p *OIDCIdentityProvider) Authenticate(context.Context, IdentityRequest) (Identity, error) {
	return Identity{}, errors.New("OIDC identity provider requires interactive browser authentication")
}

func (p *OIDCIdentityProvider) Begin(_ context.Context, request IdentityRequest, state string) (string, string, error) {
	if state == "" || (p.Connector.requiresIDTokenNonce() && request.Nonce == "") {
		return "", "", errors.New("OIDC state and nonce are required")
	}
	codeVerifier := randomID() + randomID()
	digest := sha256.Sum256([]byte(codeVerifier))
	scopes := append([]string(nil), p.Connector.Scopes...)
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	values := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.ClientID},
		"redirect_uri":          {p.CallbackURL},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(digest[:])},
		"code_challenge_method": {"S256"},
	}
	if p.Connector.requiresIDTokenNonce() {
		values.Set("nonce", request.Nonce)
	}
	return p.Connector.AuthorizationEndpoint + "?" + values.Encode(), codeVerifier, nil
}

func (p *OIDCIdentityProvider) Complete(ctx context.Context, callback IdentityCallback) (Identity, error) {
	if callback.Code == "" || callback.RedirectURI == "" || callback.State == "" {
		return Identity{}, errors.New("OIDC callback code and redirect URI are required")
	}
	if callback.CodeVerifier == "" {
		return Identity{}, errors.New("OIDC upstream state is invalid or expired")
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {callback.Code},
		"redirect_uri":  {callback.RedirectURI},
		"client_id":     {p.ClientID},
		"code_verifier": {callback.CodeVerifier},
	}
	if p.Client == nil {
		p.Client = http.DefaultClient
	}
	request, err := newTokenEndpointRequest(ctx, p.Connector, p.ClientID, p.Secret, form)
	if err != nil {
		return Identity{}, err
	}
	response, err := p.Client.Do(request)
	if err != nil {
		return Identity{}, fmt.Errorf("OIDC token request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Identity{}, tokenEndpointError("OIDC token request", response)
	}
	var tokenResponse struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.NewDecoder(response.Body).Decode(&tokenResponse); err != nil {
		return Identity{}, fmt.Errorf("decode OIDC token response: %w", err)
	}
	var claims map[string]any
	switch {
	case tokenResponse.IDToken != "":
		claims, err = p.verifyIDToken(ctx, tokenResponse.IDToken, callback.Nonce)
		if err != nil {
			return Identity{}, err
		}
	case p.Connector.requiresIDToken():
		return Identity{}, errors.New("token response has no id_token")
	default:
		// Plain OAuth 2.0 (no "openid" scope requested): there is no ID token
		// to verify, so identity comes from the userinfo endpoint below,
		// authenticated with the upstream access token. The authorization
		// response is still bound to this request without one — the state is
		// one-time and consumed from the store, and PKCE binds the code
		// exchange — but the nonce binding an ID token would carry does not
		// apply, which is why this is reachable only when the connector never
		// asked for OIDC in the first place.
		claims = map[string]any{}
	}
	// The upstream access token is this user's real, already-scoped
	// downstream credential (e.g. for Databricks' own APIs). Capturing it
	// here is what lets the "upstream_session" downstream-token strategy
	// avoid depending on the upstream provider supporting RFC 8693, and lets
	// resolveIdentityClaim call a userinfo endpoint below if it needs to.
	var upstreamSession *UpstreamSession
	if tokenResponse.AccessToken != "" {
		tokenType := tokenResponse.TokenType
		if tokenType == "" {
			tokenType = "Bearer"
		}
		ttl := time.Duration(tokenResponse.ExpiresIn) * time.Second
		if ttl <= 0 {
			ttl = 5 * time.Minute
		}
		upstreamSession = &UpstreamSession{
			AccessToken:  tokenResponse.AccessToken,
			RefreshToken: tokenResponse.RefreshToken,
			TokenType:    tokenType,
			ExpiresAt:    time.Now().Add(ttl),
			Scope:        strings.Fields(tokenResponse.Scope),
		}
	}
	subject, claims, err := p.resolveIdentityClaim(ctx, claims, upstreamSession)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Subject: subject, Claims: claims, UpstreamSession: upstreamSession}, nil
}

// resolveIdentityClaim picks Identity.Subject from the first present, non-
// empty claim in the connector's configured identity_claims fallback list
// (["sub"] by default). If none are present and the connector has a known
// userinfo_endpoint, it's called once — using the upstream access token,
// never the MCP client's own token — and its claims are merged in before
// trying again. ID token claims are authoritative and are never overwritten
// by userinfo, since userinfo responses aren't signed the way ID tokens are.
func (p *OIDCIdentityProvider) resolveIdentityClaim(ctx context.Context, claims map[string]any, session *UpstreamSession) (string, map[string]any, error) {
	if subject, ok := firstStringClaim(claims, p.Connector.resolvedIdentityClaims()); ok {
		return subject, claims, nil
	}
	if p.Connector.UserinfoEndpoint == "" || session == nil || session.AccessToken == "" {
		return "", nil, errors.New("no usable identity claim, and no userinfo_endpoint to fall back to")
	}
	userinfo, err := fetchUserinfo(ctx, p.Client, p.Connector.UserinfoEndpoint, session.AccessToken)
	if err != nil {
		return "", nil, fmt.Errorf("no usable identity claim and userinfo lookup failed: %w", err)
	}
	merged := make(map[string]any, len(claims)+len(userinfo))
	for key, value := range userinfo {
		merged[key] = value
	}
	for key, value := range claims {
		merged[key] = value
	}
	if subject, ok := firstStringClaim(merged, p.Connector.resolvedIdentityClaims()); ok {
		return subject, merged, nil
	}
	return "", nil, errors.New("neither the token claims nor the userinfo response carry a usable identity claim")
}

func firstStringClaim(claims map[string]any, names []string) (string, bool) {
	for _, name := range names {
		if value, ok := claims[name].(string); ok && value != "" {
			return value, true
		}
	}
	return "", false
}

func fetchUserinfo(ctx context.Context, client *http.Client, endpoint, accessToken string) (map[string]any, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create userinfo request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch userinfo: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("userinfo endpoint returned HTTP %d", response.StatusCode)
	}
	var claims map[string]any
	if err := json.NewDecoder(io.LimitReader(response.Body, maxJWKSResponseBytes)).Decode(&claims); err != nil {
		return nil, fmt.Errorf("decode userinfo response: %w", err)
	}
	return claims, nil
}

// newTokenEndpointRequest builds an application/x-www-form-urlencoded POST
// to a connector's token endpoint, applying whichever client authentication
// method the connector is configured for. Complete, OIDCTokenExchanger, and
// UpstreamSessionExchanger all send this same shape of request.
func newTokenEndpointRequest(ctx context.Context, connector ConnectorConfig, clientID, secret string, form url.Values) (*http.Request, error) {
	if connector.TokenEndpointAuthMethod == "client_secret_post" {
		form.Set("client_secret", secret)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, connector.tokenEndpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token endpoint request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if connector.TokenEndpointAuthMethod == "client_secret_basic" {
		request.SetBasicAuth(clientID, secret)
	}
	return request, nil
}

// tokenEndpointError describes a refused token request: the status, plus the
// provider's own OAuth error code and description when it sent them. Those two
// RFC 6749 fields are what an operator needs to fix a connector; nothing else
// from the response, and nothing from the request, is included.
func tokenEndpointError(what string, response *http.Response) error {
	if detail := providerOAuthError(response.Body); detail != "" {
		return fmt.Errorf("%s returned HTTP %d: %s", what, response.StatusCode, detail)
	}
	return fmt.Errorf("%s returned HTTP %d", what, response.StatusCode)
}

// providerOAuthError reads at most 4 KiB of an error response and returns
// "error" or "error (description)" from its JSON body, cleaned of control
// characters and capped, or "" when the body is not an OAuth error object.
func providerOAuthError(body io.Reader) string {
	var parsed struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.NewDecoder(io.LimitReader(body, 4096)).Decode(&parsed) != nil || parsed.Error == "" {
		return ""
	}
	clean := func(value string, limit int) string {
		value = strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return ' '
			}
			return r
		}, value)
		value = strings.Join(strings.Fields(value), " ")
		if len(value) > limit {
			value = value[:limit]
		}
		return value
	}
	detail := clean(parsed.Error, 80)
	if description := clean(parsed.Description, 240); description != "" {
		detail += " (" + description + ")"
	}
	return detail
}

// OIDCTokenExchanger implements RFC 8693 against the selected provider.
type OIDCTokenExchanger struct {
	Connector ConnectorConfig
	Client    *http.Client
	Secret    string
}

func NewOIDCTokenExchanger(connector ConnectorConfig, allowInsecure bool) (*OIDCTokenExchanger, error) {
	if err := connector.validate("selected", allowInsecure); err != nil {
		return nil, err
	}
	secret, err := connectorSecret(connector)
	if err != nil {
		return nil, err
	}
	return &OIDCTokenExchanger{Connector: connector, Client: connector.httpClient(), Secret: secret}, nil
}

func (e *OIDCTokenExchanger) Exchange(ctx context.Context, exchange ExchangeRequest) (ExchangeResponse, error) {
	if exchange.SubjectToken == "" || exchange.Audience == "" {
		return ExchangeResponse{}, errors.New("subject token and audience are required")
	}
	if e.Client == nil {
		e.Client = http.DefaultClient
	}
	clientID := e.Connector.ExchangeClientID
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":        {exchange.SubjectToken},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {requestedTokenType(exchange.RequestedTokenType)},
		"audience":             {exchange.Audience},
		"scope":                {strings.Join(exchange.Scope, " ")},
		"client_id":            {clientID},
	}
	request, err := newTokenEndpointRequest(ctx, e.Connector, clientID, e.Secret, form)
	if err != nil {
		return ExchangeResponse{}, fmt.Errorf("create token exchange request: %w", err)
	}
	response, err := e.Client.Do(request)
	if err != nil {
		return ExchangeResponse{}, fmt.Errorf("token exchange request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ExchangeResponse{}, upstreamExchangeError(response)
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil {
		return ExchangeResponse{}, fmt.Errorf("decode token exchange response: %w", err)
	}
	if token.AccessToken == "" {
		return ExchangeResponse{}, errors.New("token exchange response has no access_token")
	}
	if token.TokenType == "" {
		token.TokenType = "Bearer"
	}
	return ExchangeResponse{AccessToken: token.AccessToken, TokenType: token.TokenType, ExpiresIn: token.ExpiresIn, Scope: token.Scope}, nil
}

func requestedTokenType(value string) string {
	if value == "" {
		return "urn:ietf:params:oauth:token-type:access_token"
	}
	return value
}

func connectorSecret(connector ConnectorConfig) (string, error) {
	if connector.TokenEndpointAuthMethod == "none" {
		return "", nil
	}
	secret := strings.TrimSpace(os.Getenv(connector.ClientSecretEnv))
	if secret == "" {
		return "", fmt.Errorf("client secret environment variable %q is empty", connector.ClientSecretEnv)
	}
	return secret, nil
}

func (p *OIDCIdentityProvider) verifyIDToken(ctx context.Context, token, expectedNonce string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("OIDC ID token is malformed")
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	if err := decodeJWTPart(parts[0], &header); err != nil || header.KeyID == "" {
		return nil, errors.New("OIDC ID token algorithm or key is invalid")
	}
	if !contains(p.Connector.resolvedAllowedAlgorithms(), header.Algorithm) {
		return nil, errors.New("OIDC ID token algorithm is not allowed")
	}
	var claims map[string]any
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		return nil, errors.New("OIDC ID token claims are invalid")
	}
	key, err := p.jwks.resolve(ctx, p.Client, p.Connector.jwksURI(), header.KeyID)
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("OIDC ID token signature is malformed")
	}
	if verifySignature(header.Algorithm, key, []byte(parts[0]+"."+parts[1]), signature) != nil {
		return nil, errors.New("OIDC ID token signature is invalid")
	}
	if claims["iss"] != p.Connector.Issuer {
		return nil, errors.New("OIDC ID token issuer is invalid")
	}
	if !audienceContains(claims["aud"], p.ClientID) {
		return nil, errors.New("OIDC ID token audience is invalid")
	}
	if !validExpiry(claims["exp"]) {
		return nil, errors.New("OIDC ID token is expired")
	}
	if !validIssuedAt(claims["iat"]) {
		return nil, errors.New("OIDC ID token was issued in the future")
	}
	if !validNotBefore(claims["nbf"]) {
		return nil, errors.New("OIDC ID token is not yet valid")
	}
	// Nonce validation is mandatory unless a connector explicitly documents that its
	// provider cannot return a nonce claim. The state and PKCE checks still bind
	// that explicitly configured compatibility flow to this request.
	if p.Connector.requiresIDTokenNonce() && (expectedNonce == "" || claims["nonce"] != expectedNonce) {
		return nil, errors.New("OIDC ID token nonce is invalid")
	}
	return claims, nil
}

func decodeJWTPart(encoded string, destination any) error {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, destination)
}

func audienceContains(value any, expected string) bool {
	switch audience := value.(type) {
	case string:
		return audience == expected
	case []any:
		for _, item := range audience {
			if item == expected {
				return true
			}
		}
	}
	return false
}

// clockSkewTolerance absorbs small clock drift between this server and the
// systems that mint tokens it verifies: upstream OIDC providers for ID
// tokens, and this server's own clock for its previously-issued access
// tokens checked as token-exchange subject_tokens.
const clockSkewTolerance = 2 * time.Minute

func validExpiry(value any) bool {
	seconds, ok := value.(float64)
	return ok && time.Now().Add(-clockSkewTolerance).Unix() < int64(seconds)
}

func validIssuedAt(value any) bool {
	seconds, ok := value.(float64)
	if !ok {
		return false
	}
	return int64(seconds) <= time.Now().Add(clockSkewTolerance).Unix()
}

func validNotBefore(value any) bool {
	if value == nil {
		return true
	}
	seconds, ok := value.(float64)
	if !ok {
		return false
	}
	return int64(seconds) <= time.Now().Add(clockSkewTolerance).Unix()
}

const (
	// defaultJWKSCacheTTL applies when the JWKS response has no usable
	// Cache-Control max-age, bounding how long a rotated-out key stays trusted.
	defaultJWKSCacheTTL = 5 * time.Minute
	// maxJWKSResponseBytes bounds how much of a JWKS response body this
	// server will read, regardless of what the upstream server claims to send.
	maxJWKSResponseBytes = 1 << 20
)

// jwksCache holds one connector's fetched signing keys (RSA or EC), keyed by
// kid, so verifying an ID token doesn't refetch the upstream JWKS on every
// request. It refreshes on expiry (per Cache-Control max-age, or
// defaultJWKSCacheTTL) and also refreshes early when asked for a kid it
// doesn't have, since key rotation can introduce a new kid before the cache
// would otherwise expire.
type jwksCache struct {
	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	expiresAt time.Time
}

func (c *jwksCache) resolve(ctx context.Context, client *http.Client, endpoint, keyID string) (crypto.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if key, ok := c.keys[keyID]; ok && time.Now().Before(c.expiresAt) {
		return key, nil
	}
	keys, ttl, err := fetchJWKS(ctx, client, endpoint)
	if err != nil {
		return nil, err
	}
	c.keys, c.expiresAt = keys, time.Now().Add(ttl)
	key, ok := keys[keyID]
	if !ok {
		return nil, errors.New("OIDC JWKS signing key was not found")
	}
	return key, nil
}

func fetchJWKS(ctx context.Context, client *http.Client, endpoint string) (map[string]crypto.PublicKey, time.Duration, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("create JWKS request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch OIDC JWKS: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, 0, fmt.Errorf("OIDC JWKS returned HTTP %d", response.StatusCode)
	}
	var document struct {
		Keys []struct {
			KeyType string `json:"kty"`
			KeyID   string `json:"kid"`
			N       string `json:"n"`
			E       string `json:"e"`
			Curve   string `json:"crv"`
			X       string `json:"x"`
			Y       string `json:"y"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxJWKSResponseBytes)).Decode(&document); err != nil {
		return nil, 0, fmt.Errorf("decode OIDC JWKS: %w", err)
	}
	keys := make(map[string]crypto.PublicKey, len(document.Keys))
	for _, candidate := range document.Keys {
		if candidate.KeyID == "" {
			continue
		}
		switch candidate.KeyType {
		case "RSA":
			n, errN := base64.RawURLEncoding.DecodeString(candidate.N)
			e, errE := base64.RawURLEncoding.DecodeString(candidate.E)
			if errN != nil || errE != nil {
				continue
			}
			exponent, err := rsaExponent(e)
			if err != nil {
				continue
			}
			keys[candidate.KeyID] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}
		case "EC":
			if candidate.Curve != "P-256" {
				continue
			}
			x, errX := base64.RawURLEncoding.DecodeString(candidate.X)
			y, errY := base64.RawURLEncoding.DecodeString(candidate.Y)
			if errX != nil || errY != nil {
				continue
			}
			keys[candidate.KeyID] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		}
	}
	if len(keys) == 0 {
		return nil, 0, errors.New("OIDC JWKS has no usable RSA keys")
	}
	return keys, jwksCacheTTL(response.Header.Get("Cache-Control")), nil
}

func jwksCacheTTL(cacheControl string) time.Duration {
	for _, directive := range strings.Split(cacheControl, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(directive), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "max-age") {
			continue
		}
		if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
	}
	return defaultJWKSCacheTTL
}

// rsaExponent decodes a JWK "e" value into an rsa.PublicKey.E. big.Int.Int64
// is documented as undefined when the value doesn't fit in an int64, and a
// real RSA public exponent is always tiny (3 or 65537 in practice), so a
// four-byte cap plus an explicit range check rejects a malformed or
// oversized exponent instead of silently producing an undefined key.
func rsaExponent(data []byte) (int, error) {
	if len(data) == 0 || len(data) > 4 {
		return 0, errors.New("RSA exponent has an invalid length")
	}
	value := new(big.Int).SetBytes(data)
	if !value.IsInt64() {
		return 0, errors.New("RSA exponent is too large")
	}
	exponent := value.Int64()
	if exponent <= 0 || exponent > math.MaxInt32 {
		return 0, errors.New("RSA exponent is out of range")
	}
	return int(exponent), nil
}

// upstreamExchangeError turns a non-2xx token-exchange response into an error
// the /token classifier can act on. RFC 6749 section 5.2 carries the error
// code in the body, so discarding it collapsed an upstream invalid_target -
// a genuinely unacceptable audience, which belongs at 400 - into a 502
// server_error. Only the code is surfaced: error_description is upstream
// controlled text and does not belong in this server's own error string.
func upstreamExchangeError(response *http.Response) error {
	var payload struct {
		Error string `json:"error"`
	}
	body, _ := io.ReadAll(io.LimitReader(response.Body, maxJWKSResponseBytes))
	_ = json.Unmarshal(body, &payload)
	switch {
	case payload.Error == "invalid_target":
		return fmt.Errorf("%w: upstream rejected the requested audience", ErrUnacceptableAudience)
	case payload.Error != "":
		return fmt.Errorf("token exchange returned HTTP %d (%s)", response.StatusCode, payload.Error)
	default:
		return fmt.Errorf("token exchange returned HTTP %d", response.StatusCode)
	}
}
