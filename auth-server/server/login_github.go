package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	githubDefaultBaseURL = "https://github.com"
	githubDefaultAPIURL  = "https://api.github.com"
	githubHTTPTimeout    = 10 * time.Second
	githubMaxBody        = 1 << 20
)

// GitHubConfig configures "Sign in with GitHub". Base and API URLs default to
// github.com and can be pointed at GitHub Enterprise Server.
type GitHubConfig struct {
	ID              string
	Label           string
	ClientID        string
	ClientIDEnv     string
	ClientSecretEnv string
	// AllowedOrgs, when set, admits only active members of at least one of
	// these organizations. It adds the read:org scope.
	AllowedOrgs []string
	BaseURL     string
	APIURL      string
}

// GitHubLoginMethod signs a person in through GitHub's OAuth web flow. GitHub
// is OAuth 2.0 rather than OIDC: there is no ID token, so identity comes from
// the API, and the stable subject is the numeric account id (a login name can
// be renamed and later claimed by someone else).
type GitHubLoginMethod struct {
	config       GitHubConfig
	clientID     string
	clientSecret string
	callbackURL  string
	client       *http.Client
}

// NewGitHubLoginMethod validates the configuration and reads the credentials.
func NewGitHubLoginMethod(config GitHubConfig, callbackURL string, allowInsecure bool) (*GitHubLoginMethod, error) {
	fail := func(format string, args ...any) (*GitHubLoginMethod, error) {
		return nil, fmt.Errorf("github login method %q: %s", config.ID, fmt.Sprintf(format, args...))
	}
	if config.BaseURL == "" {
		config.BaseURL = githubDefaultBaseURL
	}
	if config.APIURL == "" {
		config.APIURL = githubDefaultAPIURL
	}
	for name, value := range map[string]string{"base_url": config.BaseURL, "api_url": config.APIURL} {
		parsed, err := url.Parse(value)
		validScheme := err == nil && (parsed.Scheme == "https" || (allowInsecure && parsed.Scheme == "http"))
		if !validScheme || parsed.Host == "" {
			return fail("%s must be an HTTPS URL", name)
		}
	}
	config.BaseURL = strings.TrimRight(config.BaseURL, "/")
	config.APIURL = strings.TrimRight(config.APIURL, "/")
	if (config.ClientID == "") == (config.ClientIDEnv == "") {
		return fail("set exactly one of client_id or client_id_env")
	}
	clientID := config.ClientID
	if config.ClientIDEnv != "" {
		clientID = os.Getenv(config.ClientIDEnv)
		if clientID == "" {
			return fail("environment variable %s is empty", config.ClientIDEnv)
		}
	}
	if config.ClientSecretEnv == "" {
		return fail("client_secret_env is required")
	}
	secret := os.Getenv(config.ClientSecretEnv)
	if secret == "" {
		return fail("environment variable %s is empty", config.ClientSecretEnv)
	}
	for _, org := range config.AllowedOrgs {
		if strings.TrimSpace(org) == "" || strings.ContainsAny(org, "/? #") {
			return fail("allowed_orgs entries must be organization names")
		}
	}
	return &GitHubLoginMethod{
		config: config, clientID: clientID, clientSecret: secret, callbackURL: callbackURL,
		client: &http.Client{Timeout: githubHTTPTimeout},
	}, nil
}

// ID implements LoginMethod.
func (m *GitHubLoginMethod) ID() string { return m.config.ID }

// Label implements LoginMethod.
func (m *GitHubLoginMethod) Label() string { return m.config.Label }

// Begin implements RedirectLoginMethod. PKCE is sent in case the server
// supports it; a server that ignores it is unaffected, and the one-time state
// still binds the response to this request.
func (m *GitHubLoginMethod) Begin(_ context.Context, _ IdentityRequest, state string) (string, string, error) {
	if state == "" {
		return "", "", errors.New("github state is required")
	}
	verifier := randomID() + randomID()
	digest := sha256.Sum256([]byte(verifier))
	scopes := []string{"read:user"}
	if len(m.config.AllowedOrgs) > 0 {
		scopes = append(scopes, "read:org")
	}
	values := url.Values{
		"client_id":             {m.clientID},
		"redirect_uri":          {m.callbackURL},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"allow_signup":          {"false"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(digest[:])},
		"code_challenge_method": {"S256"},
	}
	return m.config.BaseURL + "/login/oauth/authorize?" + values.Encode(), verifier, nil
}

// Complete implements RedirectLoginMethod. The GitHub access token is used for
// the lookups here and then discarded.
func (m *GitHubLoginMethod) Complete(ctx context.Context, callback IdentityCallback) (Identity, error) {
	if callback.Code == "" || callback.CodeVerifier == "" {
		return Identity{}, errors.New("github callback code and verifier are required")
	}
	token, err := m.exchangeCode(ctx, callback)
	if err != nil {
		return Identity{}, err
	}
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := m.apiGet(ctx, token, "/user", &user); err != nil {
		return Identity{}, err
	}
	if user.ID <= 0 {
		return Identity{}, errors.New("github user response has no account id")
	}
	if len(m.config.AllowedOrgs) > 0 {
		if err := m.requireOrgMember(ctx, token); err != nil {
			return Identity{}, err
		}
	}
	claims := map[string]any{"login": user.Login}
	if user.Name != "" {
		claims["name"] = user.Name
	}
	if user.Email != "" {
		claims["email"] = user.Email
	}
	return Identity{Subject: strconv.FormatInt(user.ID, 10), Claims: claims}, nil
}

func (m *GitHubLoginMethod) exchangeCode(ctx context.Context, callback IdentityCallback) (string, error) {
	form := url.Values{
		"client_id":     {m.clientID},
		"client_secret": {m.clientSecret},
		"code":          {callback.Code},
		"redirect_uri":  {callback.RedirectURI},
		"code_verifier": {callback.CodeVerifier},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, m.config.BaseURL+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Without this GitHub answers in form encoding rather than JSON.
	request.Header.Set("Accept", "application/json")
	response, err := m.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("github token request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("github token request returned HTTP %d", response.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, githubMaxBody)).Decode(&body); err != nil {
		return "", fmt.Errorf("decode github token response: %w", err)
	}
	// GitHub reports a rejected code as HTTP 200 with an error field.
	if body.Error != "" || body.AccessToken == "" {
		return "", fmt.Errorf("github rejected the authorization code (%s)", body.Error)
	}
	return body.AccessToken, nil
}

func (m *GitHubLoginMethod) apiGet(ctx context.Context, token, path string, into any) error {
	status, err := m.apiRequest(ctx, token, path, into)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("github API %s returned HTTP %d", path, status)
	}
	return nil
}

func (m *GitHubLoginMethod) apiRequest(ctx context.Context, token, path string, into any) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, m.config.APIURL+path, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	// GitHub rejects API requests that carry no User-Agent.
	request.Header.Set("User-Agent", "mcp-auth")
	response, err := m.client.Do(request)
	if err != nil {
		return 0, fmt.Errorf("github API %s: %w", path, err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 200 && response.StatusCode < 300 && into != nil {
		if err := json.NewDecoder(io.LimitReader(response.Body, githubMaxBody)).Decode(into); err != nil {
			return 0, fmt.Errorf("decode github API %s: %w", path, err)
		}
	}
	return response.StatusCode, nil
}

// requireOrgMember admits the person only as an active member of an allowed
// organization. A pending invitation is not membership.
func (m *GitHubLoginMethod) requireOrgMember(ctx context.Context, token string) error {
	for _, org := range m.config.AllowedOrgs {
		var membership struct {
			State string `json:"state"`
		}
		status, err := m.apiRequest(ctx, token, "/user/memberships/orgs/"+url.PathEscape(org), &membership)
		if err != nil {
			return err
		}
		if status == http.StatusOK && membership.State == "active" {
			return nil
		}
	}
	return errors.New("account is not an active member of an allowed organization")
}
