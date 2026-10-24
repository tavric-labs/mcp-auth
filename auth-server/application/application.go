package application

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Agent-Hellboy/mcp-auth/auth-server/server"
)

// Open initializes the authorization server using its standard environment-derived configuration.
// The caller owns the returned cleanup function and HTTP listener.
func Open(config server.Config) (*server.Server, func(), error) {
	if err := config.Validate(); err != nil {
		return nil, nil, err
	}
	store, closeStore, err := buildStore(config)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*server.Server, func(), error) { closeStore(); return nil, nil, err }
	config, identity, exchanger, err := buildProviders(config, store)
	if err != nil {
		return fail(err)
	}
	auth, err := server.NewServer(config, store, identity, exchanger, os.Stderr)
	if err != nil {
		return fail(err)
	}
	if config.ResourceLoginsFile != "" {
		logins, err := server.LoadResourceLogins(config.ResourceLoginsFile, server.LoginMethodsOptions{
			CallbackURL:    config.IdentityCallbackURL(),
			ConnectorsFile: config.ConnectorsFile,
			AllowInsecure:  config.LocalDevelopment || config.AllowInsecureConnectors,
		})
		if err != nil {
			return fail(err)
		}
		for _, resource := range logins.ResourceURLs() {
			if !slices.Contains(config.Resources, resource) {
				return fail(fmt.Errorf("resource login names %q, which is not in MCP_AUTH_RESOURCES", resource))
			}
		}
		auth.ResourceLogins = logins
	}
	if err = loadResourceClients(auth.Store, config.ResourceClientsFile, config.Resources); err != nil {
		return fail(err)
	}
	external, err := server.LoadExternalCredentials(config.ExternalCredentialsFile, config.Resources, config.ScopesForResource)
	if err != nil {
		return fail(err)
	}
	if err = auth.RegisterExternalCredentials(external); err != nil {
		return fail(err)
	}
	if config.LocalDevelopment && config.LocalClientID != "" {
		if err = auth.Store.SaveClient(server.Client{ID: config.LocalClientID, Name: "local resource server", RedirectURIs: []string{"http://127.0.0.1:39001/callback"}, TokenEndpointAuth: "none"}); err != nil {
			return fail(err)
		}
	}
	if config.LocalDevelopment && config.LocalTokenExchange {
		auth.TokenExchanger = server.LocalTokenExchanger{Issuer: config.Issuer, KeyProvider: auth.KeyProvider, TTL: config.AccessTokenTTL}
	}
	if config.LocalDevelopment && config.PrivateKeyFile == "" {
		slog.Warn("INSECURE LOCAL DEVELOPMENT: using an ephemeral signing key; all tokens become invalid after restart")
	}
	localIdentity := config.LocalDevelopment && config.ConnectorName == "" && config.LoginMethodsFile == ""
	if localIdentity || (config.LocalDevelopment && config.LocalTokenExchange) {
		slog.Warn("INSECURE LOCAL DEVELOPMENT is active", "fixed_subject_identity", localIdentity, "subject", config.LocalSubject, "local_token_exchange", config.LocalTokenExchange)
		go repeatLocalDevelopmentWarning(localIdentity, config.LocalTokenExchange)
	}
	return auth, closeStore, nil
}

// loadResourceClients registers pre-provisioned private_key_jwt clients (for
// example, a resource server performing RFC 8693 token exchange) so the
// token endpoint can authenticate them. Registration is re-applied on every
// startup, so the file is the source of truth and edits take effect on restart.
func loadResourceClients(store server.Store, path string, resources []string) error {
	if path == "" {
		return nil
	}
	clients, err := server.LoadResourceClients(path)
	if err != nil {
		return err
	}
	for _, client := range clients {
		if !slices.Contains(resources, client.Resource) {
			return fmt.Errorf("resource client %q binds unconfigured resource %q", client.ClientID, client.Resource)
		}
		if err := store.SaveClient(server.Client{
			ID:                client.ClientID,
			Name:              client.Name,
			Resource:          client.Resource,
			TokenEndpointAuth: "private_key_jwt",
			PublicKeyPEM:      client.PublicKeyPEM,
			Algorithm:         client.Algorithm,
		}); err != nil {
			return fmt.Errorf("register resource client %q: %w", client.ClientID, err)
		}
	}
	return nil
}

// repeatLocalDevelopmentWarning keeps the local-development identity path
// visible for the life of the process. A single line at startup is easy to
// miss once other logs scroll past it.
func repeatLocalDevelopmentWarning(localIdentity, tokenExchange bool) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		slog.Warn("INSECURE LOCAL DEVELOPMENT is still active", "fixed_subject_identity", localIdentity, "local_token_exchange", tokenExchange)
	}
}

func buildStore(config server.Config) (server.Store, func(), error) {
	switch strings.ToLower(config.StoreBackend) {
	case "memory":
		return server.NewMemoryStore(), func() {}, nil
	case "sqlite":
		store, err := server.NewSQLiteStore(config.DatabaseURL)
		if err != nil {
			return nil, nil, err
		}
		return store, func() { _ = store.Close() }, nil
	default:
		return nil, nil, errors.New("unsupported store backend")
	}
}

func connectorNames(connectors map[string]server.ConnectorConfig) []string {
	names := make([]string, 0, len(connectors))
	for name := range connectors {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func connectorNamesExcept(connectors map[string]server.ConnectorConfig, selected string) []string {
	names := make([]string, 0, len(connectors))
	for name := range connectors {
		if name != selected {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func buildProviders(config server.Config, store server.Store) (server.Config, server.IdentityProvider, server.TokenExchanger, error) {
	if config.LoginMethodsFile != "" {
		// Registry mode: several login methods on one login page. There is no
		// single connector, so no downstream upstream-session exchanger either;
		// external credential connectors are configured separately.
		registry, err := server.LoadLoginMethods(config.LoginMethodsFile, server.LoginMethodsOptions{
			CallbackURL:    config.IdentityCallbackURL(),
			ConnectorsFile: config.ConnectorsFile,
			AllowInsecure:  config.LocalDevelopment || config.AllowInsecureConnectors,
		})
		if err != nil {
			return config, nil, nil, err
		}
		return config, registry, nil, nil
	}
	if config.ConnectorName == "" {
		if !config.LocalDevelopment {
			return config, nil, nil, errors.New("a named connector is required outside local development")
		}
		return config, server.LocalIdentityProvider{Subject: config.LocalSubject}, nil, nil
	}
	allowInsecure := config.LocalDevelopment || config.AllowInsecureConnectors
	connectors, err := server.LoadConnectorsWithOptions(config.ConnectorsFile, allowInsecure)
	if err != nil {
		return config, nil, nil, err
	}
	connector, ok := connectors[config.ConnectorName]
	if !ok {
		return config, nil, nil, fmt.Errorf(
			"connector %q was not found in %s (file defines: %s)",
			config.ConnectorName, config.ConnectorsFile, strings.Join(connectorNames(connectors), ", "),
		)
	}
	// One process serves exactly one connector, so every other entry in the
	// file is inert. Say so by name at startup rather than ignoring it
	// silently, which is how someone ends up believing a second connector is
	// live. This warns rather than refuses because a single connectors file
	// shared across deployments — a staging entry and a production one, each
	// selected by its own MCP_AUTH_CONNECTOR — is a supported layout.
	if ignored := connectorNamesExcept(connectors, config.ConnectorName); len(ignored) > 0 {
		slog.Warn(
			"connectors defined but not served by this process; only MCP_AUTH_CONNECTOR is live",
			"selected", config.ConnectorName,
			"ignored", strings.Join(ignored, ","),
		)
	}
	config.AllowedClientRedirectURIs = append([]string(nil), connector.AllowedClientRedirectURIs...)
	config.Consent = copyConsent(connector.Consent)
	callbackURL := config.IdentityCallbackURL()
	identity, err := server.NewOIDCIdentityProvider(connector, callbackURL, allowInsecure)
	if err != nil {
		return config, nil, nil, err
	}
	exchanger, err := buildTokenExchanger(connector, allowInsecure, store)
	if err != nil {
		return config, nil, nil, err
	}
	return config, identity, exchanger, nil
}

// copyConsent gives the server config its own consent block so later edits
// to the loaded connector do not change the page, matching the slice copies
// above.
func copyConsent(in *server.ConsentConfig) *server.ConsentConfig {
	if in == nil {
		return nil
	}
	out := *in
	out.IntroParagraphs = append([]string(nil), in.IntroParagraphs...)
	out.Permissions = append([]string(nil), in.Permissions...)
	if in.ScopeLabels != nil {
		out.ScopeLabels = make(map[string]string, len(in.ScopeLabels))
		for key, value := range in.ScopeLabels {
			out.ScopeLabels[key] = value
		}
	}
	return &out
}

// buildTokenExchanger selects the downstream-token strategy the connector is
// configured for. upstream_session (the default) reuses the token set
// captured at login; rfc8693 performs RFC 8693 token-exchange against the
// same upstream provider, for providers that support it.
func buildTokenExchanger(connector server.ConnectorConfig, allowInsecure bool, store server.Store) (server.TokenExchanger, error) {
	if connector.ResolvedDownstreamTokenStrategy() == server.DownstreamTokenStrategyRFC8693 {
		return server.NewOIDCTokenExchanger(connector, allowInsecure)
	}
	return server.NewUpstreamSessionExchanger(store, connector)
}
