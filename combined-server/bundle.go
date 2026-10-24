// Package combinedserver assembles the optional gateway with the unchanged
// provider-neutral OAuth application. It is the sole composition layer allowed
// to depend on both modules.
package combinedserver

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/Agent-Hellboy/mcp-auth/auth-server/server"
	credentialgateway "github.com/Agent-Hellboy/mcp-auth/credential-gateway"
)

// Attach checks deployment consistency, registers the gateway's public keys
// for per-request credential-access assertions and installs its login check.
// It is called once before either HTTP listener starts.
func Attach(auth *server.Server, gateway *credentialgateway.Runtime) error {
	if gateway.Issuer() != auth.Config.Issuer {
		return errors.New("gateway and OAuth issuer must match")
	}
	if auth.ResourceAuthorizationCheck != nil {
		return errors.New("resource authorization check is already installed")
	}
	entries := make([]server.ExternalCredentialConfig, 0, len(auth.ExternalCredentials))
	clients := map[string]bool{}
	for _, entry := range auth.ExternalCredentials {
		entries = append(entries, entry)
		clients[entry.ResourceClient.ClientID] = true
	}
	for _, resource := range gateway.Resources() {
		if !slices.Contains(auth.Config.Resources, resource.URL) {
			return errors.New("gateway resource is absent from MCP_AUTH_RESOURCES")
		}
		for _, scope := range resource.Scopes {
			if !slices.Contains(auth.Config.ScopesForResource(resource.URL), scope) {
				return errors.New("gateway requires an unconfigured OAuth scope")
			}
		}
		if _, exists := auth.ExternalCredentials[resource.URL]; exists || clients[resource.ClientID] {
			return errors.New("gateway conflicts with an external credential connector")
		}
		if existing, err := auth.Store.GetClient(resource.ClientID); err == nil && (existing.TokenEndpointAuth != "private_key_jwt" || existing.Resource != resource.URL) {
			return errors.New("gateway resource client is already registered")
		}
		clients[resource.ClientID] = true
		entries = append(entries, server.ExternalCredentialConfig{ID: resource.ID, Resource: resource.URL, RequiredScopes: resource.Scopes, ResourceClient: server.ExternalResourceClient{ClientID: resource.ClientID, PublicKeyPEM: resource.PublicKeyPEM, Algorithm: "RS256"}})
	}
	if err := auth.RegisterExternalCredentials(entries); err != nil {
		return err
	}
	if err := attachFormLogins(auth, gateway); err != nil {
		return err
	}
	auth.ResourceAuthorizationCheck = gateway.CheckAuthorization
	return nil
}

// formLogin is the sign-in page for one form-source service: one input per
// header value the service needs. It submits to the gateway, which checks the
// values at the upstream and keeps them in memory under a random subject.
type formLogin struct {
	id, label, prefix, service string
	fields                     []server.LoginField
	gateway                    *credentialgateway.Runtime
}

func (m *formLogin) ID() string                  { return m.id }
func (m *formLogin) Label() string               { return m.label }
func (m *formLogin) Fields() []server.LoginField { return m.fields }

func (m *formLogin) Authenticate(ctx context.Context, _ server.IdentityRequest, attempt server.LoginAttempt) (server.Identity, error) {
	subject, err := m.gateway.AuthenticateForm(ctx, m.service, m.prefix, attempt.Values)
	switch {
	case err == nil:
		return server.Identity{Subject: subject}, nil
	case errors.Is(err, credentialgateway.ErrRejected):
		return server.Identity{}, server.ErrInvalidCredentials
	default:
		return server.Identity{}, server.ErrMethodUnavailable
	}
}

// attachFormLogins assigns each form-source service its own sign-in method,
// scoped to that service's resource, so no identity provider is involved and
// other resources keep their existing login.
func attachFormLogins(auth *server.Server, gateway *credentialgateway.Runtime) error {
	services := gateway.FormServices()
	if len(services) == 0 {
		return nil
	}
	entries := make([]server.LoginEntry, 0, len(services))
	for _, service := range services {
		id := "form-" + service.ID
		method := &formLogin{id: id, label: "Sign in to " + service.ID, prefix: id + ":", service: service.ID, gateway: gateway}
		for _, field := range service.Fields {
			method.fields = append(method.fields, server.LoginField{Name: field.Name, Label: field.Label, Secret: field.Secret})
		}
		entries = append(entries, server.LoginEntry{Method: method, SubjectPrefix: method.prefix, Resources: []string{service.ResourceURL}})
	}
	if registry, ok := auth.IdentityProvider.(*server.LoginRegistry); ok {
		// Login methods mode: the form methods join the existing registry.
		extended, err := registry.WithEntries(entries...)
		if err != nil {
			return fmt.Errorf("form sign-in methods conflict with the login methods: %w", err)
		}
		auth.IdentityProvider = extended
		return nil
	}
	// Single connector (or local) mode: leave the identity provider, and its
	// downstream token exchange, untouched. Only the form resources use the
	// form methods; every other resource signs in as before.
	forms, err := server.NewLoginRegistry(entries...)
	if err != nil {
		return fmt.Errorf("form sign-in methods are invalid: %w", err)
	}
	auth.ResourceLogins = forms
	return nil
}
