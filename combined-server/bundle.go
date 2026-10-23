// Package combinedserver assembles the optional gateway with the unchanged
// provider-neutral OAuth application. It is the sole composition layer allowed
// to depend on both modules.
package combinedserver

import (
	"errors"
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
	auth.ResourceAuthorizationCheck = gateway.CheckAuthorization
	return nil
}
