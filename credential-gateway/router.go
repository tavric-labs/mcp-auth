package credentialgateway

import (
	"context"
	"strings"

	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/formstore"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/mappings"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/secrets"
)

// router sends a service to the store that holds its credentials: submitted
// values for form services, mapped vault references for the rest. It is the
// one mappings store and resolver the credential service sees, so the
// per-request header path does not care where values came from.
type router struct {
	vault        mappings.Store
	resolver     secrets.Resolver
	forms        *formstore.Store
	formServices map[string]bool
}

func (r *router) Lookup(issuer, subject, service string) (*mappings.Mapping, error) {
	if r.formServices[service] {
		return r.forms.Lookup(issuer, subject, service)
	}
	if r.vault == nil {
		return nil, nil
	}
	return r.vault.Lookup(issuer, subject, service)
}

func (r *router) Resolve(ctx context.Context, refs map[string]string) (map[string]string, error) {
	for _, ref := range refs {
		if strings.HasPrefix(ref, formstore.RefPrefix) {
			return r.forms.Resolve(ctx, refs)
		}
	}
	if r.resolver == nil {
		return nil, secrets.ErrProviderUnavailable
	}
	return r.resolver.Resolve(ctx, refs)
}

func (r *router) Ready() bool {
	return r.resolver == nil || r.resolver.Ready()
}
