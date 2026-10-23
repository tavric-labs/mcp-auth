// Package onepassword implements service-account and local desktop credential resolution.
package onepassword

import (
	"context"
	"fmt"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/secrets"
	"log/slog"
	"sync"
	"time"

	"github.com/1password/onepassword-sdk-go"
)

type secretsAPI interface {
	Resolve(ctx context.Context, reference string) (string, error)
}

type clientFactory func(ctx context.Context, token, integration, version string) (secretsAPI, error)

func sdkFactory(ctx context.Context, token, integration, version string) (secretsAPI, error) {
	client, err := onepassword.NewClient(ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo(integration, version))
	if err != nil {
		return nil, err
	}
	return client.Secrets(), nil
}

// OnePassword resolves references with a read-only service account. The token
// is read once from a mounted file, held only in this value, and never logged,
// printed or returned.
type OnePassword struct {
	token       string
	integration string
	version     string
	timeout     time.Duration
	factory     clientFactory

	mu     sync.Mutex
	client secretsAPI
}

// NewOnePassword reads the service-account token and prepares the resolver.
func NewOnePassword(tokenFile, integration, version string, timeout time.Duration) (*OnePassword, error) {
	token, err := secrets.ReadSecretFile(tokenFile, "service account token")
	if err != nil {
		return nil, err
	}
	return &OnePassword{token: token, integration: integration, version: version, timeout: timeout, factory: sdkFactory}, nil
}

// String, GoString and LogValue keep the token out of every print path.
func (o *OnePassword) String() string             { return "OnePassword(<redacted>)" }
func (o *OnePassword) GoString() string           { return o.String() }
func (o *OnePassword) LogValue() slog.Value       { return slog.StringValue(o.String()) }
func (o *OnePassword) Ready() bool                { return o.token != "" }
func (o *OnePassword) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(o.String())) }

func (o *OnePassword) getClient(ctx context.Context) (secretsAPI, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.client != nil {
		return o.client, nil
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	client, err := o.factory(ctx, o.token, o.integration, o.version)
	if err != nil {
		slog.Warn("1password authentication failed")
		return nil, secrets.ErrProviderUnavailable
	}
	o.client = client
	return client, nil
}

// Resolve reads every reference concurrently under one bounded timeout. The
// first failure cancels the sibling reads.
func (o *OnePassword) Resolve(ctx context.Context, refs map[string]string) (map[string]string, error) {
	client, err := o.getClient(ctx)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	type result struct {
		name, value string
		err         error
	}
	results := make(chan result, len(refs))
	for name, ref := range refs {
		go func() {
			value, err := client.Resolve(ctx, ref)
			results <- result{name, value, err}
		}()
	}
	values := make(map[string]string, len(refs))
	var failure error
	for range refs {
		r := <-results
		switch {
		case r.err != nil && failure == nil:
			failure = secrets.ErrFieldUnavailable
			if ctx.Err() != nil {
				failure = secrets.ErrProviderUnavailable
			}
			cancel() // stop sibling work
			slog.Warn("1password could not resolve a mapped field", "field", r.name)
		case r.err == nil && r.value == "" && failure == nil:
			failure = secrets.ErrFieldUnavailable
			cancel()
		case r.err == nil:
			values[r.name] = r.value
		}
	}
	if failure != nil {
		return nil, failure
	}
	return values, nil
}
