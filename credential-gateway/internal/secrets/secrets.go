// Package secrets defines the provider-neutral credential resolver contract.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	// ErrProviderUnavailable: the provider could not be reached, authenticated
	// with, or answered too slowly.
	ErrProviderUnavailable = errors.New("credential provider unavailable")
	// ErrFieldUnavailable: a mapped field could not be read.
	ErrFieldUnavailable = errors.New("credential field unavailable")
)

// Resolver resolves {field: reference} into {field: value}. Implementations
// return only the sentinel errors above; provider messages are never
// propagated because they can quote references or vault contents.
type Resolver interface {
	Resolve(ctx context.Context, refs map[string]string) (map[string]string, error)
	Ready() bool
}

// ReadSecretFile reads a mounted secret, trimming whitespace.
func ReadSecretFile(path, what string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%s file %q is not readable", what, path)
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", fmt.Errorf("%s file %q is empty", what, path)
	}
	return value, nil
}
