// Package mappings defines how the credential service finds the stored values
// for a verified (issuer, subject) pair and a service id. The in-memory form
// store is the implementation that ships; Store is the seam between it and the
// credential cache.
package mappings

import "errors"

// ErrUnavailable means the store cannot answer. The gateway fails closed on it
// instead of serving a stale grant.
var ErrUnavailable = errors.New("credential mapping source unavailable")

// Mapping is one binding of an identity and service to stored field references.
type Mapping struct {
	Issuer, Subject, Service string
	// Refs maps credential field name -> an opaque reference the resolver reads.
	Refs map[string]string
	// Version changes whenever Refs change; it is part of the cache key.
	Version string
}

// Store looks up the mapping for a verified identity and service.
type Store interface {
	// Lookup returns (nil, nil) when no mapping exists.
	Lookup(issuer, subject, service string) (*Mapping, error)
}
