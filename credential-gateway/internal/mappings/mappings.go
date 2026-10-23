// Package mappings holds administrator-approved identity -> credential
// reference mappings. A mapping binds a verified (issuer, subject) pair and a
// service id to complete provider field references. Nothing a caller sends can
// influence a lookup. Store is the extension point for authenticated
// self-service enrollment; only the file-backed store ships today.
package mappings

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// ErrUnavailable means the mapping source cannot be read or is invalid. The
// gateway fails closed on it: it never serves a stale grant after the
// administrator's source stopped being valid.
var ErrUnavailable = errors.New("credential mapping source unavailable")

// Mapping is one approved identity/service binding.
type Mapping struct {
	Issuer, Subject, Service string
	// Refs maps credential field name -> complete provider reference.
	Refs map[string]string
	// Version changes whenever Refs change; it is part of the cache key.
	Version string
}

// Store looks up the mapping for a verified identity and service.
type Store interface {
	// Lookup returns (nil, nil) when no mapping exists.
	Lookup(issuer, subject, service string) (*Mapping, error)
}

var (
	// op://vault/item/field or op://vault/item/section/field

	fieldRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
)

type fileFormat struct {
	Mappings []struct {
		Issuer  string            `json:"issuer"`
		Subject string            `json:"subject"`
		Service string            `json:"service"`
		Fields  map[string]string `json:"fields"`
	} `json:"mappings"`
}

type key struct{ issuer, subject, service string }

// FileStore reads mappings from a JSON file and reloads it when it changes.
type FileStore struct {
	path     string
	required map[string][]string
	validate func(string) bool

	mu    sync.RWMutex
	sig   [2]int64
	index map[key]*Mapping
}

// NewFileStore loads path. required maps each known service id to the
// credential fields its headers need; mappings must supply them all.
func NewFileStore(path string, required map[string][]string) (*FileStore, error) {
	return NewValidatedFileStore(path, required, func(ref string) bool {
		u, err := url.Parse(ref)
		return err == nil && u.Scheme != "" && u.Host != "" && u.Path != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && !strings.ContainsAny(ref, " \t\r\n")
	})
}

// NewValidatedFileStore applies the selected provider's reference grammar.
func NewValidatedFileStore(path string, required map[string][]string, validate func(string) bool) (*FileStore, error) {
	if validate == nil {
		return nil, errors.New("reference validator is required")
	}
	s := &FileStore{path: path, required: required, validate: validate}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileStore) stat() ([2]int64, error) {
	info, err := os.Stat(s.path)
	if err != nil {
		return [2]int64{}, err
	}
	return [2]int64{info.ModTime().UnixNano(), info.Size()}, nil
}

func (s *FileStore) reload() error {
	sig, err := s.stat()
	if err != nil {
		return fmt.Errorf("mappings file %q is unreadable", s.path)
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("mappings file %q is unreadable", s.path)
	}
	index, err := s.parse(data)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.index, s.sig = index, sig
	s.mu.Unlock()
	return nil
}

func (s *FileStore) parse(data []byte) (map[key]*Mapping, error) {
	var file fileFormat
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, errors.New("mappings file is not valid JSON of the expected shape")
	}
	index := make(map[key]*Mapping, len(file.Mappings))
	for i, entry := range file.Mappings {
		here := fmt.Sprintf("mappings[%d]", i)
		if entry.Issuer == "" || entry.Subject == "" || entry.Service == "" {
			return nil, fmt.Errorf("%s: issuer, subject and service are required", here)
		}
		need, known := s.required[entry.Service]
		if !known {
			return nil, fmt.Errorf("%s: unknown service %q", here, entry.Service)
		}
		for name, ref := range entry.Fields {
			if !fieldRe.MatchString(name) {
				return nil, fmt.Errorf("%s: invalid field name %q", here, name)
			}
			if !s.validate(ref) {
				return nil, fmt.Errorf("%s: field %q must be a complete provider reference", here, name)
			}
		}
		for _, name := range need {
			if _, ok := entry.Fields[name]; !ok {
				return nil, fmt.Errorf("%s: missing required field %q", here, name)
			}
		}
		k := key{entry.Issuer, entry.Subject, entry.Service}
		if index[k] != nil {
			return nil, fmt.Errorf("%s: duplicate mapping for service %q", here, entry.Service)
		}
		index[k] = &Mapping{Issuer: entry.Issuer, Subject: entry.Subject, Service: entry.Service,
			Refs: entry.Fields, Version: version(entry.Fields)}
	}
	return index, nil
}

func version(fields map[string]string) string {
	names := make([]string, 0, len(fields))
	for n := range fields {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		h.Write([]byte(n + "\x00" + fields[n] + "\x00"))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Lookup implements Store.
func (s *FileStore) Lookup(issuer, subject, service string) (*Mapping, error) {
	sig, err := s.stat()
	if err != nil {
		return nil, ErrUnavailable
	}
	s.mu.RLock()
	current := s.sig
	s.mu.RUnlock()
	if sig != current {
		if err := s.reload(); err != nil {
			return nil, ErrUnavailable
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.index[key{issuer, subject, service}], nil
}
