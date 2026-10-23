// Package headers converts credential fields into upstream request headers
// using a small, fixed set of transforms. Nothing here evaluates code or
// templates from configuration.
package headers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const maxValue = 8192

// ErrInvalidValue is returned for credential material that cannot be a safe
// header value. It never carries the value itself.
var ErrInvalidValue = errors.New("credential header value is invalid")

var (
	tokenRe = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	fieldRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

	approvedPrefixes = map[string]bool{"Bearer": true, "Token": true}

	// forbiddenInjected are headers the gateway owns: framing, routing,
	// session and protocol semantics.
	forbiddenInjected = map[string]bool{
		"host": true, "content-length": true, "content-type": true, "content-encoding": true,
		"transfer-encoding": true, "connection": true, "keep-alive": true, "proxy-authorization": true,
		"proxy-authenticate": true, "te": true, "trailer": true, "upgrade": true, "cookie": true,
		"set-cookie": true, "accept": true, "accept-encoding": true, "origin": true,
		"mcp-session-id": true, "mcp-protocol-version": true, "last-event-id": true,
		"forwarded": true, "via": true,
	}
)

// ForwardedRequest is the allowlist of client headers copied upstream. Every
// other header is dropped, which removes caller credentials, cookies, spoofed
// identity and forwarding headers, hop-by-hop headers and destination
// overrides without relying on a deny list.
var ForwardedRequest = []string{"Accept", "Content-Type", "Mcp-Protocol-Version", "Last-Event-Id"}

// ReturnedResponse is the allowlist of upstream response headers returned.
var ReturnedResponse = []string{"Content-Type", "Cache-Control", "Retry-After", "Mcp-Protocol-Version"}

// Kinds of transform.
const (
	Direct = "direct"
	Prefix = "prefix"
	Basic  = "basic"
)

// Spec is one validated header rule.
type Spec struct {
	Name          string
	Kind          string
	Field         string
	Prefix        string
	UsernameField string
	PasswordField string
}

// Raw is the JSON form of a Spec. Unknown keys are rejected by the loader.
type Raw struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Field         string `json:"field"`
	Prefix        string `json:"prefix"`
	UsernameField string `json:"username_field"`
	PasswordField string `json:"password_field"`
}

// Parse validates raw header rules for one service.
func Parse(raw []Raw, where string) ([]Spec, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s: headers must be a non-empty list", where)
	}
	seen := map[string]bool{}
	specs := make([]Spec, 0, len(raw))
	for i, item := range raw {
		here := fmt.Sprintf("%s.headers[%d]", where, i)
		if !tokenRe.MatchString(item.Name) {
			return nil, fmt.Errorf("%s: invalid header name", here)
		}
		lowered := strings.ToLower(item.Name)
		if forbiddenInjected[lowered] || strings.HasPrefix(lowered, "x-forwarded-") || strings.HasPrefix(lowered, "sec-") {
			return nil, fmt.Errorf("%s: header %q may not be injected", here, item.Name)
		}
		if seen[lowered] {
			return nil, fmt.Errorf("%s: duplicate header %q", here, item.Name)
		}
		seen[lowered] = true
		spec := Spec{Name: item.Name, Kind: item.Type}
		unused := func(values ...string) error {
			for _, v := range values {
				if v != "" {
					return fmt.Errorf("%s: key not valid for type %q", here, item.Type)
				}
			}
			return nil
		}
		switch item.Type {
		case Direct, Prefix:
			if !fieldRe.MatchString(item.Field) {
				return nil, fmt.Errorf("%s: field must be a credential field name", here)
			}
			if err := unused(item.UsernameField, item.PasswordField); err != nil {
				return nil, err
			}
			spec.Field = item.Field
			if item.Type == Prefix {
				if !approvedPrefixes[item.Prefix] {
					return nil, fmt.Errorf("%s: prefix must be one of %v", here, sortedKeys(approvedPrefixes))
				}
				spec.Prefix = item.Prefix
			} else if err := unused(item.Prefix); err != nil {
				return nil, err
			}
		case Basic:
			if !fieldRe.MatchString(item.UsernameField) || !fieldRe.MatchString(item.PasswordField) {
				return nil, fmt.Errorf("%s: username_field and password_field must be credential field names", here)
			}
			if err := unused(item.Field, item.Prefix); err != nil {
				return nil, err
			}
			spec.UsernameField, spec.PasswordField = item.UsernameField, item.PasswordField
		default:
			return nil, fmt.Errorf("%s: type must be one of direct, prefix, basic", here)
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Fields lists the credential fields a spec reads.
func (s Spec) Fields() []string {
	if s.Kind == Basic {
		return []string{s.UsernameField, s.PasswordField}
	}
	return []string{s.Field}
}

// RequiredFields is the union of fields across specs.
func RequiredFields(specs []Spec) []string {
	set := map[string]bool{}
	for _, s := range specs {
		for _, f := range s.Fields() {
			set[f] = true
		}
	}
	return sortedKeys(set)
}

// ValidValue rejects empty, oversized, non-ASCII or control-character values,
// including CR, LF and NUL, and values with surrounding whitespace.
func ValidValue(value string) error {
	if value == "" || len(value) > maxValue || value != strings.TrimSpace(value) {
		return ErrInvalidValue
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < 0x20 && c != '\t') || c >= 0x7F {
			return ErrInvalidValue
		}
	}
	return nil
}

// Render produces the header value for one spec.
func (s Spec) Render(fields map[string]string) (string, error) {
	var value string
	switch s.Kind {
	case Direct:
		v, ok := fields[s.Field]
		if !ok {
			return "", ErrInvalidValue
		}
		value = v
	case Prefix:
		v, ok := fields[s.Field]
		if !ok {
			return "", ErrInvalidValue
		}
		value = s.Prefix + " " + v
	case Basic:
		user, uok := fields[s.UsernameField]
		pass, pok := fields[s.PasswordField]
		if !uok || !pok || strings.Contains(user, ":") {
			return "", ErrInvalidValue
		}
		// Control characters are checked on the parts as well as the result,
		// because base64 would otherwise hide them.
		if err := ValidValue(user); err != nil {
			return "", err
		}
		if err := ValidValue(pass); err != nil {
			return "", err
		}
		value = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	default:
		return "", ErrInvalidValue
	}
	if err := ValidValue(value); err != nil {
		return "", err
	}
	return value, nil
}

// RenderAll renders every spec.
func RenderAll(specs []Spec, fields map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(specs))
	for _, s := range specs {
		v, err := s.Render(fields)
		if err != nil {
			return nil, err
		}
		out[s.Name] = v
	}
	return out, nil
}
