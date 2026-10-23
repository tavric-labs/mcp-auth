package server

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const staticMaxSubject = 256

// StaticLoginMethod signs in a fixed, configured subject with no identity
// provider and no typed credentials. It is for a resource whose own gateway
// supplies and validates the upstream credentials (a header-authenticated MCP
// server): the person only approves the sign-in, the resource's pre-code
// check then reads the mapped vault values and tests them at the upstream, and
// a failure denies the authorization.
//
// Every sign-in on the method's resources shares one subject, so the resource
// serves one shared credential set. It proves nothing about who the person
// is. Assign it to a resource with `resources`, and only where one shared
// upstream credential is the intent.
type StaticLoginMethod struct {
	id      string
	label   string
	subject string
}

// NewStaticLoginMethod validates the subject the method will always return.
func NewStaticLoginMethod(id, label, subject string) (*StaticLoginMethod, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, errors.New("subject is required")
	}
	if !utf8.ValidString(subject) || len(subject) > staticMaxSubject {
		return nil, errors.New("subject must be valid UTF-8 of at most 256 bytes")
	}
	for _, r := range subject {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return nil, errors.New("subject must not contain whitespace or control characters")
		}
	}
	return &StaticLoginMethod{id: id, label: label, subject: subject}, nil
}

func (m *StaticLoginMethod) ID() string    { return m.id }
func (m *StaticLoginMethod) Label() string { return m.label }

// Fields is empty: the page shows one button.
func (m *StaticLoginMethod) Fields() []LoginField { return nil }

// AllowsNoFields lets the registry accept a credential method with no inputs.
func (m *StaticLoginMethod) AllowsNoFields() bool { return true }

func (m *StaticLoginMethod) Authenticate(_ context.Context, _ IdentityRequest, _ LoginAttempt) (Identity, error) {
	return Identity{Subject: m.subject}, nil
}
