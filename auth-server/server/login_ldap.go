package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
)

const (
	ldapDialTimeout = 5 * time.Second
	ldapOpTimeout   = 10 * time.Second
	// ldapMaxUsername and ldapMaxPassword bound what is sent to the directory.
	ldapMaxUsername = 256
	ldapMaxPassword = 1024
	// ldapMaxConcurrent bounds simultaneous directory connections per method,
	// so a flood of sign-in attempts cannot exhaust the directory.
	ldapMaxConcurrent = 16
	// ldapUsernamePlaceholder is replaced by the escaped account name in
	// user_filter and user_dn_template.
	ldapUsernamePlaceholder = "{username}"
	ldapUsernameField       = "username"
	ldapPasswordField       = "password"
)

// LDAPConfig configures a directory login. It supports two ways to find the
// person's entry:
//
//   - search: a service account searches UserSearchBase with UserFilter, which
//     must match exactly one entry; the server then binds as that entry.
//   - direct bind: UserDNTemplate builds the entry's DN from the account name.
//
// Exactly one of the two is configured.
type LDAPConfig struct {
	ID    string
	Label string
	// URL is ldaps://host[:port], or ldap://host[:port] together with StartTLS.
	URL      string
	StartTLS bool
	// CAFile adds a PEM bundle of trusted CAs. Empty uses the system roots.
	CAFile string

	// Search mode.
	BindDN         string
	BindSecretEnv  string
	UserSearchBase string
	UserFilter     string

	// Direct-bind mode.
	UserDNTemplate string

	// SubjectAttribute is the entry attribute used as the subject, or "dn".
	// Choose one that never changes for a person (entryUUID, objectGUID as text,
	// employeeNumber): a name that can be renamed or reused would let a new
	// account inherit an old account's access.
	SubjectAttribute string
	// Claims maps a claim name to an entry attribute, for example
	// {"email": "mail", "name": "cn"}.
	Claims map[string]string
	// UsernameLabel and PasswordLabel override the form's field labels.
	UsernameLabel string
	PasswordLabel string
}

// ldapConn is the slice of a directory connection the login uses. It exists
// so tests can substitute a fake without a directory server.
type ldapConn interface {
	Bind(dn, password string) error
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

type ldapDialer func(ctx context.Context) (ldapConn, error)

// LDAPLoginMethod authenticates people against a directory by binding as them.
// The password is used for that one bind and is never stored, logged or
// compared by this server.
type LDAPLoginMethod struct {
	config       LDAPConfig
	bindPassword string
	dial         ldapDialer
	slots        chan struct{}
}

// NewLDAPLoginMethod validates the configuration and prepares the method. It
// does not contact the directory, so a directory outage does not stop startup.
func NewLDAPLoginMethod(config LDAPConfig, allowInsecure bool) (*LDAPLoginMethod, error) {
	if err := config.validate(allowInsecure); err != nil {
		return nil, fmt.Errorf("ldap login method %q: %w", config.ID, err)
	}
	method := &LDAPLoginMethod{config: config, slots: make(chan struct{}, ldapMaxConcurrent)}
	if config.BindSecretEnv != "" {
		method.bindPassword = os.Getenv(config.BindSecretEnv)
		if method.bindPassword == "" {
			return nil, fmt.Errorf("ldap login method %q: environment variable %s is empty", config.ID, config.BindSecretEnv)
		}
	}
	tlsConfig, err := config.tlsConfig()
	if err != nil {
		return nil, fmt.Errorf("ldap login method %q: %w", config.ID, err)
	}
	method.dial = func(ctx context.Context) (ldapConn, error) { return dialLDAP(ctx, config, tlsConfig) }
	return method, nil
}

func (c LDAPConfig) validate(allowInsecure bool) error {
	parsed, err := url.Parse(c.URL)
	if err != nil || parsed.Hostname() == "" {
		return errors.New("url must be ldaps://host or ldap://host")
	}
	switch parsed.Scheme {
	case "ldaps":
	case "ldap":
		if !c.StartTLS && !allowInsecure {
			return errors.New("ldap:// requires start_tls (or use ldaps://); plaintext is allowed only with MCP_AUTH_ALLOW_INSECURE_CONNECTORS")
		}
	default:
		return errors.New("url must be ldaps://host or ldap://host")
	}
	if parsed.Scheme == "ldaps" && c.StartTLS {
		return errors.New("start_tls applies to ldap:// URLs, not ldaps://")
	}
	search := c.UserSearchBase != "" || c.UserFilter != "" || c.BindDN != "" || c.BindSecretEnv != ""
	direct := c.UserDNTemplate != ""
	switch {
	case search && direct:
		return errors.New("configure either a search (user_search_base, user_filter, bind_dn) or user_dn_template, not both")
	case !search && !direct:
		return errors.New("configure a search (user_search_base, user_filter, bind_dn, bind_password_env) or user_dn_template")
	}
	if search {
		if c.UserSearchBase == "" || c.UserFilter == "" || c.BindDN == "" || c.BindSecretEnv == "" {
			return errors.New("search mode requires user_search_base, user_filter, bind_dn and bind_password_env")
		}
		if strings.Count(c.UserFilter, ldapUsernamePlaceholder) != 1 {
			return errors.New("user_filter must contain " + ldapUsernamePlaceholder + " exactly once")
		}
	}
	if direct && strings.Count(c.UserDNTemplate, ldapUsernamePlaceholder) != 1 {
		return errors.New("user_dn_template must contain " + ldapUsernamePlaceholder + " exactly once")
	}
	if strings.TrimSpace(c.SubjectAttribute) == "" {
		return errors.New("subject_attribute is required: name an attribute that never changes for a person, or \"dn\"")
	}
	for claim, attribute := range c.Claims {
		if claim == "" || attribute == "" {
			return errors.New("claims entries need a claim name and an attribute")
		}
	}
	return nil
}

func (c LDAPConfig) tlsConfig() (*tls.Config, error) {
	parsed, _ := url.Parse(c.URL)
	config := &tls.Config{ServerName: parsed.Hostname(), MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_file has no usable certificates")
		}
		config.RootCAs = pool
	}
	return config, nil
}

// dialLDAP connects with its own deadlines. One deadline covers the TCP
// connect, the TLS handshake and the StartTLS exchange, because the library
// applies its operation timeout only after a connection exists, and a
// directory that accepts the connection and then stalls would otherwise hold
// the request open indefinitely.
func dialLDAP(ctx context.Context, config LDAPConfig, tlsConfig *tls.Config) (ldapConn, error) {
	parsed, err := url.Parse(config.URL)
	if err != nil {
		return nil, err
	}
	secure := parsed.Scheme == "ldaps"
	port := parsed.Port()
	if port == "" {
		port = "389"
		if secure {
			port = "636"
		}
	}
	raw, err := (&net.Dialer{Timeout: ldapDialTimeout}).DialContext(ctx, "tcp", net.JoinHostPort(parsed.Hostname(), port))
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(ldapDialTimeout + ldapOpTimeout))
	var conn *ldap.Conn
	if secure {
		tlsConn := tls.Client(raw, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		conn = ldap.NewConn(tlsConn, true)
		conn.Start()
	} else {
		conn = ldap.NewConn(raw, false)
		conn.Start()
		if config.StartTLS {
			if err := conn.StartTLS(tlsConfig); err != nil {
				_ = conn.Close()
				return nil, err
			}
		}
	}
	_ = raw.SetDeadline(time.Time{})
	conn.SetTimeout(ldapOpTimeout)
	return conn, nil
}

// ID implements LoginMethod.
func (m *LDAPLoginMethod) ID() string { return m.config.ID }

// Label implements LoginMethod.
func (m *LDAPLoginMethod) Label() string { return m.config.Label }

// Fields implements CredentialLoginMethod.
func (m *LDAPLoginMethod) Fields() []LoginField {
	username, password := m.config.UsernameLabel, m.config.PasswordLabel
	if username == "" {
		username = "Username"
	}
	if password == "" {
		password = "Password"
	}
	return []LoginField{
		{Name: ldapUsernameField, Label: username},
		{Name: ldapPasswordField, Label: password, Secret: true},
	}
}

// Authenticate implements CredentialLoginMethod.
func (m *LDAPLoginMethod) Authenticate(ctx context.Context, _ IdentityRequest, attempt LoginAttempt) (Identity, error) {
	username := strings.TrimSpace(attempt.Values[ldapUsernameField])
	password := attempt.Values[ldapPasswordField]
	// An empty password is the first thing to refuse: many directories treat
	// a bind with a name and an empty password as a successful anonymous bind,
	// which would sign anyone in as any account.
	if username == "" || password == "" ||
		len(username) > ldapMaxUsername || len(password) > ldapMaxPassword ||
		strings.ContainsAny(username, "\x00\r\n") || strings.ContainsRune(password, 0) {
		return Identity{}, ErrInvalidCredentials
	}
	select {
	case m.slots <- struct{}{}:
		defer func() { <-m.slots }()
	case <-ctx.Done():
		return Identity{}, fmt.Errorf("%w: %v", ErrMethodUnavailable, ctx.Err())
	}
	conn, err := m.dial(ctx)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: connect to directory: %v", ErrMethodUnavailable, err)
	}
	defer func() { _ = conn.Close() }()
	// The library cannot be interrupted, so a cancelled request closes the
	// connection out from under it.
	defer context.AfterFunc(ctx, func() { _ = conn.Close() })()

	attributes := m.attributes()
	var entry *ldap.Entry
	if m.config.UserDNTemplate != "" {
		dn := strings.Replace(m.config.UserDNTemplate, ldapUsernamePlaceholder, ldap.EscapeDN(username), 1)
		if err := bindAsUser(conn, dn, password); err != nil {
			return Identity{}, err
		}
		entry, err = m.readEntry(conn, dn, attributes)
	} else {
		entry, err = m.findEntry(conn, username, attributes)
		if err != nil {
			return Identity{}, err
		}
		if err := bindAsUser(conn, entry.DN, password); err != nil {
			return Identity{}, err
		}
	}
	if err != nil {
		return Identity{}, err
	}
	return m.identity(entry)
}

func (m *LDAPLoginMethod) attributes() []string {
	var names []string
	if m.config.SubjectAttribute != "dn" {
		names = append(names, m.config.SubjectAttribute)
	}
	for _, attribute := range m.config.Claims {
		names = append(names, attribute)
	}
	if len(names) == 0 {
		// "1.1" asks for no attributes, only the DN.
		names = []string{"1.1"}
	}
	return names
}

func (m *LDAPLoginMethod) findEntry(conn ldapConn, username string, attributes []string) (*ldap.Entry, error) {
	if err := conn.Bind(m.config.BindDN, m.bindPassword); err != nil {
		return nil, fmt.Errorf("%w: service account bind: %v", ErrMethodUnavailable, err)
	}
	filter := strings.Replace(m.config.UserFilter, ldapUsernamePlaceholder, ldap.EscapeFilter(username), 1)
	result, err := conn.Search(ldap.NewSearchRequest(
		m.config.UserSearchBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, int(ldapOpTimeout.Seconds()), false, filter, attributes, nil,
	))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
			return nil, fmt.Errorf("%w: user_filter matched more than one entry", ErrInvalidCredentials)
		}
		return nil, fmt.Errorf("%w: user search: %v", ErrMethodUnavailable, err)
	}
	switch len(result.Entries) {
	case 1:
		return result.Entries[0], nil
	case 0:
		return nil, ErrInvalidCredentials
	default:
		// Two entries for one name is a directory or filter mistake. Refusing
		// is the only safe answer; the caller must not guess which is meant.
		return nil, fmt.Errorf("%w: user_filter matched more than one entry", ErrInvalidCredentials)
	}
}

// readEntry reads the signed-in person's own entry after a direct bind. It is
// always read, even when only the DN is wanted: the DN built from the typed
// name keeps the typed spelling ("Alice" and "alice" are one account on a
// directory that matches DNs case-insensitively), and using it as the subject
// would give one person several. The entry returned by the directory carries
// the canonical DN.
func (m *LDAPLoginMethod) readEntry(conn ldapConn, dn string, attributes []string) (*ldap.Entry, error) {
	result, err := conn.Search(ldap.NewSearchRequest(
		dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, int(ldapOpTimeout.Seconds()), false, "(objectClass=*)", attributes, nil,
	))
	if err != nil || len(result.Entries) != 1 {
		return nil, errors.New("read the signed-in entry (the account must be allowed to read its own entry)")
	}
	return result.Entries[0], nil
}

// bindAsUser checks the person's password by binding as their entry. A
// rejected credential is a normal failure; anything else is the directory
// misbehaving and must not be reported to the person as a wrong password.
func bindAsUser(conn ldapConn, dn, password string) error {
	err := conn.Bind(dn, password)
	switch {
	case err == nil:
		return nil
	case ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials),
		ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject),
		ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidDNSyntax):
		return ErrInvalidCredentials
	default:
		return fmt.Errorf("%w: user bind: %v", ErrMethodUnavailable, err)
	}
}

func (m *LDAPLoginMethod) identity(entry *ldap.Entry) (Identity, error) {
	subject := entry.DN
	if m.config.SubjectAttribute != "dn" {
		var err error
		if subject, err = ldapSubjectValue(entry, m.config.SubjectAttribute); err != nil {
			return Identity{}, err
		}
	}
	if strings.TrimSpace(subject) == "" {
		return Identity{}, fmt.Errorf("entry has no %q value to use as the subject", m.config.SubjectAttribute)
	}
	claims := map[string]any{}
	for claim, attribute := range m.config.Claims {
		if value := entry.GetAttributeValue(attribute); value != "" {
			claims[claim] = value
		}
	}
	return Identity{Subject: subject, Claims: claims}, nil
}

// ldapSubjectValue returns the subject attribute exactly as stored. It insists
// on one value, because picking the first of several is arbitrary, and it does
// not trim, because the value is an identifier. A binary value (Active
// Directory's objectGUID, for one) or one that is not printable text is
// encoded as "hex:" plus its bytes in lowercase hex: converting arbitrary
// bytes to a string would make distinct values collide when the subject is
// later written as JSON.
func ldapSubjectValue(entry *ldap.Entry, attribute string) (string, error) {
	values := entry.GetRawAttributeValues(attribute)
	if len(values) != 1 {
		return "", fmt.Errorf("subject attribute %q must have exactly one value, found %d", attribute, len(values))
	}
	raw := values[0]
	if len(raw) == 0 {
		return "", fmt.Errorf("subject attribute %q is empty", attribute)
	}
	if !utf8.Valid(raw) || strings.IndexFunc(string(raw), func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return "hex:" + hex.EncodeToString(raw), nil
	}
	return string(raw), nil
}
