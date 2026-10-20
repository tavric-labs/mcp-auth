package server

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// fakeDirectory records every operation and answers from canned data.
type fakeDirectory struct {
	dialErr    error
	dialed     int
	closed     int
	binds      [][2]string
	searches   []*ldap.SearchRequest
	entries    []*ldap.Entry
	searchErr  error
	bindErrFor map[string]error
	// passwords maps a bind DN to its password; other DNs fail with
	// invalid credentials.
	passwords map[string]string
}

func (d *fakeDirectory) dial(context.Context) (ldapConn, error) {
	d.dialed++
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	return d, nil
}

func (d *fakeDirectory) Bind(dn, password string) error {
	d.binds = append(d.binds, [2]string{dn, password})
	if err := d.bindErrFor[dn]; err != nil {
		return err
	}
	if want, ok := d.passwords[dn]; ok && want == password {
		return nil
	}
	return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
}

func (d *fakeDirectory) Search(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	d.searches = append(d.searches, request)
	if d.searchErr != nil {
		return nil, d.searchErr
	}
	return &ldap.SearchResult{Entries: d.entries}, nil
}

func (d *fakeDirectory) Close() error { d.closed++; return nil }

func aliceEntry() *ldap.Entry {
	return ldap.NewEntry("uid=alice,ou=people,dc=example,dc=com", map[string][]string{
		"entryUUID": {"b1f6-alice"}, "mail": {"alice@example.com"}, "cn": {"Alice A"},
	})
}

func searchConfig() LDAPConfig {
	return LDAPConfig{
		ID: "corp", Label: "Corp", URL: "ldaps://ldap.example.com",
		BindDN: "cn=svc,dc=example,dc=com", BindPasswordEnv: "TEST_LDAP_BIND_PASSWORD",
		UserSearchBase: "ou=people,dc=example,dc=com", UserFilter: "(&(objectClass=person)(uid={username}))",
		SubjectAttribute: "entryUUID", Claims: map[string]string{"email": "mail", "name": "cn"},
	}
}

func newSearchMethod(t *testing.T, directory *fakeDirectory) *LDAPLoginMethod {
	t.Helper()
	t.Setenv("TEST_LDAP_BIND_PASSWORD", "service-secret")
	method, err := NewLDAPLoginMethod(searchConfig(), false)
	if err != nil {
		t.Fatal(err)
	}
	method.dial = directory.dial
	return method
}

func attempt(username, password string) LoginAttempt {
	return LoginAttempt{Values: map[string]string{"username": username, "password": password}}
}

func TestLDAPSearchModeSignsInAndReturnsClaims(t *testing.T) {
	directory := &fakeDirectory{
		entries:   []*ldap.Entry{aliceEntry()},
		passwords: map[string]string{"cn=svc,dc=example,dc=com": "service-secret", "uid=alice,ou=people,dc=example,dc=com": "s3cret"},
	}
	identity, err := newSearchMethod(t, directory).Authenticate(context.Background(), IdentityRequest{}, attempt("alice", "s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "b1f6-alice" || identity.Claims["email"] != "alice@example.com" || identity.Claims["name"] != "Alice A" {
		t.Fatalf("identity = %+v", identity)
	}
	if directory.binds[0][0] != "cn=svc,dc=example,dc=com" || directory.binds[1][0] != "uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("expected a service bind then the user's bind, got %v", directory.binds)
	}
	if directory.closed != directory.dialed {
		t.Fatalf("connection leaked: dialed %d closed %d", directory.dialed, directory.closed)
	}
}

func TestLDAPEscapesTheUsernameInTheFilter(t *testing.T) {
	directory := &fakeDirectory{passwords: map[string]string{"cn=svc,dc=example,dc=com": "service-secret"}}
	method := newSearchMethod(t, directory)
	for _, hostile := range []string{"*", "*)(uid=*", "alice)(|(uid=*", `a\b`, "al\x00ice"} {
		directory.searches = nil
		_, err := method.Authenticate(context.Background(), IdentityRequest{}, attempt(hostile, "x"))
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("%q: err = %v, want invalid credentials", hostile, err)
		}
		for _, search := range directory.searches {
			if strings.Contains(search.Filter, "(uid=*)") || strings.Contains(search.Filter, "*)(") || strings.Count(search.Filter, "(") != strings.Count(search.Filter, ")") {
				t.Fatalf("%q reached the filter unescaped: %s", hostile, search.Filter)
			}
		}
	}
	directory.searches = nil
	_, _ = method.Authenticate(context.Background(), IdentityRequest{}, attempt("*)(uid=*", "x"))
	if len(directory.searches) != 1 || !strings.Contains(directory.searches[0].Filter, `uid=\2a\29\28uid=\2a)`) {
		t.Fatalf("filter was not escaped as expected: %v", directory.searches)
	}
}

func TestLDAPNeverBindsWithAnEmptyPasswordOrName(t *testing.T) {
	directory := &fakeDirectory{entries: []*ldap.Entry{aliceEntry()}, passwords: map[string]string{"cn=svc,dc=example,dc=com": "service-secret"}}
	method := newSearchMethod(t, directory)
	for name, values := range map[string]LoginAttempt{
		"empty password":  attempt("alice", ""),
		"empty username":  attempt("", "pw"),
		"blank username":  attempt("   ", "pw"),
		"overlong name":   attempt(strings.Repeat("a", ldapMaxUsername+1), "pw"),
		"overlong pass":   attempt("alice", strings.Repeat("p", ldapMaxPassword+1)),
		"newline in name": attempt("ali\nce", "pw"),
		"NUL in password": attempt("alice", "p\x00w"),
		"missing fields":  {Values: map[string]string{}},
	} {
		_, err := method.Authenticate(context.Background(), IdentityRequest{}, values)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s: err = %v, want invalid credentials", name, err)
		}
	}
	if directory.dialed != 0 || len(directory.binds) != 0 {
		t.Fatalf("a malformed attempt reached the directory: dialed %d, binds %v", directory.dialed, directory.binds)
	}
}

func TestLDAPFailureModes(t *testing.T) {
	serviceOK := map[string]string{"cn=svc,dc=example,dc=com": "service-secret"}
	t.Run("unknown account", func(t *testing.T) {
		directory := &fakeDirectory{passwords: serviceOK}
		_, err := newSearchMethod(t, directory).Authenticate(context.Background(), IdentityRequest{}, attempt("ghost", "pw"))
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("wrong password", func(t *testing.T) {
		directory := &fakeDirectory{entries: []*ldap.Entry{aliceEntry()}, passwords: serviceOK}
		_, err := newSearchMethod(t, directory).Authenticate(context.Background(), IdentityRequest{}, attempt("alice", "nope"))
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("two entries match", func(t *testing.T) {
		directory := &fakeDirectory{entries: []*ldap.Entry{aliceEntry(), aliceEntry()}, passwords: serviceOK}
		_, err := newSearchMethod(t, directory).Authenticate(context.Background(), IdentityRequest{}, attempt("alice", "pw"))
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("err = %v, want a refusal", err)
		}
		if len(directory.binds) != 1 {
			t.Fatalf("bound as an ambiguous match: %v", directory.binds)
		}
	})
	t.Run("directory unreachable is not a wrong password", func(t *testing.T) {
		directory := &fakeDirectory{dialErr: errors.New("connection refused")}
		_, err := newSearchMethod(t, directory).Authenticate(context.Background(), IdentityRequest{}, attempt("alice", "pw"))
		if err == nil || errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("err = %v, want a non-credential error", err)
		}
	})
	t.Run("service account rejected is not a wrong password", func(t *testing.T) {
		directory := &fakeDirectory{passwords: map[string]string{}}
		_, err := newSearchMethod(t, directory).Authenticate(context.Background(), IdentityRequest{}, attempt("alice", "pw"))
		if err == nil || errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("err = %v, a broken service account must not look like a user's mistake", err)
		}
	})
	t.Run("bind server error is not a wrong password", func(t *testing.T) {
		directory := &fakeDirectory{
			entries: []*ldap.Entry{aliceEntry()}, passwords: serviceOK,
			bindErrFor: map[string]error{"uid=alice,ou=people,dc=example,dc=com": ldap.NewError(ldap.LDAPResultBusy, errors.New("busy"))},
		}
		_, err := newSearchMethod(t, directory).Authenticate(context.Background(), IdentityRequest{}, attempt("alice", "pw"))
		if err == nil || errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("entry lacks the subject attribute", func(t *testing.T) {
		bare := ldap.NewEntry("uid=alice,ou=people,dc=example,dc=com", map[string][]string{"mail": {"a@example.com"}})
		directory := &fakeDirectory{entries: []*ldap.Entry{bare}, passwords: map[string]string{"cn=svc,dc=example,dc=com": "service-secret", bare.DN: "pw"}}
		_, err := newSearchMethod(t, directory).Authenticate(context.Background(), IdentityRequest{}, attempt("alice", "pw"))
		if err == nil || errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("err = %v, a missing subject must fail closed", err)
		}
	})
}

func TestLDAPDirectBindEscapesTheDN(t *testing.T) {
	config := LDAPConfig{
		ID: "corp", Label: "Corp", URL: "ldaps://ldap.example.com",
		UserDNTemplate: "uid={username},ou=people,dc=example,dc=com", SubjectAttribute: "dn",
	}
	method, err := NewLDAPLoginMethod(config, false)
	if err != nil {
		t.Fatal(err)
	}
	directory := &fakeDirectory{passwords: map[string]string{"uid=alice,ou=people,dc=example,dc=com": "pw"}}
	method.dial = directory.dial
	identity, err := method.Authenticate(context.Background(), IdentityRequest{}, attempt("alice", "pw"))
	if err != nil || identity.Subject != "uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("identity %+v err %v", identity, err)
	}
	directory.binds = nil
	_, _ = method.Authenticate(context.Background(), IdentityRequest{}, attempt("x,ou=admins", "pw"))
	if len(directory.binds) != 1 || strings.Contains(directory.binds[0][0], "x,ou=admins,ou=people") {
		t.Fatalf("a comma in the username changed the DN structure: %v", directory.binds)
	}
	if len(directory.searches) != 0 {
		t.Fatal("subject_attribute dn needs no search")
	}
}

func TestLDAPConfigValidation(t *testing.T) {
	t.Setenv("TEST_LDAP_BIND_PASSWORD", "service-secret")
	mutate := func(edit func(*LDAPConfig)) LDAPConfig {
		config := searchConfig()
		edit(&config)
		return config
	}
	rejected := map[string]LDAPConfig{
		"plaintext without start_tls": mutate(func(c *LDAPConfig) { c.URL = "ldap://ldap.example.com" }),
		"start_tls on ldaps":          mutate(func(c *LDAPConfig) { c.StartTLS = true }),
		"http scheme":                 mutate(func(c *LDAPConfig) { c.URL = "http://ldap.example.com" }),
		"no host":                     mutate(func(c *LDAPConfig) { c.URL = "ldaps://" }),
		"both modes":                  mutate(func(c *LDAPConfig) { c.UserDNTemplate = "uid={username},dc=x" }),
		"neither mode":                mutate(func(c *LDAPConfig) { *c = LDAPConfig{ID: "corp", URL: c.URL, SubjectAttribute: "dn"} }),
		"search without bind dn":      mutate(func(c *LDAPConfig) { c.BindDN = "" }),
		"search without secret":       mutate(func(c *LDAPConfig) { c.BindPasswordEnv = "" }),
		"filter without placeholder":  mutate(func(c *LDAPConfig) { c.UserFilter = "(uid=alice)" }),
		"filter with two":             mutate(func(c *LDAPConfig) { c.UserFilter = "(|(uid={username})(mail={username}))" }),
		"no subject attribute":        mutate(func(c *LDAPConfig) { c.SubjectAttribute = " " }),
		"empty claim":                 mutate(func(c *LDAPConfig) { c.Claims = map[string]string{"email": ""} }),
		"template without user": mutate(func(c *LDAPConfig) {
			*c = LDAPConfig{ID: "corp", URL: c.URL, UserDNTemplate: "uid=alice,dc=x", SubjectAttribute: "dn"}
		}),
	}
	for name, config := range rejected {
		if _, err := NewLDAPLoginMethod(config, false); err == nil {
			t.Errorf("NewLDAPLoginMethod accepted: %s", name)
		}
	}
	if _, err := NewLDAPLoginMethod(mutate(func(c *LDAPConfig) { c.URL = "ldap://ldap.example.com"; c.StartTLS = true }), false); err != nil {
		t.Errorf("rejected ldap:// with start_tls: %v", err)
	}
	if _, err := NewLDAPLoginMethod(mutate(func(c *LDAPConfig) { c.URL = "ldap://ldap.example.com" }), true); err != nil {
		t.Errorf("plaintext should be allowed in insecure mode: %v", err)
	}
	t.Setenv("TEST_LDAP_BIND_PASSWORD", "")
	if _, err := NewLDAPLoginMethod(searchConfig(), false); err == nil {
		t.Error("an empty bind password was accepted")
	}
}

func TestLDAPCAFileMustContainACertificate(t *testing.T) {
	t.Setenv("TEST_LDAP_BIND_PASSWORD", "service-secret")
	path := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := searchConfig()
	config.CAFile = path
	if _, err := NewLDAPLoginMethod(config, false); err == nil {
		t.Fatal("a CA file with no certificates was accepted")
	}
	config.CAFile = path + ".missing"
	if _, err := NewLDAPLoginMethod(config, false); err == nil {
		t.Fatal("a missing CA file was accepted")
	}
}
