package mappings

import (
	"os"
	"path/filepath"
	"testing"
)

var required = map[string][]string{"gitlab": {"username", "api_token"}}

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "m.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const good = `{"mappings":[{"issuer":"https://as","subject":"alice","service":"gitlab","fields":{
"username":"op://Vault/Item/username","api_token":"op://Vault/Item/Section/token"}}]}`

func TestLookupIsExactOnIssuerSubjectService(t *testing.T) {
	store, err := NewFileStore(write(t, good), required)
	if err != nil {
		t.Fatal(err)
	}
	m, err := store.Lookup("https://as", "alice", "gitlab")
	if err != nil || m == nil || m.Refs["api_token"] != "op://Vault/Item/Section/token" || m.Version == "" {
		t.Fatalf("lookup = %+v, %v", m, err)
	}
	for _, args := range [][3]string{{"https://other", "alice", "gitlab"}, {"https://as", "ALICE", "gitlab"}, {"https://as", "alice", "gerrit"}, {"https://as", "", "gitlab"}} {
		if m, err := store.Lookup(args[0], args[1], args[2]); m != nil || err != nil {
			t.Fatalf("%v matched: %+v %v", args, m, err)
		}
	}
}

func TestInvalidMappingsFailStartup(t *testing.T) {
	bad := map[string]string{
		"not json":        `nope`,
		"unknown field":   `{"mappings":[],"extra":1}`,
		"unknown service": `{"mappings":[{"issuer":"i","subject":"s","service":"nope","fields":{}}]}`,
		"missing scheme":  `{"mappings":[{"issuer":"i","subject":"s","service":"gitlab","fields":{"username":"Vault/Item","api_token":"op://V/I/f"}}]}`,
		"credential URL":  `{"mappings":[{"issuer":"i","subject":"s","service":"gitlab","fields":{"username":"https://user:pass@x/y/z","api_token":"op://V/I/f"}}]}`,
		"missing field":   `{"mappings":[{"issuer":"i","subject":"s","service":"gitlab","fields":{"username":"op://V/I/f"}}]}`,
		"empty subject":   `{"mappings":[{"issuer":"i","subject":"","service":"gitlab","fields":{"username":"op://V/I/f","api_token":"op://V/I/g"}}]}`,
		"duplicate":       `{"mappings":[` + entry() + `,` + entry() + `]}`,
	}
	for name, content := range bad {
		if _, err := NewFileStore(write(t, content), required); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := NewFileStore(filepath.Join(t.TempDir(), "absent.json"), required); err == nil {
		t.Fatal("missing file accepted")
	}
}

func entry() string {
	return `{"issuer":"i","subject":"s","service":"gitlab","fields":{"username":"op://V/I/f","api_token":"op://V/I/g"}}`
}

func TestVersionChangesWithReferencesOnly(t *testing.T) {
	a := version(map[string]string{"x": "op://V/I/a"})
	b := version(map[string]string{"x": "op://V/I/b"})
	c := version(map[string]string{"x": "op://V/I/a"})
	if a == b || a != c {
		t.Fatalf("versions: %s %s %s", a, b, c)
	}
}

func TestReloadAndFailClosed(t *testing.T) {
	path := write(t, good)
	store, err := NewFileStore(path, required)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"mappings":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if m, err := store.Lookup("https://as", "alice", "gitlab"); m != nil || err != nil {
		t.Fatalf("removal not visible: %+v %v", m, err)
	}
	if err := os.WriteFile(path, []byte(`broken-and-longer`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Lookup("https://as", "alice", "gitlab"); err != ErrUnavailable {
		t.Fatalf("invalid file must fail closed, got %v", err)
	}
	_ = os.Remove(path)
	if _, err := store.Lookup("https://as", "alice", "gitlab"); err != ErrUnavailable {
		t.Fatalf("missing file must fail closed, got %v", err)
	}
}
