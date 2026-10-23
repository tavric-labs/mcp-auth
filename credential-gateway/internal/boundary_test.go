package internal_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	module     = "github.com/Agent-Hellboy/mcp-auth"
	sdk        = module + "/auth-client/go"
	authServer = module + "/auth-server"
	opSDK      = "github.com/1password/onepassword-sdk-go"
)

func imports(t *testing.T, root string) map[string][]string {
	t.Helper()
	found := map[string][]string{}
	fset := token.NewFileSet()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			found[strings.Trim(spec.Path.Value, `"`)] = append(found[strings.Trim(spec.Path.Value, `"`)], path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// The plugin depends on the resource-server SDK, never on authorization-server code.
func TestPluginDoesNotImportAuthorizationServer(t *testing.T) {
	for path := range imports(t, "..") {
		if strings.HasPrefix(path, authServer) {
			t.Fatalf("plugin imports authorization-server code: %s", path)
		}
	}
	mod, _ := os.ReadFile("../go.mod")
	if strings.Contains(string(mod), authServer) {
		t.Fatal("plugin go.mod depends on the authorization server")
	}
}

// The 1Password SDK is confined to providers/onepassword.
func TestOnePasswordSDKIsConfinedToSecretsPackage(t *testing.T) {
	for _, file := range imports(t, "..")[opSDK] {
		if !strings.Contains(filepath.ToSlash(file), "providers/onepassword/") {
			t.Fatalf("1Password SDK imported outside providers/onepassword: %s", file)
		}
	}
}

// The gateway may import only its own module and the mcp-auth client SDK.
func TestPluginUsesOnlyTheSDKFromMcpAuth(t *testing.T) {
	for path := range imports(t, "..") {
		if strings.HasPrefix(path, module+"/") && !strings.HasPrefix(path, sdk) && !strings.HasPrefix(path, module+"/credential-gateway") {
			t.Fatalf("unexpected mcp-auth import %s", path)
		}
	}
}
