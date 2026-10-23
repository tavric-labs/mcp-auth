package onepassword

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDesktopUsesAppIntegrationAndExcludesAutomationIdentities(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
test "$OP_BIOMETRIC_UNLOCK_ENABLED" = true || exit 21
test -z "$OP_SERVICE_ACCOUNT_TOKEN$OP_CONNECT_TOKEN$OP_CONNECT_HOST$OP_SESSION$OP_SESSION_example" || exit 22
test "$1" = read && test "$2" = --account && test "$3" = test-account && test "$4" = --no-newline && test "$5" = op://Vault/Item/password || exit 23
printf 'fixture-secret'
`
	if err := os.WriteFile(filepath.Join(dir, "op"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	for _, name := range []string{"OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN", "OP_CONNECT_HOST", "OP_SESSION", "OP_SESSION_example"} {
		t.Setenv(name, "must-not-be-used")
	}
	t.Setenv("OP_BIOMETRIC_UNLOCK_ENABLED", "false")
	p, err := New(json.RawMessage(`{"mode":"desktop","account":"test-account"}`), "test")
	if err != nil {
		t.Fatal(err)
	}
	values, err := p.Resolve(context.Background(), map[string]string{"password": "op://Vault/Item/password"})
	if err != nil || values["password"] != "fixture-secret" {
		t.Fatal("desktop request did not use the configured account/app integration", err)
	}
}

func TestProviderModesAndReferencesFailClosed(t *testing.T) {
	for _, raw := range []string{
		`{"mode":"service_account","account":"wrong"}`,
		`{"mode":"desktop","account":"a","service_account_token_file":"x"}`,
		`{"mode":"desktop"}`, `{"mode":"unknown"}`, `{"mode":"service_account","service_account_token_file":"/absent"}`,
		`{"mode":"desktop","account":"a","unknown":true}`,
	} {
		if _, err := New(json.RawMessage(raw), "test"); err == nil {
			t.Fatal("invalid provider options accepted")
		}
	}
	for _, ref := range []string{"op://V/I", "https://V/I/f", "op://V/I/f?query", "op://V/I/f\n"} {
		if ValidReference(ref) {
			t.Fatal("invalid reference accepted")
		}
	}
	if !ValidReference("op://V/I/section/field") {
		t.Fatal("valid complete reference rejected")
	}
	if strings.Contains((&desktop{}).String(), "account") {
		t.Fatal("desktop formatting exposes account")
	}
}
