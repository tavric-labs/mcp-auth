package headers

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, raw ...Raw) []Spec {
	t.Helper()
	specs, err := Parse(raw, "svc")
	if err != nil {
		t.Fatal(err)
	}
	return specs
}

func TestDirectPrefixAndBasicTransforms(t *testing.T) {
	specs := mustParse(t,
		Raw{Name: "X-GitLab-PAT-Token", Type: Direct, Field: "api_token"},
		Raw{Name: "X-Api-Key", Type: Prefix, Field: "api_token", Prefix: "Bearer"},
		Raw{Name: "Authorization", Type: Basic, UsernameField: "email", PasswordField: "api_token"},
	)
	out, err := RenderAll(specs, map[string]string{"api_token": "tok", "email": "a@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"X-GitLab-PAT-Token": "tok",
		"X-Api-Key":          "Bearer tok",
		"Authorization":      "Basic YUBleGFtcGxlLmNvbTp0b2s=",
	}
	for k, v := range want {
		if out[k] != v {
			t.Fatalf("%s = %q, want %q", k, out[k], v)
		}
	}
	if got := strings.Join(RequiredFields(specs), ","); got != "api_token,email" {
		t.Fatalf("required fields = %s", got)
	}
}

func TestInvalidHeaderMaterialIsRejected(t *testing.T) {
	spec := mustParse(t, Raw{Name: "X-Token", Type: Direct, Field: "t"})[0]
	for name, value := range map[string]string{
		"CR": "a\rb", "LF": "a\nb", "CRLF injection": "a\r\nX-Evil: 1", "NUL": "a\x00b", "DEL": "a\x7fb",
		"non-ascii": "café", "empty": "", "leading space": " a", "trailing space": "a ",
		"too long": strings.Repeat("a", maxValue+1), "other control": "a\x01b",
	} {
		if _, err := spec.Render(map[string]string{"t": value}); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := spec.Render(map[string]string{}); err == nil {
		t.Fatal("missing field accepted")
	}
	if _, err := spec.Render(map[string]string{"t": "tab\tok"}); err != nil {
		t.Fatalf("tab is legal: %v", err)
	}
}

func TestBasicRejectsColonAndControlsInParts(t *testing.T) {
	spec := mustParse(t, Raw{Name: "Authorization", Type: Basic, UsernameField: "u", PasswordField: "p"})[0]
	for _, fields := range []map[string]string{
		{"u": "a:b", "p": "x"}, {"u": "a", "p": "x\r\ny"}, {"u": "a\nb", "p": "x"}, {"u": "a"}, {"p": "x"},
	} {
		if _, err := spec.Render(fields); err == nil {
			t.Fatalf("accepted %v", fields)
		}
	}
}

func TestParseRejectsUnsafeConfiguration(t *testing.T) {
	bad := map[string]Raw{
		"forbidden host":       {Name: "Host", Type: Direct, Field: "f"},
		"forbidden cookie":     {Name: "Cookie", Type: Direct, Field: "f"},
		"forbidden session":    {Name: "Mcp-Session-Id", Type: Direct, Field: "f"},
		"forwarded family":     {Name: "X-Forwarded-Host", Type: Direct, Field: "f"},
		"bad name":             {Name: "X Bad", Type: Direct, Field: "f"},
		"unknown type":         {Name: "X-A", Type: "template", Field: "f"},
		"free-form prefix":     {Name: "X-A", Type: Prefix, Field: "f", Prefix: "{{secret}}"},
		"prefix on direct":     {Name: "X-A", Type: Direct, Field: "f", Prefix: "Bearer"},
		"basic with field":     {Name: "Authorization", Type: Basic, Field: "f", UsernameField: "u", PasswordField: "p"},
		"bad field name":       {Name: "X-A", Type: Direct, Field: "../etc"},
		"basic missing fields": {Name: "Authorization", Type: Basic, UsernameField: "u"},
	}
	for name, raw := range bad {
		if _, err := Parse([]Raw{raw}, "svc"); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := Parse([]Raw{{Name: "X-A", Type: Direct, Field: "f"}, {Name: "x-a", Type: Direct, Field: "g"}}, "svc"); err == nil {
		t.Fatal("duplicate header (case-insensitive) accepted")
	}
	if _, err := Parse(nil, "svc"); err == nil {
		t.Fatal("empty header list accepted")
	}
}
