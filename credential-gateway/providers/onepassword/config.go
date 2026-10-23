package onepassword

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/secrets"
)

var referencePattern = regexp.MustCompile(`^op://[^/\s?#]+/[^/\s?#]+(/[^/\s?#]+){1,2}$`)

// ValidReference confines this provider to complete, explicitly approved fields.
func ValidReference(ref string) bool { return referencePattern.MatchString(ref) }

// New constructs the explicit provider mode. No environment-token fallback exists.
func New(raw json.RawMessage, version string) (secrets.Resolver, error) {
	var options struct {
		Mode                    string  `json:"mode"`
		ServiceAccountTokenFile string  `json:"service_account_token_file"`
		Account                 string  `json:"account"`
		IntegrationName         string  `json:"integration_name"`
		TimeoutSeconds          float64 `json:"timeout_seconds"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&options) != nil {
		return nil, errors.New("invalid 1Password provider options")
	}
	if options.TimeoutSeconds == 0 {
		options.TimeoutSeconds = 30
	}
	if options.TimeoutSeconds < .1 || options.TimeoutSeconds > 120 {
		return nil, errors.New("provider timeout must be between 0.1 and 120 seconds")
	}
	timeout := time.Duration(options.TimeoutSeconds * float64(time.Second))
	if options.IntegrationName == "" {
		options.IntegrationName = "mcp-auth-credential-gateway"
	}
	switch options.Mode {
	case "service_account":
		if options.Account != "" || options.ServiceAccountTokenFile == "" {
			return nil, errors.New("service_account mode requires only service_account_token_file")
		}
		return NewOnePassword(options.ServiceAccountTokenFile, options.IntegrationName, version, timeout)
	case "desktop":
		if options.ServiceAccountTokenFile != "" || options.Account == "" {
			return nil, errors.New("desktop mode requires only account and a local 1Password app/CLI")
		}
		return newDesktop(options.Account, timeout)
	default:
		return nil, errors.New("1Password mode must be service_account or desktop")
	}
}
