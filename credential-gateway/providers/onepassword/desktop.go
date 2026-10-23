package onepassword

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/secrets"
)

// desktop runs only on the machine owning the desktop app. 1Password controls
// approval/unlock reuse; this resolver cannot force a new password prompt.
type desktop struct {
	binary, account string
	timeout         time.Duration
}

func newDesktop(account string, timeout time.Duration) (*desktop, error) {
	binary, err := exec.LookPath("op")
	if err != nil {
		return nil, errors.New("desktop provider requires the local 1Password CLI")
	}
	return &desktop{binary: binary, account: account, timeout: timeout}, nil
}

func (*desktop) Ready() bool    { return true }
func (*desktop) String() string { return "OnePasswordDesktop(<redacted>)" }

// interactiveEnv excludes automation identities so a desktop selection cannot
// silently authenticate as a service account or a pre-established CLI session.
func interactiveEnv() []string {
	var out []string
	for _, v := range os.Environ() {
		name, _, _ := strings.Cut(v, "=")
		if name == "OP_SESSION" || name == "OP_SERVICE_ACCOUNT_TOKEN" || name == "OP_CONNECT_HOST" || name == "OP_CONNECT_TOKEN" || strings.HasPrefix(name, "OP_SESSION_") {
			continue
		}
		if name == "OP_BIOMETRIC_UNLOCK_ENABLED" {
			continue
		}
		out = append(out, v)
	}
	// This CLI switch enables desktop app integration, including the app's
	// password-unlock path. It does not require biometric authentication.
	return append(out, "OP_BIOMETRIC_UNLOCK_ENABLED=true")
}

func (d *desktop) Resolve(ctx context.Context, refs map[string]string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	out := make(map[string]string, len(refs))
	for name, ref := range refs {
		if !ValidReference(ref) {
			return nil, secrets.ErrFieldUnavailable
		}
		cmd := exec.CommandContext(ctx, d.binary, "read", "--account", d.account, "--no-newline", ref)
		cmd.Env = interactiveEnv()
		// The CLI's stderr may include item names. Never propagate it.
		value, err := cmd.Output()
		if err != nil {
			return nil, secrets.ErrProviderUnavailable
		}
		if len(value) == 0 || len(value) > 8192 {
			return nil, secrets.ErrFieldUnavailable
		}
		out[name] = string(value)
	}
	return out, nil
}
