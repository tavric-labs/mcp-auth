package onepassword

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/Agent-Hellboy/mcp-auth/credential-gateway/internal/secrets"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const fakeToken = "ops_FAKE_SERVICE_ACCOUNT_TOKEN_FOR_TESTS"

type fakeAPI struct {
	resolve func(ctx context.Context, ref string) (string, error)
}

func (f fakeAPI) Resolve(ctx context.Context, ref string) (string, error) { return f.resolve(ctx, ref) }

func newResolver(t *testing.T, api secretsAPI, timeout time.Duration) (*OnePassword, *atomic.Int32) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(fakeToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o, err := NewOnePassword(path, "plugin", "test", timeout)
	if err != nil {
		t.Fatal(err)
	}
	var builds atomic.Int32
	o.factory = func(context.Context, string, string, string) (secretsAPI, error) {
		builds.Add(1)
		if api == nil {
			return nil, errors.New("authentication failed for " + fakeToken)
		}
		return api, nil
	}
	return o, &builds
}

func TestResolveReturnsValuesAndReusesClient(t *testing.T) {
	o, builds := newResolver(t, fakeAPI{func(_ context.Context, ref string) (string, error) { return "value-of-" + ref, nil }}, time.Second)
	for range 2 {
		got, err := o.Resolve(context.Background(), map[string]string{"u": "op://V/I/u", "p": "op://V/I/p"})
		if err != nil || got["u"] != "value-of-op://V/I/u" || got["p"] != "value-of-op://V/I/p" {
			t.Fatalf("%v %v", got, err)
		}
	}
	if builds.Load() != 1 {
		t.Fatalf("client built %d times", builds.Load())
	}
}

func TestTokenNeverAppearsInPrintsLogsOrErrors(t *testing.T) {
	o, _ := newResolver(t, nil, time.Second)
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)

	_, err := o.Resolve(context.Background(), map[string]string{"u": "op://V/I/u"})
	if !errors.Is(err, secrets.ErrProviderUnavailable) {
		t.Fatalf("err = %v", err)
	}
	slog.Info("resolver", "r", o)
	for _, out := range []string{
		fmt.Sprint(o), fmt.Sprintf("%v %+v %#v %s", o, o, o, o), logs.String(), err.Error(), fmt.Sprint(errors.Unwrap(err)),
	} {
		if strings.Contains(out, fakeToken) || strings.Contains(out, "FAKE_SERVICE") {
			t.Fatalf("token leaked: %s", out)
		}
	}
	if !o.Ready() {
		t.Fatal("should be ready once the token is loaded")
	}
}

func TestFieldFailureIsRedactedAndCancelsSiblings(t *testing.T) {
	cancelled := make(chan struct{})
	api := fakeAPI{func(ctx context.Context, ref string) (string, error) {
		if strings.HasSuffix(ref, "/bad") {
			return "", errors.New("secret detail: vault Org-MCP item gitlab-alice")
		}
		select {
		case <-ctx.Done():
			close(cancelled)
			return "", ctx.Err()
		case <-time.After(5 * time.Second):
			return "late", nil
		}
	}}
	o, _ := newResolver(t, api, 3*time.Second)
	start := time.Now()
	_, err := o.Resolve(context.Background(), map[string]string{"a": "op://V/I/bad", "b": "op://V/I/slow"})
	if !errors.Is(err, secrets.ErrFieldUnavailable) || strings.Contains(err.Error(), "Org-MCP") {
		t.Fatalf("err = %v", err)
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("sibling work was not cancelled")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("failure did not return promptly")
	}
}

func TestTimeoutIsProviderUnavailable(t *testing.T) {
	o, _ := newResolver(t, fakeAPI{func(ctx context.Context, _ string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}}, 100*time.Millisecond)
	if _, err := o.Resolve(context.Background(), map[string]string{"a": "op://V/I/a"}); !errors.Is(err, secrets.ErrProviderUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestEmptyValueIsRejectedAndFailedAuthIsRetried(t *testing.T) {
	o, _ := newResolver(t, fakeAPI{func(context.Context, string) (string, error) { return "", nil }}, time.Second)
	if _, err := o.Resolve(context.Background(), map[string]string{"a": "op://V/I/a"}); !errors.Is(err, secrets.ErrFieldUnavailable) {
		t.Fatalf("err = %v", err)
	}
	o, builds := newResolver(t, nil, time.Second)
	for range 2 {
		_, _ = o.Resolve(context.Background(), map[string]string{"a": "op://V/I/a"})
	}
	if builds.Load() != 2 {
		t.Fatalf("a failed authentication must not be cached; builds=%d", builds.Load())
	}
}

func TestReadSecretFile(t *testing.T) {
	dir := t.TempDir()
	empty, ok := filepath.Join(dir, "empty"), filepath.Join(dir, "ok")
	_ = os.WriteFile(empty, []byte(" \n"), 0o600)
	_ = os.WriteFile(ok, []byte("  v \n"), 0o600)
	if v, err := secrets.ReadSecretFile(ok, "x"); err != nil || v != "v" {
		t.Fatal(v, err)
	}
	for _, p := range []string{empty, filepath.Join(dir, "missing")} {
		if _, err := secrets.ReadSecretFile(p, "x"); err == nil {
			t.Fatal("accepted", p)
		}
	}
	if _, err := NewOnePassword(empty, "n", "v", time.Second); err == nil {
		t.Fatal("empty token accepted")
	}
}
