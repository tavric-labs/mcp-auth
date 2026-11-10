package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestClientMetadataURLRejected(t *testing.T) {
	rejected := []string{
		"http://127.0.0.1/client.json",
		"https://user:pw@client.example.com/client.json",
		"https://client.example.com/client.json#frag",
		"https://10.1.2.3/client.json",
		"https://169.254.169.254/latest/meta-data",
	}
	for _, value := range rejected {
		if err := validateClientMetadataURL(value); err == nil {
			t.Errorf("validateClientMetadataURL(%q) accepted an unsafe URL", value)
		}
	}
	if err := validateClientMetadataURL("https://client.example.com/oauth/client.json"); err != nil {
		t.Fatalf("https hostname: %v", err)
	}
	if err := validateClientMetadataURL("https://127.0.0.1/client.json"); err != nil {
		t.Fatalf("loopback IP literal: %v", err)
	}
}

func TestClientMetadataDocumentAuthorize(t *testing.T) {
	redirectURI := "http://127.0.0.1:39999/callback"
	var clientID string
	var accept string
	metadata := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/client.json" {
			http.NotFound(w, r)
			return
		}
		accept = r.Header.Get("Accept")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":                  clientID,
			"client_name":                "native",
			"redirect_uris":              []string{redirectURI},
			"token_endpoint_auth_method": "none",
		})
	}))
	defer metadata.Close()
	clientID = metadata.URL + "/client.json"

	instance := testServer(t)
	client := metadata.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	instance.ClientMetadataClient = client
	instance.Config.ClientIDMetadataEnabled = true

	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
		"resource":              {instance.Config.Resources[0]},
	}
	request := httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("CIMD authorize = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if accept != "application/json" {
		t.Fatalf("client metadata Accept = %q, want application/json", accept)
	}

	query.Set("redirect_uri", "http://127.0.0.1:39999/other")
	rejected := httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	rejectedRecorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(rejectedRecorder, rejected)
	if rejectedRecorder.Code != http.StatusBadRequest {
		t.Fatalf("redirect outside the metadata document = %d, want 400: %s", rejectedRecorder.Code, rejectedRecorder.Body.String())
	}

	query.Set("client_id", "http://127.0.0.1/client.json")
	query.Set("redirect_uri", redirectURI)
	badScheme := httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	badSchemeRecorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(badSchemeRecorder, badScheme)
	if badSchemeRecorder.Code != http.StatusBadRequest || !strings.Contains(badSchemeRecorder.Body.String(), "invalid_client") {
		t.Fatalf("http client_id = %d %s, want 400 invalid_client", badSchemeRecorder.Code, badSchemeRecorder.Body.String())
	}
}

// TestDialableIP covers the dial-time SSRF gate. validateClientMetadataURL
// never resolves a hostname, so this is the only check that sees the address a
// client_id metadata fetch would actually connect to.
func TestDialableIP(t *testing.T) {
	blocked := []string{
		"10.1.2.3",        // RFC 1918
		"172.16.0.1",      // RFC 1918
		"192.168.1.1",     // RFC 1918
		"169.254.169.254", // link-local, cloud metadata
		"100.64.0.1",      // carrier NAT
		"192.0.0.1",       // protocol assignments
		"198.18.0.1",      // benchmarking
		"0.0.0.0",         // unspecified
		"224.0.0.1",       // multicast
		"fc00::1",         // IPv6 unique local
		"fe80::1",         // IPv6 link local
		"::",              // IPv6 unspecified
	}
	for _, value := range blocked {
		ip := net.ParseIP(value)
		if ip == nil {
			t.Fatalf("test fixture %q is not an IP", value)
		}
		if dialableIP(ip, false) {
			t.Errorf("dialableIP(%s) allowed a blocked address", value)
		}
		if dialableIP(ip, true) {
			t.Errorf("dialableIP(%s, allowLoopback) allowed a blocked address", value)
		}
	}
	for _, value := range []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"} {
		if !dialableIP(net.ParseIP(value), false) {
			t.Errorf("dialableIP(%s) rejected a public address", value)
		}
	}
	// Loopback is fetchable only for local development, which is how the
	// httptest-backed tests above reach their metadata server.
	loopback := net.ParseIP("127.0.0.1")
	if dialableIP(loopback, false) {
		t.Error("dialableIP allowed loopback outside local development")
	}
	if !dialableIP(loopback, true) {
		t.Error("dialableIP rejected loopback in local development")
	}
}

func TestClientMetadataFetchRefusesPrivateHostname(t *testing.T) {
	instance := testServer(t)
	instance.ClientMetadataClient = nil
	instance.Config.LocalDevelopment = false
	instance.Config.ClientIDMetadataEnabled = true
	// localtest.me and its subdomains resolve to 127.0.0.1, so this is a
	// hostname that validateClientMetadataURL accepts and only the dialer can
	// refuse. A resolver failure is also a refusal, which is the safe outcome.
	_, err := instance.fetchClientMetadata(context.Background(), "https://私.localtest.me/client.json")
	if err == nil {
		t.Fatal("fetchClientMetadata accepted a hostname resolving to loopback")
	}
	var rejected *clientMetadataError
	if !errors.As(err, &rejected) {
		t.Fatalf("expected a clientMetadataError, got %T: %v", err, err)
	}
}

// TestClientIDMetadataEnabledByDefault covers the default feature gate. CIMD
// is advertised for MCP clients; operators can explicitly disable it.
func TestClientIDMetadataEnabledByDefault(t *testing.T) {
	t.Setenv("MCP_AUTH_CLIENT_ID_METADATA_ENABLED", "")
	if !ConfigFromEnv().ClientIDMetadataEnabled {
		t.Fatal("ClientIDMetadataEnabled should default to true from environment config")
	}
}

func TestClientIDMetadataCanBeDisabled(t *testing.T) {
	t.Setenv("MCP_AUTH_CLIENT_ID_METADATA_ENABLED", "false")
	if ConfigFromEnv().ClientIDMetadataEnabled {
		t.Fatal("ClientIDMetadataEnabled should honor explicit false")
	}
}

func TestClientIDMetadataHostAllowlist(t *testing.T) {
	instance := testServer(t)
	instance.Config.ClientIDMetadataEnabled = true
	instance.Config.ClientIDMetadataHosts = []string{"client.example.com"}
	fetched := false
	instance.ClientMetadataClient = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		fetched = true
		return nil, errors.New("must not be called")
	})}
	if _, err := instance.fetchClientMetadata(context.Background(), "https://other.example.com/client.json"); err == nil {
		t.Fatal("fetchClientMetadata accepted a host outside the allowlist")
	}
	if fetched {
		t.Fatal("a host outside the allowlist was still fetched")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func withResolver(t *testing.T, ips ...string) {
	t.Helper()
	previous := lookupIPAddr
	t.Cleanup(func() { lookupIPAddr = previous })
	lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		var out []net.IPAddr
		for _, value := range ips {
			out = append(out, net.IPAddr{IP: net.ParseIP(value)})
		}
		return out, nil
	}
}

func listenLoopback(t *testing.T) (port string) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	_, port, _ = net.SplitHostPort(listener.Addr().String())
	return port
}

// A dual-stack host whose first answer is an unreachable family must still
// connect over the other family: this is the chatgpt.com failure, where the
// pod has no IPv6 route and only the first address used to be tried.
func TestPublicOnlyDialFallsBackWhenFirstAddressUnreachable(t *testing.T) {
	port := listenLoopback(t)
	withResolver(t, "::1", "127.0.0.1")
	dial := publicOnlyDialContext(true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp", net.JoinHostPort("dual.example", port))
	if err != nil {
		t.Fatalf("dial did not fall back to the reachable address: %v", err)
	}
	conn.Close()
}

// A first address that blackholes must not consume the whole deadline.
func TestDialVettedPerAddressTimeoutLetsSecondAddressSucceed(t *testing.T) {
	blackhole := net.ParseIP("2001:db8::1")
	good := net.ParseIP("192.0.2.1")
	var attempted []string
	var mu sync.Mutex
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		mu.Lock()
		attempted = append(attempted, host)
		mu.Unlock()
		if host == blackhole.String() {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		client, server := net.Pipe()
		t.Cleanup(func() { server.Close() })
		return client, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := dialVetted(ctx, "tcp", "443", []net.IP{blackhole, good}, dial, 300*time.Millisecond, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("fallback took %s", elapsed)
	}
	for _, host := range attempted {
		if host != blackhole.String() && host != good.String() {
			t.Fatalf("dialed unvetted address %s", host)
		}
	}
}

func TestDialVettedPrefersIPv4AndInterleaves(t *testing.T) {
	ips := []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}
	got := orderHappyEyeballs(ips)
	want := []string{"192.0.2.1", "2001:db8::1", "192.0.2.2", "2001:db8::2"}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("order[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestDialVettedAllFail(t *testing.T) {
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") }
	_, err := dialVetted(context.Background(), "tcp", "443", []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}, dial, time.Second, time.Millisecond)
	if err == nil {
		t.Fatal("expected an error when every address fails")
	}
}

// One blocked address in the record set refuses the whole set, even when the
// other address is public and reachable.
func TestPublicOnlyDialRefusesMixedPublicAndPrivate(t *testing.T) {
	withResolver(t, "93.184.216.34", "10.0.0.5")
	dial := publicOnlyDialContext(false)
	if conn, err := dial(context.Background(), "tcp", "mixed.example:443"); err == nil {
		conn.Close()
		t.Fatal("dial accepted a record set containing a private address")
	}
}
