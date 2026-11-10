package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// clientMetadataTimeout bounds an OAuth Client ID Metadata Document fetch.
// The URL is caller-supplied, so a slow host must not stall /authorize.
const clientMetadataTimeout = 5 * time.Second

// clientMetadataError is a rejected Client ID Metadata Document. Error is the
// OAuth error code; detail is safe to put in error_description and the audit log.
type clientMetadataError struct{ detail string }

func (e *clientMetadataError) Error() string { return "invalid_client" }

// errUnknownClient is returned when /authorize names a client_id that is not
// registered and is not a Client ID Metadata Document URL.
var errUnknownClient = errors.New("unknown client")

func isClientIDURL(clientID string) bool {
	parsed, err := url.Parse(clientID)
	if err != nil || parsed.Host == "" {
		return false
	}
	return parsed.Scheme == "https" || parsed.Scheme == "http"
}

// validateClientMetadataURL applies the SSRF limits on a client_id URL:
// HTTPS only, no credentials, no fragment, and no non-loopback IP literal.
// A hostname is not resolved, so a name that points at a private address is
// not rejected here.
func validateClientMetadataURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Fragment != "" || parsed.User != nil {
		return errors.New("client_id metadata URL must be https without credentials or a fragment")
	}
	if ip := net.ParseIP(parsed.Hostname()); ip != nil && !ip.IsLoopback() {
		return errors.New("client_id metadata URL must not use a non-loopback IP address")
	}
	return nil
}

// allowedMetadataHost applies the operator's host allowlist when one is set.
// With no allowlist any public host is fetchable, which is what the Client ID
// Metadata Document draft intends; a deployment that wants a closed set names
// it in MCP_AUTH_CLIENT_ID_METADATA_HOSTS.
func (s *Server) allowedMetadataHost(clientID string) error {
	if len(s.Config.ClientIDMetadataHosts) == 0 {
		return nil
	}
	parsed, err := url.Parse(clientID)
	if err != nil {
		return errors.New("client_id metadata URL is not parseable")
	}
	host := strings.ToLower(parsed.Hostname())
	for _, allowed := range s.Config.ClientIDMetadataHosts {
		if host == strings.ToLower(strings.TrimSpace(allowed)) {
			return nil
		}
	}
	return errors.New("client_id metadata host is not allowed")
}

func (s *Server) metadataHTTPClient() *http.Client {
	if s.ClientMetadataClient != nil {
		return s.ClientMetadataClient
	}
	if s.Config.LocalDevelopment {
		return loopbackClientMetadataClient
	}
	return defaultClientMetadataClient
}

var (
	defaultClientMetadataClient  = newClientMetadataClient(false)
	loopbackClientMetadataClient = newClientMetadataClient(true)
)

func newClientMetadataClient(allowLoopback bool) *http.Client {
	return &http.Client{
		Timeout: clientMetadataTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{DialContext: publicOnlyDialContext(allowLoopback)},
	}
}

// publicOnlyDialContext resolves the host itself and refuses to connect to an
// address that is not public unicast.
//
// validateClientMetadataURL cannot cover this: it never resolves, so a
// hostname pointing at a private range passes it. Checking at dial time means
// the decision is made about the address actually being connected to, which
// also closes the rebinding window between validation and connection. Every
// resolved address must be allowed, so a record set mixing a public and a
// private answer is refused rather than raced.
// lookupIPAddr resolves the metadata host. It is a variable only so tests can
// supply a record set; production always uses the system resolver.
var lookupIPAddr = net.DefaultResolver.LookupIPAddr

func publicOnlyDialContext(allowLoopback bool) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addrs, err := lookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(addrs) == 0 {
			return nil, errors.New("client metadata host did not resolve")
		}
		ips := make([]net.IP, 0, len(addrs))
		for _, addr := range addrs {
			if !dialableIP(addr.IP, allowLoopback) {
				return nil, errors.New("client metadata host resolves to a blocked address")
			}
			ips = append(ips, addr.IP)
		}
		return dialVetted(ctx, network, port, ips, dialer.DialContext, metadataDialAttemptTimeout, metadataDialStagger)
	}
}

const (
	// metadataDialAttemptTimeout bounds one address so a family with no route
	// cannot spend the whole clientMetadataTimeout.
	metadataDialAttemptTimeout = 2 * time.Second
	// metadataDialStagger is the RFC 8305 connection attempt delay.
	metadataDialStagger = 250 * time.Millisecond
)

// orderHappyEyeballs puts IPv4 first and alternates families after that
// (RFC 8305 section 4), keeping the resolver's order within a family.
func orderHappyEyeballs(ips []net.IP) []net.IP {
	var v4, v6 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	out := make([]net.IP, 0, len(ips))
	for i := 0; i < len(v4) || i < len(v6); i++ {
		if i < len(v4) {
			out = append(out, v4[i])
		}
		if i < len(v6) {
			out = append(out, v6[i])
		}
	}
	return out
}

// dialVetted connects to one of ips, which the caller has already checked with
// dialableIP; it dials only those addresses and never resolves a name. Attempts
// start one per stagger, or immediately when the previous one failed, each
// bounded by perAttempt. The first success wins and the others are cancelled.
func dialVetted(ctx context.Context, network, port string, ips []net.IP, dial func(context.Context, string, string) (net.Conn, error), perAttempt, stagger time.Duration) (net.Conn, error) {
	ordered := orderHappyEyeballs(ips)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, len(ordered))
	launch := func(ip net.IP) {
		go func() {
			attemptCtx, attemptCancel := context.WithTimeout(ctx, perAttempt)
			defer attemptCancel()
			conn, err := dial(attemptCtx, network, net.JoinHostPort(ip.String(), port))
			results <- result{conn, err}
		}()
	}
	var firstErr error
	started, finished := 0, 0
	timer := time.NewTimer(0)
	defer timer.Stop()
	for finished < len(ordered) {
		select {
		case <-timer.C:
			if started < len(ordered) {
				launch(ordered[started])
				started++
				timer.Reset(stagger)
			}
		case res := <-results:
			finished++
			if res.err == nil {
				// Drain the losers so a late success does not leak a connection.
				go func(remaining int) {
					for ; remaining > 0; remaining-- {
						if late := <-results; late.conn != nil {
							late.conn.Close()
						}
					}
				}(len(ordered) - finished)
				return res.conn, nil
			}
			if firstErr == nil {
				firstErr = res.err
			}
			if started < len(ordered) && started == finished {
				// Everything in flight failed: try the next address now.
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(0)
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, firstErr
}

// dialableIP reports whether one resolved address may be fetched. net.IP's own
// helpers miss carrier NAT, IPv6 unique-local, and the reserved ranges that
// cloud metadata services and internal fabrics sit behind.
func dialableIP(ip net.IP, allowLoopback bool) bool {
	if ip.IsLoopback() {
		return allowLoopback
	}
	if ip.IsUnspecified() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 100 && ip4[1]&0xc0 == 64: // 100.64.0.0/10 carrier NAT
			return false
		case ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0: // 192.0.0.0/24 protocol assignments
			return false
		case ip4[0] == 198 && ip4[1]&0xfe == 18: // 198.18.0.0/15 benchmarking
			return false
		}
	} else if len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc { // fc00::/7 unique local
		return false
	}
	return ip.IsGlobalUnicast()
}

// fetchClientMetadata loads an OAuth Client ID Metadata Document
// (draft-ietf-oauth-client-id-metadata-document-00). Dynamic client
// registration stays available for clients that are not identified by a URL.
// Only token_endpoint_auth_method "none" is accepted: a metadata document
// does not establish a client secret with this server.
func (s *Server) fetchClientMetadata(ctx context.Context, clientID string) (Client, error) {
	if err := validateClientMetadataURL(clientID); err != nil {
		return Client{}, &clientMetadataError{detail: err.Error()}
	}
	if err := s.allowedMetadataHost(clientID); err != nil {
		return Client{}, &clientMetadataError{detail: err.Error()}
	}
	ctx, cancel := context.WithTimeout(ctx, clientMetadataTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return Client{}, &clientMetadataError{detail: "client metadata URL is not fetchable"}
	}
	request.Header.Set("Accept", "application/json")
	// The URL is the client_id, so this flow is the feature rather than a
	// defect: a Client ID Metadata Document is fetched from the address the
	// client names. It is safe because of the three guards above and below -
	// ClientIDMetadataEnabled gates it off when explicitly disabled, allowedMetadataHost
	// applies the operator's host list, and metadataHTTPClient dials through
	// publicOnlyDialContext, which resolves first and refuses anything that
	// is not public unicast. Delete any of those and this suppression stops
	// being true: see TestClientIDMetadataEnabledByDefault,
	// TestClientIDMetadataHostAllowlist, TestDialableIP and
	// TestClientMetadataFetchRefusesPrivateHostname.
	response, err := s.metadataHTTPClient().Do(request) // codeql[go/request-forgery]
	if err != nil {
		return Client{}, &clientMetadataError{detail: "client metadata document could not be fetched"}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Client{}, &clientMetadataError{detail: fmt.Sprintf("client metadata document returned HTTP %d", response.StatusCode)}
	}
	var document struct {
		ClientID          string   `json:"client_id"`
		ClientName        string   `json:"client_name"`
		RedirectURIs      []string `json:"redirect_uris"`
		TokenEndpointAuth string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxJWKSResponseBytes)).Decode(&document); err != nil {
		return Client{}, &clientMetadataError{detail: "client metadata document is not valid JSON"}
	}
	if document.ClientID != clientID {
		return Client{}, &clientMetadataError{detail: "client metadata client_id does not match the requested URL"}
	}
	if len(document.RedirectURIs) == 0 {
		return Client{}, &clientMetadataError{detail: "client metadata document has no redirect_uris"}
	}
	for _, redirectURI := range document.RedirectURIs {
		if !validRedirect(redirectURI) {
			return Client{}, &clientMetadataError{detail: "client metadata document has an invalid redirect_uri"}
		}
	}
	authMethod := document.TokenEndpointAuth
	if authMethod == "" {
		authMethod = "none"
	}
	if authMethod != "none" {
		return Client{}, &clientMetadataError{detail: "client metadata documents must use token_endpoint_auth_method none"}
	}
	return Client{
		ID:                clientID,
		Name:              document.ClientName,
		RedirectURIs:      document.RedirectURIs,
		TokenEndpointAuth: authMethod,
	}, nil
}

func (s *Server) resolveClient(ctx context.Context, clientID string) (Client, error) {
	if strings.TrimSpace(clientID) == "" {
		return Client{}, errUnknownClient
	}
	if isClientIDURL(clientID) {
		if !s.Config.ClientIDMetadataEnabled {
			// Not enabled, so a URL is just an unknown client rather than a
			// fetch. Reported as unknown so probing cannot tell the feature
			// apart from an unregistered client id.
			return Client{}, errUnknownClient
		}
		return s.fetchClientMetadata(ctx, clientID)
	}
	client, err := s.Store.GetClient(clientID)
	if err != nil {
		return Client{}, errUnknownClient
	}
	return client, nil
}
