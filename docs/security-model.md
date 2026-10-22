# Security model

What this server guarantees, and what your deployment still has to do.

## Authorization flow

- Authorization Code + PKCE (`S256`) is required for all authorization-code clients; there is no
  implicit or password grant.
- `/authorize` matches a dynamically registered `redirect_uri` exactly.
  Registration accepts the RFC 8252 shapes — HTTPS, loopback `http`, and
  private-use schemes — which is what desktop MCP clients use. The connector
  allowlist matches loopback `http` by scheme, hostname, and path and ignores
  the port; `http://127.0.0.1:*`, `http://localhost:*`, and `http://[::1]:*`
  match any path on that host. See
  [the deviation note](auth-server.md#client-registration-and-consent).
- A `client_id` that is an HTTPS URL is fetched as a Client ID Metadata
  Document. The fetch does not follow redirects, rejects credentialed URLs and
  non-loopback IP literals. Its transport also resolves and checks every address
  at dial time, rejecting private, link-local and other blocked ranges, including
  mixed public/private DNS answers. Local-development mode permits loopback
  addresses for tests. Dynamic registration still works.
- Registration failures and an `/authorize` for an unknown `client_id` are
  audit events. Redirect URIs are logged; tokens, secrets, codes, keys, and
  assertions are not.
- The token-exchange grant requires the caller to authenticate as a
  pre-registered resource server (RFC 7523 `private_key_jwt`) and to present a
  `subject_token` this server itself issued. It is not an open relay to the
  upstream connector.
- The consent page names the client and labels a dynamically registered
  client's name unverified, because the application supplied `client_name`
  and this server has not verified it. The consent document and the
  expired-consent response (HTTP 400) send `Content-Security-Policy`
  (`default-src 'none'`, `style-src 'unsafe-inline'` for the page's own
  style element, `form-action 'self'`, `frame-ancestors 'none'`),
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and
  `Cache-Control: no-store`. Connector `consent.website_url` and
  `consent.support_url` must be absolute `https` URLs; that is checked when
  the connector file is loaded. See
  [the consent page](auth-server.md#consent-page).

## Tokens

- Access tokens are short-lived `at+jwt` with issuer, audience/resource, scopes,
  and unique IDs. A token is bound to the single resource the client requested,
  so it is refused by any other resource server.
- Refresh tokens are opaque, hashed at rest, rotated on use, and the whole
  family is revoked on reuse.
- The direct SDK verifiers default to RS256, refresh JWKS on a bounded schedule,
  and validate `iss`, `aud`, `exp`, `nbf`, `sub`, and required scopes. Python can
  explicitly allow RS384/RS512; Go and TypeScript use RS256. The optional FastMCP
  adapter delegates token verification to FastMCP's verifier.
- Direct JWT verification is offline: revoking a refresh token does not make an
  already-issued access token fail before expiry. External credential assertions
  check the live refresh family on every uncached exchange; see
  [revocation](external-credentials.md#revocation).
- Tokens, secrets, codes, keys, and assertions are redacted from audit logs.
  An upstream token-exchange fault is `server_error` (502 or 503) with an audit
  `reason`. `invalid_target` is only an audience the exchanger rejected.
- A resource server must never forward an inbound MCP token to a downstream API.
  See [token boundaries](architecture.md#token-boundaries).

## Transport

- `MCP_AUTH_REQUIRE_HTTPS` defaults to true and checks canonical URLs and the
  request transport. The shipped binary listens over HTTP; this setting does
  not create a TLS listener. Production uses a trusted HTTPS reverse proxy.
  An application embedding the handler can provide a TLS listener itself.
- `X-Forwarded-Proto` is set by the caller, so it is **not** accepted as proof
  of TLS unless `MCP_AUTH_TRUST_PROXY_TLS=true`. That setting is a claim that a
  trusted proxy terminates TLS and is the only route in; a NetworkPolicy,
  security group, or equivalent is what makes the claim true. Enabling it
  without restricting network access lets anything that can reach the process
  satisfy the HTTPS requirement with one header.

## What the deployment owns

- A persistent signing key from a secret manager, KMS, or HSM, with a rotation
  plan. The ephemeral development key is not usable in production.
- Durable shared storage. SQLite suits a single instance; multiple replicas need
  a shared database adapter, not an unencrypted volume.
- Restrictive CORS and trusted origins, rate limits, CSRF protection at the
  login boundary, secure cookies, and reverse-proxy request limits.
- The upstream identity provider: its realm or tenant, users, client
  credentials, availability, and certificates.

The [production checklist](auth-server.md#production-checklist) is the short
form of this page.
