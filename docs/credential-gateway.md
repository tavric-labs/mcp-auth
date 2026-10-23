# Optional credential gateway

Use the combined service when an upstream MCP server still expects a username,
password, API token, or other authentication headers. MCP clients keep only the
gateway's public URL. They obtain an OAuth token from mcp-auth; the gateway
supplies the upstream headers on POST, GET/SSE, and DELETE.

This is an optional source-build feature pending review and release. The
existing OAuth-only image and SDKs keep their provider-neutral dependencies.
The separate onepassword-mcp-plugin repository remains available; this change
migrates its gateway implementation from commit
`0f9815448dc9d3fe3164d49cbb4fa2a5d05585eb` into this repository without deleting
it. Most gateway code and its tests are retained, with provider selection and
pre-authorization validation added around them.

## Packaging and ownership

| Module | Responsibility |
| --- | --- |
| `auth-server` | Identity login, consent, PKCE, scoped tokens, refresh, session revocation; generic pre-authorization callback |
| `credential-gateway` | Private identity/service mappings, credential cache, header transforms, fixed upstream proxy, bound MCP session IDs |
| `credential-gateway/providers/onepassword` | 1Password SDK service-account access or local desktop CLI access and `op://` validation |
| `combined-server` | Starts both listeners in one process and attaches the gateway's authorization check |

The combined binary serves OAuth on `MCP_AUTH_LISTEN_ADDR` (default `:8080`) and the
optional gateway on its configured listener (default `:8090`). These are two
ports of one deployment. Use the normal OAuth ingress and route the gateway's
public resource paths plus protected-resource discovery to port 8090. Preserve
streaming on that route. No gateway listener exists unless
`MCP_AUTH_CREDENTIAL_GATEWAY_CONFIG` is set.

```bash
# From the repository root; source build, no publishing or deployment.
cd combined-server
go build -o ./mcp-auth ./cmd/mcp-auth
```

Or build from the repository root:

```bash
docker build -f combined-server/Dockerfile -t mcp-auth-combined:review .
```

## Login and later requests

1. The client discovers the resource, requests consent, and authenticates through
   the configured identity connector or login method. This establishes the
   stable, verified human subject used by private mappings. For one shared
   service credential, a resource-scoped [`static` login method](login-methods.md)
   needs no identity provider; its fixed subject keys the mapping.
2. Before issuing the authorization code, the bundle resolves that subject's
   approved mapping for the requested resource. It reads current vault values,
   renders only configured headers, and calls the service's `validation_url`.
3. Validation must return 2xx only when the upstream accepts those credentials.
   Errors, redirects, missing mappings, unavailable vaults and non-2xx responses
   deny the authorization. No credential values enter the code or MCP token.
4. The client exchanges the code using PKCE and uses its MCP OAuth bearer on
   subsequent requests. The gateway obtains a fresh signed credential-access
   assertion from mcp-auth on **every request**, before consulting its cache.
5. The gateway resolves or reuses the user's approved headers, drops incoming
   credentials/cookies, binds upstream MCP session IDs to issuer/subject/service,
   and forwards to the fixed configured upstream. Session revocation blocks
   the next request even when headers are cached.

Every new OAuth authorization runs steps 1–3, including a second client for the
same user. Refresh continues the existing OAuth session. The configured vault
TTL bounds cached header reuse; a successful new authorization invalidates older
cached headers for that identity/service. Vault rotation becomes visible after
TTL expiry; expired cache entries are never used as an outage fallback.

`validation_url` is a fixed authenticated **GET** endpoint, with the same origin
as `upstream_url`. It must be safe to call at sign-in and check the same required
credentials as the MCP server. A public health endpoint or a login page that
returns 200 without authenticating is unsuitable. No validation redirect is
followed. The included Runtime upstream exposes `/mcp/auth/check` beneath its
configured MCP path for this purpose.

## Configuration

Start with [config.example.json](../examples/credential-gateway/config.example.json)
and [mappings.example.json](../examples/credential-gateway/mappings.example.json).
Replace the example hosts, vault references, and verified subject. Mount the
operator's private config, mapping file, resource-client RSA key and at least
32-character session binding key read-only. Secret contents never belong in
`mcp.json`, `.mcp/servers.yaml`, a container image, or Git.

Configure the existing identity provider as usual, then add:

```text
MCP_AUTH_ISSUER=https://auth.example.com/mcp-auth
MCP_AUTH_RESOURCES=https://credentials.example.com/vault-header-demo/mcp
MCP_AUTH_ALLOWED_SCOPES=tools:read
MCP_AUTH_CREDENTIAL_GATEWAY_CONFIG=/etc/mcp-auth/credential-gateway.json
```

Keep any other installed resources in `MCP_AUTH_RESOURCES`. Resource-specific
scopes may use `MCP_AUTH_RESOURCE_SCOPES`. The gateway resource and required
scopes must already be allowed by the OAuth configuration; startup fails on a
mismatch. The bundle derives its assertion client public keys from the mounted
private keys and registers them itself. Do not repeat those resources in
`MCP_AUTH_EXTERNAL_CREDENTIALS_FILE` or provision colliding OAuth client IDs.
Other external credential connectors remain supported.

The mapping selects `(issuer, verified subject, service ID)` exactly. A subject
from a login registry normally includes its method prefix, such as
`company:<provider-sub>`. Obtain it from the verified identity, never from a
client-supplied username or vault reference. Operators approve these bindings;
self-service mapping enrollment is not included. The file reloads when it
changes and unreadable/invalid mappings fail closed, including on cache hits.

Header transforms are `direct`, `prefix` (`Bearer` or `Token`), and `basic`.
Routing/framing/protocol headers cannot be injected. Cache defaults are 300
seconds and 1024 entries. TTL may be 0–3600 seconds. Each gateway instance uses
one configured provider; a single provider can serve multiple upstream services.

## 1Password modes

Hosted automation uses:

```json
{"type":"onepassword","options":{
  "mode":"service_account",
  "service_account_token_file":"/run/secrets/onepassword-service-account",
  "timeout_seconds":30
}}
```

Scope this service account to the required vaults. Human authentication still
comes from the configured identity provider. Service-account reads do not open
a user's desktop app. A real service-account canary is required before production
use; tests substitute a fake vault.

A **locally running** gateway may instead select:

```json
{"type":"onepassword","options":{
  "mode":"desktop","account":"my.1password.com","timeout_seconds":60
}}
```

Install `op`, run the desktop app, and enable its CLI integration on that same
machine. The provider sets the documented app-integration switch and removes
service-account, Connect and CLI-session environment credentials before `op read`.
It selects the configured account explicitly. See
[1Password desktop integration](https://developer.1password.com/docs/cli/app-integration/)
and [CLI environment variables](https://developer.1password.com/docs/cli/environment-variables/).
1Password controls the available unlock method and cached approvals; the gateway
cannot force a fresh password dialog for each client. The bundled container is
for service-account mode and does not include `op` or a desktop app.

A hosted gateway cannot invoke a remote user's desktop app. Uploading personal
desktop credentials into a hosted gateway requires a separate, authenticated
local-connector handoff; that feature is **not** included in this bundle. The
Runtime protocol fixture's local adapter is not that production handoff.

## Runtime authoring and client configuration

Runtime's `.mcp/servers.yaml` describes the **upstream** deployment and its normal
header authentication. The companion gateway JSON supplies `resource_url`,
`upstream_url`, `validation_url`, scopes and header transforms to mcp-auth.
Private user mappings and provider authorization stay with the gateway operator.
Runtime does not automatically upload the companion JSON or rewrite catalog URLs.

The client connects to **`resource_url`**, not the raw header-authenticated
upstream URL:

```json
{"mcpServers":{"vault-demo":{"url":"https://credentials.example.com/vault-header-demo/mcp"}}}
```

See the [Runtime header-only example](https://github.com/tavric-labs/mcp-runtime/tree/examples/onepassword_credential_demo/examples/vault-header-demo)
for deployable upstream source and paired configuration. No new Runtime metadata
field or CRD is needed for this separate gateway route.

## Adding another vault

Implement `credentialgateway.Resolver` (`Resolve`, `Ready`) and a
`ProviderFactory` (`New`, `ValidReference`), then pass a named factory to
`OpenWithProviders` in the composition layer. Provider options are opaque JSON
to the gateway core. Complete reference grammar, account authorization, timeouts
and redacted errors belong to the provider. Mapping, rendering, caching,
revocation and proxy behavior are reused. Do not add a vendor dependency to
`auth-server` or the language SDKs.

## Verification and deployment limits

```bash
(cd auth-server && go test -race ./... && go vet ./...)
(cd credential-gateway && MCP_AUTH_SRC=../.. go test -race ./... && go vet ./...)
(cd combined-server && go test -race ./... && go vet ./...)
```

The gateway tests cover isolation, injection on all MCP HTTP operations,
mapping removal, cache expiry, redirects, session binding and revocation.
The combined integration test uses the real OAuth server/gateway with a fake
vault and upstream, checks bad credentials before code issuance, fresh checks
for a second client, refresh and revocation. Desktop tests use a fake CLI and
verify environment isolation; they do not establish that a native prompt was
shown. No corrected-flow production deployment or real service-account canary
has been performed.

The gateway cache is bounded process memory. All replicas need consistent
mapping/configuration files and the same session-binding key to accept bound
MCP sessions across replicas. The OAuth store must meet its existing deployment
requirements. Restrict the upstream route to trusted gateway callers where the
network permits; it remains authenticated with its required headers.
