# Optional credential gateway

Use the combined service when an upstream MCP server still expects a username,
password, API token, or other authentication headers. MCP clients keep only the
gateway's public URL. They obtain an OAuth token from mcp-auth; the gateway
supplies the upstream headers on POST, GET/SSE, and DELETE.

This is an optional feature. The existing OAuth-only image and SDKs keep their
provider-neutral dependencies. The shipped binary serves **form-source** services:
the person supplies the header values at sign-in and the gateway keeps them in
memory. It bundles no vault provider; see [Vault sources](#vault-sources).

## Packaging and ownership

| Module | Responsibility |
| --- | --- |
| `auth-server` | Identity login, consent, PKCE, scoped tokens, refresh, session revocation; generic pre-authorization callback |
| `credential-gateway` | Private identity/service mappings, credential cache, header transforms, fixed upstream proxy, bound MCP session IDs |
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
and replace the example hosts. Mount the operator's private config,
resource-client RSA key and at least 32-character session binding key read-only.
Secret contents never belong in `mcp.json`, `.mcp/servers.yaml`, a container
image, or Git.

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

## Vault sources

A service with `"source": "vault"` takes its header values from mapped vault
references (`provider`, `mappings_file`) instead of from the person. The shipped
binary registers **no** vault provider, so it accepts only `source: "form"`
services and refuses a vault service at startup with "credential provider is
not registered". A deployment that wants a vault embeds the gateway and
registers its own provider; see [Adding another vault](#adding-another-vault).
Human authentication still comes from the configured identity provider, and a
hosted gateway cannot invoke a remote user's desktop password manager.

## Runtime authoring and client configuration

Runtime's `.mcp/servers.yaml` describes the **upstream** deployment and its normal
header authentication. The companion gateway JSON supplies `resource_url`,
`upstream_url`, `validation_url`, scopes and header transforms to mcp-auth.
Private user mappings and provider authorization stay with the gateway operator.
Runtime does not automatically upload the companion JSON or rewrite catalog URLs.

The client connects to **`resource_url`**, not the raw header-authenticated
upstream URL:

```json
{"mcpServers":{"gitlab":{"url":"https://auth.example.com/gitlab/mcp"}}}
```

See the [Runtime credential-form example](https://github.com/tavric-labs/mcp-runtime/tree/examples/onepassword_credential_demo/examples/credential-form-demo)
for deployable upstream source and its `servers.yaml`.

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

## Sign-in form source (no vault, no identity provider)

A service can take its header values from the person at sign-in instead of
from mapped vault references. Set `"source": "form"` and list one input per
credential field the headers read:

```json
{
  "services": [{
    "id": "gitlab",
    "resource_url": "https://auth.example.com/gitlab/mcp",
    "upstream_url": "https://gitlab.example.com/api/v4/mcp_server",
    "validation_url": "https://gitlab.example.com/auth/check",
    "required_scopes": ["tools:read"],
    "resource_client": {"client_id": "gitlab-gateway", "key_id": "k1", "private_key_file": "/etc/mcp-auth-gateway/client.pem"},
    "source": "form",
    "form_fields": [
      {"name": "username", "label": "GitLab username"},
      {"name": "api_token", "label": "Personal access token", "secret": true}
    ],
    "headers": [
      {"name": "X-GitLab-Username", "type": "direct", "field": "username"},
      {"name": "X-GitLab-PAT-Token", "type": "direct", "field": "api_token"}
    ]
  }]
}
```

The MCP client's configuration is the resource URL alone. Its OAuth flow shows
a sign-in page for this resource only, with those inputs. A browser password
manager, such as a browser or extension, can fill them. The gateway sends the
values to `validation_url`; only a 2xx response issues the authorization code.
A refused sign-in shows the form again, throttled per account name; an
unreachable upstream shows a temporary-failure message.

Accepted values are held **in process memory only**, under a random per-sign-in
subject, for `form_credentials.ttl_seconds` (default 3600, 60 to 86400) and at
most `form_credentials.max_entries` entries (default 1024; the oldest are
evicted first). They are never logged, never returned to the client, and lost
on restart, so people sign in again. They are not shared between replicas, so
run one replica or route a client to the same one. Rejected values are never
stored. Each header then uses the same transforms and per-request injection as
vault services.

`form_fields` must be exactly the credential fields the headers read. A
deployment with only form services needs no `provider` or `mappings_file`, and
setting them is an error.

The gateway adds a sign-in method `form-<id>` scoped to the service's resource.
With a single identity connector (`MCP_AUTH_CONNECTOR`), the connector keeps
serving every other resource unchanged, including downstream token exchange;
only the form resource uses the form. With login methods mode
(`MCP_AUTH_LOGIN_METHODS_FILE`), the form methods join the registry and the
existing methods keep serving their resources.
