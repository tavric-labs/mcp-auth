# Optional credential gateway

Use the combined service when an upstream MCP server needs a username, password,
API token, or other authentication headers. MCP clients keep only the gateway's
public URL and an OAuth bearer token. The first time a client connects, a sign-in
page asks the person for the header values. From then on the gateway supplies
those headers to the upstream on every request (POST, GET/SSE and DELETE).

No identity provider is involved for these resources, and no vault is configured:
the person fills the form by hand or with their browser's own password manager.
The gateway never gives the values back to the client.

## Packaging

| Module | Responsibility |
| --- | --- |
| `auth-server` | Consent, PKCE, scoped tokens, refresh, session revocation, the sign-in page and a generic pre-authorization callback |
| `credential-gateway` | In-memory store of submitted values, header transforms, credential cache, fixed upstream proxy, bound MCP session IDs |
| `combined-server` | Starts both listeners in one process, adds a sign-in method per form service and attaches the gateway's authorization check |

The combined binary serves OAuth on `MCP_AUTH_LISTEN_ADDR` (default `:8080`) and
the gateway on its configured listener (default `:8090`). These are two ports of
one deployment. Use the normal OAuth ingress and route the gateway's public
resource paths plus protected-resource discovery to port 8090, preserving
streaming. No gateway listener exists unless `MCP_AUTH_CREDENTIAL_GATEWAY_CONFIG`
is set.

```bash
cd combined-server
go build -o ./mcp-auth ./cmd/mcp-auth
# or, from the repository root:
docker build -f combined-server/Dockerfile -t mcp-auth-combined:review .
```

## Sign-in and later requests

1. The client discovers the resource and requests consent.
2. After consent, the person sees a sign-in page for **that resource only**, with
   one input per header the service needs. Other resources keep their normal
   login.
3. On submit, the gateway renders the headers and sends them to the service's
   `validation_url`. Only a 2xx response continues. A refused value shows the form
   again ("Sign-in failed"); an unreachable upstream shows a temporary-failure
   message. Attempts are throttled per account name (the first non-secret input).
4. On success the gateway keeps the values in memory under a random, per-sign-in
   subject, and mcp-auth issues the authorization code. The client exchanges it
   using PKCE. No value enters the code or the token.
5. On every later request the client sends its bearer token. The gateway obtains a
   signed credential-access assertion from mcp-auth, looks up the values stored for
   that sign-in, drops incoming credentials and cookies, binds upstream MCP session
   IDs to the sign-in, and forwards to the fixed upstream with the headers added.
   Revoking the session blocks the next request even though values are stored.

Each new authorization, including a second client for the same person, starts at
step 2. Refresh continues the existing session and keeps its stored values.

`validation_url` is a fixed authenticated **GET** endpoint on the same origin as
`upstream_url`. It must be safe to call at sign-in and check the same credentials
as the MCP server. A public health endpoint, or a page that returns 200 without
authenticating, is unsuitable. Redirects are not followed.

## Configuration

Start with [config.example.json](../examples/credential-gateway/config.example.json)
and replace the example hosts. Mount the gateway config, the resource-client RSA
key and a session binding key of at least 32 characters read-only. Secret contents
never belong in `mcp.json`, `.mcp/servers.yaml`, a container image or Git.

```json
{
  "listen": {"host": "0.0.0.0", "port": 8090},
  "authorization_server": {"issuer": "https://auth.example.com/mcp-auth"},
  "session_binding_key_file": "/run/secrets/gateway-session-binding",
  "form_credentials": {"ttl_seconds": 3600, "max_entries": 1024},
  "services": [{
    "id": "gitlab",
    "resource_url": "https://auth.example.com/gitlab/mcp",
    "upstream_url": "https://mcp.example.com/gitlab/mcp",
    "validation_url": "https://mcp.example.com/gitlab/mcp/auth/check",
    "required_scopes": ["tools:read"],
    "resource_client": {"client_id": "gitlab-gateway", "key_id": "gateway-1", "private_key_file": "/run/secrets/gitlab-client.pem"},
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

- **`form_fields`** must be exactly the credential fields the `headers` read, so a
  form can neither omit a value a header needs nor collect one nothing uses. A
  `label` defaults to the field name; `secret` renders a masked input. A `source`
  key may be omitted or `"form"`; nothing else is supported.
- **`headers`** are `direct`, `prefix` (`Bearer` or `Token`) or `basic` (username
  and password fields). Any valid HTTP header name works. Routing, framing and
  protocol headers cannot be injected, and neither can `Via`, `Accept-Encoding`,
  `Last-Event-Id` or `Sec-*`. The person supplies the complete value, for example
  `Bearer abc` for an `Authorization` header with a `direct` rule.
- **`form_credentials`**: `ttl_seconds` (default 3600, 60 to 86400) and
  `max_entries` (default 1024, oldest evicted first).
- **`credential_cache`**: rendered headers are also cached briefly. Defaults are
  300 seconds and 1024 entries; the TTL may be 0 to 3600 seconds. A cache entry
  never outlives the OAuth session.

Configure mcp-auth as usual, then add:

```text
MCP_AUTH_ISSUER=https://auth.example.com/mcp-auth
MCP_AUTH_RESOURCES=https://auth.example.com/gitlab/mcp
MCP_AUTH_ALLOWED_SCOPES=tools:read
MCP_AUTH_CREDENTIAL_GATEWAY_CONFIG=/etc/mcp-auth/credential-gateway.json
```

Keep any other installed resources in `MCP_AUTH_RESOURCES`; resource-specific scopes
may use `MCP_AUTH_RESOURCE_SCOPES`. Each gateway resource and its required scopes
must already be allowed by the OAuth configuration; startup fails on a mismatch.
The bundle derives its assertion client public keys from the mounted private keys
and registers them itself, so do not repeat these resources in
`MCP_AUTH_EXTERNAL_CREDENTIALS_FILE` or provision colliding client IDs.

### Identity modes

The gateway adds a sign-in method `form-<id>`, scoped to each service's resource.
- **Single connector** (`MCP_AUTH_CONNECTOR`): the connector keeps serving every
  other resource unchanged, including downstream token exchange. Only the form
  resources use the form.
- **Login methods** (`MCP_AUTH_LOGIN_METHODS_FILE`): the form methods join the
  registry and the existing methods keep serving their resources.

## Where the values are kept

Submitted values live **only in mcp-auth's process memory**. Nothing is written to
disk, the database or a Secret, and values are never logged. They are rejected
before storage if the upstream refuses them. The consequences:

- They are lost when mcp-auth restarts. A person's token may still be valid, but
  the gateway has no values for it, so they sign in again.
- They are not shared between replicas. Run one replica, or route a client to the
  same instance.
- They expire after `form_credentials.ttl_seconds`.

## Runtime authoring and client configuration

Runtime's `.mcp/servers.yaml` can declare `auth.credentialGateway` for a
header-mode server, and `mcp-runtime cluster mcp-auth-gateway sync` derives the
service entries from the pushed servers. See the
[Runtime credential-form example](https://github.com/tavric-labs/mcp-runtime/tree/examples/onepassword_credential_demo/examples/credential-form-demo).

The client connects to **`resource_url`**, not the raw upstream URL:

```json
{"mcpServers":{"gitlab":{"url":"https://auth.example.com/gitlab/mcp"}}}
```

## Verification and deployment limits

```bash
(cd auth-server && go test -race ./... && go vet ./...)
(cd credential-gateway && MCP_AUTH_SRC=../.. go test -race ./... && go vet ./...)
(cd combined-server && go test -race ./... && go vet ./...)
```

The gateway tests cover isolation, injection on all MCP HTTP operations, cache
expiry, redirects, session binding and revocation. The combined test uses the real
OAuth server and gateway with a fake upstream: it checks that wrong values are
refused before a code is issued, that values with symbols and form-encoding
characters reach the upstream unchanged, that refresh keeps the stored values and
that revocation stops the next request, with and without a login registry.

Restrict the upstream route to trusted gateway callers where the network permits;
it remains authenticated with its required headers. The gateway must be able to
reach `upstream_url` and `validation_url` from where it runs: a pod that cannot
connect to its own cluster's public address needs an in-cluster route for that
hostname.
