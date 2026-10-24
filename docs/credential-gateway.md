# Optional credential gateway

Use the gateway when an upstream MCP server needs a username, password, API token,
or other authentication headers. MCP clients keep only the gateway's public URL and
an OAuth bearer token. The first time a client connects, a sign-in page asks the
person for the header values. From then on the gateway supplies those headers to
the upstream on every request (POST, GET/SSE and DELETE).

The gateway is **its own service**, next to an unmodified mcp-auth. No identity
provider is involved for these resources and no vault is configured: the person
fills the form by hand or with their browser's own password manager. The gateway
never gives the values back, and mcp-auth never sees them.

## Architecture

```
            ┌───────────── sign-in (once per client) ─────────────┐
 browser ──▶ mcp-auth /authorize ──▶ consent ──▶ gateway /login/authorize (the form)
                                                         │ person submits
                                                         ▼
                                            gateway validates at the upstream,
                                            keeps the values in memory
 browser ◀── mcp-auth /identity/callback ◀───────────────┘ (one-use code)
              mcp-auth ⇄ gateway /login/token, /login/userinfo   (back channel; opaque subject only)
 client ◀── mcp-auth issues its own code and token

            ┌───────────── every MCP request ─────────────┐
 client ──bearer──▶ gateway ──▶ mcp-auth /token  (signed assertion: session still active?)
                       │
                       └─ adds the stored headers ──▶ upstream MCP server
```

| Service | Responsibility |
| --- | --- |
| `mcp-auth` (`auth-server`) | Consent, PKCE, tokens, refresh and revocation. Routes the gateway's resources to their sign-in through a resource login. Unchanged for every other resource. |
| `mcp-credential-gateway` | The sign-in endpoints mcp-auth uses (`/login/authorize`, `/approve`, `/token`, `/userinfo`), the in-memory value store, header injection and the fixed upstream proxy. |

Each MCP request makes one extra call from the gateway to mcp-auth's token endpoint,
for a signed credential-access assertion. That call is what makes revocation take
effect on the very next request; nothing is cached across requests. Measured against
a live cluster it adds a few milliseconds per request.

## Sign-in and later requests

1. The client discovers the resource and requests consent at mcp-auth.
2. mcp-auth sends the browser to the gateway's sign-in page for that resource, the
   way it would to an identity provider. Other resources keep their normal login.
3. The page has one input per header the service needs. On submit the gateway sends
   the values to the service's `validation_url`. Only a 2xx response continues; a
   refused value shows the form again, and an unreachable upstream shows a
   temporary-failure message. Each sign-in attempt allows five tries.
4. On success the gateway keeps the values **in memory only**, under a random
   subject, and redirects back to mcp-auth with a one-use code. mcp-auth exchanges
   it with the gateway on the back channel, reads the opaque subject from
   `/login/userinfo`, and issues its own code and token. No value reaches mcp-auth.
5. On every later request the client sends its bearer token. The gateway verifies
   it, asks mcp-auth for the assertion, looks up the values stored for that sign-in,
   drops incoming credentials and cookies, binds upstream MCP session IDs to the
   sign-in, and forwards to the fixed upstream with the headers added. Revoking the
   session blocks the next request even though values are stored.

Each new authorization, including a second client for the same person, starts at
step 2. Refresh continues the existing session and keeps its stored values.

`validation_url` is a fixed authenticated **GET** endpoint on the same origin as
`upstream_url`. It must be safe to call at sign-in and check the same credentials
as the MCP server. A public health endpoint, or a page that returns 200 without
authenticating, is unsuitable. Redirects are not followed.

## Configure the gateway

Start with [config.example.json](../examples/credential-gateway/config.example.json)
and replace the example hosts. Run `mcp-credential-gateway` with
`MCP_GATEWAY_CONFIG` set to the file (or `-config`). Mount the config, the
resource-client RSA key and a session binding key of at least 32 characters
read-only. Secret contents never belong in `mcp.json`, `.mcp/servers.yaml`, a
container image or Git.

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

The gateway's public routes are each service's path (the MCP endpoint), its
`/login/*` sub-paths and `/.well-known/oauth-protected-resource/<path>`. Route them
to the gateway's port; preserve streaming on the MCP route.

## Configure mcp-auth

mcp-auth needs four things per service, all in its existing configuration. Use the
gateway's two naming conventions, which the gateway also uses: the sign-in client id
is `login-<id>` and the subject prefix is `form-<id>:`.

1. **The resource and its scope** in `MCP_AUTH_RESOURCES` and
   `MCP_AUTH_RESOURCE_SCOPES` (or `MCP_AUTH_ALLOWED_SCOPES`).
2. **The gateway as an external credential client**, so it can ask for assertions:
   `MCP_AUTH_EXTERNAL_CREDENTIALS_FILE`, see
   [external-credentials.example.json](../examples/credential-gateway/external-credentials.example.json).
   It holds the *public* half of the gateway's resource-client key.
3. **The sign-in endpoints as a plain OAuth 2.0 connector** in
   `MCP_AUTH_CONNECTORS_FILE`, see
   [mcp-auth-connectors.example.json](../examples/credential-gateway/mcp-auth-connectors.example.json).
   `allowed_upstream_callback_uris` must contain mcp-auth's
   `<issuer>/identity/callback`.
4. **A resource login** that sends the resource to that connector:
   `MCP_AUTH_RESOURCE_LOGINS_FILE` with a method that names the resource and the
   `form-<id>:` prefix, see
   [resource-logins.example.json](../examples/credential-gateway/resource-logins.example.json)
   and [login methods](login-methods.md#resource-logins-next-to-a-single-connector).

With a single connector (`MCP_AUTH_CONNECTOR`) the connector keeps serving every
other resource unchanged, including downstream token exchange. With login methods
mode, list the method in `MCP_AUTH_LOGIN_METHODS_FILE` with `resources` instead.

## Where the values are kept

Submitted values live **only in the gateway's process memory**. Nothing is written to
disk, the database or a Secret, and values are never logged. They are rejected before
storage if the upstream refuses them. The consequences:

- They are lost when the gateway restarts. A person's token may still be valid, but
  the gateway has no values for it, so they sign in again.
- They are not shared between replicas. Run one replica, or route a client to the
  same instance.
- They expire after `form_credentials.ttl_seconds`.

The gateway and mcp-auth restart independently, so restarting mcp-auth does **not**
clear anyone's stored values.

## Runtime authoring and client configuration

Runtime's `.mcp/servers.yaml` can declare `auth.credentialGateway` for a
header-mode server, and `mcp-runtime cluster mcp-auth-gateway sync` derives the
gateway's service entries and the mcp-auth wiring from the pushed servers. See the
[Runtime credential-form example](https://github.com/tavric-labs/mcp-runtime/tree/examples/onepassword_credential_demo/examples/credential-form-demo).

The client connects to **`resource_url`**, not the raw upstream URL:

```json
{"mcpServers":{"gitlab":{"url":"https://auth.example.com/gitlab/mcp"}}}
```

## Verification and deployment limits

```bash
(cd auth-server && go test -race ./... && go vet ./...)
(cd credential-gateway && MCP_AUTH_SRC=../.. go test -race ./... && go vet ./...)
```

The gateway tests cover isolation, injection on all MCP HTTP operations, cache expiry,
redirects, session binding, revocation, and the sign-in endpoints including forged
origins, replayed codes, wrong PKCE verifiers and attempt limits. The end-to-end test
starts the real mcp-auth binary and the gateway as separate HTTP servers and walks the
whole flow across both: the redirect to the gateway's form, refusal of wrong values,
the back channel, two people with separate headers, and revocation of one session.

Restrict the upstream route to trusted gateway callers where the network permits; it
remains authenticated with its required headers. The gateway must be able to reach
`upstream_url` and `validation_url`, and mcp-auth's token endpoint and signing keys,
from where it runs. A pod that cannot connect to its own cluster's public address
needs an in-cluster route for that hostname. mcp-auth must be able to reach the
gateway's `/login/token` and `/login/userinfo`.
