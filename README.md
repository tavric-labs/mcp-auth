# mcp-auth

[![CI](https://github.com/tavric-labs/mcp-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/tavric-labs/mcp-auth/actions/workflows/ci.yml)
[![CodeQL](https://github.com/tavric-labs/mcp-auth/actions/workflows/codeql.yml/badge.svg)](https://github.com/tavric-labs/mcp-auth/actions/workflows/codeql.yml)
[![Security policy](https://img.shields.io/badge/security-policy-4C1?logo=securityscorecard)](SECURITY.md)
[![Container scan](https://img.shields.io/badge/container%20scan-Trivy-1904DA?logo=aqua)](.github/workflows/ci.yml)
[![Dependency audit](https://img.shields.io/badge/dependencies-audited-2EA44F)](.github/workflows/ci.yml)
[![Resource-server SDKs: Python, Go, TypeScript](https://img.shields.io/badge/resource%20server%20SDKs-Python%20%7C%20Go%20%7C%20TypeScript-5865F2)](docs/auth-client.md)
[![Go server 1.26+](https://img.shields.io/badge/Go%20server-1.26%2B-00ADD8?logo=go&logoColor=white)](auth-server/go.mod)
[![Go SDK 1.18+](https://img.shields.io/badge/Go%20SDK-1.18%2B-00ADD8?logo=go&logoColor=white)](auth-client/go/go.mod)
[![Go tested 1.26 | 1.27](https://img.shields.io/badge/Go%20tested-1.26%20%7C%201.27-00ADD8?logo=go&logoColor=white)](.github/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![Python tested 3.12 | 3.13 | 3.14](https://img.shields.io/badge/Python%20tested-3.12%20%7C%203.13%20%7C%203.14-3776AB?logo=python&logoColor=white)](.github/workflows/ci.yml)
[![Node 22+](https://img.shields.io/badge/Node-22%2B-5FA04E?logo=node.js&logoColor=white)](auth-client/typescript/package.json)
[![Node tested 22 | 24 | 26](https://img.shields.io/badge/Node%20tested-22%20%7C%2024%20%7C%2026-5FA04E?logo=node.js&logoColor=white)](.github/workflows/ci.yml)
[![TypeScript 5.9](https://img.shields.io/badge/TypeScript-5.9-3178C6?logo=typescript&logoColor=white)](auth-client/typescript/package.json)
[![MCP authorization](https://img.shields.io/badge/MCP-authorization-7C3AED)](docs/architecture.md)
[![GitHub release](https://img.shields.io/github/v/release/tavric-labs/mcp-auth?display_name=tag)](https://github.com/tavric-labs/mcp-auth/releases)
[![Docker pulls](https://img.shields.io/docker/pulls/princekrroshan01/mcp-auth-server)](https://hub.docker.com/r/princekrroshan01/mcp-auth-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A provider-neutral OAuth 2.1 authorization broker for the Model Context Protocol
(MCP) ecosystem. mcp-auth sits between MCP clients and resource servers on one
side and an organization's upstream identity provider on the other. It provides
a standalone authorization server, plus Python, Go, and TypeScript SDKs for the
resource-server side.

It separates three concerns that are often coupled:

- **MCP clients** complete the OAuth 2.1 Authorization Code flow with mandatory
  PKCE S256.
- **MCP resource servers** validate narrowly scoped access tokens with reusable
  Python, Go, or TypeScript SDKs.
- **Identity providers and downstream APIs** stay behind runtime-configured
  connectors.

Both an OIDC provider (a connector requesting `openid`, with a verified ID token)
and a plain OAuth 2.0 provider (no `openid`, identity from `userinfo_endpoint`)
are supported. Endpoints may be configured directly or discovered from the
issuer, and ID tokens may use RS256, PS256, or ES256. See
[connect an organization's identity provider](docs/auth-server.md#connect-an-organizations-identity-provider)
for setup. The provider's upstream protocol is separate from the OAuth 2.1
flow between the MCP client and mcp-auth.

Maintained by [Tavric Labs](https://github.com/tavric-labs).
Browse the [documentation](docs/README.md), [releases](https://github.com/tavric-labs/mcp-auth/releases),
or [report a bug](https://github.com/tavric-labs/mcp-auth/issues). For security
reports, follow the [security policy](SECURITY.md).

## Standards position

mcp-auth supports the MCP OAuth 2.1 authorization profile, including RFC 8414
Authorization Server Metadata, RFC 9728 Protected Resource Metadata, mandatory
PKCE S256, resource indicators and audience-bound tokens, refresh-token
rotation, RFC 9207 authorization-response `iss`, and Client ID Metadata
Documents (CIMD), enabled by default. Set
`MCP_AUTH_CLIENT_ID_METADATA_ENABLED=false` to opt out. MCP clients should prefer pre-registered credentials when
available, then CIMD when the authorization server advertises support, and use
Dynamic Client Registration (DCR) as a backwards-compatibility fallback. DCR
is not a second registration step after CIMD. The authorization server brokers
authorization; it is not an identity provider. MFA, directory policy, user
lifecycle, and upstream credentials belong to the upstream IdP.

mcp-auth does not claim to implement every OAuth extension or every
responsibility in the MCP specification. MCP clients, resource servers, and
authorization servers have distinct normative responsibilities; the bundled
authorization server and resource-server SDKs cover their respective roles.

## How it fits together

![MCP authorization flow: client, resource server, authorization broker, identity provider, and downstream API](docs/images/auth-flow.png)

[Editable Mermaid source](docs/images/auth-flow.mmd)

Detailed diagrams: [choose a login mode](docs/use-cases.md#choose-a-login-mode),
[one issuer with multiple resources](docs/use-cases.md#one-enterprise-provider-several-mcp-resources),
[per-request credential access](docs/use-cases.md#a-gateway-with-external-per-user-credentials),
and the [HTTPS deployment boundary](docs/auth-server.md#https-deployment-boundary).

The token sent by the MCP client is valid only for the MCP resource server. It is
never forwarded to the downstream API; the resource server obtains a separate
downstream credential through token exchange or the connector's upstream session.

## Optional credential gateway

For header-authenticated upstream MCP servers, mcp-auth supports
[resource logins](docs/credential-gateway.md): a resource can be sent to its own
sign-in page, served by a separate gateway such as MCP Runtime's `mcp-gateway`
in credential mode. mcp-auth sends the browser to the gateway's sign-in page for that
resource; the page asks for the headers the server declares, validates them at the
upstream, and keeps them in memory. The client then holds only a bearer token and a
URL, and the gateway supplies the headers on every request. mcp-auth never sees the
values, and no identity provider or vault is involved. This repository ships no
gateway image; the authorization server and SDKs have no gateway dependency.

## Try it

```bash
docker run --rm -p 8080:8080 \
  -e MCP_AUTH_ISSUER=http://localhost:8080 \
  -e MCP_AUTH_RESOURCES=http://localhost:8081/mcp \
  -e MCP_AUTH_LOCAL_DEVELOPMENT=true \
  -e MCP_AUTH_REGISTRATION_ENABLED=true \
  -e MCP_AUTH_REQUIRE_HTTPS=false \
  princekrroshan01/mcp-auth-server:0.6.0
```

Local-development only — no TLS, no identity provider. See
[Authorization server](docs/auth-server.md) before deploying it anywhere real.

## Choose your starting point

| I want to… | Read |
| --- | --- |
| Choose a deployment and credential flow | [Use cases](docs/use-cases.md) |
| Deploy the authorization server | [Authorization server](docs/auth-server.md) |
| Offer Google, GitHub, LDAP and OIDC sign-in together | [Login methods](docs/login-methods.md) |
| Protect an MCP resource server | [Auth client SDKs](docs/auth-client.md) |
| Understand the protocol flow | [Architecture](docs/architecture.md) |
| Know what is guaranteed, and what I own | [Security model](docs/security-model.md) |
| Run an end-to-end example | [Demo MCP + Keycloak](docs/demo-example.md) |
| Build a Node.js MCP server | [TypeScript example](examples/typescript-mcp) |
| Build a Go MCP server | [Go example](examples/go-mcp) |
| Contribute, run tests, or cut a release | [Local development](docs/development.md) |

## Repository layout

- `auth-server/` — standalone Go OAuth authorization server
  (`github.com/Agent-Hellboy/mcp-auth/auth-server`, tagged `auth-server/vX.Y.Z`)
- `auth-client/go/` — Go resource-server SDK
  (`github.com/Agent-Hellboy/mcp-auth/auth-client/go/mcpauth`, tagged
  `auth-client/go/vX.Y.Z`)
- `auth-client/python/` — Python resource-server SDK, including a FastMCP adapter
- `auth-client/typescript/` — TypeScript resource-server SDK for Node.js
- `examples/demo-mcp/` — dummy FastMCP resource server used by the Compose E2E
- `examples/typescript-mcp/` — protected TypeScript MCP JSON-RPC server
- `examples/go-mcp/` — protected Go MCP JSON-RPC server

The repository is hosted at `tavric-labs/mcp-auth`. The Go module declarations
currently retain the `github.com/Agent-Hellboy/mcp-auth/...` paths shown above;
use those exact import paths until a release changes the module declarations.

The Python SDK installs from the current repository while its API settles:

```bash
python -m pip install "mcp-auth-client @ git+https://github.com/tavric-labs/mcp-auth.git#subdirectory=auth-client/python"
```

MCP authorization is optional at the protocol level. A resource server may still
require it when it exposes private data or actions.

## Contributing

Start with [local development](docs/development.md) for setup, tests and release
packaging. Open bugs and proposals in [GitHub issues](https://github.com/tavric-labs/mcp-auth/issues)
and submit changes through [pull requests](https://github.com/tavric-labs/mcp-auth/pulls).

## Contributors

- Prince Roshan

## License

MIT. See [LICENSE](LICENSE).
