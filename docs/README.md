# mcp-auth documentation

mcp-auth is a provider-neutral authorization server and resource-server SDKs
maintained by [Tavric Labs](https://github.com/tavric-labs). Start with the path
that matches your role. The [use-case guide](use-cases.md) maps supported flows
to configuration, runnable examples and verification coverage.

## Deploy the authorization server

Read [Architecture](architecture.md) for the OAuth flow and component boundaries,
then [Authorization server](auth-server.md) for configuration, identity-provider
connectors and the production checklist. Use [Login methods](login-methods.md)
when offering multiple sign-in options.

Production needs a configured upstream identity source (one OIDC/OAuth connector
or the login-method registry, including LDAP) and a public HTTPS issuer.
The local-development quickstart in the [repository README](../README.md#try-it)
is for trying the server on your machine.

## Protect an MCP server

The [SDK guide](auth-client.md) covers Python, Go and TypeScript token validation,
resource metadata, bearer challenges and token exchange. Read the
[security model](security-model.md) before deciding which audiences and scopes
your server accepts. Use [External credentials](external-credentials.md) when
integrating a credential source. For a bundled proxy with 1Password support,
use [Optional credential gateway](credential-gateway.md).

## Run an example

Start with the [demo and Keycloak walkthrough](demo-example.md) for a complete
local authorization flow. The [examples index](../examples/README.md) links the
Python, Go and TypeScript resource servers.

## Contribute and troubleshoot

[Local development](development.md) covers checkout, prerequisites, tests,
shared verifier cases and release packaging. The
[Codex refresh reproduction](codex-refresh-reproduction.md) is a focused
troubleshooting scenario.

Open bugs and proposals in [GitHub issues](https://github.com/tavric-labs/mcp-auth/issues).
Report suspected vulnerabilities through the [security policy](../SECURITY.md).
Published binaries, SDK archives and checksums are available in
[GitHub releases](https://github.com/tavric-labs/mcp-auth/releases).
