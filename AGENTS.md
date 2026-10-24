# Module boundaries and checks

The repository ships the provider-neutral OAuth core (`auth-server`) and language
SDKs, plus an optional `credential-gateway` service. The gateway talks to mcp-auth
over HTTP like any resource server and imports only the Go SDK, never the OAuth
server. It keeps submitted header values in memory only and has no vault or
password-manager integration. See [the gateway guide](docs/credential-gateway.md).

Run checks in each touched Go module, with its declared Go version:

```bash
(cd auth-server && go test -race ./... && go vet ./...)
(cd credential-gateway && MCP_AUTH_SRC=../.. go test -race ./... && go vet ./...)
```

The gateway image builds from the repository root with
`docker build -f credential-gateway/Dockerfile .`; the OAuth image builds from
`auth-server`. Update the gateway guide and sample config when changing its
configuration or lifecycle. Do not commit private keys or real header values.
Tests use a fake upstream; do not describe them as evidence about a real
password manager's autofill.
