# Module boundaries and checks

The repository ships the provider-neutral OAuth core (`auth-server`) and language
SDKs. Header-credential sign-in is a resource login (see
[the guide](docs/credential-gateway.md)); the gateway that serves the sign-in page
and injects headers lives in MCP Runtime's `mcp-gateway`, not in this repository.

Run checks in each touched Go module, with its declared Go version:

```bash
(cd auth-server && go test -race ./... && go vet ./...)
```

The OAuth image builds from `auth-server`. Update the resource-login guide and
sample files when changing their configuration or lifecycle. Do not commit private keys or real header values.
Tests use a fake upstream; do not describe them as evidence about a real
password manager's autofill.
