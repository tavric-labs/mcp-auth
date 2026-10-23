# Module boundaries and checks

The repository ships the provider-neutral OAuth core (`auth-server`) and language
SDKs, plus an optional `credential-gateway` and `combined-server` composition.
Only the composition module imports both the OAuth server and gateway. Vault
SDKs and reference grammar belong in gateway provider packages; keep them out of
the OAuth core and SDKs. See [the gateway guide](docs/credential-gateway.md).

Run checks in each touched Go module, with its declared Go version:

```bash
(cd auth-server && go test -race ./... && go vet ./...)
(cd credential-gateway && MCP_AUTH_SRC=../.. go test -race ./... && go vet ./...)
(cd combined-server && go test -race ./... && go vet ./...)
```

The optional image builds from the repository root with
`docker build -f combined-server/Dockerfile .`; the OAuth-only image still builds
from `auth-server`. Update the gateway guide and sample config when changing its
configuration or lifecycle. Do not commit private mapping files, vault tokens,
private keys or local CLI account configuration. Distinguish fake-provider test
evidence from a real vault canary or native desktop approval.
