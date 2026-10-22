# mcp-auth-client

Installable Python SDK for MCP resource servers. For now install it from Git:

```bash
python -m pip install "mcp-auth-client @ git+https://github.com/tavric-labs/mcp-auth.git#subdirectory=auth-client/python"
```

See the repository's [auth-client guide](../../docs/auth-client.md) for verifier, discovery, FastMCP, and token-exchange usage.

Requires Python 3.12 or newer. CPython still supports 3.11, and this package does not: 3.12 is the oldest interpreter the repository type-checks and tests, so 3.11 is excluded instead of being advertised without a CI run. CI tests 3.12, 3.13, and 3.14.

`JWTVerifier` allows 60 seconds of clock skew by default (`clock_skew`, passed to PyJWT as `leeway`) and waits at most 10 seconds for a JWKS response (`http_timeout`). `TokenExchangeClient` posts only to an `https` token endpoint unless `allow_insecure=True`.

`ssrf_safe` (the default) checks the JWKS URL text, not DNS. It blocks non-HTTPS URLs except loopback names, URLs with userinfo, and non-loopback IP literals. A hostname that resolves to a private address is not blocked, because `jwks_uri` is operator-configured.

Shared verifier cases live in [`sdk-conformance/`](../../sdk-conformance). Add a case to `cases.json` and run the Python, Go, and TypeScript suites; do not check in a signed JWT or a PEM file.
