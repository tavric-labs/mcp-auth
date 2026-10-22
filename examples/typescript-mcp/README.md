# TypeScript MCP resource server

A minimal protected MCP JSON-RPC server using `@mcp-auth/client`. It publishes
RFC 9728 metadata, returns bearer challenges, validates MCP access tokens, and
exposes a `whoami` tool.

```bash
# From the repository root, build the local SDK before starting the example.
npm ci --prefix auth-client/typescript
npm run build --prefix auth-client/typescript
npm ci --prefix examples/typescript-mcp
npm start --prefix examples/typescript-mcp
```

The defaults expect the local-development authorization server on port 8080
and serve the MCP endpoint at `http://localhost:8081/mcp`. The server uses the
path in `MCP_RESOURCE` for both MCP requests and the matching protected-resource
metadata URL, including nested paths such as
`https://mcp.example.com/my-server/mcp`. Override `MCP_AUTH_ISSUER`,
`MCP_AUTH_JWKS_URI`, `MCP_RESOURCE`, or `MCP_PORT` as needed.
