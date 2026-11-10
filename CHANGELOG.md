# Changelog

Release notes for tagged versions are also published as
[GitHub releases](https://github.com/tavric-labs/mcp-auth/releases).

## Unreleased

## [0.9.1] - 2026-11-10

### Fixed

- Fetching a Client ID Metadata Document from a dual-stack host (for example
  `https://chatgpt.com/oauth/codex/client.json`) no longer fails with
  `client metadata document could not be fetched` on a network with no working
  IPv6 route. The fetch used to dial only the first resolved address, so an
  unreachable AAAA answer consumed the whole 5 second timeout. All resolved
  addresses must still be public, then the vetted addresses are tried IPv4
  first with RFC 8305 style fallback and a 2 second per-address limit.

### Changed

- `/token` and `/authorize` cache successfully fetched Client ID Metadata
  Documents in memory (`Cache-Control: max-age` clamped to 30 seconds to 1
  hour, default 5 minutes, at most 256 entries, failures never cached), so a
  token request no longer refetches the document from the client's host. The
  requested `redirect_uri` is still validated on every request.
- The `authorization_rejected` audit event for `client_metadata_rejected` now
  carries a `detail` field with the safe rejection reason.

### Added

- `docs/connector-architecture.md`: how connectors, login methods, resource logins and resource clients are loaded and used, with component and lifecycle diagrams, the files read at startup, failure behavior, how MCP Runtime supplies the files and a which-file-to-edit table. Linked from the README, the docs index and the site navigation.

## [0.9.0] - 2026-11-10

### Changed (behavior)

- **A login method with invalid configuration no longer stops the server.**
  Previously one method that named a connector missing from the connectors file
  (or had any other invalid setting) made the whole process exit at startup, so
  one dangling entry took all sign-in down on the next restart. Now that method
  is disabled: it is logged at ERROR level with its id and the reason, it is
  not shown on the login page, and `/readyz` stays `200` and lists the ids as
  `login_methods_disabled`. Every valid method keeps serving. A resource scoped
  to a disabled method is refused with `access_denied`; it never falls back to a
  default method or to the single connector.
- Startup still fails for an unparsable methods file, a missing, malformed or
  duplicate method `id`, invalid `resources`, colliding subject prefixes, an
  unreadable or invalid connectors file, a resource login without `resources`
  or with an empty `subject_prefix`, and when every method in login-methods
  mode is disabled.
- `MCP_AUTH_STRICT_LOGIN_METHODS=true` restores fail-fast loading.
- Go API: `LoginMethodsOptions.SkipInvalidMethods` (off by default, so library
  callers keep fail-fast loading), `LoginRegistry.DisabledMethods` and
  `LoginRegistry.EnabledCount`.

### Added

- `docs/connectors.md`: the inventory of connector and login method types, the
  connector and method schemas, how resource logins relate to connectors, and a
  guide to writing a custom connector (no-code and in code), with example files
  `examples/connectors.oauth2-only.example.json` and
  `examples/login-methods.oauth2-only.example.json`.

### Fixed

- Documentation image tags now point at `0.9.0` instead of `0.6.0`.
