# Changelog

Release notes for tagged versions are also published as
[GitHub releases](https://github.com/tavric-labs/mcp-auth/releases).

## Unreleased

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

- Documentation image tags now point at `0.8.0` instead of `0.6.0`.
