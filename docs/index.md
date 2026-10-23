---
layout: home
title: Documentation
hero:
  name: mcp-auth
  text: OAuth 2.1 authorization for MCP
  tagline: A provider-neutral authorization broker and resource-server SDKs for Python, Go and TypeScript.
  image:
    src: /logo.svg
    alt: mcp-auth
  actions:
    - theme: brand
      text: Choose a flow
      link: /use-cases
    - theme: alt
      text: Architecture
      link: /architecture
    - theme: alt
      text: View on GitHub
      link: https://github.com/tavric-labs/mcp-auth
features:
  - icon: 🔐
    title: OAuth 2.1 with PKCE
    details: Authorization Code flow with mandatory PKCE S256, refresh-token rotation and dynamic client registration.
    link: /auth-server
    linkText: Authorization server
  - icon: 🔌
    title: Provider-neutral
    details: Bring any OIDC or OAuth 2.0 identity source, or offer several sign-in options including LDAP.
    link: /login-methods
    linkText: Login methods
  - icon: 🧰
    title: SDKs for resource servers
    details: Validate tokens, publish resource metadata and issue bearer challenges from Python, Go or TypeScript.
    link: /auth-client
    linkText: Auth client SDKs
  - icon: 🛡️
    title: Explicit security model
    details: Audience and scope enforcement stays at the resource server; your tools never see which IdP signed the user in.
    link: /security-model
    linkText: Security model
  - icon: 🔑
    title: Downstream credentials
    details: Connect or exchange credentials for downstream APIs while keeping the MCP token boundary explicit.
    link: /external-credentials
    linkText: External credentials
  - icon: 🧪
    title: Runnable examples
    details: A full local flow with Keycloak, plus Python, Go and TypeScript resource servers verified by shared cases.
    link: /demo-example
    linkText: Run the demo
---

<div class="home-section">

## How the pieces fit

```mermaid
flowchart LR
    client["MCP client"]
    subgraph rs["Your MCP server"]
        sdk["mcp-auth SDK<br/>verify token, audience, scopes"]
        tools["MCP tools"]
        sdk --> tools
    end
    as["mcp-auth<br/>authorization server"]
    idp["Your identity provider<br/>OIDC, OAuth 2.0 or LDAP"]

    client <-->|"OAuth 2.1 + PKCE"| as
    as <-->|"Sign-in"| idp
    client -->|"Bearer access token"| sdk
```

## Start with your role

<div class="home-paths">
  <a class="home-path" href="./architecture">
    <strong>Deploy the authorization server</strong>
    <span>Understand the flow, configure a connector and work through the production checklist.</span>
  </a>
  <a class="home-path" href="./auth-client">
    <strong>Protect an MCP server</strong>
    <span>Add token validation, resource metadata and scopes with the Python, Go or TypeScript SDK.</span>
  </a>
  <a class="home-path" href="./demo-example">
    <strong>Try it locally</strong>
    <span>Run the complete Keycloak walkthrough on your own machine.</span>
  </a>
  <a class="home-path" href="./development">
    <strong>Contribute</strong>
    <span>Set up a checkout, run the tests and the shared SDK conformance cases.</span>
  </a>
</div>

</div>
