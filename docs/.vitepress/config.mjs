import { defineDocsConfig } from '@tavric-labs/docs-theme/config'

// Served at /docs/ on the shared host; versioned builds (DOCS_BASE, DOCS_VERSION,
// DOCS_REF) are produced by .github/workflows/docs-version.yml.
export default defineDocsConfig({
  name: 'mcp-auth',
  repo: 'tavric-labs/mcp-auth',
  siteUrl: 'https://mcp-auth.tavric-labs.net',
  description:
    'Provider-neutral OAuth 2.1 authorization broker for the Model Context Protocol, with Python, Go and TypeScript SDKs.',
  defaultBase: '/docs/',
  docsRoot: '/docs/',
  nav: [
    { text: 'Get started', link: '/use-cases', activeMatch: '^/(use-cases|README)' },
    { text: 'Concepts', link: '/architecture', activeMatch: '^/(architecture|security-model)' },
    { text: 'Reference', items: [
      { text: 'Authorization server', link: '/auth-server' },
      { text: 'Login methods', link: '/login-methods' },
      { text: 'Auth client SDKs', link: '/auth-client' },
      { text: 'External credentials', link: '/external-credentials' } ] },
    { text: 'Guides', items: [
      { text: 'Demo and Keycloak walkthrough', link: '/demo-example' },
      { text: 'Local development', link: '/development' } ] },
    { text: 'Releases', link: 'https://github.com/tavric-labs/mcp-auth/releases' }
  ],
  sidebar: [
    { text: 'Get started', items: [
      { text: 'Documentation index', link: '/README' },
      { text: 'Choose a flow', link: '/use-cases' } ] },
    { text: 'Concepts', items: [
      { text: 'Architecture', link: '/architecture' },
      { text: 'Security model', link: '/security-model' } ] },
    { text: 'Authorization server', items: [
      { text: 'Server and configuration', link: '/auth-server' },
      { text: 'Login methods', link: '/login-methods' },
      { text: 'External credentials', link: '/external-credentials' } ] },
    { text: 'Resource servers', items: [
      { text: 'Auth client SDKs', link: '/auth-client' } ] },
    { text: 'Guides', items: [
      { text: 'Demo and Keycloak walkthrough', link: '/demo-example' },
      { text: 'Local development', link: '/development' },
      { text: 'Codex refresh reproduction', link: '/codex-refresh-reproduction' } ] }
  ]
})
