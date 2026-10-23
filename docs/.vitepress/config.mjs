import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { withMermaid } from 'vitepress-plugin-mermaid'

const docsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const repoDir = path.resolve(docsDir, '..')
const repoUrl = 'https://github.com/tavric-labs/mcp-auth'
const siteUrl = 'https://mcp-auth.tavric-labs.net'

// Links that leave docs/ (tests, examples, SECURITY, ...) point at repo files;
// send them to GitHub instead of failing the dead-link check.
function repoLinks(md) {
  md.core.ruler.push('repo-links', (state) => {
    const rel = state.env.relativePath
    if (!rel) return
    const from = path.dirname(path.join(docsDir, rel))
    const walk = (tokens) => {
      for (const t of tokens) {
        if (t.type === 'link_open') {
          const href = t.attrGet('href')
          if (href && !/^([a-z]+:|#|\/)/i.test(href)) {
            const [file, hash = ''] = href.split('#')
            const abs = path.resolve(from, file)
            if (abs.startsWith(repoDir + path.sep) && !abs.startsWith(docsDir + path.sep)) {
              const isDir = fs.existsSync(abs) && fs.statSync(abs).isDirectory()
              const target = path.relative(repoDir, abs).split(path.sep).join('/')
              t.attrSet('href', `${repoUrl}/${isDir ? 'tree' : 'blob'}/main/${target}${hash ? '#' + hash : ''}`)
            }
          }
        }
        if (t.children) walk(t.children)
      }
    }
    walk(state.tokens)
  })
}

const description =
  'Provider-neutral OAuth 2.1 authorization broker for the Model Context Protocol, with Python, Go and TypeScript SDKs.'

export default withMermaid({
  title: 'mcp-auth',
  titleTemplate: ':title | mcp-auth',
  description,
  lang: 'en-US',
  base: '/docs/',
  cleanUrls: true,
  lastUpdated: true,
  sitemap: { hostname: siteUrl },
  markdown: { config: repoLinks },
  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/docs/favicon.svg' }],
    ['meta', { name: 'theme-color', content: '#6d4aea' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:site_name', content: 'mcp-auth' }],
    ['meta', { property: 'og:title', content: 'mcp-auth documentation' }],
    ['meta', { property: 'og:description', content: description }],
    ['meta', { property: 'og:image', content: `${siteUrl}/docs/logo.svg` }],
    ['meta', { name: 'twitter:card', content: 'summary' }]
  ],
  mermaid: {
    theme: 'neutral',
    fontFamily: 'ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
    flowchart: { htmlLabels: true, curve: 'basis', padding: 14, wrappingWidth: 320, useMaxWidth: true },
    sequence: { mirrorActors: false, useMaxWidth: true },
    state: { useMaxWidth: true },
    class: { useMaxWidth: true }
  },
  themeConfig: {
    logo: '/logo.svg',
    siteTitle: 'mcp-auth',
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
      { text: 'Releases', link: `${repoUrl}/releases` }
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
    ],
    socialLinks: [{ icon: 'github', link: repoUrl }],
    editLink: { pattern: `${repoUrl}/edit/main/docs/:path`, text: 'Edit this page on GitHub' },
    lastUpdated: { text: 'Last updated', formatOptions: { dateStyle: 'medium' } },
    outline: { level: [2, 3], label: 'On this page' },
    docFooter: { prev: 'Previous', next: 'Next' },
    search: { provider: 'local', options: { detailedView: true } },
    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © Tavric Labs'
    }
  }
})
