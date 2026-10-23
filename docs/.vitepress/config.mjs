import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const docsDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const repoDir = path.resolve(docsDir, '..')
const repoUrl = 'https://github.com/mcp-runtime/mcp-auth'

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

export default {
  title: 'mcp-auth',
  description: 'Provider-neutral OAuth 2.1 authorization broker for the Model Context Protocol',
  base: '/docs/',
  cleanUrls: true,
  lastUpdated: false,
  markdown: { config: repoLinks },
  themeConfig: {
    nav: [{ text: 'GitHub', link: 'https://github.com/mcp-runtime/mcp-auth' }],
    sidebar: [
      { text: 'Overview', items: [
        { text: 'Documentation index', link: '/README' },
        { text: 'Choose a flow', link: '/use-cases' },
        { text: 'Architecture', link: '/architecture' },
        { text: 'Security model', link: '/security-model' } ] },
      { text: 'Components', items: [
        { text: 'Auth server', link: '/auth-server' },
        { text: 'Login methods', link: '/login-methods' },
        { text: 'Auth client SDKs', link: '/auth-client' },
        { text: 'External credentials', link: '/external-credentials' } ] },
      { text: 'Guides', items: [
        { text: 'Demo example', link: '/demo-example' },
        { text: 'Development', link: '/development' },
        { text: 'Codex refresh reproduction', link: '/codex-refresh-reproduction' } ] }
    ],
    socialLinks: [{ icon: 'github', link: 'https://github.com/mcp-runtime/mcp-auth' }],
    search: { provider: 'local' }
  }
}
