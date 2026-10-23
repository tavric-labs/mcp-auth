#!/usr/bin/env node
// Prepare a versioned docs build: take the markdown (and images) from a
// release tag's docs/ and lay it over the current site's docs/ so the tag is
// rendered with today's theme. Landing-page links to pages the tag does not
// have are pointed at /architecture.
//
// usage: docs-version-overlay.mjs <tag-docs-dir> <site-docs-dir>
import fs from 'node:fs'
import path from 'node:path'

const [src, dest] = process.argv.slice(2)
if (!src || !dest) {
  console.error('usage: docs-version-overlay.mjs <tag-docs-dir> <site-docs-dir>')
  process.exit(2)
}

for (const entry of fs.readdirSync(dest)) {
  if (entry === '.vitepress' || entry === 'public' || entry === 'index.md') continue
  fs.rmSync(path.join(dest, entry), { recursive: true, force: true })
}
for (const entry of fs.readdirSync(src)) {
  if (entry === 'index.md' || entry === '.vitepress' || entry === 'public') continue
  fs.cpSync(path.join(src, entry), path.join(dest, entry), { recursive: true })
}

const indexPath = path.join(dest, 'index.md')
const exists = (link) => fs.existsSync(path.join(dest, `${link.replace(/^\.?\//, '')}.md`))
const fixed = fs
  .readFileSync(indexPath, 'utf8')
  .replace(/(link:\s*)(\/[A-Za-z0-9_-]+)\s*$/gm, (m, k, l) => (exists(l) ? m : `${k}/architecture`))
  .replace(/href="\.\/([A-Za-z0-9_-]+)"/g, (m, l) => (exists(l) ? m : 'href="./architecture"'))
fs.writeFileSync(indexPath, fixed)
console.log(`overlaid ${src} onto ${dest}`)
