import DefaultTheme from 'vitepress/theme'
import { h, onMounted, onUnmounted } from 'vue'
import VersionBanner from './VersionBanner.vue'
import VersionSwitcher from './VersionSwitcher.vue'
import './custom.css'

// Click a rendered Mermaid diagram to view it at natural size.
function openDiagram(svg) {
  const overlay = document.createElement('div')
  overlay.className = 'diagram-overlay'
  overlay.setAttribute('role', 'dialog')
  overlay.setAttribute('aria-label', 'Enlarged diagram')
  const clone = svg.cloneNode(true)
  const box = svg.viewBox && svg.viewBox.baseVal
  if (box && box.width) clone.setAttribute('width', String(box.width))
  clone.removeAttribute('style')
  overlay.appendChild(clone)
  const close = () => {
    overlay.remove()
    document.removeEventListener('keydown', onKey)
  }
  const onKey = (e) => e.key === 'Escape' && close()
  overlay.addEventListener('click', close)
  document.addEventListener('keydown', onKey)
  document.body.appendChild(overlay)
}

export default {
  extends: DefaultTheme,
  Layout: () =>
    h(DefaultTheme.Layout, null, {
      'nav-bar-content-after': () => h(VersionSwitcher),
      'doc-before': () => h(VersionBanner)
    }),
  setup() {
    const onClick = (e) => {
      const target = e.target instanceof Element ? e.target.closest('.mermaid') : null
      const svg = target && target.querySelector('svg')
      if (svg) openDiagram(svg)
    }
    onMounted(() => document.addEventListener('click', onClick))
    onUnmounted(() => document.removeEventListener('click', onClick))
  }
}
