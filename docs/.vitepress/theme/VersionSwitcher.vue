<script setup>
import { onMounted, ref } from 'vue'
import { useData } from 'vitepress'

const { theme, page } = useData()
const root = theme.value.docsRoot
const current = theme.value.docsVersion || ''
const versions = ref([])

onMounted(async () => {
  try {
    const res = await fetch(`${root}versions.json`, { cache: 'no-cache' })
    if (res.ok) versions.value = await res.json()
  } catch {
    // The switcher is optional; the docs work without it.
  }
})

function go(event) {
  const target = event.target.value
  const rel = page.value.relativePath.replace(/(^|\/)index\.md$/, '$1').replace(/\.md$/, '')
  window.location.href = `${root}${target ? target + '/' : ''}${rel}`
}
</script>

<template>
  <label v-if="versions.length" class="version-switcher">
    <span class="sr-only">Documentation version</span>
    <select :value="current" @change="go">
      <option value="">Latest</option>
      <option v-for="v in versions" :key="v" :value="v">{{ v }}</option>
    </select>
  </label>
</template>

<style scoped>
.version-switcher { display: flex; align-items: center; margin-left: 12px; }
select {
  height: 32px; padding: 0 8px; font-size: 13px; cursor: pointer;
  color: var(--vp-c-text-1); background: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-divider); border-radius: 8px;
}
select:hover { border-color: var(--vp-c-brand-1); }
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
@media (max-width: 767px) { .version-switcher { display: none; } }
</style>
