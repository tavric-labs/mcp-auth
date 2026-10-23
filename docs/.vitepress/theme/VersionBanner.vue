<script setup>
import { useData } from 'vitepress'

const { theme } = useData()
const version = theme.value.docsVersion
const latest = theme.value.docsRoot
</script>

<template>
  <div v-if="version" class="version-banner">
    You are reading the documentation for <strong>{{ version }}</strong>.
    <a :href="latest">Switch to the latest docs</a>
  </div>
</template>

<style scoped>
.version-banner {
  margin-bottom: 24px; padding: 10px 14px; font-size: 14px;
  color: var(--vp-c-text-1); background: var(--vp-c-brand-soft);
  border: 1px solid var(--vp-c-brand-1); border-radius: 8px;
}
</style>
