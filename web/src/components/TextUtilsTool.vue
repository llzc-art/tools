<template>
  <div class="tool-panel">
    <h2>🧹 文本处理</h2>

    <div class="card">
      <div class="form-group">
        <label>原始文本</label>
        <textarea class="input-textarea" v-model="input" rows="7" placeholder="输入要处理的文本，按行操作..."></textarea>
      </div>

      <div class="btn-group">
        <button class="btn btn-outline btn-sm" @click="dedupe">按行去重</button>
        <button class="btn btn-outline btn-sm" @click="sortLines('asc')">升序排序</button>
        <button class="btn btn-outline btn-sm" @click="sortLines('desc')">降序排序</button>
        <button class="btn btn-outline btn-sm" @click="removeEmpty">去空行</button>
        <button class="btn btn-outline btn-sm" @click="trimLines">去首尾空格</button>
        <button class="btn btn-outline btn-sm" @click="toUpper">转大写</button>
        <button class="btn btn-outline btn-sm" @click="toLower">转小写</button>
        <button class="btn btn-outline btn-sm" @click="reverse">反转文本</button>
        <button class="btn btn-outline btn-sm" @click="shuffleLines">随机打乱</button>
      </div>

      <div class="form-group" style="margin-top:0.75rem">
        <label>处理结果</label>
        <textarea class="input-textarea" v-model="output" rows="7" readonly></textarea>
      </div>
      <div class="action-row">
        <button class="btn btn-primary btn-sm" @click="copy(output)">复制结果</button>
        <span class="action-info">共 {{ lineCount }} 行</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, inject } from 'vue'

const showToast = inject('showToast')
const input = ref('')
const output = ref('')

const lineCount = computed(() => output.value === '' ? 0 : output.value.split('\n').length)

function getLines() {
  return input.value.split('\n')
}
function setLines(lines) {
  output.value = lines.join('\n')
}
function dedupe() {
  const seen = new Set()
  setLines(getLines().filter(l => {
    const k = l.trim()
    if (seen.has(k)) return false
    seen.add(k)
    return true
  }))
  showToast('已按行去重')
}
function sortLines(order) {
  const lines = getLines().sort((a, b) => order === 'asc' ? a.localeCompare(b, 'zh') : b.localeCompare(a, 'zh'))
  setLines(lines)
}
function removeEmpty() {
  setLines(getLines().filter(l => l.trim() !== ''))
}
function trimLines() {
  setLines(getLines().map(l => l.trim()))
}
function toUpper() { output.value = input.value.toUpperCase() }
function toLower() { output.value = input.value.toLowerCase() }
function reverse() { output.value = input.value.split('').reverse().join('') }
function shuffleLines() {
  const a = getLines()
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[a[i], a[j]] = [a[j], a[i]]
  }
  setLines(a)
}
function copy(text) {
  if (!text) { showToast('结果为空'); return }
  navigator.clipboard.writeText(text).then(() => showToast('已复制结果'))
}
</script>

<style scoped>
.action-row { display: flex; align-items: center; gap: 0.75rem; margin-top: 0.5rem; }
.action-info { font-size: 0.78rem; color: var(--text-secondary); }
</style>
