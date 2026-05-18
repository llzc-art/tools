<template>
  <div class="tool-panel">
    <h2>JSON 格式化 / 压缩</h2>
    <div class="card">
      <div class="form-group">
        <label>输入 JSON</label>
        <textarea v-model="input" placeholder='{"key":"value"}' class="input-textarea" rows="6"></textarea>
      </div>
      <div class="btn-group">
        <button @click="format" class="btn btn-primary">格式化</button>
        <button @click="compress" class="btn btn-secondary">压缩</button>
      </div>
      <div v-if="output" class="result-box">
        <div class="result-label">{{ resultLabel }}</div>
        <pre class="result-value result-pre" @click="copy(output)">{{ output }}</pre>
        <div v-if="saved !== null" class="result-info">压缩前: {{ before }} 字节 → 压缩后: {{ after }} 字节 (节省 {{ saved }} 字节)</div>
        <div class="result-hint">点击复制</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject } from 'vue'
import { apiPost, copyToClipboard } from '../api.js'

const showToast = inject('showToast')

function copy(text) {
  copyToClipboard(text).then(ok => showToast(ok ? '已复制到剪贴板' : '复制失败'))
}

const input = ref('')
const output = ref('')
const resultLabel = ref('')
const before = ref(0)
const after = ref(0)
const saved = ref(null)

async function format() {
  saved.value = null
  const res = await apiPost('/api/json/format', { input: input.value, indent: 2 })
  if (res.code === 0) {
    output.value = res.data.output
    resultLabel.value = '格式化结果'
  } else showToast(res.message)
}

async function compress() {
  const res = await apiPost('/api/json/compress', { input: input.value })
  if (res.code === 0) {
    output.value = res.data.output
    resultLabel.value = '压缩结果'
    before.value = res.data.before
    after.value = res.data.after
    saved.value = res.data.saved
  } else showToast(res.message)
}
</script>
