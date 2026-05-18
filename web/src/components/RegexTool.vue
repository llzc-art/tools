<template>
  <div class="tool-panel">
    <h2>正则表达式测试</h2>
    <div class="card">
      <div class="form-group">
        <label>正则表达式</label>
        <input v-model="pattern" placeholder="如: \d+ 或 [a-z]+" class="input-field" />
      </div>
      <div class="form-group">
        <label>测试字符串</label>
        <textarea v-model="input" placeholder="输入要匹配的字符串" class="input-textarea" rows="4"></textarea>
      </div>
      <div class="form-group">
        <label>替换字符串 (可选)</label>
        <input v-model="replace" placeholder="留空则仅匹配" class="input-field" />
      </div>
      <div class="btn-group">
        <button @click="match" class="btn btn-primary">匹配测试</button>
        <button @click="replaceFn" class="btn btn-secondary">替换</button>
      </div>
      <div v-if="output" class="result-box">
        <div class="result-label">{{ resultLabel }}</div>
        <pre class="result-value result-pre" @click="copy(output)">{{ output }}</pre>
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

const pattern = ref('')
const input = ref('')
const replace = ref('')
const output = ref('')
const resultLabel = ref('')

async function match() {
  const res = await apiPost('/api/regex/match', { pattern: pattern.value, input: input.value })
  if (res.code === 0) {
    resultLabel.value = res.data.matched ? `匹配成功 (${res.data.matches.length} 个结果)` : '无匹配'
    output.value = res.data.matches.join('\n')
  } else showToast(res.message)
}

async function replaceFn() {
  const res = await apiPost('/api/regex/replace', { pattern: pattern.value, input: input.value, replace: replace.value })
  if (res.code === 0) {
    resultLabel.value = '替换结果'
    output.value = res.data.output
  } else showToast(res.message)
}
</script>
