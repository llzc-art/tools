<template>
  <div class="tool-panel">
    <h2>URL 编解码</h2>
    <div class="card">
      <div class="form-group">
        <label>输入字符串</label>
        <textarea v-model="input" placeholder="输入要编解码的字符串" class="input-textarea" rows="3"></textarea>
      </div>
      <div class="btn-group">
        <button @click="encode" class="btn btn-primary">URL 编码</button>
        <button @click="decode" class="btn btn-secondary">URL 解码</button>
      </div>
      <div v-if="output" class="result-box">
        <div class="result-label">结果</div>
        <div class="result-value" @click="copy(output)">{{ output }}</div>
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

async function encode() {
  const res = await apiPost('/api/url/encode', { input: input.value })
  if (res.code === 0) output.value = res.data.output
  else showToast(res.message)
}

async function decode() {
  const res = await apiPost('/api/url/decode', { input: input.value })
  if (res.code === 0) output.value = res.data.output
  else showToast(res.message)
}
</script>
