<template>
  <div class="tool-panel">
    <h2>Base64 编解码</h2>
    <div class="card">
      <div class="form-group">
        <label>编码类型</label>
        <div class="encoding-tabs">
          <button v-for="e in encodings" :key="e.value" :class="['tab-btn', { active: encoding === e.value }]" @click="encoding = e.value" :title="e.desc">{{ e.label }}</button>
        </div>
      </div>
      <div class="base64-panels">
        <div class="base64-panel">
          <div class="form-group">
            <label>输入字符串</label>
            <textarea v-model="input" placeholder="输入要编码的字符串" class="input-textarea" rows="5"></textarea>
          </div>
          <button @click="encode" class="btn btn-primary">编码 ↓</button>
          <div v-if="encodeOutput" class="result-box">
            <div class="result-label">编码结果</div>
            <div class="result-value" @click="copy(encodeOutput)">{{ encodeOutput }}</div>
            <div class="result-hint">点击复制</div>
          </div>
        </div>
        <div class="base64-panel">
          <div class="form-group">
            <label>输入 Base64 字符串</label>
            <textarea v-model="decodeInput" placeholder="输入要解码的 Base64 字符串" class="input-textarea" rows="5"></textarea>
          </div>
          <button @click="decode" class="btn btn-primary">解码 ↓</button>
          <div v-if="decodeOutput" class="result-box">
            <div class="result-label">解码结果</div>
            <div class="result-value" @click="copy(decodeOutput)">{{ decodeOutput }}</div>
            <div class="result-hint">点击复制</div>
          </div>
          <div v-if="decodeError" class="error-box">{{ decodeError }}</div>
        </div>
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

const encodings = [
  { value: 'standard', label: 'Standard', desc: '标准 Base64（A-Za-z0-9+/，带 = 填充）' },
  { value: 'url', label: 'Base64URL', desc: 'URL 安全 Base64（A-Za-z0-9-_，带 = 填充）' },
  { value: 'raw', label: 'Standard-No-Padding', desc: '标准 Base64 无填充（A-Za-z0-9+/）' },
  { value: 'url_raw', label: 'Base64URL-No-Padding', desc: 'URL 安全 Base64 无填充（A-Za-z0-9-_）' },
]
const encoding = ref('standard')

const input = ref('')
const encodeOutput = ref('')

const decodeInput = ref('')
const decodeOutput = ref('')
const decodeError = ref('')

async function encode() {
  encodeOutput.value = ''
  const res = await apiPost('/api/base64/encode', { input: input.value, encoding: encoding.value })
  if (res.code === 0) encodeOutput.value = res.data.output
  else showToast(res.message)
}

async function decode() {
  decodeError.value = ''
  decodeOutput.value = ''
  const res = await apiPost('/api/base64/decode', { input: decodeInput.value, encoding: encoding.value })
  if (res.code === 0) decodeOutput.value = res.data.output
  else decodeError.value = res.message
}
</script>

<style scoped>
.encoding-tabs {
  display: flex;
  gap: 0.35rem;
  flex-wrap: wrap;
}

.tab-btn {
  padding: 0.3rem 0.7rem;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--card-bg);
  color: var(--text-secondary);
  font-size: 0.78rem;
  cursor: pointer;
  transition: all 0.15s;
}

.tab-btn:hover {
  border-color: var(--primary);
  color: var(--primary);
}

.tab-btn.active {
  background: var(--primary);
  border-color: var(--primary);
  color: #fff;
}

.base64-panels {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
  margin-top: 0.75rem;
}

.base64-panel {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

@media (max-width: 768px) {
  .base64-panels {
    grid-template-columns: 1fr;
  }
}
</style>
