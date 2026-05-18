<template>
  <div class="tool-panel">
    <h2>JWT 解码</h2>
    <div class="card">
      <div class="form-group">
        <label>JWT Token</label>
        <textarea v-model="input" placeholder="粘贴 JWT Token (三段以 . 分隔)" class="input-textarea" rows="4"></textarea>
      </div>
      <button @click="decode" class="btn btn-primary">解码</button>
      <div v-if="result" class="result-box">
        <div class="result-label">
          解码结果
          <span :class="result.valid ? 'tag-success' : 'tag-error'">{{ result.valid ? '有效' : '无效' }}</span>
          <span v-if="result.format" class="tag-info">{{ result.format === 'url' ? 'Base64URL' : 'Standard Base64' }}</span>
        </div>
        <div v-if="result.error" class="error-msg">{{ result.error }}</div>
        <template v-if="result.valid">
          <div v-if="result.header" class="json-section">
            <div class="section-title">Header <span class="section-hint">算法与类型</span></div>
            <pre class="result-value result-pre" @click="copy(JSON.stringify(result.header, null, 2))">{{ JSON.stringify(result.header, null, 2) }}</pre>
          </div>
          <div v-if="result.payload" class="json-section">
            <div class="section-title">Payload <span class="section-hint">数据声明</span></div>
            <pre class="result-value result-pre" @click="copy(JSON.stringify(result.payload, null, 2))">{{ JSON.stringify(result.payload, null, 2) }}</pre>
            <div v-if="result.timeFields && Object.keys(result.timeFields).length" class="time-fields">
              <div v-for="(formatted, key) in result.timeFields" :key="key" class="time-field">
                <span class="time-key">{{ key }}</span>
                <span class="time-value">{{ formatted }}</span>
                <span class="time-rel">{{ relativeTime(formatted) }}</span>
              </div>
            </div>
          </div>
          <div v-if="result.signature" class="json-section">
            <div class="section-title">Signature <span class="section-hint">签名 (hex)</span></div>
            <pre class="result-value result-pre sig-pre" @click="copy(result.signature)">{{ result.signature }}</pre>
          </div>
        </template>
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
const result = ref(null)

function relativeTime(dateStr) {
  const d = new Date(dateStr.replace(' ', 'T'))
  const now = new Date()
  const diff = d - now
  const absDiff = Math.abs(diff)
  const isFuture = diff > 0

  if (absDiff < 60000) return isFuture ? '即将' : '刚刚'
  if (absDiff < 3600000) {
    const mins = Math.floor(absDiff / 60000)
    return isFuture ? `${mins}分钟后` : `${mins}分钟前`
  }
  if (absDiff < 86400000) {
    const hours = Math.floor(absDiff / 3600000)
    return isFuture ? `${hours}小时后` : `${hours}小时前`
  }
  const days = Math.floor(absDiff / 86400000)
  return isFuture ? `${days}天后` : `${days}天前`
}

async function decode() {
  result.value = null
  const res = await apiPost('/api/jwt/decode', { token: input.value.trim() })
  if (res.code === 0) result.value = res.data
  else showToast(res.message)
}
</script>

<style scoped>
.tag-info {
  font-size: 0.72rem;
  padding: 0.1rem 0.45rem;
  border-radius: 3px;
  background: rgba(59, 130, 246, 0.1);
  color: #3b82f6;
  margin-left: 0.4rem;
}

.section-hint {
  font-size: 0.72rem;
  color: var(--text-secondary);
  font-weight: 400;
  margin-left: 0.5rem;
}

.time-fields {
  margin-top: 0.4rem;
  padding: 0.5rem 0.65rem;
  background: rgba(59, 130, 246, 0.04);
  border-radius: 4px;
  border: 1px solid rgba(59, 130, 246, 0.12);
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem 1.2rem;
}

.time-field {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  font-size: 0.78rem;
}

.time-key {
  font-weight: 600;
  color: var(--primary);
  font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  font-size: 0.74rem;
}

.time-value {
  color: var(--text-primary);
  font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  font-size: 0.74rem;
}

.time-rel {
  color: var(--text-secondary);
  font-size: 0.7rem;
}

.sig-pre {
  word-break: break-all;
  font-size: 0.75rem;
  line-height: 1.5;
}
</style>
