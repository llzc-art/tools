<template>
  <div class="tool-panel">
    <h2>🔢 进制转换</h2>

    <div class="card">
      <div class="form-group">
        <label>输入数值</label>
        <input
          v-model="inputValue"
          type="text"
          class="input-text"
          placeholder="输入数字或带前缀的值 (如: 255, 0xFF, 0b1111, 0377)"
          @input="convert"
        />
      </div>

      <div class="base-grid">
        <div v-for="base in bases" :key="base.value" class="base-item">
          <div class="base-header">
            <span class="base-label">{{ base.label }}</span>
            <button class="copy-btn" @click="copy(base.value)" title="复制">📋</button>
          </div>
          <div :class="['base-value', { 'is-valid': isValid, 'is-current': activeBase === base.value }]" @click="setInput(base)">
            {{ results[base.value] || '-' }}
          </div>
          <div class="base-hint">{{ base.hint }}</div>
        </div>
      </div>
    </div>

    <div v-if="error" class="error-box">{{ error }}</div>

    <div class="card">
      <h3>常见转换参考</h3>
      <table class="format-table">
        <thead>
          <tr>
            <th>十进制</th>
            <th>十六进制</th>
            <th>二进制</th>
            <th>八进制</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="n in [1, 2, 4, 8, 10, 16, 32, 64, 100, 128, 255, 256, 512, 1024, 1000, 65535]" :key="n">
            <td><code>{{ n }}</code></td>
            <td><code>0x{{ n.toString(16).toUpperCase() }}</code></td>
            <td><code>{{ n.toString(2) }}</code></td>
            <td><code>0{{ n.toString(8) }}</code></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, inject } from 'vue'

const showToast = inject('showToast')

const inputValue = ref('')
const activeBase = ref(null)
const error = ref('')
const results = reactive({
  2: '',
  8: '',
  10: '',
  16: '',
  36: '',
})

const bases = [
  { value: 2, label: '二进制', hint: 'Binary' },
  { value: 8, label: '八进制', hint: 'Octal' },
  { value: 10, label: '十进制', hint: 'Decimal' },
  { value: 16, label: '十六进制', hint: 'Hex' },
  { value: 36, label: '36进制', hint: 'Base36' },
]

function detectBase(str) {
  const s = str.trim()
  if (s.startsWith('0x') || s.startsWith('0X')) return 16
  if (s.startsWith('0b') || s.startsWith('0B')) return 2
  if (s.startsWith('0') && s.length > 1 && /^[0-7]+$/.test(s)) return 8
  return 10
}

function convert() {
  error.value = ''
  const val = inputValue.value.trim()
  if (!val) {
    Object.keys(results).forEach(k => results[k] = '')
    return
  }

  let num
  const base = detectBase(val)
  const cleanVal = val.replace(/^0[xbX]/i, '')

  if (base === 36) {
    num = parseInt(cleanVal, 36)
  } else {
    num = parseInt(cleanVal, base)
  }

  if (isNaN(num)) {
    error.value = '无效的数值格式'
    Object.keys(results).forEach(k => results[k] = '')
    return
  }

  if (num > Number.MAX_SAFE_INTEGER) {
    error.value = '数值超出安全范围'
    return
  }

  results[2] = '0b' + num.toString(2)
  results[8] = '0' + num.toString(8)
  results[10] = num.toString(10)
  results[16] = '0x' + num.toString(16).toUpperCase()
  results[36] = num.toString(36).toUpperCase()
}

function setInput(base) {
  activeBase.value = base.value
  if (!results[base.value]) return
  
  let displayVal = results[base.value]
  if (base.value === 10) {
    displayVal = inputValue.value.trim().replace(/^0+/, '') || '0'
  }
  inputValue.value = displayVal
  convert()
}

function copy(base) {
  const val = results[base]
  if (!val) return
  navigator.clipboard.writeText(val).then(() => {
    showToast('已复制: ' + val)
  })
}

const isValid = ref(false)
</script>

<style scoped>
.base-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 0.75rem;
  margin-top: 1rem;
}

.base-item {
  background: #f8fafc;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.75rem;
}

.base-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.4rem;
}

.base-label {
  font-size: 0.78rem;
  font-weight: 600;
  color: var(--text-secondary);
}

.copy-btn {
  background: none;
  border: none;
  cursor: pointer;
  font-size: 0.75rem;
  opacity: 0.6;
  transition: opacity 0.15s;
  padding: 0.1rem;
}

.copy-btn:hover {
  opacity: 1;
}

.base-value {
  font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--text);
  padding: 0.4rem;
  background: white;
  border-radius: 4px;
  border: 1px solid var(--border);
  cursor: pointer;
  transition: all 0.15s;
  word-break: break-all;
}

.base-value:hover {
  border-color: var(--primary);
  background: var(--primary-light);
}

.base-value.is-current {
  border-color: var(--primary);
  background: var(--primary-light);
  color: var(--primary);
}

.base-hint {
  font-size: 0.68rem;
  color: var(--text-secondary);
  margin-top: 0.3rem;
  text-align: center;
}
</style>