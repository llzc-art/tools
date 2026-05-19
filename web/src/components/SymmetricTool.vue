<template>
  <div class="tool-panel">
    <h2>🔑 对称加密</h2>
    <div class="card">
      <div class="form-group">
        <label>选择算法</label>
        <div class="algo-group">
          <button
            v-for="a in algos"
            :key="a.id"
            @click="selectAlgo(a.id)"
            :class="['algo-btn', algo === a.id ? 'algo-btn-active' : '']"
          >
            <span class="algo-icon">{{ a.icon }}</span>
            <span class="algo-name">{{ a.name }}</span>
          </button>
        </div>
      </div>

      <div class="form-group">
        <label>加密模式</label>
        <div class="algo-group">
          <button
            v-for="m in availableModes"
            :key="m.id"
            @click="mode = m.id"
            :class="['algo-btn', mode === m.id ? 'algo-btn-active' : '']"
            :disabled="false"
          >
            {{ m.name }}
          </button>
        </div>
        <div v-if="mode === 'gcm'" class="mode-hint">GCM 认证加密模式：自动生成随机 nonce，密文包含 nonce(12字节) + 密文 + 认证标签(16字节)</div>
      </div>

      <div class="form-group">
        <label>操作类型</label>
        <div class="algo-group">
          <button
            @click="operation = 'encrypt'"
            :class="['algo-btn', operation === 'encrypt' ? 'algo-btn-active' : '']"
          >加密</button>
          <button
            @click="operation = 'decrypt'"
            :class="['algo-btn', operation === 'decrypt' ? 'algo-btn-active' : '']"
          >解密</button>
        </div>
      </div>

      <div v-if="needsPadding" class="form-group">
        <label>填充方式</label>
        <div class="algo-group">
          <button
            v-for="p in paddings"
            :key="p.id"
            @click="padding = p.id"
            :class="['algo-btn', padding === p.id ? 'algo-btn-active' : '']"
          >{{ p.name }}</button>
        </div>
        <div v-if="padding === 'none'" class="mode-hint mode-hint-warn">NoPadding：明文长度必须是块大小的整数倍，否则加密失败</div>
      </div>

      <div v-if="needsIV" class="form-group">
        <label>IV (Hex) <span class="hint">{{ ivHint }}</span></label>
        <div class="iv-row">
          <input
            v-model="iv"
            placeholder="留空则使用默认IV"
            class="input-field"
          />
          <button @click="generateIV" class="btn btn-sm">随机生成</button>
        </div>
      </div>

      <div class="form-row">
        <div class="form-group" style="flex:3">
          <label>{{ operation === 'encrypt' ? '明文' : '密文 (Hex)' }}</label>
          <textarea
            v-model="input"
            :placeholder="operation === 'encrypt' ? '输入要加密的明文' : '输入要解密的密文(Hex格式)'"
            class="input-textarea"
            rows="3"
          ></textarea>
        </div>
        <div class="form-group" style="flex:2">
          <label>密钥 <span class="key-format-switch">
            <button :class="['fmt-btn', keyFormat === 'text' ? 'fmt-btn-active' : '']" @click="keyFormat = 'text'">明文</button>
            <button :class="['fmt-btn', keyFormat === 'hex' ? 'fmt-btn-active' : '']" @click="keyFormat = 'hex'">Hex</button>
          </span> <span class="hint">{{ keyHint }}</span></label>
          <textarea
            v-model="key"
            :placeholder="keyPlaceholder"
            class="input-textarea"
            rows="3"
          ></textarea>
          <button @click="generateKey" class="btn btn-sm" style="margin-top:0.4rem">随机生成密钥</button>
        </div>
      </div>

      <button @click="compute" class="btn btn-primary" :disabled="!input.trim() || !key.trim()">
        {{ operation === 'encrypt' ? '加密' : '解密' }}
      </button>

      <div v-if="output" class="result-box">
        <div class="result-label">{{ operation === 'encrypt' ? '密文' : '明文' }}</div>
        <div class="result-value" @click="copy(output)">{{ output }}</div>
        <div class="result-hint">点击复制</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, inject } from 'vue'
import { apiPost, copyToClipboard } from '../api.js'

const showToast = inject('showToast')
function copy(text) {
  copyToClipboard(text).then(ok => showToast(ok ? '已复制到剪贴板' : '复制失败'))
}

const input = ref('')
const output = ref('')
const algo = ref('aes')
const mode = ref('cbc')
const operation = ref('encrypt')
const key = ref('')
const keyFormat = ref('hex')
const padding = ref('pkcs7')
const iv = ref('')

const paddings = [
  { id: 'pkcs7', name: 'PKCS7' },
  { id: 'zero', name: 'ZeroPadding' },
  { id: 'none', name: 'NoPadding' },
]

// ECB/CBC 需要填充，流模式和 GCM 不需要
const needsPadding = computed(() => {
  return mode.value === 'ecb' || mode.value === 'cbc'
})

// CBC/CFB/OFB/CTR 需要 IV，ECB 和 GCM 不需要
const needsIV = computed(() => {
  return ['cbc', 'cfb', 'ofb', 'ctr'].includes(mode.value)
})

const ivByteLen = computed(() => {
  switch (algo.value) {
    case 'aes': return 16
    case 'des': return 8
    case '3des': return 8
    case 'sm4': return 16
    default: return 16
  }
})

const ivHint = computed(() => `${ivByteLen.value}字节 / ${ivByteLen.value * 2}个hex字符`)

const algos = [
  { id: 'aes', name: 'AES', icon: '🔒' },
  { id: 'des', name: 'DES', icon: '🔢' },
  { id: '3des', name: '3DES', icon: '🔐' },
  { id: 'sm4', name: 'SM4', icon: '🇨🇳' },
]

const keyByteLen = computed(() => {
  switch (algo.value) {
    case 'aes': return 32
    case 'des': return 8
    case '3des': return 24
    case 'sm4': return 16
    default: return 16
  }
})

const keyHint = computed(() => {
  if (keyFormat.value === 'hex') return `${keyByteLen.value}字节 / ${keyByteLen.value * 2}个hex字符`
  return `${keyByteLen.value}个字符`
})
const keyPlaceholder = computed(() => {
  if (keyFormat.value === 'hex') return `输入${keyByteLen.value * 2}位hex密钥`
  return `输入${keyByteLen.value}个字符的密钥`
})

const allModes = [
  { id: 'ecb', name: 'ECB' },
  { id: 'cbc', name: 'CBC' },
  { id: 'cfb', name: 'CFB' },
  { id: 'ofb', name: 'OFB' },
  { id: 'ctr', name: 'CTR' },
  { id: 'gcm', name: 'GCM' },
]

const availableModes = computed(() => {
  // DES/3DES 不支持 GCM
  if (algo.value === 'des' || algo.value === '3des') {
    return allModes.filter(m => m.id !== 'gcm')
  }
  return allModes
})

function selectAlgo(id) {
  algo.value = id
  output.value = ''
  // 如果当前 GCM 但新算法不支持，回退到 CBC
  if (mode.value === 'gcm' && (id === 'des' || id === '3des')) {
    mode.value = 'cbc'
  }
}

function generateKey() {
  const bytes = new Uint8Array(keyByteLen.value)
  crypto.getRandomValues(bytes)
  if (keyFormat.value === 'hex') {
    key.value = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
  } else {
    key.value = Array.from(bytes).map(b => String.fromCharCode(33 + (b % 94))).join('')
  }
}

function generateIV() {
  const bytes = new Uint8Array(ivByteLen.value)
  crypto.getRandomValues(bytes)
  iv.value = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

async function compute() {
  if (!input.value.trim() || !key.value.trim()) return
  const res = await apiPost('/api/symmetric/compute', {
    algo: algo.value,
    mode: mode.value,
    operation: operation.value,
    input: input.value,
    key: key.value,
    keyFormat: keyFormat.value,
    padding: padding.value,
    iv: iv.value,
  })
  if (res.code === 0) output.value = res.data.output
  else showToast(res.message)
}
</script>

<style scoped>
.algo-group {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.algo-btn {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.5rem 1rem;
  border: 1.5px solid var(--border);
  border-radius: 8px;
  background: white;
  cursor: pointer;
  font-size: 0.875rem;
  color: var(--text);
  transition: all 0.2s;
}

.algo-btn:hover {
  border-color: var(--primary);
  color: var(--primary);
  background: #f8f7ff;
}

.algo-btn-active {
  border-color: var(--primary);
  background: var(--primary);
  color: white;
}

.algo-btn-active:hover {
  background: var(--primary-hover, #4338ca);
  color: white;
}

.algo-icon { font-size: 1rem; }
.algo-name { font-weight: 500; }

.form-row {
  display: flex;
  gap: 1rem;
}

.hint {
  font-weight: 400;
  font-size: 0.8rem;
  color: var(--text-secondary);
}

.key-format-switch {
  display: inline-flex;
  margin-left: 0.3rem;
  border: 1px solid var(--border);
  border-radius: 4px;
  overflow: hidden;
  vertical-align: middle;
}
.fmt-btn {
  padding: 0.1rem 0.5rem;
  font-size: 0.72rem;
  border: none;
  background: white;
  color: var(--text-secondary);
  cursor: pointer;
  transition: all 0.15s;
}
.fmt-btn + .fmt-btn {
  border-left: 1px solid var(--border);
}
.fmt-btn-active {
  background: var(--primary);
  color: white;
}

.btn-sm {
  padding: 0.3rem 0.75rem;
  font-size: 0.78rem;
  border: 1.5px solid var(--primary);
  color: var(--primary);
  background: white;
  border-radius: 6px;
  cursor: pointer;
}

.btn-sm:hover {
  background: var(--primary);
  color: white;
}

.mode-hint {
  margin-top: 0.35rem;
  padding: 0.4rem 0.65rem;
  background: #f0fdf4;
  border: 1px solid #bbf7d0;
  border-radius: 6px;
  font-size: 0.78rem;
  color: #15803d;
  line-height: 1.5;
}
.mode-hint-warn {
  background: #fffbeb;
  border-color: #fde68a;
  color: #b45309;
}

.iv-row {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

.input-field {
  flex: 1;
  padding: 0.45rem 0.65rem;
  border: 1.5px solid var(--border);
  border-radius: 6px;
  font-family: monospace;
  font-size: 0.82rem;
  outline: none;
  transition: border-color 0.2s;
}
.input-field:focus {
  border-color: var(--primary);
}
</style>
