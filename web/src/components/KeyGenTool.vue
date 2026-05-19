<template>
  <div class="tool-panel">
    <h2>🗝️ 密钥生成</h2>
    <div class="card">
      <!-- 密钥类型选择 -->
      <div class="form-group">
        <label>密钥类型</label>
        <div class="type-grid">
          <button
            v-for="t in keyTypes"
            :key="t.type"
            @click="selectType(t.type)"
            :class="['type-card', selectedType === t.type ? 'type-card-active' : '']"
          >
            <div class="type-icon">{{ t.icon }}</div>
            <div class="type-name">{{ t.name }}</div>
            <div v-if="t.tag" class="type-tag">{{ t.tag }}</div>
          </button>
        </div>
      </div>

      <!-- 密钥长度选择 -->
      <div v-if="currentTypeInfo?.keyBits" class="form-group">
        <label>密钥长度</label>
        <div class="algo-group">
          <button
            v-for="b in currentTypeInfo.keyBits"
            :key="b"
            @click="keyBits = b"
            :class="['algo-btn', keyBits === b ? 'algo-btn-active' : '']"
          >{{ b }} bit</button>
        </div>
      </div>

      <button @click="generate" class="btn btn-primary" :disabled="generating">
        {{ generating ? '生成中...' : '生成密钥对' }}
      </button>

      <div v-if="result" class="result-box">
        <div class="result-header">
          <span class="result-label">{{ result.algo }} {{ result.bits ? result.bits + 'bit' : '' }}</span>
          <div class="result-actions">
            <button @click="downloadFile('public', result.publicKey)" class="btn btn-sm">下载公钥</button>
            <button @click="downloadFile('private', result.privateKey)" class="btn btn-sm">下载私钥</button>
          </div>
        </div>

        <div class="key-section">
          <div class="key-header">
            <span class="key-title">公钥</span>
            <button @click="copy(result.publicKey)" class="btn-copy">复制</button>
          </div>
          <div class="key-content">{{ result.publicKey }}</div>
        </div>

        <div class="key-section">
          <div class="key-header">
            <span class="key-title">私钥</span>
            <button @click="copy(result.privateKey)" class="btn-copy">复制</button>
          </div>
          <div class="key-content private-key">{{ result.privateKey }}</div>
        </div>
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

const selectedType = ref('rsa')
const keyBits = ref(2048)
const result = ref(null)
const generating = ref(false)

const keyTypes = [
  { type: 'rsa', name: 'RSA', icon: '🔐', tag: null, keyBits: [1024, 2048, 3072, 4096] },
  { type: 'ecdsa', name: 'ECDSA', icon: '🔓', tag: null, keyBits: [224, 256, 384, 521] },
  { type: 'ed25519', name: 'Ed25519', icon: '🔑', tag: null, keyBits: null },
  { type: 'sm2', name: 'SM2', icon: '🇨🇳', tag: '国密', keyBits: null },
  { type: 'ssh-rsa', name: 'SSH RSA', icon: '🖥️', tag: 'SSH', keyBits: [2048, 3072, 4096] },
  { type: 'ssh-ed25519', name: 'SSH Ed25519', icon: '💻', tag: 'SSH', keyBits: null },
  { type: 'ssh-ecdsa', name: 'SSH ECDSA', icon: '📟', tag: 'SSH', keyBits: [256, 384, 521] },
]

const currentTypeInfo = computed(() => keyTypes.find(t => t.type === selectedType.value))

function selectType(type) {
  selectedType.value = type
  result.value = null
  const info = keyTypes.find(t => t.type === type)
  if (info?.keyBits) {
    keyBits.value = info.keyBits[info.keyBits.length > 1 ? 1 : 0]
  }
}

async function generate() {
  generating.value = true
  const res = await apiPost('/api/keygen/generate', { type: selectedType.value, bits: keyBits.value })
  generating.value = false
  if (res.code === 0) {
    result.value = res.data
    showToast('密钥对生成成功')
  } else {
    showToast(res.message)
  }
}

function downloadFile(type, content) {
  const info = currentTypeInfo.value
  const isSSH = info?.tag === 'SSH'
  let filename, ext

  if (isSSH) {
    if (type === 'public') {
      filename = 'id_' + selectedType.value.replace('ssh-', '') + '.pub'
      ext = ''
    } else {
      filename = 'id_' + selectedType.value.replace('ssh-', '')
      ext = ''
    }
  } else {
    if (type === 'public') {
      filename = selectedType.value + '_public'
      ext = '.pem'
    } else {
      filename = selectedType.value + '_private'
      ext = '.pem'
    }
  }

  const blob = new Blob([content], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename + ext
  a.click()
  URL.revokeObjectURL(url)
  showToast('文件已下载')
}
</script>

<style scoped>
.type-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
  gap: 0.6rem;
}

.type-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.3rem;
  padding: 0.75rem 0.5rem;
  border: 1.5px solid var(--border);
  border-radius: 10px;
  background: white;
  cursor: pointer;
  transition: all 0.2s;
  position: relative;
}

.type-card:hover {
  border-color: var(--primary);
  background: #f8f7ff;
}

.type-card-active {
  border-color: var(--primary);
  background: rgba(79, 70, 229, 0.08);
  box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1);
}

.type-icon { font-size: 1.4rem; }
.type-name { font-size: 0.82rem; font-weight: 600; color: var(--text); }

.type-tag {
  position: absolute;
  top: 4px;
  right: 4px;
  font-size: 0.6rem;
  padding: 0.1rem 0.35rem;
  border-radius: 4px;
  background: var(--primary);
  color: white;
  font-weight: 600;
}

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

.result-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.75rem;
}

.result-actions {
  display: flex;
  gap: 0.5rem;
}

.btn-sm {
  padding: 0.3rem 0.75rem;
  font-size: 0.78rem;
  border: 1.5px solid var(--primary);
  color: var(--primary);
  background: white;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-sm:hover {
  background: var(--primary);
  color: white;
}

.key-section {
  margin-bottom: 0.75rem;
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}

.key-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.4rem 0.75rem;
  background: #f8fafc;
  border-bottom: 1px solid var(--border);
}

.key-title {
  font-size: 0.82rem;
  font-weight: 600;
  color: var(--text-secondary);
}

.btn-copy {
  font-size: 0.75rem;
  padding: 0.15rem 0.5rem;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: white;
  cursor: pointer;
  color: var(--text-secondary);
  transition: all 0.15s;
}

.btn-copy:hover {
  border-color: var(--primary);
  color: var(--primary);
}

.key-content {
  padding: 0.6rem 0.75rem;
  font-family: monospace;
  font-size: 0.78rem;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 180px;
  overflow-y: auto;
  color: var(--text);
  line-height: 1.5;
}

.private-key {
  background: #fffbeb;
}
</style>
