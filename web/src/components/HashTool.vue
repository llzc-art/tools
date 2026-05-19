<template>
  <div class="tool-panel">
    <h2>🔐 Hash 哈希计算</h2>
    <div class="card">
      <!-- 算法选择放顶部 -->
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
        <label>输入字符串</label>
        <textarea
          v-model="input"
          placeholder="输入要计算哈希的字符串"
          class="input-textarea"
          rows="3"
          @input="onInputChange"
        ></textarea>
      </div>

      <button @click="compute" class="btn btn-primary" :disabled="!input.trim()">计算哈希</button>

      <div v-if="output" class="result-box">
        <div class="result-label">{{ currentAlgoName }} 结果</div>
        <div class="result-value" @click="copy(output)">{{ output }}</div>
        <div class="result-hint">点击复制</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, inject, watch } from 'vue'
import { apiPost, copyToClipboard } from '../api.js'

const showToast = inject('showToast')

function copy(text) {
  copyToClipboard(text).then(ok => showToast(ok ? '已复制到剪贴板' : '复制失败'))
}

const input = ref('')
const output = ref('')
const algo = ref('md5')
const algos = [
  { id: 'md5', name: 'MD5', icon: '🔢' },
  { id: 'sha1', name: 'SHA-1', icon: '🔐' },
  { id: 'sha256', name: 'SHA-256', icon: '🛡️' },
  { id: 'sha512', name: 'SHA-512', icon: '🔒' },
  { id: 'sm3', name: 'SM3', icon: '🇨🇳' },
]

const currentAlgoName = computed(() => {
  const a = algos.find(a => a.id === algo.value)
  return a ? a.name : algo.value
})

// 切换算法时自动重新计算
watch(algo, () => {
  if (input.value.trim()) {
    compute()
  }
})

// 输入变更时清空结果（用户需手动计算或算法切换时自动计算）
function onInputChange() {
  if (!input.value.trim()) {
    output.value = ''
  }
}

function selectAlgo(id) {
  algo.value = id
}

async function compute() {
  if (!input.value.trim()) return
  const res = await apiPost('/api/hash/compute', { input: input.value, algo: algo.value })
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

.algo-icon {
  font-size: 1rem;
}

.algo-name {
  font-weight: 500;
}
</style>
