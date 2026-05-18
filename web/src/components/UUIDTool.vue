<template>
  <div class="tool-panel">
    <h2>随机字符串生成</h2>
    <div class="card">
      <!-- 1. 生成模式 -->
      <div class="form-group">
        <label>生成模式</label>
        <div class="mode-tabs">
          <button v-for="m in modes" :key="m.value" :class="['tab-btn', { active: mode === m.value }]" @click="mode = m.value" :title="m.desc">{{ m.label }}</button>
        </div>
      </div>

      <!-- 2. 雪花算法参数 -->
      <div v-if="mode === 'snowflake'" class="form-group">
        <label>起始时间 (Epoch)</label>
        <input v-model="snowEpochStr" type="date" class="input-field" />
        <div class="epoch-presets">
          <span class="preset-label">快捷选择：</span>
          <button v-for="p in epochPresets" :key="p.value" :class="['preset-btn', { active: snowEpochStr === p.value }]" @click="snowEpochStr = p.value">{{ p.label }}</button>
        </div>
      </div>

      <div v-if="mode === 'snowflake'" class="form-group">
        <label>节点 ID (0-1023)</label>
        <input v-model.number="snowNodeId" type="number" min="0" max="1023" class="input-field" style="max-width:160px" />
      </div>

      <!-- 3. 随机字符串字符集 -->
      <div v-if="mode === 'random'" class="form-group">
        <label>字符集</label>
        <div class="charset-tabs">
          <button v-for="c in charsetOptions" :key="c.value" :class="['tab-btn', { active: charset === c.value }]" @click="charset = c.value" :title="c.desc">{{ c.label }}</button>
        </div>
      </div>

      <div v-if="mode === 'custom'" class="form-group">
        <label>自定义字符集</label>
        <input v-model="customCharset" class="input-field" placeholder="输入自定义字符，如：ABCDEF0123456789" />
      </div>

      <!-- 4. 长度 -->
      <div class="form-group" v-if="mode === 'random' || mode === 'custom'">
        <label>长度</label>
        <input v-model.number="length" type="number" min="1" max="1024" class="input-field" style="max-width:160px" />
      </div>

      <!-- 5. 数量 -->
      <div class="form-group">
        <label>生成数量</label>
        <input v-model.number="count" type="number" min="1" max="100" class="input-field" style="max-width:160px" />
      </div>

      <button @click="generate" class="btn btn-primary" style="margin-top:0.5rem">生成</button>

      <div v-if="items.length" class="result-box">
        <div class="result-label">
          生成结果 ({{ items.length }} 个)
          <button class="icon-btn-sm" @click="copyAll" title="复制全部" style="margin-left:0.5rem">📋 全部复制</button>
        </div>
        <div class="result-list">
          <div v-for="(item, i) in items" :key="i" class="result-value" @click="copy(item)">{{ item }}</div>
        </div>
        <div class="result-hint">点击单行可复制</div>
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

const count = ref(5)
const length = ref(32)
const mode = ref('uuid')
const charset = ref('alphanumeric')
const customCharset = ref('')
const items = ref([])

// 雪花算法参数 - 默认起始时间为今天
const today = new Date()
const todayStr = today.getFullYear() + '-' + String(today.getMonth() + 1).padStart(2, '0') + '-' + String(today.getDate()).padStart(2, '0')
const snowEpochStr = ref(todayStr)
const snowNodeId = ref(1)

const epochPresets = [
  { label: '今天', value: todayStr },
  { label: '2024', value: '2024-01-01' },
  { label: '2020', value: '2020-01-01' },
  { label: '2015', value: '2015-01-01' },
  { label: '2010', value: '2010-01-01' },
  { label: '2000', value: '2000-01-01' },
]

function epochToMs(dateStr) {
  return new Date(dateStr + 'T00:00:00Z').getTime()
}

const modes = [
  { value: 'uuid', label: 'UUID v4', desc: '标准 UUID v4（8-4-4-4-12 格式）' },
  { value: 'uuid_nodash', label: 'UUID 无横线', desc: 'UUID v4 去掉横线（32位十六进制）' },
  { value: 'snowflake', label: '雪花算法', desc: 'Twitter Snowflake 分布式 ID（64位整数）' },
  { value: 'random', label: '随机字符串', desc: '从指定字符集随机生成' },
  { value: 'custom', label: '自定义字符集', desc: '指定任意字符集生成' },
]

const charsetOptions = [
  { value: 'alphanumeric', label: '字母+数字', desc: 'A-Za-z0-9' },
  { value: 'alpha', label: '纯字母', desc: 'A-Za-z' },
  { value: 'upper', label: '大写字母', desc: 'A-Z' },
  { value: 'lower', label: '小写字母', desc: 'a-z' },
  { value: 'numeric', label: '纯数字', desc: '0-9' },
  { value: 'hex', label: '十六进制', desc: '0-9a-f' },
  { value: 'hex_upper', label: '十六进制大写', desc: '0-9A-F' },
  { value: 'base62', label: 'Base62', desc: 'A-Za-z0-9' },
  { value: 'base64', label: 'Base64', desc: 'A-Za-z0-9+/' },
  { value: 'symbol', label: '特殊符号', desc: '!@#$%^&*()_+-=...' },
  { value: 'alphanum_sym', label: '字母+数字+符号', desc: 'A-Za-z0-9!@#$%^&*()_+-=' },
]

async function generate() {
  const params = { count: count.value, mode: mode.value }
  if (mode.value === 'random') {
    params.length = length.value
    params.charset = charset.value
  } else if (mode.value === 'custom') {
    params.length = length.value
    params.customCharset = customCharset.value
    if (!customCharset.value.trim()) {
      showToast('请输入自定义字符集')
      return
    }
  } else if (mode.value === 'snowflake') {
    params.snowEpoch = epochToMs(snowEpochStr.value)
    params.snowNodeId = snowNodeId.value
  }
  const res = await apiPost('/api/random/generate', params)
  if (res.code === 0) items.value = res.data.items
  else showToast(res.message)
}

function copyAll() {
  copy(items.value.join('\n')).then(() => showToast('已复制全部结果'))
}
</script>

<style scoped>
.mode-tabs, .charset-tabs {
  display: flex;
  gap: 0.35rem;
  flex-wrap: wrap;
}

.tab-btn {
  padding: 0.3rem 0.65rem;
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

.epoch-presets {
  display: flex;
  align-items: center;
  gap: 0.3rem;
  margin-top: 0.35rem;
  flex-wrap: wrap;
}

.preset-label {
  font-size: 0.75rem;
  color: var(--text-secondary);
}

.preset-btn {
  padding: 0.15rem 0.5rem;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--card-bg);
  color: var(--text-secondary);
  font-size: 0.72rem;
  cursor: pointer;
  transition: all 0.15s;
}

.preset-btn:hover {
  border-color: var(--primary);
  color: var(--primary);
}

.preset-btn.active {
  background: rgba(79, 70, 229, 0.08);
  border-color: var(--primary);
  color: var(--primary);
  font-weight: 600;
}

.result-list {
  max-height: 300px;
  overflow-y: auto;
}

.result-value {
  font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  font-size: 0.82rem;
  word-break: break-all;
}

.icon-btn-sm {
  padding: 0.15rem 0.5rem;
  border: 1px solid var(--border);
  border-radius: 3px;
  background: var(--card-bg);
  cursor: pointer;
  font-size: 0.72rem;
  color: var(--text-secondary);
  transition: all 0.15s;
}

.icon-btn-sm:hover {
  border-color: var(--primary);
  color: var(--primary);
}
</style>
