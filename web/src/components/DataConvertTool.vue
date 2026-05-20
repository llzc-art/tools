<template>
  <div class="tool-panel">
    <h2>数据格式转换</h2>
    <div class="card">
      <!-- 顶部控制栏 -->
      <div class="control-bar">
        <div class="format-selectors">
          <div class="format-select">
            <label>源格式</label>
            <select v-model="inputFormat" @change="autoDetected=false" class="input-field">
              <option value="auto">自动识别</option>
              <option value="json">JSON</option>
              <option value="yaml">YAML</option>
              <option value="xml">XML</option>
            </select>
          </div>
          <div class="arrow-icon" title="转换方向">→</div>
          <div class="format-select">
            <label>目标格式</label>
            <select v-model="targetFormat" class="input-field">
              <option value="json">JSON</option>
              <option value="yaml">YAML</option>
              <option value="xml">XML</option>
            </select>
          </div>
          <button @click="doConvert" class="btn btn-primary" :disabled="loading">
            {{ loading ? '转换中...' : '转换' }}
          </button>
        </div>
        <div class="quick-actions">
          <span class="quick-label">快捷:</span>
          <button v-for="q in quickOptions" :key="q.target" class="btn-quick"
            :class="{ active: inputFormat===q.source && targetFormat===q.target }"
            @click="inputFormat=q.source;targetFormat=q.target;doConvert()">
            {{ q.label }}
          </button>
        </div>
      </div>

      <!-- 双面板区域 -->
      <div class="panels">
        <div class="panel input-panel">
          <div class="panel-header">
            <span>输入数据</span>
            <div class="panel-actions">
              <span v-if="detectedFormat" :class="['format-tag', 'tag-'+detectedFormat]">
                {{ detectedFormat.toUpperCase() }}
              </span>
              <button v-if="!autoDetected" class="btn-icon" @click="inputFormat='auto';autoDetected=true" title="重置为自动识别">↻</button>
              <button class="btn-icon" @click="inputData='';output='';error=''" title="清空">✕</button>
            </div>
          </div>
          <textarea v-model="inputData" class="panel-body mono" placeholder='JSON: { "name": "hello" }&#10;YAML: name: hello&#10;XML: <name>hello</name>'></textarea>
        </div>
        <div class="panel output-panel">
          <div class="panel-header">
            <span>输出结果 <span v-if="outputFormat" :class="['format-tag', 'tag-'+outputFormat]">{{ outputFormat.toUpperCase() }}</span></span>
            <div class="panel-actions">
              <button v-if="output" class="btn-icon" @click="swapIO" title="交换输入输出">⇄</button>
              <button v-if="output" class="btn-icon" @click="copy(output)" title="复制">📋</button>
            </div>
          </div>
          <div class="panel-body output-body">
            <pre v-if="output" class="output-pre mono">{{ output }}</pre>
            <div v-else class="output-placeholder">转换结果将在此显示</div>
          </div>
        </div>
      </div>

      <div v-if="error" class="error-msg">{{ error }}</div>
    </div>
  </div>
</template>

<script setup>
import { ref, watch, inject } from 'vue'
import { apiPost, copyToClipboard } from '../api.js'

const showToast = inject('showToast')

const inputData = ref('')
const inputFormat = ref('auto')
const targetFormat = ref('json')
const output = ref('')
const outputFormat = ref('')
const loading = ref(false)
const error = ref('')
const detectedFormat = ref('')
const autoDetected = ref(true)

const quickOptions = [
  { source: 'json', target: 'yaml', label: 'JSON → YAML' },
  { source: 'json', target: 'xml', label: 'JSON → XML' },
  { source: 'yaml', target: 'json', label: 'YAML → JSON' },
  { source: 'yaml', target: 'xml', label: 'YAML → XML' },
  { source: 'xml', target: 'json', label: 'XML → JSON' },
  { source: 'xml', target: 'yaml', label: 'XML → YAML' },
]

let detectTimer = null

watch(inputData, (val) => {
  if (!val.trim()) { detectedFormat.value = ''; return }
  if (!autoDetected.value) return
  clearTimeout(detectTimer)
  detectTimer = setTimeout(async () => {
    try {
      const res = await apiPost('/api/data-convert/detect', { input: val })
      if (res.code === 0) detectedFormat.value = res.data.format
      else detectedFormat.value = ''
    } catch { detectedFormat.value = '' }
  }, 500)
})

async function doConvert() {
  if (!inputData.value.trim()) { error.value = '请输入数据'; return }
  loading.value = true; error.value = ''; output.value = ''
  try {
    const srcFmt = inputFormat.value === 'auto' ? '' : inputFormat.value
    const res = await apiPost('/api/data-convert/convert', {
      input: inputData.value,
      source_format: srcFmt,
      target_format: targetFormat.value,
    })
    if (res.code === 0) {
      output.value = res.data.output || ''
      outputFormat.value = res.data.target_format || targetFormat.value
      if (res.data.error) error.value = res.data.error
      if (res.data.source_format) detectedFormat.value = res.data.source_format
    } else {
      error.value = res.message
    }
  } catch { error.value = '请求失败' } finally { loading.value = false }
}

function swapIO() {
  if (!output.value) return
  const tmpData = output.value
  const tmpFmt = outputFormat.value
  output.value = ''
  outputFormat.value = ''
  inputData.value = tmpData
  if (tmpFmt) {
    inputFormat.value = tmpFmt
    autoDetected.value = false
  }
}

function copy(text) {
  copyToClipboard(text).then(ok => showToast(ok ? '已复制到剪贴板' : '复制失败'))
}
</script>

<style scoped>
/* 顶部控制栏 */
.control-bar {
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
  margin-bottom: 1rem;
  padding-bottom: 0.8rem;
  border-bottom: 1px solid var(--border, #e5e7eb);
}
.format-selectors {
  display: flex;
  align-items: flex-end;
  gap: 0.6rem;
  flex-wrap: wrap;
}
.format-select {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
.format-select label {
  font-size: 0.75rem;
  color: var(--text-secondary, #6b7280);
  font-weight: 500;
}
.format-select .input-field {
  min-width: 110px;
  padding: 0.35rem 0.6rem;
  font-size: 0.85rem;
}
.arrow-icon {
  font-size: 1.3rem;
  color: var(--primary, #4f46e5);
  font-weight: 700;
  padding-bottom: 0.3rem;
}
.quick-actions {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  flex-wrap: wrap;
}
.quick-label {
  font-size: 0.78rem;
  color: var(--text-secondary, #6b7280);
  white-space: nowrap;
}
.btn-quick {
  background: #f1f5f9;
  border: 1px solid #e2e8f0;
  color: #475569;
  font-size: 0.72rem;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.15s;
  white-space: nowrap;
}
.btn-quick:hover {
  background: #e2e8f0;
  color: #1e293b;
}
.btn-quick.active {
  background: var(--primary, #4f46e5);
  color: #fff;
  border-color: var(--primary, #4f46e5);
}

/* 双面板 */
.panels {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.8rem;
  min-height: 400px;
}
.panel {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--border, #e5e7eb);
  border-radius: var(--radius, 6px);
  overflow: hidden;
}
.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.4rem 0.7rem;
  background: #f8fafc;
  border-bottom: 1px solid var(--border, #e5e7eb);
  font-size: 0.82rem;
  font-weight: 600;
  color: var(--text-primary, #1e293b);
}
.panel-actions {
  display: flex;
  align-items: center;
  gap: 0.4rem;
}
.panel-body {
  flex: 1;
  resize: none;
  border: none;
  outline: none;
  padding: 0.7rem;
  font-size: 0.82rem;
  line-height: 1.5;
  min-height: 350px;
}
.mono { font-family: 'Menlo', 'Monaco', 'Courier New', monospace; }

/* 输出面板 */
.output-body {
  padding: 0;
  overflow: auto;
  background: #fafbfc;
}
.output-pre {
  margin: 0;
  padding: 0.7rem;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 0.82rem;
  line-height: 1.5;
  color: var(--text-primary, #1e293b);
}
.output-placeholder {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  min-height: 350px;
  color: var(--text-secondary, #9ca3af);
  font-size: 0.88rem;
}

/* 格式标签 */
.format-tag {
  display: inline-block;
  font-size: 0.68rem;
  font-weight: 700;
  padding: 0.1rem 0.4rem;
  border-radius: 3px;
  text-transform: uppercase;
  vertical-align: middle;
}
.tag-json { background: #dbeafe; color: #2563eb; }
.tag-yaml { background: #fef3c7; color: #d97706; }
.tag-xml { background: #fce7f3; color: #db2777; }

/* 按钮 */
.btn-icon {
  background: none;
  border: none;
  cursor: pointer;
  font-size: 0.9rem;
  padding: 0.15rem 0.3rem;
  border-radius: 3px;
  color: var(--text-secondary, #6b7280);
  transition: all 0.15s;
}
.btn-icon:hover {
  background: #e2e8f0;
  color: var(--text-primary, #1e293b);
}

/* 错误 */
.error-msg {
  margin-top: 0.8rem;
  padding: 0.6rem 0.8rem;
  background: #fef2f2;
  color: #dc2626;
  border-radius: 6px;
  font-size: 0.85rem;
}

/* 响应式 */
@media (max-width: 768px) {
  .panels {
    grid-template-columns: 1fr;
    min-height: auto;
  }
  .panel-body, .output-placeholder {
    min-height: 200px;
  }
  .format-selectors {
    flex-wrap: wrap;
  }
}
</style>
