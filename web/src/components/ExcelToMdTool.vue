<template>
  <div class="tool-panel">
    <h2>Excel 转 Markdown</h2>
    <div class="card">
      <div class="form-group">
        <label>上传 Excel 文件</label>
        <div class="upload-area" @click="triggerFileInput" @dragover.prevent @drop.prevent="handleDrop">
          <input ref="fileInput" type="file" accept=".xlsx,.xls" @change="handleFileChange" style="display: none" />
          <div v-if="!fileName" class="upload-placeholder">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="17 8 12 3 7 8"/>
              <line x1="12" y1="3" x2="12" y2="15"/>
            </svg>
            <span>点击或拖拽上传 .xlsx 文件</span>
          </div>
          <div v-else class="upload-file-info">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
              <polyline points="14 2 14 8 20 8"/>
            </svg>
            <span class="file-name">{{ fileName }}</span>
            <button class="btn-clear" @click.stop="clearFile" title="清除文件">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
              </svg>
            </button>
          </div>
        </div>
      </div>

      <div class="form-group">
        <label>输出 Markdown 文件路径 <span class="label-hint">（可选，留空则不保存到文件）</span></label>
        <input v-model="outputPath" type="text" class="input-text" placeholder="例如: ./output/result.md" />
      </div>

      <div class="btn-group">
        <button @click="convert" class="btn btn-primary" :disabled="converting || !fileName">
          {{ converting ? '转换中...' : '转换为 Markdown' }}
        </button>
      </div>

      <div v-if="error" class="error-box">{{ error }}</div>

      <div v-if="result" class="result-box">
        <div class="result-header">
          <span class="result-label">Markdown 内容</span>
          <div class="result-actions">
            <button @click="copy(result.markdown)" class="btn btn-sm btn-secondary">复制</button>
            <button @click="downloadMd" class="btn btn-sm btn-secondary">下载 .md</button>
          </div>
        </div>
        <pre class="result-value result-pre md-preview">{{ result.markdown }}</pre>
        <div v-if="result.output_path" class="result-info">已保存到: {{ result.output_path }}</div>
        <div v-if="result.warnings && result.warnings.length > 0" class="result-warnings">
          <div class="warnings-title">转换警告:</div>
          <ul>
            <li v-for="(w, i) in result.warnings" :key="i">{{ w }}</li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject } from 'vue'
import { copyToClipboard } from '../api.js'

const showToast = inject('showToast')

const fileInput = ref(null)
const fileName = ref('')
const selectedFile = ref(null)
const outputPath = ref('')
const converting = ref(false)
const result = ref(null)
const error = ref('')

function triggerFileInput() {
  fileInput.value.click()
}

function handleFileChange(e) {
  const file = e.target.files[0]
  if (file) setFile(file)
}

function handleDrop(e) {
  const file = e.dataTransfer.files[0]
  if (file) setFile(file)
}

function setFile(file) {
  const ext = file.name.toLowerCase()
  if (!ext.endsWith('.xlsx') && !ext.endsWith('.xls')) {
    showToast('仅支持 .xlsx/.xls 格式文件')
    return
  }
  selectedFile.value = file
  fileName.value = file.name
  result.value = null
  error.value = ''
}

function clearFile() {
  selectedFile.value = null
  fileName.value = ''
  result.value = null
  error.value = ''
  if (fileInput.value) fileInput.value.value = ''
}

function copy(text) {
  copyToClipboard(text).then(ok => showToast(ok ? '已复制到剪贴板' : '复制失败'))
}

function downloadMd() {
  if (!result.value || !result.value.markdown) return
  const blob = new Blob([result.value.markdown], { type: 'text/markdown;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = fileName.value.replace(/\.(xlsx|xls)$/i, '.md')
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
  showToast('下载成功')
}

async function convert() {
  if (!selectedFile.value) {
    showToast('请先选择文件')
    return
  }
  converting.value = true
  result.value = null
  error.value = ''

  try {
    const formData = new FormData()
    formData.append('file', selectedFile.value)
    if (outputPath.value.trim()) {
      formData.append('output_path', outputPath.value.trim())
    }

    const resp = await fetch('/api/document/excel-to-md', {
      method: 'POST',
      body: formData,
    })

    const res = await resp.json()
    if (res.code === 0) {
      result.value = res.data
    } else {
      error.value = res.message || '转换失败'
    }
  } catch (e) {
    error.value = '请求失败: ' + e.message
  } finally {
    converting.value = false
  }
}
</script>

<style scoped>
.upload-area {
  border: 2px dashed var(--border);
  border-radius: 8px;
  padding: 1.5rem;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s;
  background: var(--card-bg);
}
.upload-area:hover {
  border-color: var(--primary);
  background: rgba(79, 70, 229, 0.03);
}
.upload-placeholder {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
  color: var(--text-secondary);
  font-size: 0.88rem;
}
.upload-placeholder svg {
  color: var(--text-secondary);
  opacity: 0.5;
}
.upload-file-info {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  color: var(--primary);
  font-size: 0.9rem;
}
.file-name { font-weight: 600; }
.btn-clear {
  display: flex; align-items: center; justify-content: center;
  width: 24px; height: 24px; border: none; border-radius: 50%;
  background: rgba(239, 68, 68, 0.1); color: #ef4444;
  cursor: pointer; transition: background 0.15s;
}
.btn-clear:hover { background: rgba(239, 68, 68, 0.2); }
.label-hint { font-size: 0.78rem; color: var(--text-secondary); font-weight: 400; }
.result-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem; }
.result-actions { display: flex; gap: 0.4rem; }
.btn-sm { padding: 0.25rem 0.6rem; font-size: 0.75rem; }
.md-preview { max-height: 500px; overflow-y: auto; white-space: pre-wrap; word-break: break-word; font-size: 0.85rem; line-height: 1.6; }
.result-info { margin-top: 0.5rem; font-size: 0.8rem; color: var(--text-secondary); }
.result-warnings { margin-top: 0.5rem; padding: 0.5rem 0.75rem; background: #fef3c7; border-radius: 4px; font-size: 0.8rem; color: #92400e; }
.warnings-title { font-weight: 600; margin-bottom: 0.25rem; }
.result-warnings ul { margin: 0; padding-left: 1.2rem; }
</style>
