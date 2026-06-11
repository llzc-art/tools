<template>
  <div class="tool-panel">
    <h2>DDL 解析工具</h2>
    <p class="tool-desc">输入 CREATE TABLE 语句，自动生成 UML 类图和表结构说明表格</p>

    <div class="card">
      <!-- 输入区域 -->
      <div class="input-section">
        <div class="section-header">
          <span>DDL 语句</span>
          <div class="header-actions">
            <button class="btn-sm" @click="loadSample" :disabled="loading">加载示例</button>
            <button class="btn-sm btn-danger" @click="inputDdl='';results=null" :disabled="loading">清空</button>
          </div>
        </div>
        <textarea
          v-model="inputDdl"
          class="ddl-input mono"
          placeholder="请输入 DDL 语句，支持多条 CREATE TABLE 语句...&#10;&#10;示例：&#10;CREATE TABLE users (&#10;  id BIGINT PRIMARY KEY AUTO_INCREMENT,&#10;  name VARCHAR(100) NOT NULL COMMENT '用户名',&#10;  email VARCHAR(255) DEFAULT '' COMMENT '邮箱'&#10;) COMMENT='用户表' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
          @keydown.ctrl.enter="doParse"
          @keydown.meta.enter="doParse"
        ></textarea>
        <div class="input-footer">
          <span class="hint">提示：Ctrl+Enter 快速解析</span>
          <button @click="doParse" class="btn btn-primary" :disabled="loading || !inputDdl.trim()">
            {{ loading ? '解析中...' : '🔍 解析 DDL' }}
          </button>
        </div>
      </div>

      <!-- 错误提示 -->
      <div v-if="error" class="error-msg">{{ error }}</div>

      <!-- 解析统计 -->
      <div v-if="results" class="parse-stats">
        <span>✅ 解析出 <strong>{{ results.table_count }}</strong> 张表</span>
        <span v-if="results.skipped_count > 0">，已忽略 <strong>{{ results.skipped_count }}</strong> 条非 CREATE TABLE 语句</span>
      </div>

      <!-- 结果区域 -->
      <div v-if="results" class="results-section">
        <div class="tabs">
          <button
            v-for="tab in tabs"
            :key="tab.id"
            :class="['tab', { active: activeTab === tab.id }]"
            @click="activeTab = tab.id"
          >{{ tab.label }}</button>
        </div>

        <!-- UML 类图 -->
        <div v-show="activeTab === 'uml'" class="tab-content">
          <div class="section-header">
            <span>UML 类图 (Mermaid)</span>
            <div class="header-actions">
              <button class="btn-sm" @click="copy(results.mermaid_class_diagram)">📋 复制语法</button>
            </div>
          </div>
          <div ref="mermaidContainer" class="mermaid-container">
            <div v-if="mermaidError" class="mermaid-error">{{ mermaidError }}</div>
            <div ref="mermaidRender" class="mermaid-render"></div>
          </div>
          <details class="code-details">
            <summary>查看 Mermaid 源码</summary>
            <pre class="code-block mono">{{ results.mermaid_class_diagram }}</pre>
          </details>
        </div>

        <!-- 表结构 HTML -->
        <div v-show="activeTab === 'html'" class="tab-content">
          <div class="section-header">
            <span>表结构说明</span>
            <div class="header-actions">
              <button class="btn-sm" @click="copyHTML">📋 复制 HTML</button>
            </div>
          </div>
          <div class="html-preview" v-html="results.html_tables"></div>
        </div>

        <!-- Markdown 表格 -->
        <div v-show="activeTab === 'markdown'" class="tab-content">
          <div class="section-header">
            <span>Markdown 表格</span>
            <div class="header-actions">
              <button class="btn-sm" @click="copy(results.markdown_tables)">📋 复制</button>
            </div>
          </div>
          <pre class="code-block mono">{{ results.markdown_tables }}</pre>
        </div>

        <!-- 原始 JSON -->
        <div v-show="activeTab === 'json'" class="tab-content">
          <div class="section-header">
            <span>解析结果 (JSON)</span>
            <div class="header-actions">
              <button class="btn-sm" @click="copyJSON">📋 复制</button>
            </div>
          </div>
          <pre class="code-block mono">{{ jsonOutput }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, nextTick, watch, inject } from 'vue'
import { apiPost, copyToClipboard } from '../api.js'

const showToast = inject('showToast')

const inputDdl = ref('')
const loading = ref(false)
const error = ref('')
const results = ref(null)
const activeTab = ref('uml')
const mermaidRender = ref(null)
const mermaidContainer = ref(null)
const mermaidError = ref('')

const tabs = [
  { id: 'uml', label: 'UML 类图' },
  { id: 'html', label: '表结构' },
  { id: 'markdown', label: 'Markdown' },
  { id: 'json', label: 'JSON' },
]

const jsonOutput = ref('')
const mermaidLoaded = ref(false)
let mermaidInstance = null

// 动态加载 Mermaid.js
function loadMermaid() {
  if (mermaidLoaded.value) return Promise.resolve(mermaidInstance)
  
  return new Promise((resolve, reject) => {
    if (window.mermaid) {
      mermaidLoaded.value = true
      mermaidInstance = window.mermaid
      resolve(mermaidInstance)
      return
    }
    
    const script = document.createElement('script')
    script.src = 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js'
    script.onload = () => {
      window.mermaid.initialize({
        startOnLoad: false,
        theme: 'default',
        securityLevel: 'loose',
        classDiagram: {
          useMaxWidth: true,
        }
      })
      mermaidLoaded.value = true
      mermaidInstance = window.mermaid
      resolve(mermaidInstance)
    }
    script.onerror = () => reject(new Error('Mermaid.js 加载失败'))
    document.head.appendChild(script)
  })
}

// 渲染 Mermaid 图
async function renderMermaid(diagram) {
  if (!diagram) return
  
  try {
    mermaidError.value = ''
    const mermaid = await loadMermaid()
    
    await nextTick()
    
    if (mermaidRender.value) {
      // 生成唯一 ID
      const id = 'mermaid-' + Date.now()
      const { svg } = await mermaid.render(id, diagram)
      mermaidRender.value.innerHTML = svg
    }
  } catch (err) {
    console.error('Mermaid 渲染失败:', err)
    mermaidError.value = 'UML 图渲染失败: ' + err.message
  }
}

// 监听结果变化自动渲染
watch(() => results.value?.mermaid_class_diagram, (diagram) => {
  if (diagram && activeTab.value === 'uml') {
    renderMermaid(diagram)
  }
})

// 切换 tab 时重新渲染
watch(activeTab, (tab) => {
  if (tab === 'uml' && results.value?.mermaid_class_diagram) {
    nextTick(() => renderMermaid(results.value.mermaid_class_diagram))
  }
})

async function doParse() {
  if (!inputDdl.value.trim()) return
  
  loading.value = true
  error.value = ''
  results.value = null
  mermaidError.value = ''
  
  try {
    const res = await apiPost('/api/ddl/parse', { ddl: inputDdl.value })
    if (res.code === 0) {
      results.value = res.data
      jsonOutput.value = JSON.stringify(res.data.tables, null, 2)
      
      await nextTick()
      if (activeTab.value === 'uml') {
        renderMermaid(res.data.mermaid_class_diagram)
      }
    } else {
      error.value = res.message
    }
  } catch (err) {
    error.value = '网络请求失败: ' + err.message
  } finally {
    loading.value = false
  }
}

function copy(text) {
  copyToClipboard(text).then(ok => showToast(ok ? '已复制到剪贴板' : '复制失败'))
}

function copyHTML() {
  if (!results.value) return
  copyToClipboard(results.value.html_tables).then(ok => showToast(ok ? 'HTML 已复制' : '复制失败'))
}

function copyJSON() {
  if (!results.value) return
  copyToClipboard(jsonOutput.value).then(ok => showToast(ok ? 'JSON 已复制' : '复制失败'))
}

function loadSample() {
  inputDdl.value = `CREATE TABLE users (
  id BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT '主键ID',
  username VARCHAR(64) NOT NULL COMMENT '用户名',
  password_hash VARCHAR(255) NOT NULL COMMENT '密码哈希',
  email VARCHAR(128) DEFAULT '' COMMENT '邮箱',
  phone VARCHAR(20) DEFAULT '' COMMENT '手机号',
  role VARCHAR(20) NOT NULL DEFAULT 'user' COMMENT '角色: admin,user',
  status TINYINT NOT NULL DEFAULT 1 COMMENT '状态: 0-禁用,1-启用',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表';

CREATE TABLE orders (
  id BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT '订单ID',
  order_no VARCHAR(32) NOT NULL COMMENT '订单号',
  user_id BIGINT NOT NULL COMMENT '用户ID',
  product_name VARCHAR(200) NOT NULL COMMENT '商品名称',
  amount DECIMAL(10,2) NOT NULL COMMENT '金额',
  status VARCHAR(20) NOT NULL DEFAULT 'pending' COMMENT '状态',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  UNIQUE KEY uk_order_no (order_no),
  INDEX idx_user_id (user_id),
  INDEX idx_status (status),
  FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='订单表';
`
}
</script>

<style scoped>
.tool-desc {
  color: var(--text-secondary);
  font-size: 0.88rem;
  margin-top: -0.5rem;
  margin-bottom: 1rem;
}

/* 输入区域 */
.input-section {
  margin-bottom: 1rem;
}

.section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.5rem;
  font-size: 0.88rem;
  font-weight: 600;
  color: var(--text);
}

.header-actions {
  display: flex;
  gap: 0.4rem;
}

.btn-sm {
  padding: 0.25rem 0.6rem;
  font-size: 0.78rem;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: #f8fafc;
  color: var(--text-secondary);
  cursor: pointer;
  transition: all 0.15s;
}

.btn-sm:hover {
  background: #e2e8f0;
  color: var(--text);
}

.btn-danger:hover {
  background: #fef2f2;
  color: #dc2626;
  border-color: #fca5a5;
}

.ddl-input {
  width: 100%;
  min-height: 280px;
  padding: 0.8rem;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 0.84rem;
  line-height: 1.6;
  resize: vertical;
  outline: none;
  background: #fafbfc;
  color: var(--text);
  font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
  transition: border-color 0.2s;
}

.ddl-input:focus {
  border-color: var(--primary);
  background: #fff;
}

.ddl-input::placeholder {
  color: #c4c4c4;
}

.input-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-top: 0.5rem;
}

.hint {
  font-size: 0.75rem;
  color: var(--text-secondary);
}

/* 错误 */
.error-msg {
  margin: 0.8rem 0;
  padding: 0.6rem 0.8rem;
  background: #fef2f2;
  color: #dc2626;
  border-radius: 6px;
  font-size: 0.85rem;
}

/* 解析统计 */
.parse-stats {
  margin-top: 0.8rem;
  padding: 0.5rem 0.8rem;
  background: #f0fdf4;
  border: 1px solid #bbf7d0;
  border-radius: 6px;
  font-size: 0.85rem;
  color: #166534;
}

/* 结果区域 */
.results-section {
  margin-top: 1.5rem;
  border-top: 1px solid var(--border);
  padding-top: 1rem;
}

/* Tab 切换 */
.tabs {
  display: flex;
  gap: 0;
  border-bottom: 2px solid var(--border);
  margin-bottom: 1rem;
}

.tab {
  padding: 0.5rem 1rem;
  border: none;
  background: none;
  color: var(--text-secondary);
  font-size: 0.85rem;
  font-weight: 500;
  cursor: pointer;
  border-bottom: 2px solid transparent;
  margin-bottom: -2px;
  transition: all 0.15s;
}

.tab:hover {
  color: var(--text);
}

.tab.active {
  color: var(--primary);
  border-bottom-color: var(--primary);
}

.tab-content {
  min-height: 100px;
}

/* Mermaid 容器 */
.mermaid-container {
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1.5rem;
  background: #fff;
  overflow-x: auto;
  margin-bottom: 0.75rem;
  min-height: 100px;
}

.mermaid-render {
  display: flex;
  justify-content: center;
}

.mermaid-render :deep(svg) {
  max-width: 100%;
  height: auto;
}

.mermaid-error {
  color: #dc2626;
  font-size: 0.85rem;
  padding: 0.5rem;
  background: #fef2f2;
  border-radius: 4px;
}

/* 代码预览 */
.code-details {
  margin-bottom: 0.5rem;
}

.code-details summary {
  cursor: pointer;
  font-size: 0.82rem;
  color: var(--text-secondary);
  padding: 0.3rem 0;
}

.code-block {
  background: #1e293b;
  color: #e2e8f0;
  padding: 1rem;
  border-radius: 6px;
  font-size: 0.82rem;
  line-height: 1.5;
  overflow-x: auto;
  white-space: pre;
  margin: 0;
}

/* HTML 预览 */
.html-preview {
  overflow-x: auto;
}

.html-preview :deep(table) {
  width: 100%;
  border-collapse: collapse;
  margin-bottom: 1rem;
}

.html-preview :deep(th) {
  padding: 0.5rem 0.7rem;
  text-align: left;
  font-size: 0.82rem;
}

.html-preview :deep(td) {
  padding: 0.4rem 0.7rem;
  font-size: 0.82rem;
  border: 1px solid var(--border);
}

.html-preview :deep(h3) {
  font-size: 1rem;
  margin: 1rem 0 0.5rem;
}

.html-preview :deep(h4) {
  font-size: 0.9rem;
  margin: 0.8rem 0 0.3rem;
}

.html-preview :deep(code) {
  background: #f1f5f9;
  padding: 0.1rem 0.3rem;
  border-radius: 3px;
  font-size: 0.8rem;
}

/* 按钮 */
.btn {
  padding: 0.45rem 1rem;
  border: none;
  border-radius: 6px;
  font-size: 0.85rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary {
  background: var(--primary, #4f46e5);
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background: #4338ca;
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* 响应式 */
@media (max-width: 768px) {
  .ddl-input {
    min-height: 200px;
    font-size: 0.78rem;
  }

  .tabs {
    gap: 0;
  }

  .tab {
    padding: 0.4rem 0.6rem;
    font-size: 0.8rem;
  }

  .input-footer {
    flex-direction: column;
    gap: 0.5rem;
  }
}
</style>
