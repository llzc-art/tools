<template>
  <div class="tool-panel">
    <h2>云平台 API 调试</h2>
    <div class="card">
      <!-- 平台选择 -->
      <div class="form-group">
        <label>云平台</label>
        <select v-model="platformId" @change="onPlatformChange" class="input-field">
          <option value="">请选择云平台</option>
          <option v-for="p in platforms" :key="p.id" :value="p.id">{{ p.name }}</option>
        </select>
      </div>

      <template v-if="currentPlatform">
        <!-- 区域选择 -->
        <div class="form-group" v-if="currentPlatform.regions && currentPlatform.regions.length > 0">
          <label>区域 <span class="hint">(配置文件预设，可在 config/integration/cloud.yaml 修改)</span></label>
          <select v-model="authData.region" class="input-field">
            <option v-for="r in currentPlatform.regions" :key="r.value" :value="r.value">{{ r.label }} ({{ r.value }})</option>
          </select>
        </div>

        <!-- 认证配置 - 动态字段 -->
        <div class="form-group">
          <label>认证配置 <span class="hint">(签名自动生成)</span></label>
          <div class="auth-grid">
            <div class="auth-field" v-for="field in currentPlatform.auth_fields" :key="field.key">
              <span class="auth-label">{{ field.label }}</span>
              <input
                v-model="authData[field.key]"
                :type="field.type"
                class="input-field"
                :placeholder="field.placeholder"
              />
            </div>
          </div>
        </div>

        <!-- API 选择 -->
        <div class="form-group">
          <label>API 接口 (配置文件预设，可在 config/integration/cloud.yaml 修改)</label>
          <select v-model="selectedApiId" @change="onApiChange" class="input-field">
            <option value="">请选择接口（选择后自动填充请求参数）</option>
            <optgroup v-for="cat in apiCategories" :key="cat" :label="cat">
              <option v-for="api in getApisByCategory(cat)" :key="api.id" :value="api.id">
                {{ api.name }} - {{ api.description }}
              </option>
            </optgroup>
          </select>
        </div>

        <!-- 请求信息（只读展示，签名自动处理） -->
        <div v-if="currentApi" class="request-info">
          <div class="info-row">
            <span class="info-label">请求方法</span>
            <span class="info-value"><span :class="['method-tag', 'method-'+currentApi.method.toLowerCase()]">{{ currentApi.method }}</span></span>
          </div>
          <div class="info-row">
            <span class="info-label">请求路径</span>
            <span class="info-value mono">{{ resolvedPath }}</span>
          </div>
        </div>

        <!-- 请求体 -->
        <div class="form-group" v-if="currentApi && (currentApi.body_template || currentApi.method === 'POST')">
          <label>请求体 <span class="hint">(变量 {{variable}} 自动替换为认证配置中的值)</span></label>
          <textarea v-model="reqBody" rows="8" class="input-field mono" placeholder='请求体内容'></textarea>
        </div>

        <!-- 发送 -->
        <div class="btn-group">
          <button @click="sendRequest" class="btn btn-primary" :disabled="loading">
            {{ loading ? '请求中...' : '发送请求（自动签名）' }}
          </button>
          <button @click="formatBody" class="btn btn-outline" v-if="currentApi && currentApi.body_template">格式化JSON</button>
        </div>

        <!-- 响应 -->
        <div v-if="resp" class="result-section">
          <div class="result-header">
            <span>响应结果</span>
            <span :class="['status-badge', resp.status_code < 400 ? 'badge-ok' : 'badge-fail']">
              {{ resp.status_code }}
            </span>
            <span class="duration-badge">{{ resp.duration }}ms</span>
            <span class="size-badge">{{ formatSize(resp.size) }}</span>
          </div>
          <div class="resp-headers" v-if="showRespHeaders">
            <div class="resp-headers-title" @click="showRespHeaders = !showRespHeaders">▼ 响应头</div>
            <div v-for="(v, k) in resp.headers" :key="k" class="resp-header-row">
              <span class="resp-header-key">{{ k }}:</span>
              <span class="resp-header-val">{{ v }}</span>
            </div>
          </div>
          <div v-else class="resp-headers-toggle" @click="showRespHeaders = true">▶ 显示响应头</div>
          <pre class="resp-body" v-html="formatJSON(resp.body)"></pre>
        </div>

        <div v-if="error" class="error-msg">{{ error }}</div>
      </template>

      <div v-else class="empty-hint">请先选择云平台</div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { apiGet, apiPost } from '../api.js'

const platforms = ref([])
const platformId = ref('')
const authData = ref({})
const selectedApiId = ref('')
const reqBody = ref('')
const loading = ref(false)
const resp = ref(null)
const error = ref('')
const showRespHeaders = ref(false)

const currentPlatform = computed(() => platforms.value.find(p => p.id === platformId.value))
const currentApi = computed(() => {
  if (!currentPlatform.value) return null
  return (currentPlatform.value.apis || []).find(a => a.id === selectedApiId.value)
})

const apiCategories = computed(() => {
  if (!currentPlatform.value) return []
  const apis = currentPlatform.value.apis || []
  const cats = new Set(apis.map(a => a.category))
  return [...cats]
})

// 解析后的路径（替换模板变量）
const resolvedPath = computed(() => {
  if (!currentApi.value) return ''
  let path = currentApi.value.path
  for (const [k, v] of Object.entries(authData.value)) {
    path = path.replaceAll(`{{${k}}}`, v || `{{${k}}}`)
  }
  return path
})

function getApisByCategory(cat) {
  if (!currentPlatform.value) return []
  return (currentPlatform.value.apis || []).filter(a => a.category === cat)
}

async function loadPlatforms() {
  const res = await apiGet('/api/integration/cloud/platforms')
  if (res.code === 0) {
    platforms.value = res.data
  }
}

function onPlatformChange() {
  // 初始化认证字段
  authData.value = {}
  if (currentPlatform.value) {
    for (const field of (currentPlatform.value.auth_fields || [])) {
      authData.value[field.key] = ''
    }
    // 自动设置默认 region
    if (currentPlatform.value.region) {
      authData.value['region'] = currentPlatform.value.region
    }
  }
  selectedApiId.value = ''
  reqBody.value = ''
  resp.value = null
  error.value = ''
}

function onApiChange() {
  if (!currentApi.value) {
    reqBody.value = ''
    return
  }
  // 自动填充请求体模板
  if (currentApi.value.body_template) {
    let body = currentApi.value.body_template
    for (const [k, v] of Object.entries(authData.value)) {
      body = body.replaceAll(`{{${k}}}`, v || `{{${k}}}`)
    }
    reqBody.value = body
  } else {
    reqBody.value = ''
  }
  resp.value = null
  error.value = ''
}

async function sendRequest() {
  if (!platformId.value) {
    error.value = '请选择云平台'
    return
  }
  if (!selectedApiId.value) {
    error.value = '请选择API接口'
    return
  }

  // 检查必填认证字段
  if (currentPlatform.value) {
    for (const field of (currentPlatform.value.auth_fields || [])) {
      if (field.required && !authData.value[field.key]) {
        error.value = `请填写 ${field.label}`
        return
      }
    }
  }

  loading.value = true
  resp.value = null
  error.value = ''
  showRespHeaders.value = false

  try {
    const res = await apiPost('/api/integration/cloud/call', {
      platform_id: platformId.value,
      api_id: selectedApiId.value,
      auth: authData.value,
      body: reqBody.value,
      timeout: 30,
    })
    if (res.code === 0) {
      resp.value = res.data
    } else {
      error.value = res.message
    }
  } catch (e) {
    error.value = '请求失败'
  } finally {
    loading.value = false
  }
}

function formatBody() {
  try {
    const obj = JSON.parse(reqBody.value)
    reqBody.value = JSON.stringify(obj, null, 2)
  } catch {
    // ignore
  }
}

function formatJSON(str) {
  try {
    const obj = JSON.parse(str)
    return escapeHtml(JSON.stringify(obj, null, 2))
  } catch {
    return escapeHtml(str)
  }
}

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + 'B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + 'KB'
  return (bytes / 1024 / 1024).toFixed(1) + 'MB'
}

onMounted(() => loadPlatforms())
</script>

<style scoped>
.auth-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.8rem;
}
.auth-field {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
}
.auth-label {
  font-size: 0.78rem;
  color: var(--text-secondary);
  font-weight: 500;
}
.hint {
  font-size: 0.75rem;
  color: var(--text-secondary);
  font-weight: 400;
}
.mono {
  font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
  font-size: 0.82rem;
}

/* 请求信息展示 */
.request-info {
  background: #f8fafc;
  border: 1px solid var(--border, #e5e7eb);
  border-radius: 6px;
  padding: 0.6rem 0.85rem;
  margin-bottom: 0.75rem;
}
.info-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.25rem 0;
}
.info-label {
  font-size: 0.78rem;
  color: var(--text-secondary, #6b7280);
  font-weight: 500;
  min-width: 70px;
}
.info-value {
  font-size: 0.82rem;
  color: var(--text, #1e293b);
}

/* 方法标签 */
.method-tag {
  display: inline-block;
  font-size: 0.72rem;
  font-weight: 700;
  padding: 0.15rem 0.5rem;
  border-radius: 3px;
  text-transform: uppercase;
}
.method-get { background: #dcfce7; color: #16a34a; }
.method-post { background: #dbeafe; color: #2563eb; }
.method-put { background: #fef3c7; color: #d97706; }
.method-delete { background: #fee2e2; color: #dc2626; }
.method-patch { background: #f3e8ff; color: #7c3aed; }

/* 结果区域 */
.result-section {
  margin-top: 1rem;
  border-top: 1px solid var(--border, #e5e7eb);
  padding-top: 1rem;
}
.result-header {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  font-weight: 600;
  font-size: 0.9rem;
  margin-bottom: 0.6rem;
}
.status-badge {
  font-size: 0.78rem;
  font-weight: 700;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
}
.badge-ok { background: #dcfce7; color: #16a34a; }
.badge-fail { background: #fee2e2; color: #dc2626; }
.duration-badge, .size-badge {
  font-size: 0.75rem;
  color: var(--text-secondary, #9ca3af);
  background: #f1f5f9;
  padding: 0.1rem 0.4rem;
  border-radius: 3px;
}
.resp-headers-toggle, .resp-headers-title {
  font-size: 0.8rem;
  color: var(--primary, #4f46e5);
  cursor: pointer;
  margin-bottom: 0.4rem;
}
.resp-header-row {
  display: flex;
  gap: 0.5rem;
  font-size: 0.78rem;
  padding: 0.15rem 0;
}
.resp-header-key {
  color: var(--text-secondary, #6b7280);
  min-width: 160px;
  font-family: monospace;
}
.resp-header-val {
  color: var(--text, #1e293b);
  font-family: monospace;
  word-break: break-all;
}
.resp-body {
  background: #1e293b;
  color: #e2e8f0;
  padding: 1rem;
  border-radius: 8px;
  font-size: 0.82rem;
  line-height: 1.5;
  overflow-x: auto;
  max-height: 500px;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-all;
}
.error-msg {
  margin-top: 0.8rem;
  padding: 0.6rem 0.8rem;
  background: #fef2f2;
  color: #dc2626;
  border-radius: 6px;
  font-size: 0.85rem;
}
.empty-hint {
  text-align: center;
  padding: 2rem;
  color: var(--text-secondary, #9ca3af);
  font-size: 0.9rem;
}
.btn-group {
  display: flex;
  gap: 0.5rem;
}
@media (max-width: 640px) {
  .auth-grid { grid-template-columns: 1fr; }
}
</style>
