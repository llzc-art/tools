<template>
  <div class="tool-panel api-tester">
    <div class="api-layout">
      <!-- 左侧：分组 + 环境 -->
      <div class="api-sidebar">
        <div class="sidebar-section">
          <div class="sidebar-header">
            <span>🌐 环境</span>
            <div>
              <button class="icon-btn" @click="addEnvironment" title="新增环境">+</button>
              <button class="icon-btn" @click="showEnvModal = true" title="管理环境">⚙</button>
            </div>
          </div>
          <select v-model="activeEnvId" class="sidebar-select">
            <option value="">无环境</option>
            <option v-for="e in environments" :key="e.id" :value="e.id">{{ e.name }}</option>
          </select>
          <div v-if="activeEnv" class="env-quick-edit">
            <div class="env-quick-row">
              <input v-if="activeEnv._editing" v-model="activeEnv.name" class="inline-edit-input env-quick-name" @blur="finishEnvEdit(activeEnv)" @keydown.enter="finishEnvEdit(activeEnv)" />
              <span v-else class="env-quick-label" @dblclick="startEnvEdit(activeEnv)">{{ activeEnv.name }}</span>
              <button class="icon-btn-sm edit-btn" @click="startEnvEdit(activeEnv)" title="重命名">✏</button>
            </div>
            <input v-model="activeEnv.baseUrl" class="env-baseurl-input" placeholder="Base URL" />
          </div>
        </div>
        <div class="sidebar-section sidebar-groups">
          <div class="sidebar-header">
            <span>📂 分组</span>
            <div>
              <button class="icon-btn" @click="showImportModal = true" title="导入 OpenAPI">📥</button>
              <button class="icon-btn" @click="addGroup" title="添加分组">+</button>
            </div>
          </div>
          <div class="group-list">
            <div v-for="(g, gi) in groups" :key="g.id" class="group-item">
              <div :class="['group-title', { active: activeGroupId === g.id }]" @click="activeGroupId = g.id">
                <span class="group-arrow" @click.stop="toggleGroup(g.id)">{{ g.expanded ? '▾' : '▸' }}</span>
                <input v-if="g._editing" v-model="g.name" class="inline-edit-input" @blur="finishEdit(g)" @keydown.enter="finishEdit(g)" ref="groupEditInputs" />
                <span v-else class="group-name" @dblclick="startEdit(g)">{{ g.name }}</span>
                <button class="icon-btn-sm edit-btn" @click.stop="startEdit(g)" title="重命名">✏</button>
                <button class="icon-btn-sm" @click.stop="deleteGroup(gi)">✕</button>
              </div>
              <div v-show="g.expanded" class="group-apis">
                <div v-for="(api, ai) in g.apis" :key="api.id"
                  :class="['api-item', { active: activeApiId === api.id }]"
                  @click="selectApi(g.id, api.id)">
                  <span :class="['method-tag', methodClass(api.method)]">{{ api.method.slice(0, 4) }}</span>
                  <input v-if="api._editing" v-model="api.name" class="inline-edit-input" @blur="finishEdit(api)" @keydown.enter="finishEdit(api)" />
                  <span v-else class="api-path" @dblclick="startEdit(api)">{{ api.name || api.path }}</span>
                  <button class="icon-btn-sm edit-btn" @click.stop="startEdit(api)" title="重命名">✏</button>
                  <button class="icon-btn-sm" @click.stop="deleteApi(gi, ai)">✕</button>
                </div>
                <button class="add-api-btn" @click="addApi(g.id)">+ 新增接口</button>
              </div>
            </div>
            <div v-if="!groups.length" class="sidebar-empty">暂无分组</div>
          </div>
        </div>
      </div>

      <!-- 右侧：请求 + 响应 -->
      <div class="api-main">
        <div class="card">
          <div v-if="activeApiId" class="api-name-row">
            <input v-model="currentApiName" class="api-name-input" placeholder="接口名称" />
          </div>
          <div class="request-bar">
            <select v-model="method" class="method-select">
              <option v-for="m in methods" :key="m" :value="m">{{ m }}</option>
            </select>
            <input v-model="url" type="text" class="url-input"
              :placeholder="activeEnv?.baseUrl ? activeEnv.baseUrl + '/...' : 'https://api.example.com/users'"
              @keydown.enter="sendRequest" />
            <button class="btn btn-primary send-btn" @click="sendRequest" :disabled="loading">
              {{ loading ? '⏳' : '🚀' }} 发送
            </button>
            <label class="proxy-toggle" title="开启后通过后端代理发送请求，可绕过浏览器跨域限制">
              <input type="checkbox" v-model="useProxy" />
              <span class="proxy-label">代理</span>
            </label>
            <button class="btn btn-outline curl-import-btn" @click="showCurlModal = true" title="从 cURL 命令导入">📋 cURL</button>
          </div>
          <div v-if="activeEnv" class="env-hint">🌐 {{ activeEnv.name }}: {{ activeEnv.baseUrl }}</div>

          <div class="tabs">
            <button v-for="tab in tabs" :key="tab.id" :class="['tab-btn', { active: activeTab === tab.id }]" @click="activeTab = tab.id">
              {{ tab.label }}
              <span v-if="tab.id === 'headers' && headers.length" class="tab-badge">{{ headers.length }}</span>
              <span v-if="tab.id === 'params' && queryParams.length" class="tab-badge">{{ queryParams.length }}</span>
            </button>
          </div>

          <!-- Params -->
          <div v-show="activeTab === 'params'" class="tab-panel">
            <div class="kv-editor">
              <div class="kv-row kv-header-row"><span class="kv-check"></span><span class="kv-key-label">参数名</span><span class="kv-val-label">参数值</span><span class="kv-action"></span></div>
              <div v-for="(p, i) in queryParams" :key="i" class="kv-row">
                <input type="checkbox" v-model="p.enabled" class="kv-check" />
                <input v-model="p.key" class="kv-input" placeholder="key" @input="buildUrlFromParams" />
                <input v-model="p.value" class="kv-input" placeholder="value (支持 {{var}})" @input="buildUrlFromParams" />
                <button class="kv-del-btn" @click="queryParams.splice(i, 1); buildUrlFromParams()">✕</button>
              </div>
              <button class="btn btn-sm btn-outline kv-add-btn" @click="queryParams.push({ key: '', value: '', enabled: true })">+ 添加参数</button>
            </div>
          </div>

          <!-- Headers -->
          <div v-show="activeTab === 'headers'" class="tab-panel">
            <div v-if="mergedInheritedHeaders.length" class="inherited-headers">
              <div class="section-title">继承的 Headers</div>
              <div v-for="h in mergedInheritedHeaders" :key="h.key" class="kv-row inherited-row">
                <span class="kv-key-readonly">{{ h.key }}</span>
                <span class="kv-val-readonly">{{ h.value }}</span>
              </div>
            </div>
            <div class="kv-editor" style="margin-top:0.5rem">
              <div class="kv-row kv-header-row"><span class="kv-check"></span><span class="kv-key-label">Header 名</span><span class="kv-val-label">Header 值</span><span class="kv-action"></span></div>
              <div v-for="(h, i) in headers" :key="i" class="kv-row">
                <input type="checkbox" v-model="h.enabled" class="kv-check" />
                <input v-model="h.key" class="kv-input" placeholder="Content-Type" />
                <input v-model="h.value" class="kv-input" placeholder="值 (支持 {{var}})" />
                <button class="kv-del-btn" @click="headers.splice(i, 1)">✕</button>
              </div>
              <button class="btn btn-sm btn-outline kv-add-btn" @click="headers.push({ key: '', value: '', enabled: true })">+ 添加 Header</button>
            </div>
          </div>

          <!-- Body -->
          <div v-show="activeTab === 'body'" class="tab-panel">
            <div class="body-type-row">
              <label v-for="bt in bodyTypes" :key="bt.id" :class="['radio-label', { active: bodyType === bt.id }]">
                <input type="radio" v-model="bodyType" :value="bt.id" /> {{ bt.label }}
              </label>
            </div>
            <div v-if="bodyType === 'none'" class="body-hint">此请求不携带 Body</div>
            <div v-else-if="bodyType === 'json'">
              <textarea v-model="body" class="code-textarea" placeholder='{"key": "value"}' rows="8"></textarea>
              <button class="btn btn-sm btn-outline" style="margin-top:0.4rem" @click="formatJSON">格式化 JSON</button>
            </div>
            <div v-else-if="bodyType === 'form'">
              <div class="kv-editor">
                <div v-for="(f, i) in formData" :key="i" class="kv-row">
                  <input type="checkbox" v-model="f.enabled" class="kv-check" />
                  <input v-model="f.key" class="kv-input" placeholder="key" />
                  <input v-model="f.value" class="kv-input" placeholder="value" />
                  <button class="kv-del-btn" @click="formData.splice(i, 1)">✕</button>
                </div>
                <button class="btn btn-sm btn-outline kv-add-btn" @click="formData.push({ key: '', value: '', enabled: true, type: 'text', filename: '', fileContent: '' })">+ 添加字段</button>
              </div>
            </div>
            <div v-else-if="bodyType === 'multipart'">
              <div class="kv-editor">
                <div v-for="(f, i) in formData" :key="i" class="kv-row multipart-row">
                  <input type="checkbox" v-model="f.enabled" class="kv-check" />
                  <select v-model="f.type" class="type-select"><option value="text">文本</option><option value="file">文件</option></select>
                  <input v-model="f.key" class="kv-input" placeholder="字段名" />
                  <div v-if="f.type === 'file'" class="file-input-wrap">
                    <input type="file" class="file-real-input" @change="handleFileSelect($event, i)" />
                    <span class="file-label">{{ f.filename || '选择文件' }}</span>
                  </div>
                  <input v-else v-model="f.value" class="kv-input" placeholder="值" />
                  <button class="kv-del-btn" @click="formData.splice(i, 1)">✕</button>
                </div>
                <button class="btn btn-sm btn-outline kv-add-btn" @click="formData.push({ key: '', value: '', enabled: true, type: 'text', filename: '', fileContent: '' })">+ 添加字段</button>
              </div>
            </div>
            <div v-else-if="bodyType === 'raw'">
              <textarea v-model="body" class="code-textarea" placeholder="Raw request body..." rows="8"></textarea>
            </div>
          </div>

          <!-- Auth -->
          <div v-show="activeTab === 'auth'" class="tab-panel">
            <div class="body-type-row">
              <label v-for="at in authTypes" :key="at.id" :class="['radio-label', { active: authType === at.id }]">
                <input type="radio" v-model="authType" :value="at.id" /> {{ at.label }}
              </label>
            </div>
            <div v-if="authType === 'bearer'" class="form-group" style="margin-top:0.5rem">
              <label>Token</label>
              <input v-model="authToken" class="input-text" placeholder="支持 {{token}}" />
            </div>
            <div v-else-if="authType === 'basic'" style="margin-top:0.5rem">
              <div class="form-row">
                <div class="form-group half"><label>用户名</label><input v-model="authUser" class="input-text" /></div>
                <div class="form-group half"><label>密码</label><input v-model="authPass" class="input-text" type="password" /></div>
              </div>
            </div>
            <div v-else class="body-hint">此请求不使用认证</div>
          </div>

          <!-- 变量 -->
          <div v-show="activeTab === 'variables'" class="tab-panel">
            <div class="var-hint">使用 <code v-pre>{{变量名}}</code> 在 URL、Header、Body 中引用变量，运行时自动替换为当前环境的变量值。</div>
            <div class="kv-editor" style="margin-top:0.5rem">
              <div class="kv-row kv-header-row"><span class="kv-key-label">变量名</span><span class="kv-val-label">当前值（{{ activeEnv?.name || '无环境' }}）</span><span class="kv-action"></span></div>
              <div v-for="(v, i) in localVars" :key="i" class="kv-row">
                <input v-model="v.key" class="kv-input" placeholder="变量名" />
                <input v-model="v.value" class="kv-input" placeholder="变量值" />
                <button class="kv-del-btn" @click="localVars.splice(i, 1)">✕</button>
              </div>
              <button class="btn btn-sm btn-outline kv-add-btn" @click="localVars.push({ key: '', value: '' })">+ 添加变量</button>
            </div>
          </div>
        </div>

        <!-- 响应 -->
        <div v-if="response" class="card">
          <div class="response-header">
            <h3>响应</h3>
            <div class="response-meta">
              <span :class="['status-badge', statusClass]">{{ response.status_code }}</span>
              <span class="meta-item">⏱ {{ response.duration }}ms</span>
              <span class="meta-item">📦 {{ formatSize(response.size) }}</span>
              <span :class="['content-type-badge', 'ctype-' + respBodyType]">{{ respBodyTypeLabel }}</span>
            </div>
          </div>
          <div class="tabs">
            <button :class="['tab-btn', { active: respTab === 'body' }]" @click="respTab = 'body'">Body</button>
            <button :class="['tab-btn', { active: respTab === 'headers' }]" @click="respTab = 'headers'">Headers</button>
          </div>
          <div v-show="respTab === 'body'" class="tab-panel">
            <div class="response-body-actions">
              <button class="btn btn-sm btn-outline" @click="copyBody">📋 复制</button>
              <button v-if="isJSON || isXML || isHTML" class="btn btn-sm btn-outline" @click="toggleRespFormat">{{ respFormatted ? '📑 压缩' : '✨ 格式化' }}</button>
            </div>
            <!-- 图片预览 -->
            <div v-if="isImage" class="response-image-preview">
              <img :src="respImageSrc" alt="Response Image" class="preview-img" @error="onImageError" />
              <div v-if="imageLoadError" class="image-error-hint">图片加载失败，原始数据如下：</div>
            </div>
            <!-- 音视频 -->
            <div v-if="isMedia" class="response-media-preview">
              <audio v-if="respContentType.startsWith('audio/')" :src="respImageSrc" controls class="preview-audio"></audio>
              <video v-else-if="respContentType.startsWith('video/')" :src="respImageSrc" controls class="preview-video"></video>
            </div>
            <!-- 二进制 -->
            <div v-if="isBinary" class="response-binary-hint">
              <span>📎 二进制文件（{{ formatSize(response.size) }}），无法预览</span>
            </div>
            <!-- 文本类响应（JSON/XML/HTML/Text）使用语法高亮 -->
            <pre v-if="!isImage && !isMedia && !isBinary" class="response-body" :class="{ 'response-error': response.status_code >= 400 }" v-html="respBodyHTML"></pre>
          </div>
          <div v-show="respTab === 'headers'" class="tab-panel">
            <table class="format-table">
              <thead><tr><th>Header</th><th>Value</th></tr></thead>
              <tbody>
                <tr v-for="(v, k) in response.headers" :key="k"><td><code>{{ k }}</code></td><td style="word-break:break-all">{{ v }}</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <!-- 环境管理弹窗 -->
    <div v-if="showEnvModal" class="modal-overlay" @click.self="showEnvModal = false">
      <div class="modal env-modal">
        <div class="modal-header"><h3>🌍 环境管理</h3><button class="icon-btn" @click="showEnvModal = false">✕</button></div>
        <div class="modal-body">
          <div v-if="!environments.length" class="env-empty">
            <p>暂无环境，点击下方按钮新增</p>
          </div>
          <div v-for="(env, i) in environments" :key="env.id" class="env-card">
            <div class="env-card-header">
              <div class="env-card-name-wrap">
                <input v-if="env._editing" v-model="env.name" class="inline-edit-input env-name-inline" @blur="finishEnvEdit(env)" @keydown.enter="finishEnvEdit(env)" />
                <span v-else class="env-card-name" @dblclick="startEnvEdit(env)">{{ env.name || '未命名环境' }}</span>
                <button class="icon-btn-sm edit-btn" @click="startEnvEdit(env)" title="重命名">✏</button>
              </div>
              <div class="env-card-actions">
                <button v-if="activeEnvId === env.id" class="env-active-badge">当前</button>
                <button class="icon-btn-sm" @click="activeEnvId = env.id" title="设为当前" v-else>⬡</button>
                <button class="icon-btn-sm" @click="deleteEnvironment(i)" title="删除环境">✕</button>
              </div>
            </div>
            <div class="form-group"><label>Base URL</label><input v-model="env.baseUrl" class="input-text" placeholder="https://api.example.com" /></div>
            <div class="form-group"><label>环境变量 <code v-pre>{{变量名}}</code></label>
              <div class="kv-editor">
                <div v-for="(v, vi) in env.variables" :key="vi" class="kv-row">
                  <input v-model="v.key" class="kv-input" placeholder="变量名" /><input v-model="v.value" class="kv-input" placeholder="变量值" /><button class="kv-del-btn" @click="env.variables.splice(vi, 1)">✕</button>
                </div>
                <button class="btn btn-sm btn-outline kv-add-btn" @click="env.variables.push({ key: '', value: '' })">+ 添加变量</button>
              </div>
            </div>
            <div class="form-group"><label>公共 Headers</label>
              <div class="kv-editor">
                <div v-for="(h, hi) in env.headers" :key="hi" class="kv-row">
                  <input v-model="h.key" class="kv-input" placeholder="Header 名" /><input v-model="h.value" class="kv-input" placeholder="Header 值" /><button class="kv-del-btn" @click="env.headers.splice(hi, 1)">✕</button>
                </div>
                <button class="btn btn-sm btn-outline kv-add-btn" @click="env.headers.push({ key: '', value: '' })">+ 添加 Header</button>
              </div>
            </div>
          </div>
          <button class="btn btn-primary" @click="addEnvironment" style="margin-top:0.5rem">+ 新增环境</button>
        </div>
      </div>
    </div>

    <!-- OpenAPI 导入弹窗 -->
    <div v-if="showImportModal" class="modal-overlay" @click.self="showImportModal = false">
      <div class="modal">
        <div class="modal-header"><h3>📥 导入 OpenAPI</h3><button class="icon-btn" @click="showImportModal = false">✕</button></div>
        <div class="modal-body">
          <p class="import-hint">支持 Swagger 2.0 和 OpenAPI 3.0 JSON 格式</p>
          <div class="form-group"><label>从 URL 导入</label>
            <div style="display:flex;gap:0.5rem">
              <input v-model="importUrl" class="input-text" placeholder="https://petstore.swagger.io/v2/swagger.json" />
              <button class="btn btn-primary" @click="doImport('url')" :disabled="importing">{{ importing ? '...' : '拉取' }}</button>
            </div>
          </div>
          <div class="form-group" style="margin-top:0.75rem"><label>或粘贴 JSON 内容</label>
            <textarea v-model="importContent" class="code-textarea" rows="8" placeholder='{"openapi":"3.0.0",...}'></textarea>
          </div>
          <button class="btn btn-primary" style="margin-top:0.5rem" @click="doImport('content')" :disabled="importing">导入</button>
        </div>
      </div>
    </div>

    <!-- cURL 导入弹窗 -->
    <div v-if="showCurlModal" class="modal-overlay" @click.self="showCurlModal = false">
      <div class="modal">
        <div class="modal-header"><h3>📋 从 cURL 导入</h3><button class="icon-btn" @click="showCurlModal = false">✕</button></div>
        <div class="modal-body">
          <p class="import-hint">粘贴从浏览器开发者工具复制的 cURL 命令，自动解析填充请求参数</p>
          <div class="form-group">
            <textarea v-model="curlInput" class="code-textarea" rows="10" placeholder="curl 'https://api.example.com/users' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer token123' \
  --data-raw '{&quot;name&quot;:&quot;test&quot;}'"></textarea>
          </div>
          <button class="btn btn-primary" style="margin-top:0.5rem" @click="importCurl">解析并填充</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch, nextTick, inject } from 'vue'
import { apiPost, copyToClipboard } from '../api.js'

const showAlert = inject('showAlert')

const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
const bodyTypes = [
  { id: 'none', label: 'none' }, { id: 'json', label: 'JSON' },
  { id: 'form', label: 'x-www-form' }, { id: 'multipart', label: 'form-data' }, { id: 'raw', label: 'Raw' },
]
const authTypes = [
  { id: 'none', label: 'none' }, { id: 'bearer', label: 'Bearer Token' }, { id: 'basic', label: 'Basic Auth' },
]
const tabs = [
  { id: 'params', label: 'Params' }, { id: 'headers', label: 'Headers' },
  { id: 'body', label: 'Body' }, { id: 'auth', label: 'Auth' }, { id: 'variables', label: '变量' },
]

// === 状态 ===
const method = ref('GET')
const url = ref('')
const activeTab = ref('params')
const respTab = ref('body')
const loading = ref(false)
const importing = ref(false)
const response = ref(null)
const bodyType = ref('none')
const authType = ref('none')
const authToken = ref('')
const authUser = ref('')
const authPass = ref('')
const body = ref('')
const showEnvModal = ref(false)
const showImportModal = ref(false)
const importUrl = ref('')
const importContent = ref('')
const showCurlModal = ref(false)
const curlInput = ref('')
const activeEnvId = ref('')
const activeGroupId = ref('')
const activeApiId = ref('')
const useProxy = ref(false)

let idCounter = Date.now()
function genId() { return String(++idCounter) }

const groups = ref([])
const environments = ref([])
const queryParams = ref([{ key: '', value: '', enabled: true }])
const headers = ref([
  { key: 'Content-Type', value: 'application/json', enabled: true },
  { key: 'Accept', value: '*/*', enabled: true },
])
const formData = ref([{ key: '', value: '', enabled: true, type: 'text', filename: '', fileContent: '' }])
const localVars = ref([])

// === 计算属性 ===
const activeEnv = computed(() => environments.value.find(e => e.id === activeEnvId.value))
const activeGroup = computed(() => groups.value.find(g => g.id === activeGroupId.value))
const activeApi = computed(() => {
  if (!activeGroup.value) return null
  return activeGroup.value.apis.find(a => a.id === activeApiId.value) || null
})

const currentApiName = computed({
  get() { return activeApi.value?.name || '' },
  set(val) { if (activeApi.value) activeApi.value.name = val }
})

const mergedInheritedHeaders = computed(() => {
  const result = []
  if (activeEnv.value?.headers) {
    for (const h of activeEnv.value.headers) {
      if (h.key?.trim()) result.push({ key: h.key, value: h.value, source: 'env' })
    }
  }
  if (activeGroup.value?.headers) {
    for (const h of activeGroup.value.headers) {
      if (h.key?.trim()) result.push({ key: h.key, value: h.value, source: 'group' })
    }
  }
  return result
})

// === 变量替换 ===
function resolveVariables(text) {
  if (!text) return text
  const vars = {}
  if (activeEnv.value) {
    for (const v of activeEnv.value.variables) { if (v.key) vars[v.key] = v.value || '' }
  }
  for (const v of localVars.value) { if (v.key) vars[v.key] = v.value || '' }
  return text.replace(/\{\{(\w+)\}\}/g, (_, key) => vars[key] !== undefined ? vars[key] : `{{${key}}}`)
}

// === 持久化 ===
let _saveTimer = null
let _loaded = false

onMounted(async () => {
  // 从后端加载状态
  try {
    const res = await apiPost('/api/api-tester/state/get')
    if (res.code === 0 && res.data) {
      const s = res.data
      if (s.method) method.value = s.method
      if (s.url) url.value = s.url
      if (s.bodyType) bodyType.value = s.bodyType
      if (s.body) body.value = s.body
      if (s.authType) authType.value = s.authType
      if (s.authToken) authToken.value = s.authToken
      if (s.authUser !== undefined) authUser.value = s.authUser
      if (s.authPass !== undefined) authPass.value = s.authPass
      if (s.headers?.length) headers.value = s.headers
      if (s.queryParams?.length) queryParams.value = s.queryParams
      if (s.formData?.length) formData.value = s.formData
      if (s.localVars?.length) localVars.value = s.localVars
      if (s.groups?.length) groups.value = s.groups
      if (s.environments?.length) environments.value = s.environments
      if (s.activeEnvId) activeEnvId.value = s.activeEnvId
      if (s.activeGroupId) activeGroupId.value = s.activeGroupId
      if (s.activeApiId) activeApiId.value = s.activeApiId
      if (s.idCounter) idCounter = s.idCounter
      if (s.useProxy !== undefined) useProxy.value = s.useProxy
    }
  } catch {}
  _loaded = true
})

function saveState() {
  if (!_loaded) return
  // 防抖：500ms 内只保存一次
  if (_saveTimer) clearTimeout(_saveTimer)
  _saveTimer = setTimeout(() => {
    apiPost('/api/api-tester/state/save', {
      method: method.value, url: url.value, bodyType: bodyType.value, body: body.value,
      authType: authType.value, authToken: authToken.value, authUser: authUser.value, authPass: authPass.value,
      headers: headers.value, queryParams: queryParams.value, formData: formData.value,
      localVars: localVars.value, groups: groups.value, environments: environments.value,
      activeEnvId: activeEnvId.value, activeGroupId: activeGroupId.value, activeApiId: activeApiId.value, idCounter,
      useProxy: useProxy.value,
    }).catch(() => {})
  }, 500)
}

watch([method, url, bodyType, body, authType, authToken, authUser, authPass, activeEnvId, activeGroupId, activeApiId, useProxy], saveState, { deep: true })
watch([headers, queryParams, formData, localVars, groups, environments], saveState, { deep: true })

// === 分组管理 ===
function addGroup() {
  const g = { id: genId(), name: '新分组', expanded: true, baseUrl: '', headers: [], apis: [] }
  groups.value.push(g); activeGroupId.value = g.id
}
function deleteGroup(gi) { groups.value.splice(gi, 1) }
function toggleGroup(id) { const g = groups.value.find(g => g.id === id); if (g) g.expanded = !g.expanded }

// 内联编辑
function startEdit(item) {
  item._editing = true
  nextTick(() => {
    const el = document.querySelector('.inline-edit-input')
    if (el) el.focus()
  })
}
function finishEdit(item) {
  item._editing = false
  if (!item.name?.trim()) item.name = item.path || '未命名'
}
// === cURL 解析导入 ===
function parseCurl(curlStr) {
  // 预处理：合并多行（反斜杠续行）
  let str = curlStr.trim().replace(/\\\r?\n/g, ' ').replace(/\s+/g, ' ')

  // 提取 token（支持单引号、双引号、无引号）
  const tokens = []
  let i = 0
  while (i < str.length) {
    if (str[i] === ' ') { i++; continue }
    let token = ''
    if (str[i] === "'") {
      i++
      while (i < str.length && str[i] !== "'") { token += str[i]; i++ }
      i++ // skip closing quote
    } else if (str[i] === '"') {
      i++
      while (i < str.length && str[i] !== '"') {
        if (str[i] === '\\' && i + 1 < str.length) { token += str[i + 1]; i += 2 }
        else { token += str[i]; i++ }
      }
      i++ // skip closing quote
    } else {
      while (i < str.length && str[i] !== ' ') { token += str[i]; i++ }
    }
    if (token) tokens.push(token)
  }

  const result = { method: 'GET', url: '', headers: [], body: '', bodyType: 'none' }
  let j = 0

  // 跳过 curl 命令本身
  if (tokens[0]?.toLowerCase() === 'curl') j = 1

  while (j < tokens.length) {
    const t = tokens[j]

    // -X / --request
    if (t === '-X' || t === '--request') {
      result.method = tokens[++j] || 'GET'
      j++
      continue
    }

    // -H / --header
    if (t === '-H' || t === '--header') {
      const hdr = tokens[++j] || ''
      const colonIdx = hdr.indexOf(':')
      if (colonIdx > 0) {
        result.headers.push({
          key: hdr.slice(0, colonIdx).trim(),
          value: hdr.slice(colonIdx + 1).trim(),
          enabled: true,
        })
      }
      j++
      continue
    }

    // -d / --data / --data-raw / --data-binary / --data-urlencode
    if (t === '-d' || t === '--data' || t === '--data-raw' || t === '--data-binary' || t === '--data-urlencode') {
      result.body = tokens[++j] || ''
      if (result.method === 'GET') result.method = 'POST'
      j++
      continue
    }

    // -F / --form
    if (t === '-F' || t === '--form') {
      result.bodyType = 'multipart'
      // form 字段暂存到 body，后续处理
      const field = tokens[++j] || ''
      if (!result.body) result.body = field
      else result.body += '\n' + field
      if (result.method === 'GET') result.method = 'POST'
      j++
      continue
    }

    // --compressed / -k / --insecure / -s / --silent / -v / --verbose / -L / --location
    if (['--compressed', '-k', '--insecure', '-s', '--silent', '-S', '--show-error', '-v', '--verbose', '-L', '--location', '-g', '--globoff', '-i', '--include', '-N', '--no-buffer'].includes(t)) {
      j++
      continue
    }

    // -u / --user (Basic Auth)
    if (t === '-u' || t === '--user') {
      const cred = tokens[++j] || ''
      const colonIdx = cred.indexOf(':')
      if (colonIdx > 0) {
        result.authType = 'basic'
        result.authUser = cred.slice(0, colonIdx)
        result.authPass = cred.slice(colonIdx + 1)
      }
      j++
      continue
    }

    // -b / --cookie
    if (t === '-b' || t === '--cookie') {
      const cookie = tokens[++j] || ''
      result.headers.push({ key: 'Cookie', value: cookie, enabled: true })
      j++
      continue
    }

    // -A / --user-agent
    if (t === '-A' || t === '--user-agent') {
      const ua = tokens[++j] || ''
      result.headers.push({ key: 'User-Agent', value: ua, enabled: true })
      j++
      continue
    }

    // -e / --referer
    if (t === '-e' || t === '--referer') {
      const ref = tokens[++j] || ''
      result.headers.push({ key: 'Referer', value: ref, enabled: true })
      j++
      continue
    }

    // -o / --output / -w / --write-out / --connect-timeout / --max-time / -m / --retry 等（跳过带值的 flag）
    if (['-o', '--output', '-w', '--write-out', '--connect-timeout', '--max-time', '-m', '--retry', '--retry-delay', '--retry-max-time', '--limit-rate', '--local-port', '-E', '--cert', '--cert-type', '--key', '--key-type', '--cacert', '--capath', '-T', '--upload-file', '-c', '--cookie-jar'].includes(t)) {
      j += 2
      continue
    }

    // URL（第一个不以 - 开头的 token）
    if (!t.startsWith('-')) {
      if (!result.url) {
        result.url = t
        // 移除 URL 外层引号
        if ((result.url.startsWith("'") && result.url.endsWith("'")) ||
            (result.url.startsWith('"') && result.url.endsWith('"'))) {
          result.url = result.url.slice(1, -1)
        }
      }
      j++
      continue
    }

    // 其他未知 flag，跳过
    j++
  }

  // 根据 Content-Type 推断 bodyType
  const ct = result.headers.find(h => h.key.toLowerCase() === 'content-type')
  if (result.body && result.bodyType === 'none') {
    if (ct?.value.includes('application/json')) result.bodyType = 'json'
    else if (ct?.value.includes('application/x-www-form-urlencoded')) result.bodyType = 'form'
    else if (ct?.value.includes('multipart/form-data')) result.bodyType = 'multipart'
    else result.bodyType = 'raw'
  }

  // 提取 Bearer Token
  const authHdr = result.headers.find(h => h.key.toLowerCase() === 'authorization')
  if (authHdr && !result.authType) {
    if (authHdr.value.startsWith('Bearer ')) {
      result.authType = 'bearer'
      result.authToken = authHdr.value.slice(7)
      // 从 headers 中移除，用 Auth 面板管理
      result.headers = result.headers.filter(h => h !== authHdr)
    }
  }

  return result
}

function importCurl() {
  if (!curlInput.value.trim()) { showToast('请粘贴 cURL 命令'); return }
  try {
    const parsed = parseCurl(curlInput.value)

    // 如果没有选中接口，自动在第一个分组下创建新接口
    if (!activeApiId.value && groups.value.length) {
      if (!activeGroupId.value) activeGroupId.value = groups.value[0].id
      addApi(activeGroupId.value)
    }

    method.value = parsed.method
    url.value = parsed.url

    // 解析 URL 中的 query params
    try {
      const u = new URL(parsed.url)
      const params = []
      u.searchParams.forEach((v, k) => params.push({ key: k, value: v, enabled: true }))
      if (params.length) {
        queryParams.value = params
        url.value = u.origin + u.pathname
      }
    } catch {}

    if (parsed.headers.length) headers.value = parsed.headers
    if (parsed.body) {
      bodyType.value = parsed.bodyType
      body.value = parsed.body
      // JSON 格式化
      if (parsed.bodyType === 'json') {
        try { body.value = JSON.stringify(JSON.parse(parsed.body), null, 2) } catch {}
      }
    }
    if (parsed.authType && parsed.authType !== 'none') {
      authType.value = parsed.authType
      if (parsed.authType === 'bearer') authToken.value = parsed.authToken || ''
      if (parsed.authType === 'basic') {
        authUser.value = parsed.authUser || ''
        authPass.value = parsed.authPass || ''
      }
    }

    showCurlModal.value = false
    curlInput.value = ''
    showToast('cURL 导入成功')
    saveState()
  } catch (e) {
    showToast('解析 cURL 失败: ' + e.message)
  }
}

function addApi(groupId) {
  const g = groups.value.find(g => g.id === groupId); if (!g) return
  const api = { id: genId(), name: '新接口', method: 'GET', path: '/', summary: '', headers: [], params: [], bodyType: 'none', body: '', authType: 'none', authToken: '' }
  g.apis.push(api); selectApi(groupId, api.id)
}
function deleteApi(gi, ai) { groups.value[gi].apis.splice(ai, 1) }
function selectApi(groupId, apiId) {
  saveCurrentApiState()
  activeGroupId.value = groupId; activeApiId.value = apiId
  const g = groups.value.find(g => g.id === groupId); if (!g) return
  const api = g.apis.find(a => a.id === apiId); if (!api) return
  method.value = api.method || 'GET'
  url.value = (g.baseUrl || '') + (api.path || '')
  bodyType.value = api.bodyType || 'none'; body.value = api.body || ''
  authType.value = api.authType || 'none'; authToken.value = api.authToken || ''
  queryParams.value = api.params?.length ? JSON.parse(JSON.stringify(api.params)) : [{ key: '', value: '', enabled: true }]
  headers.value = api.headers?.length ? JSON.parse(JSON.stringify(api.headers)) : [{ key: 'Content-Type', value: 'application/json', enabled: true }, { key: 'Accept', value: '*/*', enabled: true }]
}

function saveCurrentApiState() {
  if (!activeApi.value) return
  const api = activeApi.value
  api.method = method.value
  let path = url.value
  if (activeGroup.value?.baseUrl && path.startsWith(activeGroup.value.baseUrl)) {
    path = path.slice(activeGroup.value.baseUrl.length) || '/'
  }
  api.path = path
  api.bodyType = bodyType.value
  api.body = body.value
  api.authType = authType.value
  api.authToken = authToken.value
  api.params = JSON.parse(JSON.stringify(queryParams.value))
  api.headers = JSON.parse(JSON.stringify(headers.value))
}

watch([method, url, bodyType, body, authType, authToken, headers, queryParams], () => {
  saveCurrentApiState()
}, { deep: true })

// === 环境管理 ===
function addEnvironment() {
  const env = { id: genId(), name: '新环境', baseUrl: '', variables: [{ key: '', value: '' }], headers: [], _editing: false }
  environments.value.push(env)
  activeEnvId.value = env.id
  // 自动进入编辑名称
  nextTick(() => startEnvEdit(env))
}
function deleteEnvironment(i) {
  const env = environments.value[i]
  if (activeEnvId.value === env.id) activeEnvId.value = ''
  environments.value.splice(i, 1)
}
function startEnvEdit(env) {
  env._editing = true
  nextTick(() => {
    const el = document.querySelector('.env-name-inline')
    if (el) { el.focus(); el.select() }
  })
}
function finishEnvEdit(env) {
  env._editing = false
  if (!env.name?.trim()) env.name = '未命名环境'
}

// === 文件上传 ===
function handleFileSelect(event, index) {
  const file = event.target.files[0]; if (!file) return
  const reader = new FileReader()
  reader.onload = () => {
    const base64 = (reader.result.split(',')[1] || reader.result)
    formData.value[index].filename = file.name
    formData.value[index].fileContent = base64
    formData.value[index].value = file.name
  }
  reader.readAsDataURL(file)
}

// === 请求发送 ===
function buildRequestPayload() {
  const reqHeaders = {}
  // 环境级 Headers
  if (activeEnv.value?.headers) {
    for (const h of activeEnv.value.headers) { if (h.key?.trim()) reqHeaders[h.key.trim()] = resolveVariables(h.value) }
  }
  // 分组级 Headers
  if (activeGroup.value?.headers) {
    for (const h of activeGroup.value.headers) { if (h.key?.trim()) reqHeaders[h.key.trim()] = resolveVariables(h.value) }
  }
  // 请求级 Headers
  for (const h of headers.value) { if (h.enabled && h.key.trim()) reqHeaders[h.key.trim()] = resolveVariables(h.value) }
  // Auth
  if (authType.value === 'bearer' && authToken.value) reqHeaders['Authorization'] = `Bearer ${resolveVariables(authToken.value)}`
  else if (authType.value === 'basic' && authUser.value) reqHeaders['Authorization'] = `Basic ${btoa(`${authUser.value}:${authPass.value}`)}`

  let reqBody = '', reqBodyType = bodyType.value
  const multipartFiles = []

  if (bodyType.value === 'json') {
    reqBody = resolveVariables(body.value)
    if (!reqHeaders['Content-Type']) reqHeaders['Content-Type'] = 'application/json'
  } else if (bodyType.value === 'form') {
    const params = new URLSearchParams()
    for (const f of formData.value) { if (f.enabled && f.key.trim()) params.append(f.key.trim(), resolveVariables(f.value)) }
    reqBody = params.toString(); reqHeaders['Content-Type'] = 'application/x-www-form-urlencoded'
  } else if (bodyType.value === 'multipart') {
    reqBodyType = 'multipart'
    for (const f of formData.value) {
      if (f.enabled && f.type === 'file' && f.key.trim() && f.fileContent) {
        multipartFiles.push({ fieldname: f.key.trim(), filename: f.filename || 'file', content: f.fileContent, content_type: '' })
      }
    }
  } else if (bodyType.value === 'raw') {
    reqBody = resolveVariables(body.value)
  }

  // URL 替换
  let finalUrl = resolveVariables(url.value)
  if (activeEnv.value?.baseUrl && !finalUrl.startsWith('http')) {
    finalUrl = activeEnv.value.baseUrl.replace(/\/+$/, '') + '/' + finalUrl.replace(/^\/+/, '')
  }

  return {
    method: method.value, url: finalUrl, headers: reqHeaders, body: reqBody, body_type: reqBodyType,
    form_data: formData.value.filter(f => f.enabled && f.key.trim() && f.type !== 'file').map(f => ({ key: f.key, value: resolveVariables(f.value), enabled: f.enabled, type: f.type || 'text' })),
    multipart_files: multipartFiles, timeout: 30,
  }
}

async function sendRequest() {
  if (!url.value.trim()) return
  loading.value = true; response.value = null; respTab.value = 'body'
  const startTime = Date.now()
  try {
    if (useProxy.value) {
      // 后端代理模式
      const payload = buildRequestPayload()
      const res = await apiPost('/api/proxy/send', payload)
      response.value = res.code === 0 ? res.data : { status_code: 0, headers: {}, body: `请求失败: ${res.message}`, size: 0, duration: 0 }
    } else {
      // 前端直发模式
      response.value = await sendDirect()
    }
  } catch (err) {
    response.value = { status_code: 0, headers: {}, body: `网络错误: ${err.message}`, size: 0, duration: Date.now() - startTime }
  } finally { loading.value = false }
}

// 前端直接发送 HTTP 请求（不走代理）
async function sendDirect() {
  const startTime = Date.now()
  // URL 替换
  let finalUrl = resolveVariables(url.value)
  if (activeEnv.value?.baseUrl && !finalUrl.startsWith('http')) {
    finalUrl = activeEnv.value.baseUrl.replace(/\/+$/, '') + '/' + finalUrl.replace(/^\/+/, '')
  }

  // 构建请求头
  const reqHeaders = {}
  if (activeEnv.value?.headers) {
    for (const h of activeEnv.value.headers) { if (h.key?.trim()) reqHeaders[h.key.trim()] = resolveVariables(h.value) }
  }
  if (activeGroup.value?.headers) {
    for (const h of activeGroup.value.headers) { if (h.key?.trim()) reqHeaders[h.key.trim()] = resolveVariables(h.value) }
  }
  for (const h of headers.value) { if (h.enabled && h.key.trim()) reqHeaders[h.key.trim()] = resolveVariables(h.value) }
  if (authType.value === 'bearer' && authToken.value) reqHeaders['Authorization'] = `Bearer ${resolveVariables(authToken.value)}`
  else if (authType.value === 'basic' && authUser.value) reqHeaders['Authorization'] = `Basic ${btoa(`${authUser.value}:${authPass.value}`)}`

  // 构建 Body
  let reqBody = undefined
  if (bodyType.value === 'json') {
    reqBody = resolveVariables(body.value)
    if (!reqHeaders['Content-Type']) reqHeaders['Content-Type'] = 'application/json'
  } else if (bodyType.value === 'form') {
    const params = new URLSearchParams()
    for (const f of formData.value) { if (f.enabled && f.key.trim()) params.append(f.key.trim(), resolveVariables(f.value)) }
    reqBody = params.toString()
    reqHeaders['Content-Type'] = 'application/x-www-form-urlencoded'
  } else if (bodyType.value === 'raw') {
    reqBody = resolveVariables(body.value)
  } else if (bodyType.value === 'multipart') {
    const fd = new FormData()
    for (const f of formData.value) {
      if (!f.enabled || !f.key.trim()) continue
      if (f.type === 'file' && f.fileContent) {
        // base64 转 Blob
        const byteStr = atob(f.fileContent)
        const ab = new Uint8Array(byteStr.length)
        for (let i = 0; i < byteStr.length; i++) ab[i] = byteStr.charCodeAt(i)
        const blob = new Blob([ab])
        fd.append(f.key.trim(), blob, f.filename || 'file')
      } else {
        fd.append(f.key.trim(), resolveVariables(f.value))
      }
    }
    reqBody = fd
    // 让浏览器自动设置 Content-Type（含 boundary）
    delete reqHeaders['Content-Type']
  }

  const fetchOpts = { method: method.value, headers: reqHeaders }
  if (reqBody !== undefined && !['GET', 'HEAD'].includes(method.value)) fetchOpts.body = reqBody

  const resp = await fetch(finalUrl, fetchOpts)
  const respBody = await resp.text()
  const respHeaders = {}
  resp.headers.forEach((v, k) => { respHeaders[k] = v })

  return {
    status_code: resp.status,
    headers: respHeaders,
    body: respBody,
    size: new Blob([respBody]).size,
    duration: Date.now() - startTime,
  }
}

// === OpenAPI 导入 ===
async function doImport(mode) {
  importing.value = true
  try {
    const payload = mode === 'url' ? { url: importUrl.value } : { content: importContent.value }
    const res = await apiPost('/api/proxy/openapi-import', payload)
    if (res.code === 0) { applyImport(res.data); showImportModal.value = false }
    else await showAlert({ title: '导入失败', message: res.message })
  } catch (err) { await showAlert({ title: '导入失败', message: err.message }) }
  finally { importing.value = false }
}

function applyImport(data) {
  for (const g of data.groups || []) {
    groups.value.push({
      id: genId(), name: g.name || '未命名', expanded: true,
      baseUrl: g.base_url || '',
      headers: (g.headers || []).map(h => ({ key: h.key, value: h.value, enabled: h.enabled !== false })),
      apis: (g.apis || []).map(api => ({
        id: genId(), name: api.summary || api.name || api.path, method: api.method || 'GET',
        path: api.path || '/', summary: api.summary || '',
        headers: (api.headers || []).map(h => ({ key: h.key, value: h.value, enabled: h.enabled !== false })),
        params: (api.params || []).map(p => ({ key: p.key, value: p.value, enabled: p.enabled !== false })),
        bodyType: api.body_type || 'none', body: api.body || '',
        authType: api.auth_type || 'none', authToken: api.auth_token || '',
      })),
    })
  }
}

// === 辅助函数 ===
function buildUrlFromParams() {
  try {
    const u = new URL(url.value); u.search = ''
    for (const p of queryParams.value) { if (p.enabled && p.key.trim()) u.searchParams.append(p.key.trim(), p.value) }
    url.value = u.toString()
  } catch {}
}

function formatJSON() {
  try { body.value = JSON.stringify(JSON.parse(body.value), null, 2) } catch {}
}

// === 响应内容类型检测与美化 ===
const respFormatted = ref(true)

// 从响应头获取 Content-Type（小写 key 匹配）
const respContentType = computed(() => {
  if (!response.value?.headers) return ''
  for (const [k, v] of Object.entries(response.value.headers)) {
    if (k.toLowerCase() === 'content-type') return (v || '').toLowerCase()
  }
  return ''
})

// 检测响应体的实际内容类型
const respBodyType = computed(() => {
  if (!response.value?.body) return 'empty'
  const ct = respContentType.value
  const body = response.value.body.trim()

  // 图片（Base64 或二进制标识）
  if (ct.startsWith('image/')) return 'image'
  // 音视频
  if (ct.startsWith('audio/') || ct.startsWith('video/')) return 'media'
  // PDF
  if (ct.includes('pdf')) return 'pdf'
  // 二进制
  if (ct.includes('octet-stream') || ct.includes('zip') || ct.includes('gzip') || ct.includes('binary')) return 'binary'

  // JSON
  if (ct.includes('json') || ct.includes('javascript')) return 'json'
  try { const p = JSON.parse(body); if (typeof p === 'object' && p !== null) return 'json' } catch {}

  // HTML
  if (ct.includes('html') || /^\s*<!doctype\s+html/i.test(body) || /^\s*<html/i.test(body)) return 'html'

  // XML
  if (ct.includes('xml') || /^\s*<\?xml/i.test(body) || (/^\s*<\w/i.test(body) && body.includes('</'))) return 'xml'

  // CSS
  if (ct.includes('css')) return 'css'

  // 纯文本 / 未知
  if (ct.includes('text/') || ct.includes('plain')) return 'text'

  // 尝试通过内容猜测
  if (/^\s*[\{\[]/.test(body)) return 'json'
  if (/<\w+[^>]*>/.test(body)) return 'html'

  return 'text'
})

const isJSON = computed(() => respBodyType.value === 'json')
const isXML = computed(() => respBodyType.value === 'xml')
const isHTML = computed(() => respBodyType.value === 'html')
const isImage = computed(() => respBodyType.value === 'image')
const isMedia = computed(() => respBodyType.value === 'media')
const isBinary = computed(() => respBodyType.value === 'binary' || respBodyType.value === 'pdf')
const isText = computed(() => ['text', 'css', 'empty'].includes(respBodyType.value))

// 内容类型显示名称
const respBodyTypeLabel = computed(() => {
  const labels = {
    json: 'JSON', xml: 'XML', html: 'HTML', css: 'CSS',
    image: 'Image', media: 'Media', binary: 'Binary', pdf: 'PDF',
    text: 'Text', empty: 'Empty',
  }
  return labels[respBodyType.value] || 'Text'
})

// 美化后的响应体
const respBodyDisplay = computed(() => {
  if (!response.value) return ''
  const body = response.value.body
  if (!body) return ''

  // JSON：根据 respFormatted 切换格式化/压缩
  if (isJSON.value) {
    try {
      const parsed = JSON.parse(body)
      return respFormatted.value ? JSON.stringify(parsed, null, 2) : JSON.stringify(parsed)
    } catch { return body }
  }

  // XML/HTML：尝试格式化
  if (isXML.value || isHTML.value) {
    if (respFormatted.value) {
      try { return formatXML(body) } catch { return body }
    }
    return body
  }

  return body
})

// 简易 XML/HTML 格式化
function formatXML(xml) {
  let formatted = ''
  let indent = 0
  const tab = '  '
  // 移除已有缩进
  xml = xml.replace(/>\s+</g, '><').replace(/>\s+$/gm, '>').replace(/^\s+</gm, '<')
  const tokens = xml.split(/(<[^>]+>)/g).filter(t => t.trim())
  for (const token of tokens) {
    if (/^<\//.test(token)) {
      indent = Math.max(0, indent - 1)
      formatted += tab.repeat(indent) + token.trim() + '\n'
    } else if (/^<[^/].*\/\s*>$/.test(token)) {
      formatted += tab.repeat(indent) + token.trim() + '\n'
    } else if (/^</.test(token)) {
      formatted += tab.repeat(indent) + token.trim() + '\n'
      if (!/^<[^/].*\/\s*>$/.test(token) && !/^<\?/.test(token) && !/^<!/.test(token)) {
        indent++
      }
    } else {
      formatted += tab.repeat(indent) + token.trim() + '\n'
    }
  }
  return formatted.trimEnd()
}

// 语法高亮：JSON
function highlightJSON(code) {
  return code.replace(/("(?:\\.|[^"\\])*")\s*:/g, '<span class="hl-json-key">$1</span>:')
    .replace(/:(\s*"(?:\\.|[^"\\])*")/g, ':<span class="hl-json-string">$1</span>')
    .replace(/:(\s*-?\d+\.?\d*([eE][+-]?\d+)?)/g, ':<span class="hl-json-number">$1</span>')
    .replace(/:(\s*(true|false))/g, ':<span class="hl-json-boolean">$1</span>')
    .replace(/:(\s*null)/g, ':<span class="hl-json-null">$1</span>')
}

// 语法高亮：XML/HTML
function highlightXML(code) {
  return code
    .replace(/(&lt;|<)!--([\s\S]*?)--(>|&gt;)/g, '<span class="hl-xml-comment">&lt;!--$2--&gt;</span>')
    .replace(/(&lt;|<)(\/?)([\w:-]+)/g, '<span class="hl-xml-tag">&lt;$2$3</span>')
    .replace(/([\w:-]+)(=)/g, '<span class="hl-xml-attr">$1</span>$2')
    .replace(/("(?:\\.|[^"\\])*")/g, '<span class="hl-xml-string">$1</span>')
}

// 带语法高亮的响应体 HTML
const respBodyHTML = computed(() => {
  const display = respBodyDisplay.value
  if (!display) return ''
  const escaped = display.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  if (isJSON.value) return highlightJSON(escaped)
  if (isXML.value || isHTML.value) return highlightXML(escaped)
  return escaped
})

// 图片预览 URL
const respImageSrc = computed(() => {
  if (!isImage.value || !response.value?.body) return ''
  const ct = respContentType.value || 'image/png'
  // 判断是否为 Base64 格式
  const body = response.value.body.trim()
  if (/^data:image\//i.test(body)) return body
  if (/^[A-Za-z0-9+/=\s]+$/.test(body) && body.length > 100) {
    return `data:${ct};base64,${body.replace(/\s/g, '')}`
  }
  // 非 Base64，尝试用 Blob
  try {
    const blob = new Blob([response.value.body], { type: ct })
    return URL.createObjectURL(blob)
  } catch { return '' }
})

const imageLoadError = ref(false)
function onImageError() { imageLoadError.value = true }
function toggleRespFormat() { respFormatted.value = !respFormatted.value }
watch(response, () => { respFormatted.value = true; imageLoadError.value = false })

function copyBody() {
  if (response.value) {
    const text = isImage.value ? '[Image Data]' : respBodyDisplay.value
    copyToClipboard(text)
  }
}

const statusClass = computed(() => {
  if (!response.value) return ''; const c = response.value.status_code
  if (c === 0) return 'status-err'; if (c < 300) return 'status-ok'; if (c < 400) return 'status-warn'; return 'status-err'
})

function methodClass(m) {
  return { GET: 'method-get', POST: 'method-post', PUT: 'method-put', DELETE: 'method-delete', PATCH: 'method-patch' }[m] || 'method-get'
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / 1024 / 1024).toFixed(1) + ' MB'
}
</script>

<style scoped>
.api-tester { height: calc(100vh - 52px); display: flex; flex-direction: column; }
.api-layout { display: flex; gap: 0.75rem; flex: 1; min-height: 0; overflow: hidden; }
.api-sidebar { width: 232px; flex-shrink: 0; display: flex; flex-direction: column; gap: 0.5rem; overflow-y: auto; padding: 0.75rem; }
.api-main { flex: 1; min-width: 0; overflow-y: auto; padding: 0.75rem; display: flex; flex-direction: column; gap: 0.75rem; }
.api-main .card { margin-bottom: 0; }

.sidebar-section { background: var(--card-bg); border-radius: var(--radius-lg); padding: 0.75rem; border: 1px solid var(--border); }
.sidebar-groups { flex: 1; min-height: 0; display: flex; flex-direction: column; }
.sidebar-header { display: flex; justify-content: space-between; align-items: center; font-size: 0.82rem; font-weight: 600; color: var(--text); margin-bottom: 0.5rem; }
.sidebar-select { width: 100%; padding: 0.35rem 0.5rem; border: 1px solid var(--border); border-radius: 6px; font-size: 0.82rem; outline: none; }
.group-list { flex: 1; overflow-y: auto; }
.group-title { display: flex; align-items: center; gap: 0.3rem; padding: 0.3rem 0.4rem; border-radius: 4px; cursor: pointer; font-size: 0.82rem; font-weight: 500; }
.group-title:hover, .group-title.active { background: var(--primary-light); }
.group-arrow { font-size: 0.7rem; cursor: pointer; color: var(--text-secondary); }
.group-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.group-apis { padding-left: 0.5rem; }

/* 内联编辑 */
.inline-edit-input { border: 1px solid var(--primary); border-radius: 3px; padding: 0.1rem 0.3rem; font-size: inherit; font-weight: inherit; outline: none; width: 100%; min-width: 60px; background: white; }
.edit-btn { opacity: 0 !important; transition: opacity 0.15s; }
.group-title:hover .edit-btn, .api-item:hover .edit-btn, .env-quick-row:hover .edit-btn { opacity: 0.5 !important; }
.edit-btn:hover { opacity: 1 !important; }
.api-item { display: flex; align-items: center; gap: 0.3rem; padding: 0.25rem 0.4rem; border-radius: 4px; cursor: pointer; font-size: 0.78rem; }
.api-item:hover, .api-item.active { background: #eef2ff; }
.api-path { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-secondary); }
.add-api-btn { width: 100%; padding: 0.3rem; border: 1px dashed var(--border); border-radius: 4px; background: transparent; font-size: 0.75rem; color: var(--text-secondary); cursor: pointer; margin-top: 0.25rem; }
.add-api-btn:hover { border-color: var(--primary); color: var(--primary); }
.sidebar-empty { text-align: center; font-size: 0.8rem; color: var(--text-secondary); padding: 1rem; }

/* 环境快捷编辑 */
.env-quick-edit { margin-top: 0.5rem; padding-top: 0.5rem; border-top: 1px solid var(--border); }
.env-quick-row { display: flex; align-items: center; gap: 0.3rem; margin-bottom: 0.35rem; }
.env-quick-label { flex: 1; font-size: 0.82rem; font-weight: 600; color: var(--primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.env-quick-name { font-size: 0.82rem; font-weight: 600; }
.env-baseurl-input { width: 100%; padding: 0.3rem 0.5rem; border: 1px solid var(--border); border-radius: 4px; font-size: 0.78rem; color: var(--text-secondary); outline: none; font-family: "SF Mono", Monaco, monospace; }
.env-baseurl-input:focus { border-color: var(--primary); }

.icon-btn { background: none; border: none; cursor: pointer; font-size: 0.9rem; padding: 0.1rem; opacity: 0.7; }
.icon-btn:hover { opacity: 1; }
.icon-btn-sm { background: none; border: none; cursor: pointer; font-size: 0.7rem; padding: 0.1rem; opacity: 0.5; }
.icon-btn-sm:hover { opacity: 1; color: var(--error); }

/* 请求栏 */
.api-name-row { margin-bottom: 0.5rem; }
.api-name-input { width: 100%; padding: 0.35rem 0.6rem; border: 1px solid var(--border); border-radius: 6px; font-size: 0.85rem; font-weight: 600; color: var(--text); background: white; outline: none; }
.api-name-input:focus { border-color: var(--primary); box-shadow: 0 0 0 2px rgba(79,70,229,0.08); }
.request-bar { display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.5rem; }
.method-select { padding: 0.5rem 0.6rem; border: 1.5px solid var(--border); border-radius: var(--radius); font-size: 0.875rem; font-weight: 600; color: var(--primary); background: white; cursor: pointer; outline: none; min-width: 90px; }
.method-select:focus { border-color: var(--primary); }
.url-input { flex: 1; padding: 0.5rem 0.75rem; border: 1.5px solid var(--border); border-radius: var(--radius); font-size: 0.875rem; color: var(--text); background: white; outline: none; font-family: "SF Mono", Monaco, "Cascadia Code", monospace; }
.url-input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(79,70,229,0.1); }
.send-btn { white-space: nowrap; padding: 0.5rem 1.5rem; }
.send-btn:disabled { opacity: 0.6; cursor: not-allowed; }

/* 代理开关 */
.proxy-toggle { display: flex; align-items: center; gap: 0.25rem; cursor: pointer; white-space: nowrap; font-size: 0.78rem; color: var(--text-secondary); user-select: none; }
.proxy-toggle input[type="checkbox"] { accent-color: var(--primary); width: 14px; height: 14px; }
.proxy-toggle input[type="checkbox"]:checked + .proxy-label { color: var(--primary); font-weight: 600; }
.proxy-label { font-size: 0.78rem; }

.curl-import-btn { white-space: nowrap; font-size: 0.75rem; padding: 0.3rem 0.6rem; }

.env-hint { font-size: 0.75rem; color: var(--primary); margin-bottom: 0.5rem; background: var(--primary-light); padding: 0.25rem 0.5rem; border-radius: 4px; }

/* 选项卡 */
.tabs { display: flex; gap: 0.25rem; border-bottom: 1.5px solid var(--border); margin-bottom: 0.75rem; }
.tab-btn { padding: 0.4rem 0.9rem; border: none; border-bottom: 2px solid transparent; background: transparent; font-size: 0.82rem; font-weight: 500; color: var(--text-secondary); cursor: pointer; }
.tab-btn:hover { color: var(--text); }
.tab-btn.active { color: var(--primary); border-bottom-color: var(--primary); }
.tab-badge { font-size: 0.65rem; background: var(--primary-light); color: var(--primary); padding: 0.05rem 0.35rem; border-radius: 8px; margin-left: 0.3rem; }
.tab-panel { min-height: 60px; }

/* KV 编辑器 */
.kv-editor { display: flex; flex-direction: column; gap: 0.35rem; }
.kv-row { display: flex; gap: 0.4rem; align-items: center; }
.kv-header-row { font-size: 0.72rem; color: var(--text-secondary); font-weight: 600; padding-bottom: 0.2rem; }
.kv-check { width: 18px; height: 18px; flex-shrink: 0; cursor: pointer; }
.kv-key-label, .kv-val-label { flex: 1; font-size: 0.72rem; }
.kv-input { flex: 1; padding: 0.4rem 0.6rem; border: 1px solid var(--border); border-radius: 6px; font-size: 0.82rem; color: var(--text); background: white; outline: none; }
.kv-input:focus { border-color: var(--primary); }
.kv-del-btn { width: 28px; height: 28px; border: none; border-radius: 6px; background: transparent; color: var(--text-secondary); cursor: pointer; font-size: 0.85rem; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
.kv-del-btn:hover { background: #fee2e2; color: var(--error); }
.kv-add-btn { align-self: flex-start; margin-top: 0.25rem; }
.kv-action { width: 28px; flex-shrink: 0; }

/* 继承 Headers */
.inherited-headers { background: #f8fafc; border-radius: 6px; padding: 0.5rem; }
.inherited-row { display: flex; gap: 0.5rem; padding: 0.15rem 0; font-size: 0.78rem; }
.kv-key-readonly { font-weight: 600; color: var(--text-secondary); min-width: 120px; }
.kv-val-readonly { color: var(--text); font-family: "SF Mono", Monaco, monospace; font-size: 0.78rem; }

/* Multipart */
.multipart-row { flex-wrap: wrap; }
.type-select { padding: 0.35rem; border: 1px solid var(--border); border-radius: 4px; font-size: 0.78rem; outline: none; min-width: 60px; }
.file-input-wrap { position: relative; flex: 1; }
.file-real-input { position: absolute; inset: 0; opacity: 0; cursor: pointer; }
.file-label { display: block; padding: 0.4rem 0.6rem; border: 1px dashed var(--border); border-radius: 6px; font-size: 0.78rem; color: var(--text-secondary); background: #fafbfc; cursor: pointer; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* Body 类型 */
.body-type-row { display: flex; gap: 1rem; margin-bottom: 0.5rem; }
.radio-label { display: flex; align-items: center; gap: 0.3rem; font-size: 0.82rem; color: var(--text-secondary); cursor: pointer; padding: 0.3rem 0.6rem; border-radius: 6px; }
.radio-label:hover { background: #f1f5f9; }
.radio-label.active { background: var(--primary-light); color: var(--primary); font-weight: 500; }
.radio-label input[type="radio"] { accent-color: var(--primary); }
.body-hint { color: var(--text-secondary); font-size: 0.85rem; padding: 1.5rem 0; text-align: center; }
.code-textarea { width: 100%; padding: 0.6rem 0.75rem; border: 1.5px solid var(--border); border-radius: var(--radius); font-size: 0.82rem; font-family: "SF Mono", Monaco, "Cascadia Code", monospace; color: var(--text); background: #fafbfc; outline: none; resize: vertical; line-height: 1.5; }
.code-textarea:focus { border-color: var(--primary); }
.var-hint { font-size: 0.8rem; color: var(--text-secondary); line-height: 1.6; }
.var-hint code { background: #f1f5f9; padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.78rem; }

/* 响应区 */
.response-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
.response-header h3 { margin-bottom: 0; }
.response-meta { display: flex; gap: 0.75rem; align-items: center; }
.status-badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 12px; font-size: 0.78rem; font-weight: 700; }
.status-ok { background: #d1fae5; color: #065f46; }
.status-warn { background: #fef3c7; color: #92400e; }
.status-err { background: #fee2e2; color: #991b1b; }
.meta-item { font-size: 0.78rem; color: var(--text-secondary); }
.response-body-actions { display: flex; gap: 0.4rem; margin-bottom: 0.5rem; }
.response-body { background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: var(--radius); font-family: "SF Mono", Monaco, "Cascadia Code", monospace; font-size: 0.82rem; line-height: 1.5; max-height: 500px; overflow: auto; white-space: pre-wrap; word-break: break-all; }
.response-body.response-error { background: #2d1b1b; color: #fca5a5; }

/* JSON 语法高亮 */
.hl-json-key { color: #7dd3fc; }
.hl-json-string { color: #86efac; }
.hl-json-number { color: #fbbf24; }
.hl-json-boolean { color: #c4b5fd; }
.hl-json-null { color: #94a3b8; font-style: italic; }

/* XML/HTML 语法高亮 */
.hl-xml-comment { color: #6b7280; font-style: italic; }
.hl-xml-tag { color: #f472b6; }
.hl-xml-attr { color: #7dd3fc; }
.hl-xml-string { color: #86efac; }

/* 内容类型标签 */
.content-type-badge { display: inline-block; padding: 0.12rem 0.5rem; border-radius: 8px; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.3px; }
.ctype-json { background: #dbeafe; color: #1e40af; }
.ctype-xml { background: #ede9fe; color: #5b21b6; }
.ctype-html { background: #fce7f3; color: #9d174d; }
.ctype-css { background: #d1fae5; color: #065f46; }
.ctype-image { background: #fef3c7; color: #92400e; }
.ctype-media { background: #e0e7ff; color: #3730a3; }
.ctype-binary, .ctype-pdf { background: #f1f5f9; color: #475569; }
.ctype-text { background: #f1f5f9; color: #475569; }
.ctype-empty { background: #f1f5f9; color: #94a3b8; }

/* 图片预览 */
.response-image-preview { text-align: center; margin-bottom: 0.5rem; }
.preview-img { max-width: 100%; max-height: 400px; border-radius: var(--radius); border: 1px solid var(--border); background: repeating-conic-gradient(#f3f4f6 0% 25%, #fff 0% 50%) 0 0 / 16px 16px; }
.image-error-hint { color: var(--text-secondary); font-size: 0.8rem; margin-top: 0.3rem; }

/* 音视频预览 */
.response-media-preview { text-align: center; margin-bottom: 0.5rem; }
.preview-audio, .preview-video { max-width: 100%; border-radius: var(--radius); }
.preview-video { max-height: 300px; }

/* 二进制提示 */
.response-binary-hint { text-align: center; padding: 2rem; color: var(--text-secondary); background: #f8fafc; border-radius: var(--radius); border: 1px dashed var(--border); }

/* Method 标签 */
.method-tag { font-size: 0.65rem; font-weight: 700; padding: 0.08rem 0.35rem; border-radius: 3px; min-width: 30px; text-align: center; }
.method-get { background: #dbeafe; color: #1e40af; }
.method-post { background: #d1fae5; color: #065f46; }
.method-put { background: #fef3c7; color: #92400e; }
.method-delete { background: #fee2e2; color: #991b1b; }
.method-patch { background: #ede9fe; color: #5b21b6; }

/* 弹窗 */
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center; z-index: 200; }
.modal { background: white; border-radius: 12px; width: 640px; max-width: 95vw; max-height: 85vh; display: flex; flex-direction: column; box-shadow: 0 20px 40px rgba(0,0,0,0.15); }
.modal-header { display: flex; justify-content: space-between; align-items: center; padding: 1rem 1.25rem; border-bottom: 1px solid var(--border); }
.modal-header h3 { margin: 0; font-size: 1rem; }
.modal-body { padding: 1rem 1.25rem; overflow-y: auto; flex: 1; }
.env-card { background: #f8fafc; border: 1px solid var(--border); border-radius: 8px; padding: 0.75rem; margin-bottom: 0.75rem; }
.env-card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
.env-card-name-wrap { display: flex; align-items: center; gap: 0.3rem; flex: 1; min-width: 0; }
.env-card-name { font-size: 0.9rem; font-weight: 600; cursor: default; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.env-card-name:hover { cursor: text; }
.env-name-inline { font-size: 0.9rem; font-weight: 600; width: 200px; }
.env-card-actions { display: flex; align-items: center; gap: 0.25rem; flex-shrink: 0; }
.env-active-badge { font-size: 0.7rem; background: var(--primary-light); color: var(--primary); border: none; border-radius: 8px; padding: 0.1rem 0.5rem; font-weight: 600; cursor: default; }
.env-empty { text-align: center; color: var(--text-secondary); padding: 2rem 0; font-size: 0.85rem; }
.import-hint { font-size: 0.82rem; color: var(--text-secondary); margin-bottom: 0.75rem; }

@media (max-width: 768px) {
  .api-layout { flex-direction: column; }
  .api-sidebar { width: 100%; }
  .request-bar { flex-wrap: wrap; }
  .method-select { min-width: 70px; }
  .body-type-row { flex-wrap: wrap; gap: 0.5rem; }
}
</style>
