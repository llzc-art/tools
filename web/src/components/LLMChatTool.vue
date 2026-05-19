<template>
  <div class="tool-panel">
    <div class="chat-topbar">
      <div class="chat-topbar-left">
        <h2>🤖 LLM 对话</h2>
        <span v-if="activeConfigId" class="config-badge">{{ currentConfigName }}</span>
      </div>
      <div class="chat-topbar-right">
        <button class="btn btn-sm btn-outline" @click="toggleStream">
          {{ config.stream ? '🔄 流式' : '📦 非流式' }}
        </button>
        <button class="btn btn-sm btn-outline" @click="clearChat">🗑 清空</button>
        <button :class="['btn btn-sm btn-outline', { 'btn-active': configExpanded }]" @click="configExpanded = !configExpanded">
          ⚙️ 配置
        </button>
      </div>
    </div>

    <!-- 配置区域（可收起） -->
    <Transition name="slide">
      <div v-if="configExpanded" class="card config-card">
        <div class="form-group">
          <label>配置</label>
          <div class="config-select-row">
            <select v-model="activeConfigId" class="input-text" @change="loadConfig">
              <option value="">新建配置</option>
              <option v-for="c in configList" :key="c.id" :value="c.id">{{ c.name || '未命名' }}</option>
            </select>
            <button class="btn btn-sm btn-outline" @click="saveCurrentConfig" title="保存配置">💾 保存</button>
            <button class="btn btn-sm btn-outline" @click="deleteCurrentConfig" v-if="activeConfigId" title="删除配置">🗑</button>
          </div>
        </div>
        <div v-if="!activeConfigId" class="form-group">
          <label>配置名称</label>
          <input v-model="config.name" type="text" class="input-text" placeholder="给配置起个名字" />
        </div>
        <div class="form-group">
          <label>API 地址</label>
          <input v-model="config.baseUrl" type="text" class="input-text" placeholder="https://api.openai.com/v1" />
        </div>
        <div class="form-row">
          <div class="form-group half">
            <label>模型 ID</label>
            <input v-model="config.model" type="text" class="input-text" placeholder="gpt-3.5-turbo" />
          </div>
          <div class="form-group half">
            <label>API Key</label>
            <div class="key-input-wrap">
              <input v-model="config.apiKey" :type="showKey ? 'text' : 'password'" class="input-text" placeholder="sk-..." />
              <button class="toggle-key-btn" @click="showKey = !showKey">{{ showKey ? '🙈' : '👁' }}</button>
            </div>
          </div>
        </div>
        <div class="form-row">
          <div class="form-group half">
            <label>温度 ({{ config.temperature }})</label>
            <input v-model.number="config.temperature" type="range" min="0" max="2" step="0.1" class="range-input" />
          </div>
          <div class="form-group half">
            <label>Top P ({{ config.topP }})</label>
            <input v-model.number="config.topP" type="range" min="0" max="1" step="0.05" class="range-input" />
          </div>
        </div>
        <div class="form-row">
          <div class="form-group half">
            <label>最大 Tokens</label>
            <input v-model.number="config.maxTokens" type="number" class="input-text" placeholder="4096" min="1" max="128000" />
          </div>
          <div class="form-group half">
            <label>重复惩罚 ({{ config.frequencyPenalty }})</label>
            <input v-model.number="config.frequencyPenalty" type="range" min="-2" max="2" step="0.1" class="range-input" />
          </div>
        </div>
        <div class="form-row">
          <div class="form-group half">
            <label>存在惩罚 ({{ config.presencePenalty }})</label>
            <input v-model.number="config.presencePenalty" type="range" min="-2" max="2" step="0.1" class="range-input" />
          </div>
          <div class="form-group half">
            <label>停止序列</label>
            <input v-model="stopStr" type="text" class="input-text" placeholder="逗号分隔，如: ###,END" />
          </div>
        </div>
        <div class="form-row">
          <div class="form-group half">
            <label>响应格式</label>
            <select v-model="config.responseFormat" class="input-text">
              <option value="">默认 (text)</option>
              <option value="json_object">JSON Object</option>
            </select>
          </div>
        </div>
      </div>
    </Transition>

    <!-- 对话区域 -->
    <div class="card chat-card">
      <!-- 消息列表 -->
      <div class="chat-messages" ref="messagesRef">
        <div v-if="messages.length === 0" class="chat-empty">
          <p>💭 开始对话吧！配置模型参数后输入消息。</p>
        </div>
        <div v-for="(msg, idx) in messages" :key="idx" :class="['chat-message', `chat-message-${msg.role}`]">
          <div class="message-avatar">{{ msg.role === 'user' ? '👤' : '🤖' }}</div>
          <div class="message-body">
            <div v-if="msg.role === 'user'" class="message-text">{{ msg.content }}</div>
            <div v-else class="message-text markdown-body" v-html="renderMarkdown(msg.content)"></div>
            <div v-if="msg.loading" class="message-loading">
              <span class="loading-dot"></span>
              <span class="loading-dot"></span>
              <span class="loading-dot"></span>
            </div>
            <!-- 元信息：finish_reason / usage -->
            <div v-if="msg.meta" class="message-meta">
              <span v-if="msg.meta.finishReason" class="meta-tag" :class="'meta-' + msg.meta.finishReason">
                {{ finishReasonLabel(msg.meta.finishReason) }}
              </span>
              <span v-if="msg.meta.model" class="meta-tag meta-model">{{ msg.meta.model }}</span>
              <span v-if="msg.meta.usage" class="meta-tag meta-usage">
                {{ msg.meta.usage.prompt_tokens }}→{{ msg.meta.usage.completion_tokens }} / {{ msg.meta.usage.total_tokens }} tokens
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- 输入区域 -->
      <div class="chat-input-area">
        <textarea v-model="inputText" class="chat-input" placeholder="输入消息，按 Enter 发送，Shift+Enter 换行..." rows="3" @keydown="handleKeydown" :disabled="loading"></textarea>
        <button class="btn btn-primary chat-send-btn" @click="sendMessage" :disabled="loading || !inputText.trim()">
          {{ loading ? '⏳ 生成中...' : '📤 发送' }}
        </button>
      </div>

      <!-- 错误提示 -->
      <div v-if="errorMsg" class="error-box">{{ errorMsg }}</div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, nextTick, onMounted, computed, inject } from 'vue'
import { Marked } from 'marked'
import hljs from 'highlight.js'
import { apiPost } from '../api.js'

const showConfirm = inject('showConfirm')

// Markdown 渲染器配置
const marked = new Marked({
  renderer: {
    code({ text, lang }) {
      const language = lang && hljs.getLanguage(lang) ? lang : 'plaintext'
      const highlighted = hljs.highlight(text, { language }).value
      return `<div class="code-block"><div class="code-header"><span class="code-lang">${language}</span><button class="code-copy-btn" onclick="navigator.clipboard.writeText(this.parentElement.nextElementSibling.textContent)">复制</button></div><pre><code class="hljs language-${language}">${highlighted}</code></pre></div>`
    }
  }
})

const config = reactive({
  name: '',
  baseUrl: '',
  model: '',
  apiKey: '',
  temperature: 0.7,
  topP: 1.0,
  maxTokens: 4096,
  stream: true,
  presencePenalty: 0,
  frequencyPenalty: 0,
  responseFormat: '',
})

const stopStr = ref('')

const configList = ref([])
const activeConfigId = ref('')
const showKey = ref(false)
const inputText = ref('')
const messages = ref([])
const loading = ref(false)
const errorMsg = ref('')
const messagesRef = ref(null)
const configExpanded = ref(true)

const currentConfigName = computed(() => {
  const c = configList.value.find(c => String(c.id) === activeConfigId.value)
  return c ? (c.name || c.model || '未命名') : ''
})

function finishReasonLabel(reason) {
  const map = {
    stop: '正常结束',
    length: '达到长度限制',
    content_filter: '内容过滤',
    tool_calls: '工具调用',
  }
  return map[reason] || reason
}

// 从后端加载配置列表
async function loadConfigList() {
  try {
    const res = await apiPost('/api/llm/config/list')
    if (res.code === 0) {
      configList.value = res.data || []
    }
  } catch {}
}

// 加载默认配置
async function loadDefaultConfig() {
  try {
    const res = await apiPost('/api/llm/config/get-default')
    if (res.code === 0 && res.data) {
      activeConfigId.value = String(res.data.id)
      applyConfigToForm(res.data)
      await loadMessages()
    }
  } catch {}
}

// 切换配置时加载
async function loadConfig() {
  if (!activeConfigId.value) {
    Object.assign(config, { name: '', baseUrl: '', model: '', apiKey: '', temperature: 0.7, topP: 1.0, maxTokens: 4096, stream: true, presencePenalty: 0, frequencyPenalty: 0, responseFormat: '' })
    stopStr.value = ''
    messages.value = []
    return
  }
  try {
    const res = await apiPost('/api/llm/config/get', { id: Number(activeConfigId.value) })
    if (res.code === 0 && res.data) {
      applyConfigToForm(res.data)
      await loadMessages()
    }
  } catch {}
}

function applyConfigToForm(c) {
  config.name = c.name || ''
  config.baseUrl = c.base_url || ''
  config.model = c.model || ''
  config.apiKey = c.api_key || ''
  config.temperature = c.temperature ?? 0.7
  config.topP = c.top_p ?? 1.0
  config.maxTokens = c.max_tokens ?? 4096
  config.stream = c.stream !== false
  config.presencePenalty = c.presence_penalty ?? 0
  config.frequencyPenalty = c.frequency_penalty ?? 0
  config.responseFormat = c.response_format || ''
  stopStr.value = (c.stop || []).join(', ')
}

// 保存当前配置到后端
async function saveCurrentConfig() {
  if (!config.baseUrl || !config.model) {
    errorMsg.value = '请先填写 API 地址和模型 ID'
    return
  }

  const payload = {
    name: config.name,
    base_url: config.baseUrl,
    api_key: config.apiKey,
    model: config.model,
    temperature: config.temperature,
    top_p: config.topP,
    max_tokens: config.maxTokens,
    stream: config.stream,
    presence_penalty: config.presencePenalty,
    frequency_penalty: config.frequencyPenalty,
    response_format: config.responseFormat || null,
    stop: stopStr.value ? stopStr.value.split(',').map(s => s.trim()).filter(Boolean) : [],
    is_default: true,
  }

  try {
    if (activeConfigId.value) {
      payload.id = Number(activeConfigId.value)
      await apiPost('/api/llm/config/update', payload)
    } else {
      const res = await apiPost('/api/llm/config/create', { ...payload, name: config.name || config.model })
      if (res.code === 0 && res.data) {
        activeConfigId.value = String(res.data.id)
        await apiPost('/api/llm/config/set-default', { id: res.data.id })
      }
    }
    await loadConfigList()
  } catch (err) {
    errorMsg.value = '保存配置失败: ' + err.message
  }
}

// 删除当前配置
async function deleteCurrentConfig() {
  if (!activeConfigId.value) return
  const ok = await showConfirm({ title: '删除配置', message: '确定删除此配置？删除后不可恢复。', icon: '🗑️', danger: true })
  if (!ok) return

  try {
    await apiPost('/api/llm/config/delete', { id: Number(activeConfigId.value) })
    activeConfigId.value = ''
    messages.value = []
    await loadConfigList()
    await loadDefaultConfig()
  } catch {}
}

// 加载消息
async function loadMessages() {
  if (!activeConfigId.value) { messages.value = []; return }
  try {
    const res = await apiPost('/api/llm/messages/get', { config_id: Number(activeConfigId.value) })
    if (res.code === 0) {
      messages.value = (res.data || []).map(m => ({ role: m.role, content: m.content, meta: m.meta || null }))
    }
  } catch {}
}

// 保存消息到后端
async function saveMessages() {
  if (!activeConfigId.value) return
  try {
    await apiPost('/api/llm/messages/save', {
      config_id: Number(activeConfigId.value),
      messages: messages.value.map(m => ({ role: m.role, content: m.content, meta: m.meta || null })),
    })
  } catch {}
}

// 初始化
onMounted(async () => {
  await loadConfigList()
  await loadDefaultConfig()
})

function toggleStream() {
  config.stream = !config.stream
  if (activeConfigId.value) saveCurrentConfig()
}

function clearChat() {
  messages.value = []
  errorMsg.value = ''
  if (activeConfigId.value) {
    apiPost('/api/llm/messages/clear', { config_id: Number(activeConfigId.value) }).catch(() => {})
  }
}

function renderMarkdown(text) {
  if (!text) return ''
  try {
    return marked.parse(text)
  } catch {
    return text.replace(/</g, '&lt;').replace(/>/g, '&gt;')
  }
}

function scrollToBottom() {
  nextTick(() => {
    if (messagesRef.value) {
      messagesRef.value.scrollTop = messagesRef.value.scrollHeight
    }
  })
}

function handleKeydown(e) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault()
    sendMessage()
  }
}

function buildRequestPayload() {
  const stop = stopStr.value ? stopStr.value.split(',').map(s => s.trim()).filter(Boolean) : undefined
  const responseFormat = config.responseFormat ? { type: config.responseFormat } : undefined
  return {
    base_url: config.baseUrl,
    api_key: config.apiKey,
    model: config.model,
    messages: messages.value.filter(m => !m.loading).map(m => ({ role: m.role, content: m.content })),
    stream: config.stream,
    max_tokens: config.maxTokens,
    temperature: config.temperature,
    top_p: config.topP,
    presence_penalty: config.presencePenalty,
    frequency_penalty: config.frequencyPenalty,
    stop: stop && stop.length > 0 ? stop : undefined,
    response_format: responseFormat,
  }
}

async function sendMessage() {
  const text = inputText.value.trim()
  if (!text || loading.value) return

  if (!config.baseUrl || !config.model) {
    errorMsg.value = '请先配置 API 地址和模型 ID'
    return
  }

  // 自动保存配置
  if (!activeConfigId.value) {
    await saveCurrentConfig()
  }

  errorMsg.value = ''

  // 添加用户消息
  messages.value.push({ role: 'user', content: text })
  inputText.value = ''
  scrollToBottom()

  // 添加助手占位消息
  const assistantMsg = reactive({ role: 'assistant', content: '', loading: true, meta: null })
  messages.value.push(assistantMsg)
  loading.value = true
  scrollToBottom()

  try {
    if (config.stream) {
      await sendStreamRequest(assistantMsg)
    } else {
      await sendNormalRequest(assistantMsg)
    }
  } catch (err) {
    errorMsg.value = err.message || '请求失败'
    assistantMsg.content = `[错误] ${errorMsg.value}`
  } finally {
    assistantMsg.loading = false
    loading.value = false
    saveMessages()
    scrollToBottom()
  }
}

async function sendNormalRequest(assistantMsg) {
  const payload = buildRequestPayload()
  payload.stream = false

  const resp = await fetch('/api/llm/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })

  const data = await resp.json()
  if (data.code !== 0) {
    throw new Error(data.message)
  }

  const chatResp = data.data
  // 提取第一个 choice 的内容
  if (chatResp.choices && chatResp.choices.length > 0) {
    const choice = chatResp.choices[0]
    assistantMsg.content = choice.message?.content || ''
    assistantMsg.meta = {
      finishReason: choice.finish_reason || null,
      model: chatResp.model || null,
      usage: chatResp.usage || null,
    }
  } else if (chatResp.content) {
    // 兼容旧格式
    assistantMsg.content = chatResp.content
  }
}

async function sendStreamRequest(assistantMsg) {
  const payload = buildRequestPayload()
  payload.stream = true

  const resp = await fetch('/api/llm/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })

  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}`)
  }

  const reader = resp.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let lastFinishReason = null
  let lastModel = null

  while (true) {
    const { done, value } = await reader.read()
    if (done) break

    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split('\n')
    buffer = lines.pop() || ''

    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed.startsWith('data: ')) continue
      const data = trimmed.slice(6).trim()
      if (!data) continue

      if (data === '[DONE]') break

      try {
        const chunk = JSON.parse(data)

        // 检查是否是错误事件
        if (chunk.error) {
          throw new Error(chunk.error.message || 'API 错误')
        }

        // 提取 choices[0] 内容
        if (chunk.choices && chunk.choices.length > 0) {
          const choice = chunk.choices[0]
          if (choice.delta?.content) {
            assistantMsg.content += choice.delta.content
            scrollToBottom()
          }
          if (choice.finish_reason) {
            lastFinishReason = choice.finish_reason
          }
        }

        // 提取 model
        if (chunk.model) {
          lastModel = chunk.model
        }
      } catch (e) {
        if (e.message && !e.message.includes('JSON')) throw e
      }
    }
  }

  // 设置元信息
  assistantMsg.meta = {
    finishReason: lastFinishReason,
    model: lastModel,
    usage: null, // 流式模式通常无 usage
  }
}
</script>

<style scoped>
/* 顶栏 */
.chat-topbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
}
.chat-topbar h2 {
  margin-bottom: 0;
  font-size: 1.15rem;
}
.chat-topbar-left {
  display: flex;
  align-items: center;
  gap: 0.6rem;
}
.chat-topbar-right {
  display: flex;
  gap: 0.4rem;
  align-items: center;
}
.config-badge {
  display: inline-block;
  padding: 0.15rem 0.55rem;
  background: rgba(79, 70, 229, 0.1);
  color: var(--primary);
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  max-width: 180px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.btn-active {
  background: var(--primary) !important;
  color: white !important;
  border-color: var(--primary) !important;
}

/* 配置区收起动画 */
.slide-enter-active,
.slide-leave-active {
  transition: all 0.25s ease;
  overflow: hidden;
}
.slide-enter-from,
.slide-leave-to {
  max-height: 0;
  opacity: 0;
  margin-bottom: 0;
  padding-top: 0;
  padding-bottom: 0;
}
.slide-enter-to,
.slide-leave-from {
  max-height: 500px;
  opacity: 1;
}

.config-card {
  margin-bottom: 0.75rem;
}

.config-select-row {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}
.config-select-row .input-text {
  flex: 1;
}
.key-input-wrap {
  position: relative;
  display: flex;
  align-items: center;
}
.key-input-wrap .input-text {
  padding-right: 2.5rem;
}
.toggle-key-btn {
  position: absolute;
  right: 0.5rem;
  background: none;
  border: none;
  cursor: pointer;
  font-size: 1rem;
  padding: 0.2rem;
}
.range-input {
  width: 100%;
  margin-top: 0.3rem;
}
.chat-card {
  display: flex;
  flex-direction: column;
}
.chat-messages {
  flex: 1;
  min-height: 200px;
  max-height: calc(100vh - 320px);
  overflow-y: auto;
  padding: 0.5rem;
  margin-bottom: 1rem;
  border: 1.5px solid var(--border);
  border-radius: var(--radius);
  background: #f8fafc;
}
.chat-empty {
  text-align: center;
  padding: 3rem 1rem;
  color: var(--text-secondary);
}
.chat-message {
  display: flex;
  gap: 0.75rem;
  margin-bottom: 1rem;
  align-items: flex-start;
}
.chat-message-user {
  flex-direction: row-reverse;
}
.message-avatar {
  font-size: 1.5rem;
  flex-shrink: 0;
  width: 2rem;
  text-align: center;
}
.message-body {
  max-width: 80%;
  min-width: 0;
}
.chat-message-user .message-body {
  align-items: flex-end;
}
.chat-message-user .message-text {
  background: var(--primary);
  color: white;
  border-radius: 12px 12px 2px 12px;
}
.chat-message-assistant .message-text {
  background: white;
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 12px 12px 12px 2px;
}
.message-text {
  padding: 0.75rem 1rem;
  font-size: 0.9rem;
  line-height: 1.6;
  word-break: break-word;
}

/* 元信息标签 */
.message-meta {
  display: flex;
  gap: 0.4rem;
  flex-wrap: wrap;
  margin-top: 0.3rem;
}
.meta-tag {
  display: inline-block;
  padding: 0.1rem 0.45rem;
  border-radius: 4px;
  font-size: 0.68rem;
  font-weight: 600;
  line-height: 1.4;
}
.meta-stop {
  background: #dcfce7;
  color: #16a34a;
}
.meta-length {
  background: #fef3c7;
  color: #d97706;
}
.meta-content_filter {
  background: #fee2e2;
  color: #dc2626;
}
.meta-tool_calls {
  background: #dbeafe;
  color: #2563eb;
}
.meta-model {
  background: #f1f5f9;
  color: var(--text-secondary);
}
.meta-usage {
  background: #f0f0ff;
  color: var(--primary);
}

/* Markdown 渲染样式 */
.markdown-body :deep(h1), .markdown-body :deep(h2), .markdown-body :deep(h3) { margin-top: 1rem; margin-bottom: 0.5rem; font-weight: 600; }
.markdown-body :deep(h1) { font-size: 1.3rem; }
.markdown-body :deep(h2) { font-size: 1.15rem; }
.markdown-body :deep(h3) { font-size: 1.05rem; }
.markdown-body :deep(p) { margin-bottom: 0.5rem; }
.markdown-body :deep(ul), .markdown-body :deep(ol) { margin-bottom: 0.5rem; padding-left: 1.5rem; }
.markdown-body :deep(li) { margin-bottom: 0.2rem; }
.markdown-body :deep(blockquote) { border-left: 3px solid var(--primary); padding-left: 0.75rem; margin: 0.5rem 0; color: var(--text-secondary); }
.markdown-body :deep(table) { width: 100%; border-collapse: collapse; margin: 0.5rem 0; font-size: 0.85rem; }
.markdown-body :deep(th), .markdown-body :deep(td) { border: 1px solid var(--border); padding: 0.4rem 0.6rem; text-align: left; }
.markdown-body :deep(th) { background: #f1f5f9; font-weight: 600; }
.markdown-body :deep(code) { background: #f1f5f9; padding: 0.15rem 0.35rem; border-radius: 3px; font-size: 0.85em; font-family: "SF Mono", Monaco, "Cascadia Code", monospace; }
.markdown-body :deep(pre) { margin: 0.5rem 0; border-radius: 6px; overflow-x: auto; }
.markdown-body :deep(pre code) { background: transparent; padding: 0; font-size: 0.85rem; line-height: 1.5; }
.markdown-body :deep(.code-block) { margin: 0.5rem 0; border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }
.markdown-body :deep(.code-header) { display: flex; justify-content: space-between; align-items: center; padding: 0.4rem 0.75rem; background: #e2e8f0; font-size: 0.75rem; }
.markdown-body :deep(.code-lang) { color: var(--text-secondary); font-weight: 600; text-transform: uppercase; }
.markdown-body :deep(.code-copy-btn) { background: var(--primary); color: white; border: none; padding: 0.2rem 0.6rem; border-radius: 4px; cursor: pointer; font-size: 0.7rem; }
.markdown-body :deep(.code-copy-btn:hover) { background: var(--primary-hover); }
.markdown-body :deep(.code-block pre) { margin: 0; border: none; border-radius: 0; }
.markdown-body :deep(.code-block pre code) { padding: 0.75rem; display: block; }
.markdown-body :deep(strong) { font-weight: 700; }
.markdown-body :deep(em) { font-style: italic; }
.markdown-body :deep(hr) { border: none; border-top: 1px solid var(--border); margin: 1rem 0; }
.message-loading { display: flex; gap: 0.3rem; padding: 0.5rem 0.75rem; }
.loading-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--text-secondary); animation: bounce 1.4s infinite ease-in-out both; }
.loading-dot:nth-child(1) { animation-delay: -0.32s; }
.loading-dot:nth-child(2) { animation-delay: -0.16s; }
@keyframes bounce { 0%, 80%, 100% { transform: scale(0); } 40% { transform: scale(1); } }
.chat-input-area { display: flex; gap: 0.5rem; align-items: flex-end; }
.chat-input { flex: 1; padding: 0.6rem 0.75rem; border: 1.5px solid var(--border); border-radius: var(--radius); font-size: 0.9rem; color: var(--text); background: white; resize: none; outline: none; font-family: inherit; transition: border-color 0.2s; }
.chat-input:focus { border-color: var(--primary); }
.chat-input:disabled { background: #f1f5f9; cursor: not-allowed; }
.chat-send-btn { white-space: nowrap; height: fit-content; }
.chat-send-btn:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
