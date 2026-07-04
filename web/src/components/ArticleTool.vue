<template>
  <div class="tool-panel article-tool">
    <h2>📰 文章写作与发布</h2>

    <!-- 主布局 -->
    <div class="article-layout">
      <!-- 左侧：文章列表 -->
      <div class="article-sidebar card">
        <div class="sidebar-header">
          <h3>文章列表</h3>
          <button class="btn btn-primary btn-sm" @click="createArticle">+ 新建</button>
        </div>
        <div class="article-list">
          <div v-if="articles.length === 0" class="empty-hint">暂无文章，点击新建开始创作</div>
          <div
            v-for="a in articles"
            :key="a.id"
            :class="['article-item', { active: currentArticle?.id === a.id }]"
            @click="selectArticle(a)"
          >
            <div class="article-item-title">{{ a.title || '未命名文章' }}</div>
            <div class="article-item-meta">
              <span :class="['status-tag', a.status]">{{ a.status === 'published' ? '已发布' : '草稿' }}</span>
              <span class="article-item-time">{{ formatTime(a.updated_at) }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 右侧：编辑器（全宽） -->
      <div class="article-editor card">
        <div class="editor-toolbar">
          <div class="toolbar-left">
            <button class="btn btn-sm btn-outline" @click="saveArticle" :disabled="!currentArticle">💾 保存</button>
            <button class="btn btn-sm btn-outline" @click="deleteArticle" :disabled="!currentArticle" style="color:#ef4444;border-color:#ef4444;">🗑 删除</button>
          </div>
          <span class="toolbar-title">{{ currentArticle?.title || '新建文章' }}</span>
          <div class="toolbar-right">
            <button class="btn btn-sm btn-outline" @click="showPreviewModal = true" :disabled="!currentArticle">👁 预览</button>
            <button class="btn btn-primary btn-sm" @click="openPublishModal" :disabled="!currentArticle || channels.length === 0">🚀 一键发布</button>
            <button class="btn btn-sm btn-outline" @click="showChannelModal = true">⚙ 渠道配置</button>
          </div>
        </div>
        <input
          v-if="currentArticle"
          v-model="editTitle"
          class="title-input"
          placeholder="输入文章标题..."
          @input="markDirty"
        />
        <textarea
          v-if="currentArticle"
          v-model="editContent"
          class="editor-textarea"
          placeholder="使用 Markdown 语法写作...

# 一级标题
## 二级标题

**粗体** *斜体*

- 列表项
- 列表项

> 引用

`行内代码`

```代码块```"
@input="markDirty"
        ></textarea>
        <div v-if="!currentArticle" class="empty-editor">
          <div class="empty-icon">📝</div>
          <p>选择一篇文章开始编辑，或点击「新建」创建文章</p>
        </div>
      </div>

    </div>

    <!-- 预览弹窗 -->
    <div v-if="showPreviewModal" class="modal-overlay" @click.self="showPreviewModal = false">
      <div class="modal-box preview-modal-box">
        <div class="modal-header">
          <h3>📄 预览 — {{ currentArticle?.title || '未命名文章' }}</h3>
          <button class="modal-close" @click="showPreviewModal = false">✕</button>
        </div>
        <div class="preview-body markdown-body" v-html="renderedHTML"></div>
        <div v-if="!editContent" class="empty-preview">暂无内容可预览</div>
      </div>
    </div>

    <!-- 一键发布弹窗 -->
    <div v-if="showPublishModal" class="modal-overlay" @click.self="showPublishModal = false">
      <div class="modal-box publish-modal-box">
        <div class="modal-header">
          <h3>📡 选择发布渠道</h3>
          <button class="modal-close" @click="showPublishModal = false">✕</button>
        </div>

        <div class="publish-channel-list">
          <div v-if="enabledChannels.length === 0" class="empty-hint">
            暂无可用渠道，请先<a href="javascript:void(0)" @click="showPublishModal = false; showChannelModal = true">配置渠道</a>
          </div>
          <label
            v-for="ch in enabledChannels"
            :key="ch.id"
            :class="['channel-select-card', { selected: publishSelectedIds.includes(ch.id) }]"
          >
            <input
              type="checkbox"
              :value="ch.id"
              v-model="publishSelectedIds"
              class="channel-card-checkbox"
            />
            <span class="channel-select-icon">{{ channelIcon(ch.channel_type) }}</span>
            <div class="channel-select-info">
              <span class="channel-select-name">{{ ch.name }}</span>
              <span class="channel-select-type">{{ ch.channel_type }}</span>
            </div>
          </label>
        </div>

        <div class="publish-modal-actions">
          <button class="btn btn-outline" @click="showPublishModal = false">取消</button>
          <button
            class="btn btn-primary"
            @click="doPublish"
            :disabled="publishSelectedIds.length === 0 || publishing"
          >
            {{ publishing ? '发布中...' : '🚀 确认发布' }}
          </button>
        </div>

        <!-- 发布结果 -->
        <div v-if="publishResult" class="publish-result">
          <div class="publish-summary">
            发布完成：<span class="success-count">{{ publishResult.success }}</span> 成功，
            <span v-if="publishResult.failed > 0" class="failed-count">{{ publishResult.failed }}</span> 失败
          </div>
          <div v-for="log in publishResult.logs" :key="log.channel_id" :class="['publish-log-item', log.status]">
            <span class="log-icon">{{ log.status === 'success' ? '✅' : '❌' }}</span>
            <span class="log-channel">{{ log.channel_name }}</span>
            <span class="log-msg">{{ log.message }}</span>
          </div>
        </div>

        <!-- 历史发布日志 -->
        <div v-if="publishLogs.length > 0" class="publish-logs">
          <h4>发布历史</h4>
          <div v-for="log in publishLogs" :key="log.id" :class="['log-row', log.status]">
            <span class="log-channel-name">{{ log.channel_name || '未知渠道' }}</span>
            <span :class="['log-status-badge', log.status]">{{ log.status === 'success' ? '成功' : '失败' }}</span>
            <span class="log-time">{{ log.published_at }}</span>
            <span class="log-msg-text">{{ log.message }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- 渠道管理弹窗 -->
    <div v-if="showChannelModal" class="modal-overlay" @click.self="showChannelModal = false">
      <div class="modal-box">
        <div class="modal-header">
          <h3>管理发布渠道</h3>
          <button class="modal-close" @click="showChannelModal = false">✕</button>
        </div>

        <!-- 渠道列表 -->
        <div class="channel-list">
          <div v-if="channels.length === 0" class="empty-hint">暂无渠道，请添加</div>
          <div v-for="ch in channels" :key="ch.id" class="channel-config-row">
            <div class="channel-info">
              <span class="channel-type-icon">{{ channelIcon(ch.channel_type) }}</span>
              <div class="channel-detail">
                <div class="channel-name-row">
                  <strong>{{ ch.name }}</strong>
                  <span class="channel-type-tag">{{ ch.channel_type }}</span>
                  <span :class="['status-badge', ch.enabled ? 'enabled' : 'disabled']">
                    {{ ch.enabled ? '启用' : '禁用' }}
                  </span>
                </div>
                <div class="channel-config-preview">{{ ch.config }}</div>
              </div>
            </div>
            <div class="channel-actions">
              <button class="btn btn-sm btn-outline" @click="editChannel(ch)">编辑</button>
              <button class="btn btn-sm btn-outline" style="color:#ef4444;border-color:#ef4444;" @click="deleteChannel(ch.id)">删除</button>
            </div>
          </div>
        </div>

        <!-- 添加/编辑渠道表单 -->
        <div class="channel-form">
          <h4>{{ editingChannel ? '编辑渠道' : '添加渠道' }}</h4>
          <div class="form-row">
            <div class="form-group half">
              <label>渠道名称</label>
              <input v-model="channelForm.name" class="input-text" placeholder="如：我的公众号" />
            </div>
            <div class="form-group half">
              <label>渠道类型</label>
              <select v-model="channelForm.channel_type" class="input-select">
                <option value="">请选择</option>
                <option value="wechat">微信公众号</option>
                <option value="csdn">CSDN</option>
                <option value="tencent_cloud">腾讯云社区</option>
                <option value="juejin">掘金</option>
                <option value="custom">自定义</option>
              </select>
            </div>
          </div>
          <div class="form-group">
            <label>
              渠道配置 (JSON)
              <span class="config-hint">
                {{ channelTypeHint(channelForm.channel_type) }}
              </span>
            </label>
            <textarea
              v-model="channelForm.config"
              class="input-textarea"
              rows="4"
              placeholder='{"key": "value"}'
            ></textarea>
          </div>
          <div class="form-group">
            <label>
              <input type="checkbox" v-model="channelForm.enabled" style="margin-right:0.35rem;" />
              启用该渠道
            </label>
          </div>
          <div class="form-actions">
            <button class="btn btn-primary btn-sm" @click="saveChannel">
              {{ editingChannel ? '更新' : '添加' }}
            </button>
            <button v-if="editingChannel" class="btn btn-sm" style="background:#f1f5f9;" @click="cancelEditChannel">取消</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted, inject } from 'vue'
import { apiGet, apiPost } from '../api.js'

const showToast = inject('showToast')
const showConfirm = inject('showConfirm')

// --- 文章数据 ---
const articles = ref([])
const currentArticle = ref(null)
const editTitle = ref('')
const editContent = ref('')
const dirty = ref(false)
const publishing = ref(false)
const publishResult = ref(null)
const publishLogs = ref([])

// --- 渠道数据 ---
const channels = ref([])
const publishSelectedIds = ref([])
const showChannelModal = ref(false)
const showPreviewModal = ref(false)
const showPublishModal = ref(false)
const editingChannel = ref(null)
const channelForm = ref({
  name: '',
  channel_type: '',
  config: '{}',
  enabled: true
})

// 已启用的渠道列表（用于发布弹窗）
const enabledChannels = computed(() => channels.value.filter(c => c.enabled))

// 监听渠道类型变化，自动填充配置模板
watch(() => channelForm.value.channel_type, (newType) => {
  if (editingChannel.value) return  // 编辑模式不覆盖
  const templates = {
    wechat: '{"app_id": "你的AppID", "app_secret": "你的AppSecret", "author": "作者名"}',
    csdn: '{"cookie": "登录CSDN后从浏览器复制完整Cookie", "tags": "技术标签1,技术标签2", "categories": "分类", "type": "original"}',
    tencent_cloud: '{"cookie": "登录cloud.tencent.com后从浏览器复制Cookie", "tags": "标签1,标签2"}',
    juejin: '{"cookie": "登录juejin.cn后从浏览器复制Cookie", "authorization": "Bearer xxx", "category_id": "6809637769959178254", "tag_ids": "tag_id1,tag_id2"}',
    custom: '{"url": "https://example.com/api/publish", "headers": "{}"}'
  }
  if (templates[newType]) {
    channelForm.value.config = templates[newType]
  }
})

// --- 初始化 ---
onMounted(async () => {
  await loadArticles()
  await loadChannels()
})

async function loadArticles() {
  const res = await apiGet('/api/article/list')
  if (res.code === 0) {
    articles.value = res.data.articles || []
  }
}

async function loadChannels() {
  const res = await apiGet('/api/article/channel/list')
  if (res.code === 0) {
    channels.value = res.data.channels || []
  }
}

// --- 文章操作 ---
function selectArticle(a) {
  if (dirty.value && currentArticle.value && currentArticle.value.id !== a.id) {
    // 自动保存当前文章
    saveArticleSilent()
  }
  currentArticle.value = a
  editTitle.value = a.title
  editContent.value = a.content
  dirty.value = false
  publishResult.value = null
  loadPublishLogs(a.id)
}

async function createArticle() {
  if (dirty.value && currentArticle.value) {
    await saveArticleSilent()
  }
  const res = await apiPost('/api/article/create', {
    title: '未命名文章',
    content: ''
  })
  if (res.code === 0) {
    await loadArticles()
    selectArticle(res.data)
    showToast('文章已创建')
  } else {
    showToast(res.message)
  }
}

function openPublishModal() {
  if (!currentArticle.value) return
  publishResult.value = null
  publishSelectedIds.value = []
  showPublishModal.value = true
}

function markDirty() {
  dirty.value = true
}

async function saveArticleSilent() {
  if (!currentArticle.value) return
  // 只有脏数据才保存
  if (editTitle.value === currentArticle.value.title && editContent.value === currentArticle.value.content) return
  const res = await apiPost('/api/article/update', {
    id: currentArticle.value.id,
    title: editTitle.value,
    content: editContent.value
  })
  if (res.code === 0) {
    currentArticle.value.title = res.data.title
    currentArticle.value.content = res.data.content
    currentArticle.value.updated_at = res.data.updated_at
    dirty.value = false
    await loadArticles()
  }
}

async function saveArticle() {
  await saveArticleSilent()
  if (!dirty.value) showToast('已保存')
}

async function deleteArticle() {
  if (!currentArticle.value) return
  const ok = await showConfirm({
    title: '删除文章',
    message: `确定要删除「${currentArticle.value.title}」吗？此操作不可撤销。`,
    icon: '🗑',
    danger: true
  })
  if (!ok) return
  const res = await apiPost('/api/article/delete', { id: currentArticle.value.id })
  if (res.code === 0) {
    showToast('已删除')
    currentArticle.value = null
    editTitle.value = ''
    editContent.value = ''
    dirty.value = false
    publishResult.value = null
    publishLogs.value = []
    await loadArticles()
  } else {
    showToast(res.message)
  }
}

// --- 发布操作 ---
async function doPublish() {
  if (!currentArticle.value || publishSelectedIds.value.length === 0) return
  // 先保存
  await saveArticleSilent()

  // 确认发布
  const channelNames = publishSelectedIds.value
    .map(id => channels.value.find(c => c.id === id)?.name)
    .filter(Boolean)
    .join('、')

  const ok = await showConfirm({
    title: '确认发布',
    message: `即将发布「${currentArticle.value.title}」到：${channelNames}`,
    icon: '📡'
  })
  if (!ok) return

  publishing.value = true
  publishResult.value = null

  const res = await apiPost('/api/article/publish', {
    article_id: currentArticle.value.id,
    channel_ids: publishSelectedIds.value
  })

  publishing.value = false

  if (res.code === 0) {
    publishResult.value = res.data
    showToast(`发布完成：${res.data.success} 成功${res.data.failed > 0 ? '，' + res.data.failed + ' 失败' : ''}`)
    await loadArticles()
    await loadPublishLogs(currentArticle.value.id)
  } else {
    showToast(res.message)
  }
}

async function loadPublishLogs(articleId) {
  const res = await apiGet(`/api/article/publish/logs?article_id=${articleId}`)
  if (res.code === 0) {
    publishLogs.value = res.data.logs || []
  }
}

// --- 渠道管理 ---
function channelIcon(type) {
  const icons = {
    wechat: '💬',
    csdn: '📘',
    tencent_cloud: '☁️',
    juejin: '💎',
    custom: '🔗'
  }
  return icons[type] || '📡'
}

function channelTypeHint(type) {
  const hints = {
    wechat: '需要 app_id, app_secret, 可选 author',
    csdn: '需要 cookie（登录后抓取）, 可选 tags, categories, type',
    tencent_cloud: '需要 cookie（登录后抓取）, 可选 tags',
    juejin: '需要 cookie, authorization（登录后抓取）, 可选 category_id, tag_ids',
    custom: '需要 url, 可选 headers'
  }
  return hints[type] || ''
}

function editChannel(ch) {
  editingChannel.value = ch
  channelForm.value = {
    name: ch.name,
    channel_type: ch.channel_type,
    config: ch.config,
    enabled: ch.enabled
  }
}

function cancelEditChannel() {
  editingChannel.value = null
  channelForm.value = { name: '', channel_type: '', config: '{}', enabled: true }
}

async function saveChannel() {
  if (!channelForm.value.name || !channelForm.value.channel_type) {
    showToast('请填写渠道名称和类型')
    return
  }

  if (editingChannel.value) {
    const res = await apiPost('/api/article/channel/update', {
      id: editingChannel.value.id,
      name: channelForm.value.name,
      channel_type: channelForm.value.channel_type,
      config: channelForm.value.config,
      enabled: channelForm.value.enabled
    })
    if (res.code === 0) {
      showToast('渠道已更新')
      editingChannel.value = null
      channelForm.value = { name: '', channel_type: '', config: '{}', enabled: true }
      await loadChannels()
    } else {
      showToast(res.message)
    }
  } else {
    const res = await apiPost('/api/article/channel/create', {
      name: channelForm.value.name,
      channel_type: channelForm.value.channel_type,
      config: channelForm.value.config,
      enabled: channelForm.value.enabled
    })
    if (res.code === 0) {
      showToast('渠道已添加')
      channelForm.value = { name: '', channel_type: '', config: '{}', enabled: true }
      await loadChannels()
    } else {
      showToast(res.message)
    }
  }
}

async function deleteChannel(id) {
  const ch = channels.value.find(c => c.id === id)
  const ok = await showConfirm({
    title: '删除渠道',
    message: `确定要删除渠道「${ch?.name || id}」吗？`
  })
  if (!ok) return
  const res = await apiPost('/api/article/channel/delete', { id })
  if (res.code === 0) {
    showToast('渠道已删除')
    selectedChannels.value = selectedChannels.value.filter(cid => cid !== id)
    await loadChannels()
  } else {
    showToast(res.message)
  }
}

// --- Markdown 渲染 ---
const renderedHTML = computed(() => {
  if (!editContent.value) return ''
  return renderMarkdown(editContent.value)
})

function renderMarkdown(md) {
  let html = md
    // 转义 HTML 实体（除了代码块内的内容先占位）
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')

  // 代码块 ```
  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
    return `<pre><code class="language-${lang}">${code.trim()}</code></pre>`
  })

  // 行内代码 `
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>')

  // 图片 ![alt](url)
  html = html.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img src="$2" alt="$1" />')

  // 链接 [text](url)
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>')

  // 标题
  html = html.replace(/^#### (.+)$/gm, '<h4>$1</h4>')
  html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>')
  html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>')
  html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>')

  // 粗体 + 斜体
  html = html.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>')
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
  html = html.replace(/___(.+?)___/g, '<strong><em>$1</em></strong>')
  html = html.replace(/__(.+?)__/g, '<strong>$1</strong>')
  html = html.replace(/\*(.+?)\*/g, '<em>$1</em>')
  html = html.replace(/_(.+?)_/g, '<em>$1</em>')

  // 删除线
  html = html.replace(/~~(.+?)~~/g, '<del>$1</del>')

  // 水平线
  html = html.replace(/^---$/gm, '<hr />')
  html = html.replace(/^\*\*\*$/gm, '<hr />')

  // 引用 >
  html = html.replace(/^&gt; (.+)$/gm, '<blockquote>$1</blockquote>')

  // 有序列表
  html = html.replace(/^(\d+)\. (.+)$/gm, '<li data-type="ordered">$2</li>')

  // 无序列表
  html = html.replace(/^[\-\*\+] (.+)$/gm, '<li>$1</li>')

  // 包裹连续的 <li> 在 <ul> 或 <ol> 中
  html = html.replace(/((?:<li[^>]*>.*?<\/li>\n?)+)/g, (match) => {
    if (match.includes('data-type="ordered"')) {
      return '<ol>\n' + match.replace(/ data-type="ordered"/g, '') + '</ol>\n'
    }
    return '<ul>\n' + match + '</ul>\n'
  })

  // 段落：未被标签包裹的连续文本行
  html = html.replace(/^(?!<[a-z]|$)(.+)$/gm, '<p>$1</p>')

  // 清理多余的空白段落
  html = html.replace(/<p>\s*<\/p>/g, '')
  html = html.replace(/<p><\/p>/g, '')

  return html
}

// --- 工具函数 ---
function formatTime(t) {
  if (!t) return ''
  return t.replace('T', ' ').substring(0, 16)
}
</script>

<style scoped>
.article-tool {
  height: calc(100vh - 100px);
  display: flex;
  flex-direction: column;
}

.article-layout {
  display: flex;
  gap: 0.75rem;
  flex: 1;
  min-height: 0;
  margin-bottom: 0.75rem;
}

/* 左侧文章列表 */
.article-sidebar {
  width: 220px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.sidebar-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.75rem;
}

.sidebar-header h3 {
  margin-bottom: 0;
}

.article-list {
  flex: 1;
  overflow-y: auto;
}

.article-item {
  padding: 0.6rem 0.75rem;
  border-radius: 6px;
  cursor: pointer;
  border: 1px solid transparent;
  transition: all 0.15s;
  margin-bottom: 0.35rem;
}

.article-item:hover {
  background: #f8fafc;
  border-color: #e2e8f0;
}

.article-item.active {
  background: #eef2ff;
  border-color: #c7d2fe;
}

.article-item-title {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--text);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.article-item-meta {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-top: 0.25rem;
  font-size: 0.72rem;
  color: var(--text-secondary);
}

.status-tag {
  padding: 0.1rem 0.4rem;
  border-radius: 3px;
  font-weight: 500;
  font-size: 0.68rem;
}

.status-tag.draft {
  background: #fef3c7;
  color: #92400e;
}

.status-tag.published {
  background: #d1fae5;
  color: #065f46;
}

.article-item-time {
  font-size: 0.68rem;
  opacity: 0.7;
}

/* 编辑器 */
.article-editor {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
  overflow: hidden;
}

.editor-toolbar {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.75rem;
  padding-bottom: 0.75rem;
  border-bottom: 1px solid var(--border);
}

.toolbar-left {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.toolbar-right {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.toolbar-title {
  margin-left: auto;
  font-size: 0.85rem;
  color: var(--text-secondary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.title-input {
  width: 100%;
  padding: 0.5rem 0.75rem;
  border: 1.5px solid var(--border);
  border-radius: var(--radius);
  font-size: 1.05rem;
  font-weight: 600;
  color: var(--text);
  outline: none;
  margin-bottom: 0.75rem;
  transition: border-color 0.2s;
}

.title-input:focus {
  border-color: var(--primary);
}

.editor-textarea {
  flex: 1;
  width: 100%;
  min-height: 300px;
  padding: 0.75rem;
  border: 1.5px solid var(--border);
  border-radius: var(--radius);
  font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  font-size: 0.875rem;
  line-height: 1.7;
  color: var(--text);
  resize: none;
  outline: none;
  transition: border-color 0.2s;
}

.editor-textarea:focus {
  border-color: var(--primary);
}

.empty-editor {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  color: var(--text-secondary);
  font-size: 0.9rem;
}

.empty-icon {
  font-size: 3rem;
  margin-bottom: 0.75rem;
  opacity: 0.4;
}

/* 弹窗 - 预览 */
.preview-modal-box {
  width: 800px;
  max-width: 95vw;
  max-height: 85vh;
}

.preview-body {
  flex: 1;
  overflow-y: auto;
  padding: 0.5rem 0;
  max-height: 60vh;
}

.empty-preview {
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--text-secondary);
  font-size: 0.9rem;
  opacity: 0.6;
  padding: 3rem 0;
}

/* 发布弹窗 */
.publish-modal-box {
  width: 560px;
  max-width: 95vw;
  max-height: 80vh;
}

.publish-channel-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-bottom: 1rem;
  max-height: 40vh;
  overflow-y: auto;
}

.channel-select-card {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1rem;
  border: 2px solid var(--border);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.15s;
  user-select: none;
}

.channel-select-card:hover {
  border-color: var(--primary);
  background: #f8faff;
}

.channel-select-card.selected {
  border-color: var(--primary);
  background: #eef2ff;
}

.channel-card-checkbox {
  accent-color: var(--primary);
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}

.channel-select-icon {
  font-size: 1.3rem;
  flex-shrink: 0;
}

.channel-select-info {
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
}

.channel-select-name {
  font-weight: 600;
  font-size: 0.9rem;
  color: var(--text);
}

.channel-select-type {
  font-size: 0.72rem;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.publish-modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.75rem;
  margin-bottom: 0.5rem;
}
.markdown-body {
  line-height: 1.8;
  word-break: break-word;
}

.markdown-body :deep(h1) {
  font-size: 1.6rem;
  font-weight: 700;
  margin: 1rem 0 0.5rem;
  padding-bottom: 0.4rem;
  border-bottom: 2px solid #e5e7eb;
}

.markdown-body :deep(h2) {
  font-size: 1.3rem;
  font-weight: 700;
  margin: 0.9rem 0 0.4rem;
  padding-bottom: 0.3rem;
  border-bottom: 1px solid #f3f4f6;
}

.markdown-body :deep(h3) {
  font-size: 1.1rem;
  font-weight: 600;
  margin: 0.75rem 0 0.35rem;
}

.markdown-body :deep(h4) {
  font-size: 1rem;
  font-weight: 600;
  margin: 0.6rem 0 0.3rem;
}

.markdown-body :deep(p) {
  margin: 0.5rem 0;
}

.markdown-body :deep(strong) {
  font-weight: 700;
}

.markdown-body :deep(em) {
  font-style: italic;
}

.markdown-body :deep(del) {
  text-decoration: line-through;
  opacity: 0.7;
}

.markdown-body :deep(code) {
  background: #f1f5f9;
  padding: 0.15rem 0.4rem;
  border-radius: 4px;
  font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  font-size: 0.82rem;
  color: #e11d48;
}

.markdown-body :deep(pre) {
  background: #1e293b;
  color: #e2e8f0;
  padding: 1rem;
  border-radius: var(--radius);
  overflow-x: auto;
  margin: 0.75rem 0;
}

.markdown-body :deep(pre code) {
  background: transparent;
  color: inherit;
  padding: 0;
  font-size: 0.82rem;
  line-height: 1.6;
}

.markdown-body :deep(blockquote) {
  border-left: 4px solid var(--primary);
  padding: 0.5rem 1rem;
  margin: 0.75rem 0;
  background: #f8fafc;
  color: var(--text-secondary);
  border-radius: 0 6px 6px 0;
}

.markdown-body :deep(ul),
.markdown-body :deep(ol) {
  padding-left: 1.5rem;
  margin: 0.5rem 0;
}

.markdown-body :deep(li) {
  margin: 0.2rem 0;
}

.markdown-body :deep(hr) {
  border: none;
  border-top: 2px solid #e5e7eb;
  margin: 1rem 0;
}

.markdown-body :deep(a) {
  color: var(--primary);
  text-decoration: underline;
}

.markdown-body :deep(img) {
  max-width: 100%;
  border-radius: 6px;
  margin: 0.5rem 0;
}

/* 发布结果 */
.publish-result {
  margin-top: 0.75rem;
  padding: 0.75rem;
  background: #f8fafc;
  border: 1px solid var(--border);
  border-radius: var(--radius);
}

.publish-summary {
  font-size: 0.9rem;
  font-weight: 600;
  margin-bottom: 0.5rem;
  color: var(--text);
}

.success-count {
  color: var(--success);
}

.failed-count {
  color: var(--error);
}

.publish-log-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.35rem 0;
  font-size: 0.85rem;
}

.log-icon {
  flex-shrink: 0;
}

.log-channel {
  font-weight: 500;
  min-width: 120px;
}

.log-msg {
  color: var(--text-secondary);
  font-size: 0.8rem;
}

/* 发布历史 */
.publish-logs {
  margin-top: 1rem;
  border-top: 1px solid var(--border);
  padding-top: 0.75rem;
}

.publish-logs h4 {
  font-size: 0.85rem;
  font-weight: 600;
  margin-bottom: 0.5rem;
  color: var(--text-secondary);
}

.log-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.3rem 0;
  font-size: 0.8rem;
  border-bottom: 1px solid #f1f5f9;
}

.log-channel-name {
  font-weight: 500;
  min-width: 100px;
  color: var(--text);
}

.log-status-badge {
  padding: 0.1rem 0.4rem;
  border-radius: 3px;
  font-size: 0.7rem;
  font-weight: 600;
}

.log-status-badge.success {
  background: #d1fae5;
  color: #065f46;
}

.log-status-badge.failed {
  background: #fee2e2;
  color: #991b1b;
}

.log-time {
  color: var(--text-secondary);
  font-size: 0.72rem;
  white-space: nowrap;
}

.log-msg-text {
  color: var(--text-secondary);
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* 弹窗 */
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.4);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  backdrop-filter: blur(2px);
}

.modal-box {
  background: white;
  border-radius: 12px;
  padding: 1.5rem;
  width: 640px;
  max-width: 90vw;
  max-height: 80vh;
  overflow-y: auto;
  box-shadow: 0 20px 50px rgba(0, 0, 0, 0.15);
}

.modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1rem;
}

.modal-header h3 {
  margin-bottom: 0;
  font-size: 1.1rem;
}

.modal-close {
  width: 28px;
  height: 28px;
  border: none;
  border-radius: 50%;
  background: #f1f5f9;
  font-size: 1rem;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: background 0.15s;
}

.modal-close:hover {
  background: #e2e8f0;
}

.channel-list {
  margin-bottom: 1.25rem;
}

.channel-config-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.75rem;
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 0.5rem;
}

.channel-info {
  display: flex;
  align-items: flex-start;
  gap: 0.6rem;
  flex: 1;
  min-width: 0;
}

.channel-type-icon {
  font-size: 1.3rem;
  flex-shrink: 0;
  margin-top: 0.1rem;
}

.channel-detail {
  flex: 1;
  min-width: 0;
}

.channel-name-row {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  flex-wrap: wrap;
  margin-bottom: 0.2rem;
}

.channel-name-row strong {
  font-size: 0.9rem;
}

.channel-type-tag {
  font-size: 0.68rem;
  padding: 0.1rem 0.4rem;
  border-radius: 3px;
  background: #f1f5f9;
  color: var(--text-secondary);
}

.status-badge {
  font-size: 0.68rem;
  padding: 0.1rem 0.4rem;
  border-radius: 3px;
  font-weight: 500;
}

.status-badge.enabled {
  background: #d1fae5;
  color: #065f46;
}

.status-badge.disabled {
  background: #fee2e2;
  color: #991b1b;
}

.channel-config-preview {
  font-size: 0.72rem;
  color: var(--text-secondary);
  font-family: monospace;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 300px;
}

.channel-actions {
  display: flex;
  gap: 0.35rem;
  flex-shrink: 0;
}

.channel-form {
  border-top: 1px solid var(--border);
  padding-top: 1rem;
}

.channel-form h4 {
  font-size: 0.95rem;
  font-weight: 600;
  margin-bottom: 0.75rem;
}

.config-hint {
  font-size: 0.72rem;
  color: var(--text-secondary);
  font-weight: 400;
  margin-left: 0.5rem;
}

.form-actions {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.5rem;
}

.empty-hint {
  color: var(--text-secondary);
  font-size: 0.85rem;
  padding: 1rem 0;
  text-align: center;
}

/* 响应式 */
@media (max-width: 1024px) {
  .article-layout {
    flex-direction: column;
  }

  .article-sidebar {
    width: 100%;
    max-height: 180px;
  }

  .article-editor {
    min-height: 300px;
  }

  .editor-textarea {
    min-height: 200px;
  }

  .modal-box,
  .preview-modal-box,
  .publish-modal-box {
    width: 95vw;
  }
}
</style>
