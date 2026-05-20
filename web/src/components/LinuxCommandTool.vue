<template>
  <div class="tool-panel">
    <h2>🐧 Linux 命令查询</h2>

    <!-- 快速系统帮助查询 -->
    <div class="quick-help-bar">
      <input
        v-model="quickHelpCmd"
        type="text"
        class="quick-help-input"
        placeholder="输入命令快速获取系统帮助，如: grep, ls -la, chmod"
        @keyup.enter="fetchQuickHelp"
      />
      <button class="btn btn-primary" @click="fetchQuickHelp" :disabled="!quickHelpCmd.trim()">🔍 查询帮助</button>
    </div>

    <div class="lc-layout">
      <!-- 左侧：搜索 + 命令列表 -->
      <div class="lc-sidebar">
        <div class="sidebar-header">
          <span class="sidebar-title">命令列表</span>
          <button class="btn btn-sm btn-primary" @click="showAddForm">+ 添加</button>
        </div>
        <div class="sidebar-search">
          <input
            v-model="searchKeyword"
            type="text"
            class="search-input"
            placeholder="搜索命令..."
            @keyup.enter="searchCommand"
          />
        </div>
        <div class="sidebar-body">
          <div
            v-for="cmd in filteredCommands"
            :key="cmd.id"
            :class="['cmd-item', { active: activeCmdId === cmd.id }]"
            @click="selectCommand(cmd)"
          >
            <div class="cmd-item-name">{{ cmd.name }}</div>
            <div class="cmd-item-desc">{{ cmd.description }}</div>
          </div>
          <div v-if="filteredCommands.length === 0" class="empty-hint">暂无命令记录</div>
        </div>
      </div>

      <!-- 右侧：命令详情 -->
      <div class="lc-main">
        <!-- 快速帮助结果 -->
        <div v-if="quickHelpResult" class="workspace-card quick-help-result">
          <div class="workspace-header">
            <span class="workspace-title">📖 系统帮助: {{ quickHelpResult.command }}</span>
            <div class="header-actions">
              <button class="btn btn-sm btn-outline" @click="copyHelpText">📋 复制</button>
              <button class="btn btn-sm btn-outline" @click="systemHelpResult = null; quickHelpResult = null">关闭</button>
            </div>
          </div>
          <div class="workspace-body">
            <div v-if="quickHelpResult.error" class="error-box">{{ quickHelpResult.error }}</div>
            <pre v-else class="usage-pre">{{ quickHelpResult.help_text }}</pre>
          </div>
        </div>

        <!-- 添加/编辑表单 -->
        <div v-if="showForm" class="workspace-card">
          <div class="workspace-header">
            <span class="workspace-title">{{ isEditing ? '编辑命令' : '添加命令' }}</span>
          </div>
          <div class="workspace-body">
            <div class="form-group">
              <label>命令名称</label>
              <div class="input-with-action">
                <input v-model="formData.name" type="text" class="input-field" placeholder="如: grep" :disabled="isEditing" />
                <button v-if="formData.name && !isEditing" class="btn btn-sm btn-outline" @click="fetchHelpForForm" :disabled="fetchingHelp">
                  {{ fetchingHelp ? '获取中...' : '📥 获取帮助' }}
                </button>
              </div>
            </div>
            <div class="form-group">
              <label>简短描述</label>
              <input v-model="formData.description" type="text" class="input-field" placeholder="一句话描述命令用途" />
            </div>
            <div class="form-group">
              <label>使用方法</label>
              <textarea v-model="formData.usage" class="input-area" rows="10" placeholder="命令的详细使用方法、常用参数示例..."></textarea>
            </div>
            <div class="form-actions">
              <button class="btn btn-primary" @click="saveCommand">保存</button>
              <button class="btn btn-outline" @click="cancelForm">取消</button>
            </div>
          </div>
        </div>

        <!-- 命令详情展示 -->
        <div v-else-if="activeCmdId" class="workspace-card">
          <div class="workspace-header">
            <span class="cmd-detail-name">{{ activeCmd.name }}</span>
            <div class="workspace-actions">
              <button class="btn btn-sm btn-outline" @click="editCommand">✏️ 编辑</button>
              <button class="btn btn-sm btn-outline" @click="fetchSystemHelp(activeCmd.name)">🖥 系统帮助</button>
              <button class="btn btn-sm btn-outline btn-danger" @click="deleteCommand">🗑 删除</button>
            </div>
          </div>
          <div class="workspace-body">
            <div class="cmd-detail-desc">{{ activeCmd.description }}</div>
            <div class="section-label">使用方法</div>
            <pre class="usage-pre">{{ activeCmd.usage || '暂无使用说明' }}</pre>
          </div>
        </div>

        <!-- 系统帮助结果 -->
        <div v-if="systemHelpResult" class="workspace-card" style="margin-top:0.75rem">
          <div class="workspace-header">
            <span class="workspace-title">系统帮助: {{ systemHelpResult.command }}</span>
            <button class="btn btn-sm btn-outline" @click="systemHelpResult = null">关闭</button>
          </div>
          <div class="workspace-body">
            <div v-if="systemHelpResult.error" class="error-box">{{ systemHelpResult.error }}</div>
            <pre v-else class="usage-pre">{{ systemHelpResult.help_text }}</pre>
          </div>
        </div>

        <!-- 空状态 -->
        <div v-if="!showForm && !activeCmdId && !systemHelpResult && !quickHelpResult" class="empty-workspace">
          ← 选择命令查看详情，或添加新命令，或使用上方快速帮助查询
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, inject } from 'vue'
import { apiPost } from '../api.js'

const showToast = inject('showToast')
const showConfirm = inject('showConfirm')

// 数据
const commands = ref([])
const searchKeyword = ref('')
const activeCmdId = ref(null)
const activeCmd = ref({})
const systemHelpResult = ref(null)
const quickHelpCmd = ref('')
const quickHelpResult = ref(null)
const fetchingHelp = ref(false)

// 表单
const showForm = ref(false)
const isEditing = ref(false)
const formData = reactive({ id: 0, name: '', description: '', usage: '' })

const filteredCommands = computed(() => {
  if (!searchKeyword.value.trim()) return commands.value
  const q = searchKeyword.value.toLowerCase().trim()
  return commands.value.filter(c =>
    c.name.toLowerCase().includes(q) || c.description.toLowerCase().includes(q)
  )
})

// 加载命令列表
async function loadCommands() {
  const res = await apiPost('/api/linux-command/list')
  if (res.code === 0) commands.value = res.data
  else showToast(res.message)
}

// 搜索命令
async function searchCommand() {
  if (!searchKeyword.value.trim()) { loadCommands(); return }
  const res = await apiPost('/api/linux-command/search', { keyword: searchKeyword.value.trim() })
  if (res.code === 0) commands.value = res.data
  else showToast(res.message)
}

// 选择命令
async function selectCommand(cmd) {
  const res = await apiPost('/api/linux-command/get', { id: cmd.id })
  if (res.code === 0) {
    activeCmd.value = res.data
    activeCmdId.value = cmd.id
    showForm.value = false
    systemHelpResult.value = null
  } else {
    showToast(res.message)
  }
}

// 显示添加表单
function showAddForm() {
  isEditing.value = false
  formData.id = 0
  formData.name = ''
  formData.description = ''
  formData.usage = ''
  showForm.value = true
  activeCmdId.value = null
  systemHelpResult.value = null
}

// 编辑命令
function editCommand() {
  isEditing.value = true
  formData.id = activeCmd.value.id
  formData.name = activeCmd.value.name
  formData.description = activeCmd.value.description
  formData.usage = activeCmd.value.usage
  showForm.value = true
}

// 保存命令
async function saveCommand() {
  if (!formData.name.trim()) { showToast('命令名称不能为空'); return }
  if (isEditing.value) {
    const res = await apiPost('/api/linux-command/update', {
      id: formData.id,
      name: formData.name.trim(),
      description: formData.description.trim(),
      usage: formData.usage
    })
    if (res.code === 0) {
      showToast('更新成功')
      showForm.value = false
      await loadCommands()
      const updated = commands.value.find(c => c.id === formData.id)
      if (updated) await selectCommand(updated)
    } else {
      showToast(res.message)
    }
  } else {
    const res = await apiPost('/api/linux-command/create', {
      name: formData.name.trim(),
      description: formData.description.trim(),
      usage: formData.usage
    })
    if (res.code === 0) {
      showToast('添加成功')
      showForm.value = false
      await loadCommands()
      await selectCommand(res.data)
    } else {
      showToast(res.message)
    }
  }
}

// 删除命令
async function deleteCommand() {
  const ok = await showConfirm({ title: '删除命令', message: `确定删除「${activeCmd.value.name}」？`, icon: '⚠️', danger: true })
  if (!ok) return
  const res = await apiPost('/api/linux-command/delete', { id: activeCmd.value.id })
  if (res.code === 0) {
    activeCmdId.value = null
    activeCmd.value = {}
    await loadCommands()
  } else {
    showToast(res.message)
  }
}

function cancelForm() {
  showForm.value = false
}

// 快速帮助查询
async function fetchQuickHelp() {
  const cmd = quickHelpCmd.value.trim()
  if (!cmd) return
  const res = await apiPost('/api/linux-command/help', { command: cmd })
  if (res.code === 0) {
    quickHelpResult.value = res.data
    if (!res.data.available) {
      showToast(res.data.error || '未找到该命令')
    }
  } else {
    showToast(res.message)
  }
}

// 为表单获取帮助并填充
async function fetchHelpForForm() {
  const cmd = formData.name.trim()
  if (!cmd) return
  fetchingHelp.value = true
  const res = await apiPost('/api/linux-command/help', { command: cmd })
  fetchingHelp.value = false
  if (res.code === 0) {
    if (res.data.available && res.data.help_text) {
      formData.usage = res.data.help_text
      showToast('已填充系统帮助内容')
    } else {
      showToast(res.data.error || '未找到该命令的帮助')
    }
  } else {
    showToast(res.message)
  }
}

// 复制帮助文本
async function copyHelpText() {
  if (!quickHelpResult.value?.help_text) return
  try {
    await navigator.clipboard.writeText(quickHelpResult.value.help_text)
    showToast('已复制到剪贴板')
  } catch {
    showToast('复制失败')
  }
}

// 获取系统帮助
async function fetchSystemHelp(cmdName) {
  const res = await apiPost('/api/linux-command/help', { command: cmdName })
  if (res.code === 0) {
    systemHelpResult.value = res.data
    if (!res.data.available) {
      showToast(res.data.error || '未找到该命令')
    }
  } else {
    showToast(res.message)
  }
}

onMounted(() => {
  loadCommands()
})
</script>

<style scoped>
.lc-layout {
  display: flex;
  gap: 1rem;
  flex: 1;
  min-height: calc(100vh - 200px);
}

/* ====== 左侧边栏 ====== */
.lc-sidebar {
  width: 220px;
  flex-shrink: 0;
  min-height: 0;
  border: 1px solid var(--border, #e5e7eb);
  border-radius: 8px;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  background: #fff;
}

.sidebar-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.7rem 0.85rem;
  border-bottom: 1px solid var(--border, #e5e7eb);
  background: #f8fafc;
}

.sidebar-title {
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--text, #1e293b);
}

.sidebar-search {
  padding: 0.5rem 0.6rem;
  border-bottom: 1px solid var(--border, #e5e7eb);
}

.search-input {
  width: 100%;
  padding: 0.4rem 0.6rem;
  border: 1px solid var(--border, #e5e7eb);
  border-radius: 6px;
  font-size: 0.82rem;
  outline: none;
  transition: border-color 0.2s;
  background: #fff;
}

.search-input:focus {
  border-color: var(--primary, #4f46e5);
}

.sidebar-body {
  flex: 1;
  overflow-y: auto;
  padding: 0.4rem;
}

/* 命令列表项 */
.cmd-item {
  padding: 0.5rem 0.65rem;
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.15s;
  border-left: 2.5px solid transparent;
}

.cmd-item:hover {
  background: rgba(79, 70, 229, 0.06);
  border-left-color: #c7d2fe;
}

.cmd-item.active {
  background: rgba(79, 70, 229, 0.1);
  border-left-color: var(--primary, #4f46e5);
}

.cmd-item-name {
  font-size: 0.85rem;
  font-weight: 600;
  font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  color: var(--text, #1e293b);
}

.cmd-item-desc {
  font-size: 0.73rem;
  color: var(--text-secondary, #9ca3af);
  margin-top: 0.1rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* ====== 右侧工作区 ====== */
.lc-main {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.workspace-card {
  flex: 1;
  display: flex;
  flex-direction: column;
  border: 1px solid var(--border, #e5e7eb);
  border-radius: 8px;
  overflow: hidden;
  background: #fff;
}

.workspace-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.7rem 0.85rem;
  border-bottom: 1px solid var(--border, #e5e7eb);
  background: #f8fafc;
}

.workspace-title {
  font-size: 0.88rem;
  font-weight: 600;
  color: var(--text, #1e293b);
}

.cmd-detail-name {
  font-size: 1rem;
  font-weight: 600;
  font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  color: var(--primary, #4f46e5);
}

.workspace-actions {
  display: flex;
  align-items: center;
  gap: 0.4rem;
}

.btn-danger {
  color: #dc2626;
  border-color: #dc2626;
}

.workspace-body {
  flex: 1;
  overflow-y: auto;
  padding: 1rem;
}

/* 详情内容 */
.cmd-detail-desc {
  font-size: 0.88rem;
  color: var(--text-secondary, #6b7280);
  margin-bottom: 1rem;
  line-height: 1.5;
}

.section-label {
  font-size: 0.78rem;
  font-weight: 600;
  color: var(--text-secondary, #6b7280);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 0.5rem;
}

.usage-pre {
  background: #1e293b;
  color: #e2e8f0;
  padding: 1rem;
  border-radius: 6px;
  font-size: 0.82rem;
  line-height: 1.6;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  max-height: 500px;
  overflow-y: auto;
}

/* 表单 */
.form-group {
  margin-bottom: 0.75rem;
}

.form-group label {
  display: block;
  font-size: 0.82rem;
  font-weight: 500;
  color: var(--text, #1e293b);
  margin-bottom: 0.3rem;
}

.input-field {
  width: 100%;
  padding: 0.45rem 0.6rem;
  border: 1px solid var(--border, #e5e7eb);
  border-radius: 6px;
  font-size: 0.85rem;
  outline: none;
  transition: border-color 0.2s;
}

.input-field:focus {
  border-color: var(--primary, #4f46e5);
}

.input-area {
  width: 100%;
  padding: 0.5rem 0.6rem;
  border: 1px solid var(--border, #e5e7eb);
  border-radius: 6px;
  font-size: 0.85rem;
  font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  outline: none;
  resize: vertical;
  line-height: 1.5;
}

.input-area:focus {
  border-color: var(--primary, #4f46e5);
}

.form-actions {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.5rem;
}

/* 错误 */
.error-box {
  padding: 0.6rem 0.8rem;
  background: #fef2f2;
  color: #dc2626;
  border-radius: 6px;
  font-size: 0.85rem;
}

/* 空状态 */
.empty-hint {
  padding: 2rem 1rem;
  text-align: center;
  font-size: 0.85rem;
  color: var(--text-secondary, #9ca3af);
}

.empty-workspace {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.9rem;
  color: var(--text-secondary, #9ca3af);
  background: #fff;
  border: 1px solid var(--border, #e5e7eb);
  border-radius: 8px;
}

/* 响应式 */
@media (max-width: 768px) {
  .lc-layout {
    flex-direction: column;
  }
  .lc-sidebar {
    width: 100%;
    max-height: 280px;
  }
}

/* 快速帮助栏 */
.quick-help-bar {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1rem;
  align-items: center;
}

.quick-help-input {
  flex: 1;
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--border, #e5e7eb);
  border-radius: 6px;
  font-size: 0.85rem;
  outline: none;
  transition: border-color 0.2s;
}

.quick-help-input:focus {
  border-color: var(--primary, #4f46e5);
}

.quick-help-result {
  margin-bottom: 0.75rem;
}

/* 带操作的输入框 */
.input-with-action {
  display: flex;
  gap: 0.5rem;
}

.input-with-action .input-field {
  flex: 1;
}

/* 头部操作按钮组 */
.header-actions {
  display: flex;
  gap: 0.4rem;
}
</style>
