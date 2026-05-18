<template>
  <div class="app-layout">
    <!-- 顶栏 -->
    <header class="topbar">
      <div class="topbar-left">
        <button class="sidebar-toggle" @click="sidebarOpen = !sidebarOpen" :title="sidebarOpen ? '收起侧栏' : '展开侧栏'">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/>
          </svg>
        </button>
        <h1 class="topbar-logo">🔧 攻城师天梯</h1>
      </div>
      <div class="topbar-search">
        <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
        <input
          v-model="searchQuery"
          type="text"
          class="search-input"
          placeholder="搜索工具..."
        />
        <button v-if="searchQuery" class="search-clear" @click="searchQuery = ''">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>
    </header>

    <div class="app-body">
      <!-- 侧边栏 -->
      <aside :class="['sidebar', { open: sidebarOpen }]">
        <nav class="sidebar-nav">
          <div v-for="cat in filteredCategories" :key="cat.id" class="nav-group">
            <div class="nav-group-title" @click="toggleGroup(cat.id)">
              <span>{{ cat.label }}</span>
              <svg :class="['nav-arrow', { expanded: expandedGroups[cat.id] }]" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <polyline points="9 18 15 12 9 6"/>
              </svg>
            </div>
            <div v-show="expandedGroups[cat.id]" class="nav-group-items">
              <button
                v-for="tool in cat.tools"
                :key="tool.id"
                :class="['nav-item', { active: currentTool === tool.id }]"
                @click="selectTool(tool.id)"
              >
                <span class="nav-item-icon">{{ tool.icon }}</span>
                <span class="nav-item-name">{{ tool.name }}</span>
              </button>
            </div>
          </div>

          <div v-if="filteredCategories.length === 0" class="nav-empty">
            未找到匹配的工具
          </div>
        </nav>
      </aside>

      <!-- 遮罩层（移动端） -->
      <div v-if="sidebarOpen" class="sidebar-overlay" @click="sidebarOpen = false"></div>

      <!-- 内容区 -->
      <main class="main-content">
        <div :class="['content-wrapper', { 'full-width': currentTool === 'api-tester' }]">
          <TimestampTool v-if="currentTool === 'timestamp'" />
          <TimeFormatTool v-else-if="currentTool === 'timeformat'" />
          <Base64EncodeTool v-else-if="currentTool === 'base64'" />
          <URLTool v-else-if="currentTool === 'url'" />
          <HashTool v-else-if="currentTool === 'hash'" />
          <UUIDTool v-else-if="currentTool === 'uuid'" />
          <JSONTool v-else-if="currentTool === 'json'" />
          <URLCodeTool v-else-if="currentTool === 'urlcode'" />
          <IPTool v-else-if="currentTool === 'ip'" />
          <RegexTool v-else-if="currentTool === 'regex'" />
          <StringTool v-else-if="currentTool === 'string'" />
          <JWTTool v-else-if="currentTool === 'jwt'" />
          <LLMChatTool v-else-if="currentTool === 'llm-chat'" />
          <APITesterTool v-else-if="currentTool === 'api-tester'" />
        </div>
      </main>
    </div>
  </div>

  <!-- 自定义确认弹窗 -->
  <Transition name="fade">
    <div v-if="dialogVisible" class="dialog-overlay" @click.self="dialogCancel">
      <div class="dialog-box">
        <div class="dialog-icon">{{ dialogIcon }}</div>
        <div class="dialog-title">{{ dialogTitle }}</div>
        <div v-if="dialogMessage" class="dialog-message">{{ dialogMessage }}</div>
        <div class="dialog-actions">
          <button class="dialog-btn dialog-btn-cancel" @click="dialogCancel">取消</button>
          <button :class="['dialog-btn', dialogDanger ? 'dialog-btn-danger' : 'dialog-btn-confirm']" @click="dialogOk">确定</button>
        </div>
      </div>
    </div>
  </Transition>

  <!-- 自定义提示弹窗 -->
  <Transition name="fade">
    <div v-if="alertVisible" class="dialog-overlay" @click.self="alertClose">
      <div class="dialog-box">
        <div class="dialog-icon">ℹ️</div>
        <div v-if="alertTitle" class="dialog-title">{{ alertTitle }}</div>
        <div class="dialog-message">{{ alertMessage }}</div>
        <div class="dialog-actions">
          <button class="dialog-btn dialog-btn-confirm" @click="alertClose">知道了</button>
        </div>
      </div>
    </div>
  </Transition>

  <Transition name="fade">
    <div v-if="toastVisible" class="toast">{{ toastMessage }}</div>
  </Transition>
</template>

<script setup>
import { ref, reactive, computed, provide, onMounted, onUnmounted } from 'vue'
import TimestampTool from './components/TimestampTool.vue'
import TimeFormatTool from './components/TimeFormatTool.vue'
import Base64EncodeTool from './components/Base64EncodeTool.vue'
import URLTool from './components/URLTool.vue'
import HashTool from './components/HashTool.vue'
import UUIDTool from './components/UUIDTool.vue'
import JSONTool from './components/JSONTool.vue'
import URLCodeTool from './components/URLCodeTool.vue'
import IPTool from './components/IPTool.vue'
import RegexTool from './components/RegexTool.vue'
import StringTool from './components/StringTool.vue'
import JWTTool from './components/JWTTool.vue'
import LLMChatTool from './components/LLMChatTool.vue'
import APITesterTool from './components/APITesterTool.vue'

const currentTool = ref(localStorage.getItem('last-tool') || 'timestamp')
const searchQuery = ref('')
const sidebarOpen = ref(true)

const categories = [
  {
    id: 'dev',
    label: '开发调试',
    tools: [
      { id: 'api-tester', name: 'API 调试', icon: '🔌' },
    ]
  },
  {
    id: 'ai',
    label: '人工智能',
    tools: [
      { id: 'llm-chat', name: 'AI 对话', icon: '💬' },
    ]
  },
  {
    id: 'codec',
    label: '字符编码',
    tools: [
      { id: 'base64', name: 'Base64', icon: '🔤' },
      { id: 'url', name: 'URL编码', icon: '🔗' },
      { id: 'urlcode', name: 'URL解析', icon: '🌐' },
      { id: 'jwt', name: 'JWT解析', icon: '🎫' },
      { id: 'string', name: '字符处理', icon: '✂️' },
    ]
  },
  {
    id: 'crypto',
    label: '加密生成',
    tools: [
      { id: 'hash', name: '哈希摘要', icon: '🔏' },
      { id: 'uuid', name: 'ID生成器', icon: '🆔' },
    ]
  },
  {
    id: 'data',
    label: '数据处理',
    tools: [
      { id: 'json', name: 'JSON美化', icon: '📋' },
      { id: 'regex', name: '正则匹配', icon: '🔎' },
    ]
  },
  {
    id: 'time',
    label: '时间日期',
    tools: [
      { id: 'timestamp', name: '时间戳转换', icon: '⏱' },
      { id: 'timeformat', name: '日期格式化', icon: '📅' },
    ]
  },
  {
    id: 'network',
    label: '网络工具',
    tools: [
      { id: 'ip', name: 'IP 查询', icon: '🌍' },
    ]
  },
]

// 默认展开所有分组
const expandedGroups = reactive({})
categories.forEach(c => { expandedGroups[c.id] = true })

function toggleGroup(id) {
  expandedGroups[id] = !expandedGroups[id]
}

// 搜索过滤
const filteredCategories = computed(() => {
  if (!searchQuery.value.trim()) return categories
  const q = searchQuery.value.toLowerCase().trim()
  return categories
    .map(cat => {
      const filteredTools = cat.tools.filter(t =>
        t.name.toLowerCase().includes(q) || t.id.includes(q)
      )
      if (filteredTools.length === 0) return null
      return { ...cat, tools: filteredTools }
    })
    .filter(Boolean)
})

function selectTool(id) {
  currentTool.value = id
  localStorage.setItem('last-tool', id)
  // 移动端点击后关闭侧栏
  if (window.innerWidth < 768) {
    sidebarOpen.value = false
  }
}

const toastVisible = ref(false)
const toastMessage = ref('')

function showToast(msg) {
  toastMessage.value = msg
  toastVisible.value = true
  setTimeout(() => { toastVisible.value = false }, 2000)
}

provide('showToast', showToast)

// 全局确认弹窗
const dialogVisible = ref(false)
const dialogTitle = ref('')
const dialogMessage = ref('')
const dialogIcon = ref('⚠️')
const dialogDanger = ref(false)
let dialogResolve = null

function showConfirm({ title = '确认操作', message = '', icon = '⚠️', danger = false } = {}) {
  return new Promise(resolve => {
    dialogTitle.value = title
    dialogMessage.value = message
    dialogIcon.value = icon
    dialogDanger.value = danger
    dialogVisible.value = true
    dialogResolve = resolve
  })
}

function dialogOk() {
  dialogVisible.value = false
  if (dialogResolve) dialogResolve(true)
  dialogResolve = null
}

function dialogCancel() {
  dialogVisible.value = false
  if (dialogResolve) dialogResolve(false)
  dialogResolve = null
}

provide('showConfirm', showConfirm)

// 全局提示弹窗
const alertVisible = ref(false)
const alertTitle = ref('')
const alertMessage = ref('')
let alertResolve = null

function showAlert({ title = '', message = '' } = {}) {
  return new Promise(resolve => {
    alertTitle.value = title
    alertMessage.value = message
    alertVisible.value = true
    alertResolve = resolve
  })
}

function alertClose() {
  alertVisible.value = false
  if (alertResolve) alertResolve()
  alertResolve = null
}

provide('showAlert', showAlert)

// 响应式：移动端默认收起侧栏
function handleResize() {
  if (window.innerWidth < 768) {
    sidebarOpen.value = false
  }
}
onMounted(() => handleResize())
onUnmounted(() => window.removeEventListener('resize', handleResize))
</script>

<style scoped>
/* 整体布局 */
.app-layout {
  display: flex;
  flex-direction: column;
  height: 100vh;
  overflow: hidden;
}

/* 顶栏 */
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 52px;
  padding: 0 1rem;
  background: linear-gradient(135deg, #4f46e5 0%, #6d28d9 100%);
  color: white;
  flex-shrink: 0;
  z-index: 100;
  box-shadow: 0 1px 3px rgba(0,0,0,0.12);
}

.topbar-left {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.sidebar-toggle {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border: none;
  border-radius: 6px;
  background: rgba(255,255,255,0.15);
  color: white;
  cursor: pointer;
  transition: background 0.2s;
}

.sidebar-toggle:hover {
  background: rgba(255,255,255,0.25);
}

.topbar-logo {
  font-size: 1.1rem;
  font-weight: 700;
  white-space: nowrap;
}

.topbar-search {
  position: relative;
  width: 280px;
  max-width: 40%;
}

.search-icon {
  position: absolute;
  left: 10px;
  top: 50%;
  transform: translateY(-50%);
  color: rgba(255,255,255,0.6);
  pointer-events: none;
}

.search-input {
  width: 100%;
  padding: 0.45rem 0.75rem 0.45rem 2rem;
  border: 1px solid rgba(255,255,255,0.25);
  border-radius: 8px;
  background: rgba(255,255,255,0.15);
  color: white;
  font-size: 0.85rem;
  outline: none;
  transition: all 0.2s;
}

.search-input::placeholder {
  color: rgba(255,255,255,0.55);
}

.search-input:focus {
  background: rgba(255,255,255,0.25);
  border-color: rgba(255,255,255,0.4);
}

.search-clear {
  position: absolute;
  right: 6px;
  top: 50%;
  transform: translateY(-50%);
  display: flex;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  border: none;
  border-radius: 50%;
  background: rgba(255,255,255,0.2);
  color: white;
  cursor: pointer;
}

.search-clear:hover {
  background: rgba(255,255,255,0.35);
}

/* 主体区域 */
.app-body {
  display: flex;
  flex: 1;
  overflow: hidden;
}

/* 侧边栏 */
.sidebar {
  width: 0;
  flex-shrink: 0;
  background: var(--card-bg);
  border-right: 1px solid var(--border);
  overflow: hidden;
  transition: width 0.25s ease;
}

.sidebar.open {
  width: 232px;
}

.sidebar-nav {
  width: 232px;
  height: 100%;
  overflow-y: auto;
  padding: 0.5rem 0;
}

.sidebar-nav::-webkit-scrollbar {
  width: 3px;
}

.sidebar-nav::-webkit-scrollbar-thumb {
  background: #d1d5db;
  border-radius: 3px;
}

.nav-group {
  margin-bottom: 0.15rem;
}

.nav-group-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.6rem 0.85rem 0.35rem;
  font-size: 0.68rem;
  font-weight: 700;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  cursor: pointer;
  user-select: none;
  transition: color 0.15s;
}

.nav-group-title:hover {
  color: var(--text);
}

.nav-arrow {
  transition: transform 0.2s;
  color: var(--text-secondary);
}

.nav-arrow.expanded {
  transform: rotate(90deg);
}

.nav-group-items {
  padding: 0 0.4rem 0.15rem;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  width: 100%;
  padding: 0.42rem 0.65rem;
  border: none;
  border-radius: 6px;
  border-left: 2.5px solid transparent;
  background: transparent;
  cursor: pointer;
  font-size: 0.82rem;
  color: var(--text-secondary);
  transition: all 0.15s;
  text-align: left;
  position: relative;
}

.nav-item:hover {
  background: rgba(79, 70, 229, 0.04);
  color: var(--text);
  border-left-color: #c7d2fe;
}

.nav-item.active {
  background: rgba(79, 70, 229, 0.08);
  color: var(--primary);
  font-weight: 600;
  border-left-color: var(--primary);
}

.nav-item-icon {
  font-size: 0.92rem;
  flex-shrink: 0;
  width: 1.15rem;
  text-align: center;
  opacity: 0.85;
}

.nav-item.active .nav-item-icon {
  opacity: 1;
}

.nav-item-name {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.nav-empty {
  padding: 2rem 1rem;
  text-align: center;
  font-size: 0.85rem;
  color: var(--text-secondary);
}

/* 遮罩 */
.sidebar-overlay {
  display: none;
}

/* 内容区 */
.main-content {
  flex: 1;
  overflow-y: auto;
  background: var(--bg);
}

.content-wrapper {
  max-width: 1400px;
  margin: 0 auto;
  padding: 1.5rem 2rem;
}

.content-wrapper.full-width {
  max-width: none;
  padding: 0;
}

/* Toast */
.toast {
  position: fixed;
  bottom: 2rem;
  left: 50%;
  transform: translateX(-50%);
  background: var(--text);
  color: white;
  padding: 0.6rem 1.5rem;
  border-radius: var(--radius);
  font-size: 0.9rem;
  z-index: 1100;
  box-shadow: var(--shadow-md);
}

/* 确认/提示弹窗 */
.dialog-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.4);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1050;
  backdrop-filter: blur(2px);
}

.dialog-box {
  background: white;
  border-radius: 12px;
  padding: 1.75rem 2rem 1.5rem;
  min-width: 320px;
  max-width: 440px;
  box-shadow: 0 20px 50px rgba(0, 0, 0, 0.15);
  text-align: center;
  animation: dialog-in 0.2s ease;
}

@keyframes dialog-in {
  from { transform: scale(0.9); opacity: 0; }
  to { transform: scale(1); opacity: 1; }
}

.dialog-icon {
  font-size: 2.2rem;
  margin-bottom: 0.6rem;
}

.dialog-title {
  font-size: 1.05rem;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 0.4rem;
}

.dialog-message {
  font-size: 0.88rem;
  color: var(--text-secondary);
  margin-bottom: 1.25rem;
  line-height: 1.5;
}

.dialog-actions {
  display: flex;
  gap: 0.6rem;
  justify-content: center;
}

.dialog-btn {
  padding: 0.5rem 1.5rem;
  border-radius: 6px;
  font-size: 0.88rem;
  font-weight: 600;
  cursor: pointer;
  border: none;
  transition: all 0.15s;
}

.dialog-btn-cancel {
  background: #f1f5f9;
  color: var(--text-secondary);
}

.dialog-btn-cancel:hover {
  background: #e2e8f0;
  color: var(--text);
}

.dialog-btn-confirm {
  background: var(--primary);
  color: white;
}

.dialog-btn-confirm:hover {
  background: #4338ca;
}

.dialog-btn-danger {
  background: #ef4444;
  color: white;
}

.dialog-btn-danger:hover {
  background: #dc2626;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

/* 移动端适配 */
@media (max-width: 768px) {
  .topbar-search {
    width: 180px;
  }

  .sidebar {
    position: fixed;
    top: 52px;
    left: 0;
    bottom: 0;
    z-index: 90;
    width: 0;
    box-shadow: none;
    transition: box-shadow 0.25s;
  }

  .sidebar.open {
    width: 232px;
    box-shadow: 4px 0 12px rgba(0,0,0,0.1);
  }

  .sidebar-overlay {
    display: block;
    position: fixed;
    top: 52px;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0,0,0,0.3);
    z-index: 80;
  }

  .content-wrapper {
    padding: 1rem 1rem;
  }
}

@media (max-width: 480px) {
  .topbar-logo {
    font-size: 0.95rem;
  }

  .topbar-search {
    width: 140px;
    max-width: 50%;
  }
}
</style>
