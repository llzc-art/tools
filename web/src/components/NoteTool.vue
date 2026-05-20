<template>
  <div class="tool-panel">
    <h2>📝 笔记</h2>

    <div class="note-layout">
      <!-- 左侧：目录 + 文档列表 -->
      <div class="note-sidebar">
        <div class="sidebar-header">
          <span class="sidebar-title">目录</span>
          <button class="btn btn-sm btn-primary" @click="createFolder">+ 新建目录</button>
        </div>
        <div class="sidebar-body">
          <!-- 目录列表 -->
          <div
            v-for="folder in folders"
            :key="folder.id"
            class="folder-item"
          >
            <div
              :class="['list-item', { active: activeFolderId === folder.id && !activeDocId }]"
              @click="selectFolder(folder)"
            >
              <span class="item-icon" @click.stop="toggleFolderDocs(folder)">
                {{ expandedFolders[folder.id] ? '📂' : '📁' }}
              </span>
              <span class="item-text" v-if="editingFolderId !== folder.id">{{ folder.name }}</span>
              <input
                v-else
                v-model="editingFolderName"
                class="item-edit-input"
                @keyup.enter="saveFolderEdit(folder)"
                @keyup.escape="cancelFolderEdit"
                @blur="saveFolderEdit(folder)"
                ref="folderEditInput"
              />
              <button class="add-doc-btn" @click.stop="createDocument(folder)" title="新建笔记">+</button>
              <div class="item-actions" v-if="editingFolderId !== folder.id">
                <button class="act-btn" @click.stop="startEditFolder(folder)" title="重命名">✏️</button>
                <button class="act-btn danger" @click.stop="deleteFolder(folder)" title="删除">🗑</button>
              </div>
            </div>
            <!-- 文件列表（可展开） -->
            <div v-if="expandedFolders[folder.id] && folder.id === activeFolderId" class="doc-list">
              <div
                v-for="doc in documents"
                :key="doc.id"
                :class="['doc-item', { active: activeDocId === doc.id }]"
                :data-id="doc.id"
                @click="selectDocument(doc)"
              >
                <span class="doc-icon">📄</span>
                <span class="doc-title">{{ doc.title }}</span>
                <button class="act-btn danger" @click.stop="deleteDocument(doc)" title="删除">🗑</button>
              </div>
              <div v-if="documents.length === 0" class="empty-hint small">暂无笔记</div>
            </div>
          </div>
          <div v-if="folders.length === 0" class="empty-hint">暂无目录，点击新建</div>
        </div>
      </div>

      <!-- 右侧：文档编辑区 -->
      <div class="note-main">
        <div v-if="activeDocId" class="workspace-card">
          <div class="workspace-header">
            <input v-model="currentDoc.title" class="doc-title-input" placeholder="笔记标题" />
            <button class="btn btn-sm btn-primary" @click="saveDocument">💾 保存</button>
          </div>
          <textarea
            v-model="currentDoc.content"
            class="doc-editor"
            placeholder="开始写笔记..."
          ></textarea>
        </div>
        <div v-else class="empty-workspace">← 选择左侧目录查看笔记，或新建笔记</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, inject, nextTick } from 'vue'
import { apiPost } from '../api.js'

const showToast = inject('showToast')
const showConfirm = inject('showConfirm')

// 目录
const folders = ref([])
const activeFolderId = ref(null)
const editingFolderId = ref(null)
const editingFolderName = ref('')
const expandedFolders = ref({}) // 跟踪哪些目录的文档列表是展开的

const activeFolderName = computed(() => {
  const f = folders.value.find(f => f.id === activeFolderId.value)
  return f ? f.name : ''
})

// 文档
const documents = ref([])
const activeDocId = ref(null)
const currentDoc = reactive({ id: 0, title: '', content: '', folder_id: 0 })

// 加载目录列表
async function loadFolders() {
  const res = await apiPost('/api/note/folder/list')
  if (res.code === 0) folders.value = res.data
  else showToast(res.message)
}

// 选择目录
async function selectFolder(folder) {
  const wasActive = activeFolderId.value === folder.id
  activeFolderId.value = folder.id
  activeDocId.value = null
  // 切换展开状态或加载文档
  if (wasActive) {
    // 点击同一个目录，切换展开状态
    expandedFolders.value[folder.id] = !expandedFolders.value[folder.id]
  } else {
    expandedFolders.value[folder.id] = true
    await loadDocuments()
  }
}

// 展开/收起目录文档列表
function toggleFolderDocs(folder) {
  expandedFolders.value[folder.id] = !expandedFolders.value[folder.id]
  if (expandedFolders.value[folder.id] && activeFolderId.value !== folder.id) {
    activeFolderId.value = folder.id
    loadDocuments()
  }
}

// 新建目录
async function createFolder() {
  const name = '新目录'
  const res = await apiPost('/api/note/folder/create', { name, parent_id: 0 })
  if (res.code === 0) {
    await loadFolders()
    activeFolderId.value = res.data.id
    await loadDocuments()
  } else {
    showToast(res.message)
  }
}

// 编辑目录
function startEditFolder(folder) {
  editingFolderId.value = folder.id
  editingFolderName.value = folder.name
}

async function saveFolderEdit(folder) {
  if (!editingFolderName.value.trim()) {
    cancelFolderEdit()
    return
  }
  const res = await apiPost('/api/note/folder/update', {
    id: folder.id,
    name: editingFolderName.value.trim(),
    parent_id: folder.parent_id
  })
  if (res.code === 0) {
    folder.name = editingFolderName.value.trim()
  } else {
    showToast(res.message)
  }
  editingFolderId.value = null
}

function cancelFolderEdit() {
  editingFolderId.value = null
}

// 删除目录
async function deleteFolder(folder) {
  const ok = await showConfirm({ title: '删除目录', message: `确定删除目录「${folder.name}」及其下所有笔记？`, icon: '⚠️', danger: true })
  if (!ok) return
  const res = await apiPost('/api/note/folder/delete', { id: folder.id })
  if (res.code === 0) {
    if (activeFolderId.value === folder.id) {
      activeFolderId.value = null
      activeDocId.value = null
    }
    await loadFolders()
  } else {
    showToast(res.message)
  }
}

// 加载文档列表
async function loadDocuments() {
  if (!activeFolderId.value) { documents.value = []; return }
  const res = await apiPost('/api/note/document/list', { folder_id: activeFolderId.value })
  if (res.code === 0) documents.value = res.data
  else showToast(res.message)
}

// 选择文档
async function selectDocument(doc) {
  const res = await apiPost('/api/note/document/get', { id: doc.id })
  if (res.code === 0) {
    currentDoc.id = res.data.id
    currentDoc.title = res.data.title
    currentDoc.content = res.data.content
    currentDoc.folder_id = res.data.folder_id
    activeDocId.value = doc.id
  } else {
    showToast(res.message)
  }
}

// 新建文档
async function createDocument(folder) {
  const folderId = folder ? folder.id : activeFolderId.value
  if (!folderId) return
  
  // 确保目录展开
  expandedFolders.value[folderId] = true
  activeFolderId.value = folderId
  
  const res = await apiPost('/api/note/document/create', {
    folder_id: folderId,
    title: '未命名笔记',
    content: ''
  })
  if (res.code === 0) {
    await loadDocuments()
    currentDoc.id = res.data.id
    currentDoc.title = res.data.title
    currentDoc.content = res.data.content
    currentDoc.folder_id = res.data.folder_id
    activeDocId.value = res.data.id
    
    // 滚动到新笔记
    await nextTick()
    const newDocEl = document.querySelector(`.doc-item[data-id="${res.data.id}"]`)
    newDocEl?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  } else {
    showToast(res.message)
  }
}

// 保存文档
async function saveDocument() {
  if (!currentDoc.id) return
  const res = await apiPost('/api/note/document/update', {
    id: currentDoc.id,
    folder_id: currentDoc.folder_id,
    title: currentDoc.title || '未命名笔记',
    content: currentDoc.content
  })
  if (res.code === 0) {
    showToast('保存成功')
    await loadDocuments()
  } else {
    showToast(res.message)
  }
}

// 删除文档
async function deleteDocument(doc) {
  const ok = await showConfirm({ title: '删除笔记', message: `确定删除「${doc.title}」？`, icon: '⚠️', danger: true })
  if (!ok) return
  const res = await apiPost('/api/note/document/delete', { id: doc.id })
  if (res.code === 0) {
    if (activeDocId.value === doc.id) {
      activeDocId.value = null
    }
    await loadDocuments()
  } else {
    showToast(res.message)
  }
}

onMounted(() => {
  loadFolders()
})
</script>

<style scoped>
.note-layout {
  display: flex;
  gap: 1rem;
  flex: 1;
  min-height: calc(100vh - 140px);
}

/* ====== 左侧边栏 ====== */
.note-sidebar {
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

.sidebar-body {
  flex: 1;
  overflow-y: auto;
  padding: 0.4rem;
}

/* 列表项 */
.list-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.55rem 0.65rem;
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.15s;
}

.list-item:hover {
  background: rgba(79, 70, 229, 0.06);
}

.list-item.active {
  background: rgba(79, 70, 229, 0.1);
  color: var(--primary, #4f46e5);
  font-weight: 500;
}

/* 目录项 */
.folder-item {
  margin-bottom: 0.25rem;
}

.folder-item > .list-item {
  font-weight: 500;
}

/* 文档列表（可展开） */
.doc-list {
  padding-left: 1.5rem;
  margin-top: 0.25rem;
}

.doc-item {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.4rem 0.5rem;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.82rem;
  transition: background 0.15s;
}

.doc-item:hover {
  background: rgba(79, 70, 229, 0.04);
}

.doc-item.active {
  background: rgba(79, 70, 229, 0.08);
  color: var(--primary, #4f46e5);
}

.doc-icon {
  font-size: 0.75rem;
  flex-shrink: 0;
}

.doc-title {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.doc-item .act-btn {
  opacity: 0;
}

.doc-item:hover .act-btn {
  opacity: 0.7;
}

.add-doc-btn {
  display: none;
  padding: 0.2rem 0.5rem;
  border: none;
  border-radius: 4px;
  background: rgba(79, 70, 229, 0.1);
  color: var(--primary, #4f46e5);
  font-size: 0.85rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s;
  flex-shrink: 0;
}

.list-item:hover .add-doc-btn {
  display: block;
}

.add-doc-btn:hover {
  background: var(--primary, #4f46e5);
  color: white;
}

.item-icon {
  font-size: 0.9rem;
  flex-shrink: 0;
}

.item-text {
  flex: 1;
  font-size: 0.85rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.item-edit-input {
  flex: 1;
  padding: 0.15rem 0.4rem;
  border: 1px solid var(--primary, #4f46e5);
  border-radius: 4px;
  font-size: 0.85rem;
  outline: none;
}

.item-actions {
  display: none;
  gap: 0.1rem;
  flex-shrink: 0;
}

.list-item:hover .item-actions {
  display: flex;
}

.act-btn {
  background: none;
  border: none;
  cursor: pointer;
  font-size: 0.78rem;
  padding: 0.1rem 0.2rem;
  border-radius: 4px;
  transition: background 0.15s;
  opacity: 0.7;
}

.act-btn:hover {
  opacity: 1;
  background: rgba(0,0,0,0.05);
}

.act-btn.danger:hover {
  background: rgba(239, 68, 68, 0.1);
}

/* ====== 右侧工作区 ====== */
.note-main {
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
  gap: 0.75rem;
  padding: 0.7rem 0.85rem;
  border-bottom: 1px solid var(--border, #e5e7eb);
  background: #f8fafc;
}

.workspace-title {
  flex: 1;
  font-size: 0.88rem;
  font-weight: 600;
  color: var(--text, #1e293b);
}

.workspace-body {
  flex: 1;
  overflow-y: auto;
  padding: 0.5rem;
}

/* 文档列表项 */
.doc-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.6rem 0.75rem;
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.15s;
}

.doc-item:hover {
  background: rgba(79, 70, 229, 0.04);
}

.doc-item-info {
  flex: 1;
  display: flex;
  align-items: baseline;
  gap: 0.75rem;
  min-width: 0;
}

.doc-item-title {
  font-size: 0.88rem;
  font-weight: 500;
  color: var(--text, #1e293b);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.doc-item-meta {
  font-size: 0.75rem;
  color: var(--text-secondary, #9ca3af);
  white-space: nowrap;
  flex-shrink: 0;
}

/* 编辑器 */
.doc-title-input {
  flex: 1;
  padding: 0.35rem 0.6rem;
  border: 1px solid var(--border, #e5e7eb);
  border-radius: 6px;
  font-size: 0.88rem;
  font-weight: 500;
  outline: none;
  transition: border-color 0.2s;
  background: #fff;
}

.doc-title-input:focus {
  border-color: var(--primary, #4f46e5);
}

.doc-editor {
  flex: 1;
  padding: 1rem;
  border: none;
  resize: none;
  font-size: 0.88rem;
  line-height: 1.7;
  font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  outline: none;
  min-height: 400px;
}

/* 空状态 */
.empty-hint {
  padding: 2rem 1rem;
  text-align: center;
  font-size: 0.85rem;
  color: var(--text-secondary, #9ca3af);
}

.empty-hint.small {
  padding: 0.75rem 0.5rem;
  font-size: 0.78rem;
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
  .note-layout {
    flex-direction: column;
  }
  .note-sidebar {
    width: 100%;
    max-height: 300px;
  }
}
</style>
