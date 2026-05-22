<template>
  <div class="tool-panel">
    <h2>📝 Markdown 预览</h2>

    <div class="md-layout">
      <div class="md-editor">
        <div class="md-header">
          <span>编辑区</span>
          <button class="btn btn-sm" @click="clearEditor">清空</button>
        </div>
        <textarea
          v-model="markdown"
          class="md-input"
          placeholder="在此输入 Markdown 内容..."
          @input="updatePreview"
        ></textarea>
      </div>

      <div class="md-preview">
        <div class="md-header">
          <span>预览区</span>
          <button class="btn btn-sm btn-outline" @click="copyHtml" :disabled="!html">复制 HTML</button>
        </div>
        <div class="md-content" v-html="html"></div>
      </div>
    </div>

    <div class="md-hint">
      <span>支持 GitHub Flavored Markdown (GFM)</span>
    </div>
  </div>
</template>

<script setup>
import { ref, inject, onMounted } from 'vue'
import { marked } from 'marked'
import hljs from 'highlight.js'

const showToast = inject('showToast')

const markdown = ref('')
const html = ref('')

// 配置 marked
marked.setOptions({
  highlight: function(code, lang) {
    if (lang && hljs.getLanguage(lang)) {
      return hljs.highlight(code, { language: lang }).value
    }
    return hljs.highlightAuto(code).value
  },
  breaks: true,
  gfm: true,
})

const sampleMd = `# 欢迎使用 Markdown 预览

这是一个示例文档，展示支持的特性。

## 代码块

\`\`\`javascript
function hello() {
  console.log("Hello, World!")
}
\`\`\`

## 表格

| 姓名 | 年龄 | 城市 |
|------|------|------|
| 张三 | 25 | 北京 |
| 李四 | 30 | 上海 |

## 列表

- 第一个列表项
- 第二个列表项
  - 嵌套列表
- 第三个列表项

## 引用

> 这是一段引用文字
> 可以有多行

## 链接和图片

[访问 GitHub](https://github.com)

## 强调

**粗体文本** 和 *斜体文本*

~~删除线文本~~

## 任务列表

- [x] 已完成任务
- [ ] 待完成任务
- [ ] 另一个待办

---

> 开始编辑左侧的 Markdown 内容，右侧将实时预览！
`

onMounted(() => {
  markdown.value = sampleMd
  updatePreview()
})

function updatePreview() {
  try {
    html.value = marked.parse(markdown.value || '')
  } catch (e) {
    html.value = '<p style="color: red;">解析错误</p>'
  }
}

function clearEditor() {
  markdown.value = ''
  html.value = ''
}

function copyHtml() {
  if (!html.value) return
  navigator.clipboard.writeText(html.value).then(() => {
    showToast('HTML 已复制到剪贴板')
  })
}
</script>

<style scoped>
.md-layout {
  display: flex;
  gap: 1rem;
  height: calc(100vh - 200px);
  min-height: 500px;
}

.md-editor,
.md-preview {
  flex: 1;
  display: flex;
  flex-direction: column;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: #fff;
  overflow: hidden;
}

.md-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.5rem 0.75rem;
  background: #f8fafc;
  border-bottom: 1px solid var(--border);
  font-size: 0.78rem;
  font-weight: 600;
  color: var(--text-secondary);
}

.md-input {
  flex: 1;
  padding: 1rem;
  border: none;
  resize: none;
  font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  font-size: 0.85rem;
  line-height: 1.6;
  outline: none;
}

.md-content {
  flex: 1;
  padding: 1rem;
  overflow-y: auto;
  font-size: 0.9rem;
  line-height: 1.7;
}

.md-hint {
  text-align: center;
  font-size: 0.75rem;
  color: var(--text-secondary);
  margin-top: 0.75rem;
}

/* Markdown 渲染样式 */
:deep(.md-content h1) {
  font-size: 1.5rem;
  font-weight: 700;
  margin: 1rem 0 0.75rem;
  padding-bottom: 0.5rem;
  border-bottom: 1px solid var(--border);
}

:deep(.md-content h2) {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 1rem 0 0.5rem;
}

:deep(.md-content h3) {
  font-size: 1.1rem;
  font-weight: 600;
  margin: 0.75rem 0 0.5rem;
}

:deep(.md-content p) {
  margin: 0.5rem 0;
}

:deep(.md-content code) {
  background: #f1f5f9;
  padding: 0.15rem 0.35rem;
  border-radius: 4px;
  font-family: "SF Mono", Monaco, monospace;
  font-size: 0.85em;
}

:deep(.md-content pre) {
  background: #1e293b;
  color: #e2e8f0;
  padding: 1rem;
  border-radius: 8px;
  overflow-x: auto;
  margin: 0.75rem 0;
}

:deep(.md-content pre code) {
  background: none;
  padding: 0;
  color: inherit;
  font-size: 0.85rem;
}

:deep(.md-content blockquote) {
  border-left: 4px solid var(--primary);
  padding-left: 1rem;
  margin: 0.75rem 0;
  color: var(--text-secondary);
}

:deep(.md-content ul),
:deep(.md-content ol) {
  margin: 0.5rem 0;
  padding-left: 1.5rem;
}

:deep(.md-content li) {
  margin: 0.25rem 0;
}

:deep(.md-content table) {
  width: 100%;
  border-collapse: collapse;
  margin: 0.75rem 0;
}

:deep(.md-content th),
:deep(.md-content td) {
  border: 1px solid var(--border);
  padding: 0.5rem 0.75rem;
  text-align: left;
}

:deep(.md-content th) {
  background: #f8fafc;
  font-weight: 600;
}

:deep(.md-content a) {
  color: var(--primary);
  text-decoration: none;
}

:deep(.md-content a:hover) {
  text-decoration: underline;
}

:deep(.md-content hr) {
  border: none;
  border-top: 1px solid var(--border);
  margin: 1rem 0;
}

:deep(.md-content del) {
  color: var(--text-secondary);
}

/* 响应式 */
@media (max-width: 768px) {
  .md-layout {
    flex-direction: column;
    height: auto;
  }

  .md-editor,
  .md-preview {
    min-height: 300px;
  }
}
</style>