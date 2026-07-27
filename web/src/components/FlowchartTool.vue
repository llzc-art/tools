<template>
  <div class="tool-panel">
    <h2>🔀 流程图生成器</h2>

    <div class="card">
      <div class="form-row">
        <div class="form-group half">
          <label>示例模板</label>
          <select class="input-text" v-model="tpl" @change="loadTpl">
            <option value="flow">流程图 (Flowchart)</option>
            <option value="seq">时序图 (Sequence)</option>
            <option value="gantt">甘特图 (Gantt)</option>
            <option value="pie">饼图 (Pie)</option>
            <option value="mind">思维导图 (Mindmap)</option>
          </select>
        </div>
      </div>
      <label>Mermaid 代码</label>
      <textarea class="input-textarea mono" v-model="code" rows="10" spellcheck="false"></textarea>
      <div v-if="error" class="err-hint">语法错误：{{ error }}</div>
    </div>

    <div class="card">
      <h3>预览 <span class="hint-inline">支持标准 Mermaid 语法</span></h3>
      <div class="diagram-wrap" ref="wrap" v-html="svg"></div>
      <div class="chart-actions" v-if="svg && !error">
        <button class="btn-primary" @click="downloadSvg">下载 SVG</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, watch, inject, nextTick } from 'vue'
import mermaid from 'mermaid'

const showToast = inject('showToast')

mermaid.initialize({ startOnLoad: false, securityLevel: 'loose', theme: 'default' })

const templates = {
  flow: `flowchart TD
    A[开始] --> B{条件判断}
    B -->|是| C[执行操作]
    B -->|否| D[跳过]
    C --> E[结束]
    D --> E`,
  seq: `sequenceDiagram
    用户->>前端: 发起请求
    前端->>后端: 转发请求
    后端->>数据库: 查询数据
    数据库-->>后端: 返回结果
    后端-->>前端: 响应数据
    前端-->>用户: 展示结果`,
  gantt: `gantt
    title 项目计划
    dateFormat YYYY-MM-DD
    section 设计
    需求分析 :a1, 2026-01-01, 7d
    原型设计 :a2, after a1, 5d
    section 开发
    编码实现 :b1, after a2, 14d
    测试上线 :b2, after b1, 7d`,
  pie: `pie title 市场份额
    "产品A" : 45
    "产品B" : 30
    "产品C" : 25`,
  mind: `mindmap
  root((核心主题))
    分支一
      子项1
      子项2
    分支二
      子项3
    分支三`,
}

const tpl = ref('flow')
const code = ref(templates.flow)
const svg = ref('')
const error = ref('')

function loadTpl() { code.value = templates[tpl.value] }

let seq = 0
async function render() {
  const cur = ++seq
  if (!code.value.trim()) { svg.value = ''; error.value = ''; return }
  try {
    const { svg: out } = await mermaid.render('mmd-' + cur, code.value)
    if (cur === seq) { svg.value = out; error.value = '' }
  } catch (e) {
    if (cur === seq) error.value = (e.message || String(e)).split('\n')[0]
  }
}

let timer = null
watch(code, () => {
  clearTimeout(timer)
  timer = setTimeout(render, 400)
})

function downloadSvg() {
  if (!svg.value) return
  const blob = new Blob([svg.value], { type: 'image/svg+xml' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = 'diagram.svg'
  a.click()
  URL.revokeObjectURL(a.href)
  showToast('已下载 SVG')
}

onMounted(() => nextTick(render))
</script>

<style scoped>
.input-textarea.mono { font-family: "SF Mono", Monaco, monospace; font-size: 0.85rem; }
.err-hint { color: #ef4444; font-size: 0.8rem; margin-top: 0.4rem; }
.hint-inline { font-size: 0.72rem; font-weight: 400; color: var(--text-secondary); margin-left: 0.5rem; }
.diagram-wrap {
  min-height: 200px; display: flex; align-items: center; justify-content: center;
  background: #f8fafc; border: 1px solid var(--border); border-radius: var(--radius); padding: 1rem; overflow: auto;
}
.diagram-wrap :deep(svg) { max-width: 100%; height: auto; }
.chart-actions { margin-top: 0.9rem; }
</style>
