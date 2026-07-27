<template>
  <div class="tool-panel">
    <h2>📊 图表生成器</h2>

    <div class="card">
      <div class="form-row">
        <div class="form-group half">
          <label>图表类型</label>
          <select class="input-text" v-model="type" @change="render">
            <option value="bar">柱状图 (Bar)</option>
            <option value="line">折线图 (Line)</option>
            <option value="pie">饼图 (Pie)</option>
            <option value="doughnut">环形图 (Doughnut)</option>
            <option value="radar">雷达图 (Radar)</option>
            <option value="polarArea">极区图 (Polar)</option>
          </select>
        </div>
        <div class="form-group half">
          <label>标题</label>
          <input class="input-text" v-model="title" @input="render" placeholder="图表标题" />
        </div>
      </div>

      <label>数据 (每行「标签,数值」)</label>
      <textarea class="input-textarea" v-model="raw" @input="render" rows="7" placeholder="一月,120&#10;二月,200&#10;三月,150&#10;四月,80&#10;五月,270"></textarea>
      <div v-if="parseError" class="err-hint">{{ parseError }}</div>
    </div>

    <div class="card">
      <h3>预览</h3>
      <div class="chart-wrap">
        <canvas ref="canvasEl"></canvas>
      </div>
      <div class="chart-actions">
        <button class="btn-primary" @click="download">下载 PNG</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, inject } from 'vue'
import Chart from 'chart.js/auto'

const showToast = inject('showToast')
const canvasEl = ref(null)
const type = ref('bar')
const title = ref('月度数据')
const raw = ref('一月,120\n二月,200\n三月,150\n四月,80\n五月,270')
const parseError = ref('')
let chart = null

const palette = ['#4f46e5','#ec4899','#10b981','#f59e0b','#06b6d4','#8b5cf6','#ef4444','#3b82f6','#14b8a6','#f97316']

function parse() {
  const labels = [], data = []
  const lines = raw.value.split('\n').map(l => l.trim()).filter(Boolean)
  for (const line of lines) {
    const idx = line.lastIndexOf(',')
    if (idx === -1) continue
    const label = line.slice(0, idx).trim()
    const val = parseFloat(line.slice(idx + 1).trim())
    if (label && !isNaN(val)) { labels.push(label); data.push(val) }
  }
  return { labels, data }
}

function render() {
  const { labels, data } = parse()
  parseError.value = data.length === 0 ? '未解析到有效数据，请按「标签,数值」格式每行一条' : ''
  if (chart) { chart.destroy(); chart = null }
  if (data.length === 0 || !canvasEl.value) return

  const multiColor = ['pie', 'doughnut', 'polarArea'].includes(type.value)
  const colors = labels.map((_, i) => palette[i % palette.length])

  chart = new Chart(canvasEl.value, {
    type: type.value,
    data: {
      labels,
      datasets: [{
        label: title.value || '数据',
        data,
        backgroundColor: multiColor ? colors : (type.value === 'line' ? 'rgba(79,70,229,0.15)' : '#4f46e5'),
        borderColor: type.value === 'line' || type.value === 'radar' ? '#4f46e5' : colors,
        borderWidth: type.value === 'line' || type.value === 'radar' ? 2 : 1,
        fill: type.value === 'line' ? true : undefined,
        tension: 0.3,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        title: { display: !!title.value, text: title.value, font: { size: 16 } },
        legend: { display: multiColor || type.value === 'radar' }
      }
    }
  })
}

function download() {
  if (!chart) { showToast('暂无图表'); return }
  const a = document.createElement('a')
  a.href = canvasEl.value.toDataURL('image/png')
  a.download = (title.value || 'chart') + '.png'
  a.click()
  showToast('已下载 PNG')
}

onMounted(render)
onUnmounted(() => { if (chart) chart.destroy() })
</script>

<style scoped>
.err-hint { color: #ef4444; font-size: 0.78rem; margin-top: 0.4rem; }
.chart-wrap { height: 360px; position: relative; }
.chart-actions { margin-top: 0.9rem; display: flex; gap: 0.6rem; }
</style>
