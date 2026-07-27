<template>
  <div class="tool-panel">
    <h2>🌈 CSS 渐变生成器</h2>

    <div class="card">
      <div class="form-row">
        <div class="form-group half">
          <label>渐变类型</label>
          <select class="input-text" v-model="type">
            <option value="linear">线性渐变 (linear)</option>
            <option value="radial">径向渐变 (radial)</option>
            <option value="conic">锥形渐变 (conic)</option>
          </select>
        </div>
        <div class="form-group half" v-if="type === 'linear'">
          <label>角度: {{ angle }}°</label>
          <input type="range" min="0" max="360" v-model.number="angle" class="range" />
        </div>
      </div>

      <label>色标 (Color Stops)</label>
      <div class="stops">
        <div v-for="(stop, i) in stops" :key="i" class="stop-row">
          <input type="color" v-model="stop.color" class="color-picker" />
          <input class="input-text mini" v-model="stop.color" />
          <input type="range" min="0" max="100" v-model.number="stop.pos" class="range flex1" />
          <span class="pos-label">{{ stop.pos }}%</span>
          <button class="btn-mini danger" @click="removeStop(i)" :disabled="stops.length <= 2">✕</button>
        </div>
      </div>
      <button class="btn-secondary sm" @click="addStop">+ 添加色标</button>
    </div>

    <div class="card">
      <h3>预览</h3>
      <div class="gradient-preview" :style="{ background: gradientCss }"></div>
    </div>

    <div class="card">
      <h3>CSS 代码 <span class="hint-inline">点击复制</span></h3>
      <pre class="code-block" @click="copy(fullCss)">{{ fullCss }}</pre>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, inject } from 'vue'

const showToast = inject('showToast')
const type = ref('linear')
const angle = ref(135)
const stops = ref([
  { color: '#4f46e5', pos: 0 },
  { color: '#ec4899', pos: 100 },
])

function addStop() {
  stops.value.push({ color: '#10b981', pos: 50 })
}
function removeStop(i) {
  if (stops.value.length > 2) stops.value.splice(i, 1)
}

const stopStr = computed(() =>
  [...stops.value].sort((a, b) => a.pos - b.pos).map(s => `${s.color} ${s.pos}%`).join(', ')
)

const gradientCss = computed(() => {
  if (type.value === 'linear') return `linear-gradient(${angle.value}deg, ${stopStr.value})`
  if (type.value === 'radial') return `radial-gradient(circle, ${stopStr.value})`
  return `conic-gradient(from ${angle.value}deg, ${stopStr.value})`
})

const fullCss = computed(() => `background: ${gradientCss.value};`)

function copy(text) {
  navigator.clipboard.writeText(text).then(() => showToast('已复制 CSS'))
}
</script>

<style scoped>
.color-picker {
  width: 44px; height: 36px; padding: 0; border: 1px solid var(--border);
  border-radius: var(--radius); background: none; cursor: pointer; flex-shrink: 0;
}
.range { width: 100%; }
.range.flex1 { flex: 1; }
.stops { display: flex; flex-direction: column; gap: 0.55rem; margin: 0.5rem 0 0.75rem; }
.stop-row { display: flex; align-items: center; gap: 0.5rem; }
.input-text.mini { width: 90px; flex-shrink: 0; font-family: "SF Mono", Monaco, monospace; font-size: 0.8rem; }
.pos-label { width: 42px; font-size: 0.78rem; color: var(--text-secondary); text-align: right; }
.btn-mini { border: 1px solid var(--border); background: #f8fafc; border-radius: 6px; width: 28px; height: 28px; cursor: pointer; flex-shrink: 0; }
.btn-mini.danger { color: #ef4444; }
.btn-mini:disabled { opacity: 0.4; cursor: not-allowed; }
.btn-secondary.sm { padding: 0.35rem 0.9rem; font-size: 0.8rem; }
.gradient-preview { height: 180px; border-radius: var(--radius); border: 1px solid var(--border); }
.hint-inline { font-size: 0.72rem; font-weight: 400; color: var(--text-secondary); margin-left: 0.5rem; }
.code-block {
  background: #1e293b; color: #e2e8f0; padding: 0.9rem 1rem; border-radius: var(--radius);
  font-family: "SF Mono", Monaco, monospace; font-size: 0.85rem; cursor: pointer;
  white-space: pre-wrap; word-break: break-all; margin: 0;
}
.code-block:hover { opacity: 0.9; }
</style>
