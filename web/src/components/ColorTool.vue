<template>
  <div class="tool-panel">
    <h2>🎨 颜色转换</h2>

    <div class="card">
      <div class="form-row">
        <div class="form-group half">
          <label>取色 / 输入 HEX</label>
          <div class="color-input-row">
            <input type="color" v-model="hex" @input="fromHex" class="color-picker" />
            <input class="input-text" v-model="hex" @input="fromHex" placeholder="#4f46e5" />
          </div>
        </div>
      </div>

      <div class="color-preview" :style="{ background: normalizedHex }"></div>

      <div class="color-grid">
        <div class="color-item">
          <div class="color-label">HEX</div>
          <div class="color-value" @click="copy(hex)">{{ hex.toUpperCase() }}</div>
        </div>
        <div class="color-item">
          <div class="color-label">RGB</div>
          <div class="color-value" @click="copy(rgbStr)">{{ rgbStr }}</div>
        </div>
        <div class="color-item">
          <div class="color-label">HSL</div>
          <div class="color-value" @click="copy(hslStr)">{{ hslStr }}</div>
        </div>
        <div class="color-item">
          <div class="color-label">CMYK</div>
          <div class="color-value" @click="copy(cmykStr)">{{ cmykStr }}</div>
        </div>
      </div>
      <div class="color-hint">点击任意数值即可复制</div>
    </div>

    <div class="card">
      <h3>常用配色</h3>
      <div class="swatches">
        <button
          v-for="c in swatches"
          :key="c"
          class="swatch"
          :style="{ background: c }"
          :title="c"
          @click="setColor(c)"
        ></button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, inject } from 'vue'

const showToast = inject('showToast')
const hex = ref('#4f46e5')

const normalizedHex = computed(() => /^#[0-9a-fA-F]{6}$/.test(hex.value) ? hex.value : '#000000')

const rgb = computed(() => {
  const h = normalizedHex.value.replace('#', '')
  return {
    r: parseInt(h.slice(0, 2), 16),
    g: parseInt(h.slice(2, 4), 16),
    b: parseInt(h.slice(4, 6), 16)
  }
})
const rgbStr = computed(() => `rgb(${rgb.value.r}, ${rgb.value.g}, ${rgb.value.b})`)

const hsl = computed(() => {
  let { r, g, b } = rgb.value
  r /= 255; g /= 255; b /= 255
  const max = Math.max(r, g, b), min = Math.min(r, g, b)
  let h = 0, s = 0, l = (max + min) / 2
  if (max !== min) {
    const d = max - min
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min)
    if (max === r) h = (g - b) / d + (g < b ? 6 : 0)
    else if (max === g) h = (b - r) / d + 2
    else h = (r - g) / d + 4
    h *= 60
  }
  return { h: Math.round(h), s: Math.round(s * 100), l: Math.round(l * 100) }
})
const hslStr = computed(() => `hsl(${hsl.value.h}, ${hsl.value.s}%, ${hsl.value.l}%)`)

const cmyk = computed(() => {
  let { r, g, b } = rgb.value
  r /= 255; g /= 255; b /= 255
  const k = 1 - Math.max(r, g, b)
  if (k === 1) return { c: 0, m: 0, y: 0, k: 100 }
  const c = (1 - r - k) / (1 - k)
  const m = (1 - g - k) / (1 - k)
  const y = (1 - b - k) / (1 - k)
  return { c: Math.round(c * 100), m: Math.round(m * 100), y: Math.round(y * 100), k: Math.round(k * 100) }
})
const cmykStr = computed(() => `cmyk(${cmyk.value.c}%, ${cmyk.value.m}%, ${cmyk.value.y}%, ${cmyk.value.k}%)`)

function fromHex() {
  let v = hex.value.trim()
  if (!v.startsWith('#')) v = '#' + v
  if (/^#[0-9a-fA-F]{6}$/.test(v)) hex.value = v
}
function setColor(c) { hex.value = c }
function copy(text) {
  navigator.clipboard.writeText(String(text)).then(() => showToast('已复制: ' + text))
}

const swatches = ['#ef4444','#f59e0b','#fbbf24','#10b981','#06b6d4','#3b82f6','#6366f1','#8b5cf6','#ec4899','#64748b','#1e293b','#ffffff']
</script>

<style scoped>
.color-input-row { display: flex; gap: 0.5rem; align-items: center; }
.color-picker {
  width: 48px; height: 40px; padding: 0; border: 1px solid var(--border);
  border-radius: var(--radius); background: none; cursor: pointer; flex-shrink: 0;
}
.color-preview {
  height: 60px; border-radius: var(--radius); margin: 0.75rem 0;
  border: 1px solid var(--border);
}
.color-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 0.6rem; }
.color-item {
  background: #f8fafc; border: 1px solid var(--border); border-radius: var(--radius); padding: 0.6rem;
}
.color-label { font-size: 0.72rem; font-weight: 600; color: var(--text-secondary); margin-bottom: 0.25rem; }
.color-value {
  font-family: "SF Mono", Monaco, monospace; font-size: 0.85rem; font-weight: 600;
  cursor: pointer; word-break: break-all; color: var(--text);
}
.color-value:hover { color: var(--primary); }
.color-hint { margin-top: 0.6rem; font-size: 0.72rem; color: var(--text-secondary); }
.swatches { display: flex; flex-wrap: wrap; gap: 0.4rem; }
.swatch {
  width: 32px; height: 32px; border-radius: 6px; border: 1px solid var(--border); cursor: pointer;
  transition: transform 0.15s;
}
.swatch:hover { transform: scale(1.12); }
</style>
