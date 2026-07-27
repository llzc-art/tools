<template>
  <div class="tool-panel">
    <h2>🎨 调色板生成</h2>

    <div class="card">
      <div class="form-row">
        <div class="form-group half">
          <label>基准色</label>
          <div class="color-input-row">
            <input type="color" v-model="base" class="color-picker" />
            <input class="input-text" v-model="base" placeholder="#4f46e5" />
          </div>
        </div>
        <div class="form-group half">
          <label>配色方案</label>
          <select class="input-text" v-model="scheme">
            <option value="mono">单色渐变 (Monochromatic)</option>
            <option value="analogous">邻近色 (Analogous)</option>
            <option value="complementary">互补色 (Complementary)</option>
            <option value="triadic">三角色 (Triadic)</option>
            <option value="tetradic">四角色 (Tetradic)</option>
            <option value="shades">明暗阶梯 (Shades)</option>
          </select>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>配色结果 <span class="hint-inline">点击色块复制 HEX</span></h3>
      <div class="palette-grid">
        <div
          v-for="(c, i) in palette"
          :key="i"
          class="palette-item"
          @click="copy(c)"
        >
          <div class="palette-swatch" :style="{ background: c }"></div>
          <div class="palette-hex">{{ c.toUpperCase() }}</div>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>预览</h3>
      <div class="palette-bar">
        <div v-for="(c, i) in palette" :key="i" :style="{ background: c }" class="bar-seg"></div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, inject } from 'vue'

const showToast = inject('showToast')
const base = ref('#4f46e5')
const scheme = ref('mono')

function hexToHsl(hex) {
  let h = hex.replace('#', '')
  if (h.length === 3) h = h.split('').map(x => x + x).join('')
  let r = parseInt(h.slice(0, 2), 16) / 255
  let g = parseInt(h.slice(2, 4), 16) / 255
  let b = parseInt(h.slice(4, 6), 16) / 255
  const max = Math.max(r, g, b), min = Math.min(r, g, b)
  let hh = 0, s = 0, l = (max + min) / 2
  if (max !== min) {
    const d = max - min
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min)
    if (max === r) hh = (g - b) / d + (g < b ? 6 : 0)
    else if (max === g) hh = (b - r) / d + 2
    else hh = (r - g) / d + 4
    hh *= 60
  }
  return { h: hh, s: s * 100, l: l * 100 }
}

function hslToHex(h, s, l) {
  h = ((h % 360) + 360) % 360
  s = Math.max(0, Math.min(100, s)) / 100
  l = Math.max(0, Math.min(100, l)) / 100
  const c = (1 - Math.abs(2 * l - 1)) * s
  const x = c * (1 - Math.abs(((h / 60) % 2) - 1))
  const m = l - c / 2
  let r = 0, g = 0, b = 0
  if (h < 60) { r = c; g = x }
  else if (h < 120) { r = x; g = c }
  else if (h < 180) { g = c; b = x }
  else if (h < 240) { g = x; b = c }
  else if (h < 300) { r = x; b = c }
  else { r = c; b = x }
  const toHex = v => Math.round((v + m) * 255).toString(16).padStart(2, '0')
  return '#' + toHex(r) + toHex(g) + toHex(b)
}

const palette = computed(() => {
  const hex = /^#?[0-9a-fA-F]{6}$/.test(base.value.replace('#', '')) ? base.value : '#4f46e5'
  const { h, s, l } = hexToHsl(hex)
  const out = []
  switch (scheme.value) {
    case 'mono':
      for (let i = 0; i < 6; i++) out.push(hslToHex(h, s, 90 - i * 14))
      break
    case 'analogous':
      for (let i = -2; i <= 2; i++) out.push(hslToHex(h + i * 30, s, l))
      break
    case 'complementary':
      out.push(hslToHex(h, s, l), hslToHex(h, s, l + 15), hslToHex(h, s, l - 15),
        hslToHex(h + 180, s, l), hslToHex(h + 180, s, l + 15), hslToHex(h + 180, s, l - 15))
      break
    case 'triadic':
      [0, 120, 240].forEach(d => { out.push(hslToHex(h + d, s, l), hslToHex(h + d, s, Math.max(20, l - 20))) })
      break
    case 'tetradic':
      [0, 90, 180, 270].forEach(d => out.push(hslToHex(h + d, s, l)))
      break
    case 'shades':
      for (let i = 0; i < 6; i++) out.push(hslToHex(h, s, 15 + i * 15))
      break
  }
  return out
})

function copy(text) {
  navigator.clipboard.writeText(String(text).toUpperCase()).then(() => showToast('已复制: ' + text.toUpperCase()))
}
</script>

<style scoped>
.color-input-row { display: flex; gap: 0.5rem; align-items: center; }
.color-picker {
  width: 48px; height: 40px; padding: 0; border: 1px solid var(--border);
  border-radius: var(--radius); background: none; cursor: pointer; flex-shrink: 0;
}
.hint-inline { font-size: 0.72rem; font-weight: 400; color: var(--text-secondary); margin-left: 0.5rem; }
.palette-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 0.6rem; }
.palette-item { cursor: pointer; border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; transition: transform 0.15s; }
.palette-item:hover { transform: translateY(-3px); }
.palette-swatch { height: 70px; }
.palette-hex { text-align: center; padding: 0.4rem; font-family: "SF Mono", Monaco, monospace; font-size: 0.78rem; font-weight: 600; color: var(--text); }
.palette-bar { display: flex; height: 60px; border-radius: var(--radius); overflow: hidden; border: 1px solid var(--border); }
.bar-seg { flex: 1; }
</style>
