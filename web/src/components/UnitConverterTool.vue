<template>
  <div class="tool-panel">
    <h2>📐 单位换算</h2>

    <div class="card">
      <div class="form-row">
        <div class="form-group half">
          <label>换算类型</label>
          <select class="input-select" v-model="category" @change="onCategoryChange">
            <option v-for="(val, key) in categories" :key="key" :value="key">{{ key }}</option>
          </select>
        </div>
      </div>

      <div class="form-row">
        <div class="form-group half">
          <label>从</label>
          <select class="input-select" v-model="fromUnit">
            <option v-for="u in currentUnits" :key="u.name" :value="u.name">{{ u.name }}</option>
          </select>
        </div>
        <div class="form-group half">
          <label>到</label>
          <select class="input-select" v-model="toUnit">
            <option v-for="u in currentUnits" :key="u.name" :value="u.name">{{ u.name }}</option>
          </select>
        </div>
      </div>

      <div class="form-group">
        <label>数值</label>
        <input class="input-text" type="number" v-model="value" @input="convert" placeholder="输入要换算的数值" />
      </div>

      <div class="convert-result" v-if="output !== ''">
        <span class="conv-from">{{ formatNum(value) }} {{ fromUnit }}</span>
        <span class="conv-arrow">=</span>
        <span class="conv-to">{{ output }} {{ toUnit }}</span>
        <button class="copy-btn" @click="copy(output)">📋</button>
      </div>
    </div>

    <div class="card">
      <h3>常用换算速查（1 {{ baseUnit }} 基准）</h3>
      <table class="format-table">
        <thead>
          <tr><th>单位</th><th>等于（基准）</th></tr>
        </thead>
        <tbody>
          <tr v-for="u in currentUnits" :key="u.name">
            <td><code>1 {{ u.name }}</code></td>
            <td>{{ formatNum(u.factor) }} {{ baseUnit }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, inject } from 'vue'

const showToast = inject('showToast')

const categories = {
  '长度': { base: 'm', units: [
    { name: '米(m)', factor: 1 }, { name: '厘米(cm)', factor: 0.01 }, { name: '毫米(mm)', factor: 0.001 },
    { name: '千米(km)', factor: 1000 }, { name: '英寸(in)', factor: 0.0254 }, { name: '英尺(ft)', factor: 0.3048 },
    { name: '英里(mi)', factor: 1609.344 }, { name: '海里', factor: 1852 }
  ]},
  '重量': { base: 'kg', units: [
    { name: '千克(kg)', factor: 1 }, { name: '克(g)', factor: 0.001 }, { name: '毫克(mg)', factor: 1e-6 },
    { name: '吨(t)', factor: 1000 }, { name: '斤', factor: 0.5 }, { name: '两', factor: 0.05 },
    { name: '盎司(oz)', factor: 0.0283495 }, { name: '磅(lb)', factor: 0.453592 }
  ]},
  '面积': { base: 'm²', units: [
    { name: '平方米', factor: 1 }, { name: '平方厘米', factor: 1e-4 }, { name: '平方千米', factor: 1e6 },
    { name: '公顷', factor: 10000 }, { name: '亩', factor: 666.6667 }, { name: '平方英尺', factor: 0.092903 },
    { name: '英亩', factor: 4046.86 }
  ]},
  '体积': { base: 'L', units: [
    { name: '升(L)', factor: 1 }, { name: '毫升(mL)', factor: 0.001 }, { name: '立方米', factor: 1000 },
    { name: '加仑(美)', factor: 3.78541 }, { name: '立方厘米', factor: 0.001 }
  ]},
  '数据': { base: 'B', units: [
    { name: '字节(B)', factor: 1 }, { name: '千字节(KB)', factor: 1024 }, { name: '兆字节(MB)', factor: 1048576 },
    { name: '吉字节(GB)', factor: 1073741824 }, { name: '太字节(TB)', factor: 1099511627776 },
    { name: '比特(bit)', factor: 0.125 }
  ]},
  '时间': { base: 's', units: [
    { name: '秒(s)', factor: 1 }, { name: '毫秒(ms)', factor: 0.001 }, { name: '分钟(min)', factor: 60 },
    { name: '小时(h)', factor: 3600 }, { name: '天(d)', factor: 86400 }, { name: '周', factor: 604800 }
  ]},
  '速度': { base: 'm/s', units: [
    { name: '米/秒', factor: 1 }, { name: '千米/时', factor: 0.277778 }, { name: '英里/时', factor: 0.44704 },
    { name: '节', factor: 0.514444 }
  ]},
  '温度': { base: '℃', units: [
    { name: '摄氏度(℃)', factor: 1 }, { name: '华氏度(℉)', factor: 1 }, { name: '开尔文(K)', factor: 1 }
  ], temp: true }
}

const category = ref('长度')
const value = ref(1)
const fromUnit = ref('米(m)')
const toUnit = ref('英尺(ft)')

const currentCat = computed(() => categories[category.value])
const baseUnit = computed(() => currentCat.value.base)
const currentUnits = computed(() => currentCat.value.units)
const output = ref('')

function onCategoryChange() {
  fromUnit.value = currentUnits.value[0].name
  toUnit.value = currentUnits.value[1 % currentUnits.value.length].name
  convert()
}

function getFactor(name) {
  const u = currentUnits.value.find(x => x.name === name)
  return u ? u.factor : 1
}

function convert() {
  const v = parseFloat(value.value)
  if (isNaN(v)) { output.value = ''; return }
  const cat = currentCat.value
  if (cat.temp) {
    let c
    if (fromUnit.value.startsWith('华氏')) c = (v - 32) * 5 / 9
    else if (fromUnit.value.startsWith('开尔文')) c = v - 273.15
    else c = v
    let res
    if (toUnit.value.startsWith('华氏')) res = c * 9 / 5 + 32
    else if (toUnit.value.startsWith('开尔文')) res = c + 273.15
    else res = c
    output.value = formatNum(res)
  } else {
    const base = v * getFactor(fromUnit.value)
    output.value = formatNum(base / getFactor(toUnit.value))
  }
}

function formatNum(n) {
  if (!isFinite(n)) return '—'
  const r = Math.abs(n) >= 1e-4 && Math.abs(n) < 1e15 ? parseFloat(n.toPrecision(10)) : n.toExponential(6)
  return String(r)
}

function copy(text) {
  navigator.clipboard.writeText(String(text)).then(() => showToast('已复制: ' + text))
}

convert()
</script>

<style scoped>
.convert-result {
  margin-top: 0.5rem;
  padding: 0.85rem 1rem;
  background: #f0fdf4;
  border: 1px solid #bbf7d0;
  border-radius: var(--radius);
  display: flex;
  align-items: center;
  gap: 0.6rem;
  flex-wrap: wrap;
  font-size: 1.05rem;
}
.conv-from { color: var(--text-secondary); }
.conv-arrow { color: var(--primary); font-weight: 700; }
.conv-to { font-weight: 700; color: var(--success); font-family: "SF Mono", Monaco, monospace; }
.copy-btn {
  margin-left: auto;
  background: none; border: none; cursor: pointer; font-size: 1rem; opacity: 0.6;
}
.copy-btn:hover { opacity: 1; }
</style>
