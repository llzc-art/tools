<template>
  <div class="tool-panel">
    <h2>⚖️ BMI 计算器</h2>

    <div class="card">
      <div class="form-row">
        <div class="form-group half">
          <label>身高 (cm)</label>
          <input class="input-text" type="number" v-model="height" @input="calc" placeholder="如 170" />
        </div>
        <div class="form-group half">
          <label>体重 (kg)</label>
          <input class="input-text" type="number" v-model="weight" @input="calc" placeholder="如 65" />
        </div>
      </div>

      <div class="bmi-result" v-if="bmi">
        <div class="bmi-value">{{ bmi }}</div>
        <div class="bmi-cat" :style="{ color: catColor }">{{ category }}</div>
        <div class="bmi-bar">
          <div class="bmi-marker" :style="{ left: markerPos + '%', background: catColor }"></div>
        </div>
        <div class="bmi-scale">
          <span>偏瘦</span><span>正常</span><span>超重</span><span>肥胖</span>
        </div>
        <div class="bmi-tip">健康体重范围（BMI 18.5–24）：<b>{{ healthyMin }} ~ {{ healthyMax }} kg</b></div>
      </div>
      <div class="error-box" v-else-if="tried">请输入有效的身高和体重</div>
    </div>

    <div class="card">
      <h3>BMI 分级标准（中国成人）</h3>
      <table class="format-table">
        <thead><tr><th>分级</th><th>BMI 范围</th></tr></thead>
        <tbody>
          <tr><td>偏瘦</td><td>&lt; 18.5</td></tr>
          <tr><td>正常</td><td>18.5 ~ 23.9</td></tr>
          <tr><td>超重</td><td>24.0 ~ 27.9</td></tr>
          <tr><td>肥胖</td><td>≥ 28.0</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, inject } from 'vue'

const showToast = inject('showToast')
const height = ref(170)
const weight = ref(65)
const bmi = ref('')
const category = ref('')
const catColor = ref('#10b981')
const markerPos = ref(50)
const healthyMin = ref('')
const healthyMax = ref('')
const tried = ref(false)

function calc() {
  tried.value = true
  const h = parseFloat(height.value) / 100
  const w = parseFloat(weight.value)
  if (!h || !w || h <= 0 || w <= 0) { bmi.value = ''; return }
  const v = w / (h * h)
  bmi.value = v.toFixed(1)
  if (v < 18.5) { category.value = '偏瘦'; catColor.value = '#3b82f6' }
  else if (v < 24) { category.value = '正常'; catColor.value = '#10b981' }
  else if (v < 28) { category.value = '超重'; catColor.value = '#f59e0b' }
  else { category.value = '肥胖'; catColor.value = '#ef4444' }
  // clamp marker to 15..35 -> 0..100%
  markerPos.value = Math.min(100, Math.max(0, ((v - 15) / 20) * 100))
  const hMin = 18.5 * h * h
  const hMax = 24 * h * h
  healthyMin.value = hMin.toFixed(1)
  healthyMax.value = hMax.toFixed(1)
}

calc()
</script>

<style scoped>
.bmi-result { margin-top: 0.5rem; text-align: center; }
.bmi-value { font-size: 2.6rem; font-weight: 800; color: var(--text); line-height: 1.1; }
.bmi-cat { font-size: 1.1rem; font-weight: 700; margin-bottom: 0.6rem; }
.bmi-bar {
  position: relative;
  height: 8px;
  border-radius: 4px;
  background: linear-gradient(90deg, #3b82f6 0%, #10b981 35%, #f59e0b 65%, #ef4444 100%);
  margin: 0.5rem 0 0.2rem;
}
.bmi-marker {
  position: absolute;
  top: -4px;
  width: 4px;
  height: 16px;
  border-radius: 2px;
  transform: translateX(-50%);
  transition: left 0.3s;
}
.bmi-scale {
  display: flex;
  justify-content: space-between;
  font-size: 0.7rem;
  color: var(--text-secondary);
}
.bmi-tip { margin-top: 0.75rem; font-size: 0.85rem; color: var(--text-secondary); }
.bmi-tip b { color: var(--text); }
</style>
