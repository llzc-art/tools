<template>
  <div class="tool-panel">
    <h2>📆 日期计算器</h2>

    <div class="card">
      <div class="tab-row">
        <button :class="['tab', { active: mode === 'diff' }]" @click="mode = 'diff'">日期差值</button>
        <button :class="['tab', { active: mode === 'add' }]" @click="mode = 'add'">日期推算</button>
      </div>

      <!-- 差值 -->
      <div v-if="mode === 'diff'">
        <div class="form-row">
          <div class="form-group half"><label>开始日期</label><input class="input-text" type="date" v-model="d1" @change="calcDiff" /></div>
          <div class="form-group half"><label>结束日期</label><input class="input-text" type="date" v-model="d2" @change="calcDiff" /></div>
        </div>
        <div class="date-result" v-if="diffText">
          <div class="date-big">{{ diffDays }} 天</div>
          <div class="date-sub">{{ diffText }}</div>
        </div>
      </div>

      <!-- 推算 -->
      <div v-if="mode === 'add'">
        <div class="form-group"><label>基准日期</label><input class="input-text" type="date" v-model="base" @change="calcAdd" /></div>
        <div class="form-row">
          <div class="form-group half"><label>加 / 减天数</label><input class="input-text" type="number" v-model="addDays" @input="calcAdd" /></div>
          <div class="form-group half"><label>月数</label><input class="input-text" type="number" v-model="addMonths" @input="calcAdd" /></div>
        </div>
        <div class="form-group"><label>年数</label><input class="input-text" type="number" v-model="addYears" @input="calcAdd" style="max-width:160px" /></div>
        <div class="date-result" v-if="resultDate">
          <div class="date-big">{{ resultDate }}</div>
          <div class="date-sub">星期{{ resultWeekday }}</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject } from 'vue'

const showToast = inject('showToast')
const mode = ref('diff')

const d1 = ref('2024-01-01')
const d2 = ref('2024-12-31')
const diffDays = ref(0)
const diffText = ref('')

const base = ref('2024-01-01')
const addDays = ref(100)
const addMonths = ref(0)
const addYears = ref(0)
const resultDate = ref('')
const resultWeekday = ref('')

const WEEK = ['日', '一', '二', '三', '四', '五', '六']

function parse(d) { const [y, m, day] = d.split('-').map(Number); return new Date(y, m - 1, day) }
function fmt(dt) { return `${dt.getFullYear()}-${String(dt.getMonth()+1).padStart(2,'0')}-${String(dt.getDate()).padStart(2,'0')}` }

function calcDiff() {
  const a = parse(d1.value), b = parse(d2.value)
  const ms = b - a
  diffDays.value = Math.round(ms / 86400000)
  const w = Math.floor(Math.abs(diffDays.value) / 7)
  const r = Math.abs(diffDays.value) % 7
  diffText.value = `${Math.abs(diffDays.value)} 天（约 ${w} 周${r ? ' ' + r + ' 天' : ''}）`
}
function calcAdd() {
  const dt = parse(base.value)
  dt.setFullYear(dt.getFullYear() + Number(addYears.value || 0))
  dt.setMonth(dt.getMonth() + Number(addMonths.value || 0))
  dt.setDate(dt.getDate() + Number(addDays.value || 0))
  resultDate.value = fmt(dt)
  resultWeekday.value = WEEK[dt.getDay()]
}

calcDiff()
calcAdd()
</script>

<style scoped>
.tab-row { display: flex; gap: 0.4rem; margin-bottom: 0.85rem; }
.tab { padding: 0.4rem 0.9rem; border: 1.5px solid var(--border); background: white; border-radius: var(--radius); cursor: pointer; font-size: 0.85rem; color: var(--text-secondary); }
.tab.active { background: var(--primary); color: #fff; border-color: var(--primary); }
.date-result { margin-top: 0.75rem; text-align: center; padding: 0.85rem; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: var(--radius); }
.date-big { font-size: 1.8rem; font-weight: 800; color: var(--success); }
.date-sub { font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.2rem; }
</style>
