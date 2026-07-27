<template>
  <div class="tool-panel">
    <h2>📆 农历万年历</h2>

    <div class="card">
      <div class="form-row">
        <div class="form-group half">
          <label>选择公历日期</label>
          <input type="date" class="input-text" v-model="dateStr" />
        </div>
        <div class="form-group half btn-col">
          <button class="btn-secondary" @click="today">回到今天</button>
        </div>
      </div>
    </div>

    <div v-if="info" class="card">
      <h3>{{ info.solarFull }}</h3>
      <div class="info-grid">
        <div class="info-item"><span class="k">农历</span><span class="v">{{ info.lunarFull }}</span></div>
        <div class="info-item"><span class="k">干支纪年</span><span class="v">{{ info.ganzhi }}年 【{{ info.shengxiao }}】</span></div>
        <div class="info-item"><span class="k">星期</span><span class="v">{{ info.week }}</span></div>
        <div class="info-item"><span class="k">星座</span><span class="v">{{ info.xingzuo }}座</span></div>
        <div class="info-item"><span class="k">生肖</span><span class="v">{{ info.shengxiao }}</span></div>
        <div class="info-item"><span class="k">今日节气</span><span class="v">{{ info.jieqi || '—' }}</span></div>
        <div class="info-item"><span class="k">宜</span><span class="v good">{{ info.yi }}</span></div>
        <div class="info-item"><span class="k">忌</span><span class="v bad">{{ info.ji }}</span></div>
        <div class="info-item" v-if="info.festivals"><span class="k">节日</span><span class="v">{{ info.festivals }}</span></div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { Solar } from 'lunar-javascript'

function fmtToday() {
  const d = new Date()
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}
const dateStr = ref(fmtToday())
function today() { dateStr.value = fmtToday() }

const info = computed(() => {
  if (!dateStr.value) return null
  const [y, m, d] = dateStr.value.split('-').map(Number)
  if (!y || !m || !d) return null
  try {
    const solar = Solar.fromYmd(y, m, d)
    const lunar = solar.getLunar()
    const fes = [...solar.getFestivals(), ...lunar.getFestivals()]
    return {
      solarFull: `${y}年${m}月${d}日`,
      lunarFull: `${lunar.getYearInChinese()}年 ${lunar.getMonthInChinese()}月${lunar.getDayInChinese()}`,
      ganzhi: lunar.getYearInGanZhi(),
      shengxiao: lunar.getYearShengXiao(),
      week: '星期' + solar.getWeekInChinese(),
      xingzuo: solar.getXingZuo(),
      jieqi: lunar.getJieQi(),
      yi: lunar.getDayYi().slice(0, 6).join('、') || '诸事不宜',
      ji: lunar.getDayJi().slice(0, 6).join('、') || '无',
      festivals: fes.join('、'),
    }
  } catch (e) {
    return null
  }
})
</script>

<style scoped>
.btn-col { display: flex; align-items: flex-end; }
.info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 0.6rem; }
.info-item {
  display: flex; gap: 0.6rem; background: #f8fafc; border: 1px solid var(--border);
  border-radius: var(--radius); padding: 0.6rem 0.8rem; align-items: baseline;
}
.info-item .k { font-size: 0.75rem; color: var(--text-secondary); font-weight: 600; flex-shrink: 0; width: 4.5rem; }
.info-item .v { font-size: 0.9rem; color: var(--text); font-weight: 500; }
.info-item .v.good { color: #059669; }
.info-item .v.bad { color: #dc2626; }
</style>
