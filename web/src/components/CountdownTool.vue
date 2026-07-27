<template>
  <div class="tool-panel">
    <h2>⏳ 倒计时</h2>

    <div class="card">
      <div class="form-group">
        <label>目标时间</label>
        <input class="input-text" type="datetime-local" v-model="target" @change="restart" />
      </div>
      <div class="preset-row">
        <button class="btn btn-outline btn-sm" v-for="p in presets" :key="p.name" @click="setPreset(p)">{{ p.name }}</button>
      </div>

      <div class="countdown" v-if="!expired">
        <div class="cd-item"><div class="cd-num">{{ d }}</div><div class="cd-label">天</div></div>
        <div class="cd-sep">:</div>
        <div class="cd-item"><div class="cd-num">{{ hh }}</div><div class="cd-label">时</div></div>
        <div class="cd-sep">:</div>
        <div class="cd-item"><div class="cd-num">{{ mm }}</div><div class="cd-label">分</div></div>
        <div class="cd-sep">:</div>
        <div class="cd-item"><div class="cd-num">{{ ss }}</div><div class="cd-label">秒</div></div>
      </div>
      <div class="expired" v-else>🎉 目标时间已到达！</div>
      <div class="cd-target" v-if="target">目标：{{ targetText }}</div>
    </div>
  </div>
</template>

<script setup>
import { ref, onUnmounted, inject } from 'vue'

const showToast = inject('showToast')
const target = ref('')
const d = ref(0), hh = ref(0), mm = ref(0), ss = ref(0)
const expired = ref(false)
const targetText = ref('')
let timer = null

const presets = [
  { name: '元旦', get: () => nextYearDate(1, 1) },
  { name: '劳动节', get: () => nextYearDate(5, 1) },
  { name: '国庆', get: () => nextYearDate(10, 1) },
  { name: '春节', get: () => nextYearDate(1, 29) }
]

function nextYearDate(month, day) {
  const now = new Date()
  const y = now.getFullYear() + (now.getMonth() + 1 > month || (now.getMonth() + 1 === month && now.getDate() >= day) ? 1 : 0)
  const dt = new Date(y, month - 1, day, 0, 0, 0)
  return toLocal(dt)
}
function toLocal(dt) {
  const pad = n => String(n).padStart(2, '0')
  return `${dt.getFullYear()}-${pad(dt.getMonth()+1)}-${pad(dt.getDate())}T${pad(dt.getHours())}:${pad(dt.getMinutes())}`
}

function setPreset(p) {
  target.value = p.get()
  restart()
}
function restart() {
  if (timer) clearInterval(timer)
  expired.value = false
  tick()
  timer = setInterval(tick, 1000)
}
function tick() {
  if (!target.value) return
  const t = new Date(target.value).getTime()
  const now = Date.now()
  let diff = Math.floor((t - now) / 1000)
  if (diff <= 0) {
    expired.value = true
    d.value = hh.value = mm.value = ss.value = 0
    if (timer) clearInterval(timer)
    return
  }
  d.value = Math.floor(diff / 86400)
  hh.value = Math.floor((diff % 86400) / 3600)
  mm.value = Math.floor((diff % 3600) / 60)
  ss.value = diff % 60
  targetText.value = new Date(t).toLocaleString('zh-CN')
}

onUnmounted(() => { if (timer) clearInterval(timer) })

// 默认：下一个元旦
target.value = nextYearDate(1, 1)
restart()
</script>

<style scoped>
.preset-row { display: flex; gap: 0.4rem; flex-wrap: wrap; margin-top: 0.5rem; }
.countdown { display: flex; align-items: center; justify-content: center; gap: 0.4rem; margin: 1rem 0; }
.cd-item { background: #0f172a; color: #fff; border-radius: var(--radius); padding: 0.6rem 0.8rem; min-width: 64px; text-align: center; }
.cd-num { font-size: 1.8rem; font-weight: 800; font-variant-numeric: tabular-nums; }
.cd-label { font-size: 0.72rem; opacity: 0.7; }
.cd-sep { font-size: 1.6rem; font-weight: 800; color: var(--text-secondary); }
.expired { text-align: center; font-size: 1.4rem; font-weight: 800; color: var(--success); margin: 1rem 0; }
.cd-target { text-align: center; font-size: 0.82rem; color: var(--text-secondary); }
</style>
