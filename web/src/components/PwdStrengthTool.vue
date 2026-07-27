<template>
  <div class="tool-panel">
    <h2>🔐 密码强度检测</h2>

    <div class="card">
      <div class="form-group">
        <label>输入密码</label>
        <div class="pwd-row">
          <input :type="show ? 'text' : 'password'" class="input-text" v-model="pwd" @input="check" placeholder="输入要检测的密码" />
          <button class="btn btn-outline btn-sm" @click="show = !show">{{ show ? '隐藏' : '显示' }}</button>
        </div>
      </div>

      <div class="strength-bar" v-if="pwd">
        <div class="strength-fill" :style="{ width: score + '%', background: color }"></div>
      </div>
      <div class="strength-label" v-if="pwd" :style="{ color }">{{ label }}（强度 {{ score }} / 100）</div>

      <div class="metric-grid" v-if="pwd">
        <div class="metric"><span>长度</span><b>{{ pwd.length }}</b></div>
        <div class="metric"><span>熵值</span><b>{{ entropy }} bit</b></div>
        <div class="metric"><span>字符种类</span><b>{{ poolSize }}</b></div>
        <div class="metric"><span>预估破解</span><b>{{ crackTime }}</b></div>
      </div>

      <div class="checklist" v-if="pwd">
        <div :class="['check', c.met ? 'ok' : 'no']" v-for="c in checks" :key="c.label">
          {{ c.met ? '✓' : '✗' }} {{ c.label }}
        </div>
      </div>

      <div class="suggestions" v-if="pwd && suggestions.length">
        <div class="sug-title">改进建议</div>
        <ul><li v-for="s in suggestions" :key="s">{{ s }}</li></ul>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject } from 'vue'

const showToast = inject('showToast')
const pwd = ref('')
const show = ref(false)
const score = ref(0)
const label = ref('')
const color = ref('#ef4444')
const entropy = ref(0)
const poolSize = ref(0)
const crackTime = ref('')
const checks = ref([])
const suggestions = ref([])

function check() {
  const p = pwd.value
  if (!p) { score.value = 0; return }
  const hasLower = /[a-z]/.test(p)
  const hasUpper = /[A-Z]/.test(p)
  const hasDigit = /[0-9]/.test(p)
  const hasSymbol = /[^A-Za-z0-9]/.test(p)
  let pool = 0
  if (hasLower) pool += 26
  if (hasUpper) pool += 26
  if (hasDigit) pool += 10
  if (hasSymbol) pool += 33
  poolSize.value = pool
  const ent = p.length * (pool > 0 ? Math.log2(pool) : 1)
  entropy.value = Math.round(ent)

  let s = 0
  s += Math.min(p.length, 16) * 4
  if (hasLower) s += 6
  if (hasUpper) s += 6
  if (hasDigit) s += 6
  if (hasSymbol) s += 10
  // penalties
  if (/(.)\1\1/.test(p)) s -= 8
  if (/^[a-zA-Z]+$/.test(p) && hasUpper && !hasLower) s -= 5
  if (/^\d+$/.test(p)) s -= 10
  if (/^(.)\1+$/.test(p)) s -= 20
  s = Math.max(0, Math.min(100, s))

  score.value = s
  if (s < 40) { label.value = '弱'; color.value = '#ef4444' }
  else if (s < 70) { label.value = '中'; color.value = '#f59e0b' }
  else if (s < 90) { label.value = '强'; color.value = '#10b981' }
  else { label.value = '极强'; color.value = '#059669' }

  // crack time estimate (online ~1e3/s, offline ~1e10/s) — use offline
  const combos = Math.pow(pool, p.length)
  const secs = combos / 2 / 1e10
  crackTime.value = formatTime(secs)

  checks.value = [
    { label: '至少 8 位', met: p.length >= 8 },
    { label: '至少 12 位', met: p.length >= 12 },
    { label: '含大写字母', met: hasUpper },
    { label: '含小写字母', met: hasLower },
    { label: '含数字', met: hasDigit },
    { label: '含符号', met: hasSymbol },
  ]
  suggestions.value = []
  if (p.length < 12) suggestions.value.push('建议长度至少 12 位，越长越安全')
  if (!(hasLower && hasUpper)) suggestions.value.push('混合大小写字母可显著提升强度')
  if (!hasDigit) suggestions.value.push('加入数字')
  if (!hasSymbol) suggestions.value.push('加入符号（如 !@#$%）更安全')
  if (/(.)\1\1/.test(p)) suggestions.value.push('避免连续重复字符')
}

function formatTime(secs) {
  if (!isFinite(secs) || secs <= 0) return '瞬间'
  const units = [['年', 31536000], ['天', 86400], ['小时', 3600], ['分钟', 60], ['秒', 1]]
  for (const [name, v] of units) {
    if (secs >= v) return Math.floor(secs / v) + ' ' + name
  }
  return '瞬间'
}
</script>

<style scoped>
.pwd-row { display: flex; gap: 0.5rem; }
.pwd-row .input-text { flex: 1; }
.strength-bar { height: 8px; background: #f1f5f9; border-radius: 4px; overflow: hidden; margin: 0.5rem 0 0.25rem; }
.strength-fill { height: 100%; transition: width 0.25s, background 0.25s; }
.strength-label { font-size: 0.85rem; font-weight: 700; margin-bottom: 0.6rem; }
.metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.5rem; margin-bottom: 0.6rem; }
.metric { background: #f8fafc; border: 1px solid var(--border); border-radius: var(--radius); padding: 0.5rem 0.65rem; display: flex; flex-direction: column; }
.metric span { font-size: 0.72rem; color: var(--text-secondary); }
.metric b { font-size: 0.95rem; color: var(--text); }
.checklist { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.35rem; margin-bottom: 0.5rem; }
.check { font-size: 0.8rem; padding: 0.25rem 0.5rem; border-radius: 6px; }
.check.ok { color: #065f46; background: #d1fae5; }
.check.no { color: #991b1b; background: #fee2e2; }
.suggestions { background: #eff6ff; border: 1px solid #bfdbfe; border-radius: var(--radius); padding: 0.6rem 0.85rem; }
.sug-title { font-size: 0.8rem; font-weight: 600; color: #1e40af; margin-bottom: 0.25rem; }
.suggestions ul { margin: 0; padding-left: 1.1rem; font-size: 0.8rem; color: var(--text-secondary); }
</style>
