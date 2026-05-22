<template>
  <div class="tool-panel">
    <h2>⏰ Cron 解析</h2>

    <div class="card">
      <div class="form-group">
        <label>Cron 表达式</label>
        <input
          v-model="cronExpr"
          type="text"
          class="input-text"
          placeholder="* * * * *"
          @input="parse"
        />
      </div>

      <div class="cron-help">
        <span class="help-label">格式:</span>
        <code>分 时 日 月 周</code>
      </div>

      <div v-if="description" class="result-box">
        <div class="result-label">描述</div>
        <div class="result-value highlight">{{ description }}</div>
      </div>

      <div v-if="nextRuns.length > 0" class="result-box">
        <div class="result-label">下次执行时间</div>
        <div v-for="(run, i) in nextRuns" :key="i" class="result-row">
          <span class="run-index">{{ i + 1 }}.</span>
          <span class="run-time">{{ run.format('YYYY-MM-DD HH:mm:ss ddd') }}</span>
        </div>
      </div>

      <div v-if="error" class="error-box">{{ error }}</div>
    </div>

    <div class="card">
      <h3>字段说明</h3>
      <table class="format-table">
        <thead>
          <tr>
            <th>字段</th>
            <th>范围</th>
            <th>特殊字符</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>分 (Minute)</td>
            <td><code>0-59</code></td>
            <td><code>* , - /</code></td>
          </tr>
          <tr>
            <td>时 (Hour)</td>
            <td><code>0-23</code></td>
            <td><code>* , - /</code></td>
          </tr>
          <tr>
            <td>日 (Day)</td>
            <td><code>1-31</code></td>
            <td><code>* , - /</code></td>
          </tr>
          <tr>
            <td>月 (Month)</td>
            <td><code>1-12</code></td>
            <td><code>* , - /</code></td>
          </tr>
          <tr>
            <td>周 (Week)</td>
            <td><code>0-6</code> (0=周日)</td>
            <td><code>* , - /</code></td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <h3>常用示例</h3>
      <div class="example-list">
        <div v-for="ex in examples" :key="ex.expr" class="example-item" @click="applyExample(ex.expr)">
          <code class="example-expr">{{ ex.expr }}</code>
          <span class="example-desc">{{ ex.desc }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'

const cronExpr = ref('')
const description = ref('')
const nextRuns = ref([])
const error = ref('')

const examples = [
  { expr: '* * * * *', desc: '每分钟' },
  { expr: '0 * * * *', desc: '每小时整点' },
  { expr: '0 0 * * *', desc: '每天午夜' },
  { expr: '0 9 * * 1-5', desc: '工作日 9:00' },
  { expr: '0 9 * * 1', desc: '每周一 9:00' },
  { expr: '0 0 1 * *', desc: '每月 1 日' },
  { expr: '*/5 * * * *', desc: '每 5 分钟' },
  { expr: '0 */2 * * *', desc: '每 2 小时' },
  { expr: '30 4 1,15 * *', desc: '每月 1、15 日 4:30' },
  { expr: '0 0 * * 0', desc: '每周日午夜' },
]

function parse() {
  error.value = ''
  description.value = ''
  nextRuns.value = []

  const expr = cronExpr.value.trim()
  if (!expr) return

  const parts = expr.split(/\s+/)
  if (parts.length !== 5) {
    error.value = '格式错误: 需要 5 个字段 (分 时 日 月 周)'
    return
  }

  // 简单描述生成
  description.value = generateDescription(parts)

  // 计算下次执行时间
  nextRuns.value = getNextRuns(parts, 5)
}

function generateDescription(parts) {
  const [min, hour, day, month, dow] = parts
  const descs = []

  // 每周几
  const dayNames = ['周日', '周一', '周二', '周三', '周四', '周五', '周六']
  
  if (dow !== '*') {
    if (dow.includes(',')) {
      const days = dow.split(',').map(d => dayNames[parseInt(d)]).join('、')
      descs.push(`每周${days}`)
    } else if (dow.includes('-')) {
      const [s, e] = dow.split('-')
      descs.push(`每周${dayNames[parseInt(s)]}至${dayNames[parseInt(e)]}`)
    } else {
      descs.push(`每周${dayNames[parseInt(dow)]}`)
    }
  }

  // 每月几号
  if (day !== '*') {
    if (day.includes(',')) {
      descs.push(`每月${day}日`)
    } else if (day.includes('-')) {
      descs.push(`每月${day}日`)
    } else {
      descs.push(`每月${day}日`)
    }
  }

  // 时间
  if (min === '*' && hour === '*') {
    descs.push('每分钟')
  } else if (min === '*') {
    descs.push(`每小时第${hour}分钟`)
  } else if (hour === '*') {
    descs.push(`每小时的第 ${min} 分钟`)
  } else {
    descs.push(`每天 ${hour.padStart(2, '0')}:${min.padStart(2, '0')}`)
  }

  return descs.join(', ') || '未知规则'
}

function getNextRuns(parts, count) {
  const runs = []
  let date = new Date()
  date.setSeconds(0)
  date.setMilliseconds(0)
  date.setMinutes(date.getMinutes() + 1)

  const [minPat, hourPat, dayPat, monthPat, dowPat] = parts

  for (let i = 0; i < 100 && runs.length < count; i++) {
    const d = new Date(date)
    d.setMinutes(d.getMinutes() + i)

    if (!matchCronPart(minPat, d.getMinutes(), 0, 59)) continue
    if (!matchCronPart(hourPat, d.getHours(), 0, 23)) continue
    if (!matchCronPart(dayPat, d.getDate(), 1, 31)) continue
    if (!matchCronPart(monthPat, d.getMonth() + 1, 1, 12)) continue
    if (!matchCronPart(dowPat, d.getDay(), 0, 6)) continue

    runs.push(d)
  }

  return runs
}

function matchCronPart(pattern, value, min, max) {
  if (pattern === '*') return true

  // 处理列表
  if (pattern.includes(',')) {
    return pattern.split(',').some(p => matchCronPart(p.trim(), value, min, max))
  }

  // 处理范围
  if (pattern.includes('-')) {
    const [start, end] = pattern.split('-').map(Number)
    return value >= start && value <= end
  }

  // 处理步长
  if (pattern.includes('/')) {
    const [, step] = pattern.split('/')
    return value % parseInt(step) === 0
  }

  return parseInt(pattern) === value
}

function applyExample(expr) {
  cronExpr.value = expr
  parse()
}
</script>

<style scoped>
.cron-help {
  font-size: 0.78rem;
  color: var(--text-secondary);
  margin-top: 0.25rem;
}

.cron-help code {
  background: #f1f5f9;
  padding: 0.1rem 0.35rem;
  border-radius: 4px;
  font-family: "SF Mono", Monaco, monospace;
}

.help-label {
  margin-right: 0.5rem;
}

.result-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-top: 0.3rem;
}

.run-index {
  color: var(--text-secondary);
  font-size: 0.78rem;
}

.run-time {
  font-family: "SF Mono", Monaco, monospace;
  font-size: 0.88rem;
  color: var(--text);
}

.example-list {
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}

.example-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.5rem 0.75rem;
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.15s;
}

.example-item:hover {
  background: rgba(79, 70, 229, 0.06);
}

.example-expr {
  font-family: "SF Mono", Monaco, monospace;
  font-size: 0.85rem;
  background: #f1f5f9;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  min-width: 120px;
}

.example-desc {
  font-size: 0.82rem;
  color: var(--text-secondary);
}
</style>