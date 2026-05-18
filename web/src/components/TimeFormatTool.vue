<template>
  <div class="tool-panel">
    <h2>时间格式化工具</h2>

    <div class="card">
      <h3>时间格式转换</h3>
      <div class="form-group">
        <label>时间字符串</label>
        <input v-model="form.time" placeholder="2024-05-18 10:40:00" class="input-text">
      </div>
      <div class="form-row">
        <div class="form-group half">
          <label>源格式</label>
          <input v-model="form.fromFormat" placeholder="2006-01-02 15:04:05" class="input-text">
        </div>
        <div class="form-group half">
          <label>目标格式</label>
          <input v-model="form.toFormat" placeholder="01/02/2006 03:04 PM" class="input-text">
        </div>
      </div>
      <div class="form-row">
        <div class="form-group half">
          <label>源时区</label>
          <input v-model="form.fromTZ" placeholder="Asia/Shanghai" class="input-text">
        </div>
        <div class="form-group half">
          <label>目标时区</label>
          <input v-model="form.toTZ" placeholder="UTC" class="input-text">
        </div>
      </div>
      <button @click="convert" class="btn btn-primary">转换</button>
      <div v-if="result" class="result-box">
        <div class="result-row">
          <span class="result-label">原始：</span>
          <span class="result-value">{{ result.original }}</span>
        </div>
        <div class="result-row">
          <span class="result-label">转换：</span>
          <span class="result-value highlight" @click="copy(result.converted)">{{ result.converted }}</span>
        </div>
        <div class="result-row">
          <span class="result-label">{{ result.from_timezone }}</span>
          <span class="result-arrow">→</span>
          <span class="result-label">{{ result.to_timezone }}</span>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>常用格式参考</h3>
      <table class="format-table">
        <thead>
          <tr><th>格式</th><th>示例</th><th>说明</th></tr>
        </thead>
        <tbody>
          <tr><td><code>2006-01-02</code></td><td>2024-05-18</td><td>日期</td></tr>
          <tr><td><code>15:04:05</code></td><td>10:40:00</td><td>24小时制</td></tr>
          <tr><td><code>2006-01-02 15:04:05</code></td><td>2024-05-18 10:40:00</td><td>日期时间</td></tr>
          <tr><td><code>01/02/2006</code></td><td>05/18/2024</td><td>美式日期</td></tr>
          <tr><td><code>2006/01/02</code></td><td>2024/05/18</td><td>中式日期</td></tr>
          <tr><td><code>03:04 PM</code></td><td>10:40 AM</td><td>12小时制</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, inject } from 'vue'
import { apiPost, copyToClipboard } from '../api.js'

const showToast = inject('showToast')

function copy(text) {
  copyToClipboard(text).then(ok => showToast(ok ? '已复制到剪贴板' : '复制失败'))
}

const form = reactive({ time: '', fromFormat: '', toFormat: '', fromTZ: '', toTZ: '' })
const result = ref(null)

async function convert() {
  const body = { time: form.time, from_format: form.fromFormat, to_format: form.toFormat }
  if (form.fromTZ) body.from_tz = form.fromTZ
  if (form.toTZ) body.to_tz = form.toTZ
  const res = await apiPost('/api/timeformat/convert', body)
  if (res.code === 0) result.value = res.data
  else showToast(res.message)
}
</script>
