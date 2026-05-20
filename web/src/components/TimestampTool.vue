<template>
  <div class="tool-panel">
    <h2>时间戳工具</h2>

    <div class="card">
      <h3>获取当前时间戳</h3>
      <div class="form-row">
        <div class="form-group half">
          <select v-model="nowUnit" class="input-select">
            <option value="s">秒 (s)</option>
            <option value="ms">毫秒 (ms)</option>
          </select>
        </div>
        <div class="form-group half">
          <button @click="getNow" class="btn btn-primary">获取</button>
        </div>
      </div>
      <div v-if="nowResult" class="result-box">
        <div class="result-label">当前时间戳</div>
        <div class="result-value" @click="copy(nowResult.timestamp)">{{ nowResult.timestamp }}</div>
        <div class="result-hint">点击复制</div>
      </div>
    </div>

    <div class="card">
      <h3>时间戳 → 时间</h3>
      <div class="form-group">
        <label>时间戳</label>
        <input v-model="toTime.timestamp" type="number" placeholder="输入 Unix 时间戳" class="input-text">
      </div>
      <div class="form-row">
        <div class="form-group half">
          <label>单位</label>
          <select v-model="toTime.unit" class="input-select">
            <option value="s">秒 (s)</option>
            <option value="ms">毫秒 (ms)</option>
          </select>
        </div>
        <div class="form-group half">
          <label>格式</label>
          <input v-model="toTime.format" placeholder="2006-01-02 15:04:05" class="input-text">
        </div>
      </div>
      <div class="form-group">
        <label>时区</label>
        <input v-model="toTime.timezone" placeholder="Asia/Shanghai" class="input-text">
      </div>
      <button @click="convertToTime" class="btn btn-primary">转换</button>
      <div v-if="toTimeResult" class="result-box">
        <div class="result-value" @click="copy(toTimeResult.formatted)">{{ toTimeResult.formatted }}</div>
      </div>
    </div>

    <div class="card">
      <h3>时间 → 时间戳</h3>
      <div class="form-group">
        <label>时间字符串</label>
        <input v-model="fromTime.time" placeholder="2024-05-18 10:40:00" class="input-text">
      </div>
      <div class="form-row">
        <div class="form-group half">
          <label>格式</label>
          <input v-model="fromTime.format" placeholder="2006-01-02 15:04:05" class="input-text">
        </div>
        <div class="form-group half">
          <label>时区</label>
          <input v-model="fromTime.timezone" placeholder="Asia/Shanghai" class="input-text">
        </div>
      </div>
      <button @click="convertFromTime" class="btn btn-primary">转换</button>
      <div v-if="fromTimeResult" class="result-box">
        <div class="result-value" @click="copy(fromTimeResult.timestamp)">{{ fromTimeResult.timestamp }}</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, inject } from 'vue'
import { apiGet, apiPost, copyToClipboard } from '../api.js'

const showToast = inject('showToast')

function copy(text) {
  copyToClipboard(text).then(ok => showToast(ok ? '已复制到剪贴板' : '复制失败'))
}

const nowUnit = ref('s')
const nowResult = ref(null)

async function getNow() {
  const res = await apiGet(`/api/timestamp/now?unit=${nowUnit.value || 's'}`)
  if (res.code === 0) nowResult.value = res.data
  else showToast(res.message)
}

const toTime = reactive({ timestamp: '', unit: 's', format: '', timezone: '' })
const toTimeResult = ref(null)

async function convertToTime() {
  const body = { timestamp: Number(toTime.timestamp) }
  if (toTime.unit) body.unit = toTime.unit
  if (toTime.format) body.format = toTime.format
  if (toTime.timezone) body.timezone = toTime.timezone
  const res = await apiPost('/api/timestamp/to-time', body)
  if (res.code === 0) toTimeResult.value = res.data
  else showToast(res.message)
}

const fromTime = reactive({ time: '', format: '', timezone: '' })
const fromTimeResult = ref(null)

async function convertFromTime() {
  const body = { time: fromTime.time }
  if (fromTime.format) body.format = fromTime.format
  if (fromTime.timezone) body.timezone = fromTime.timezone
  const res = await apiPost('/api/timestamp/from-time', body)
  if (res.code === 0) fromTimeResult.value = res.data
  else showToast(res.message)
}
</script>
