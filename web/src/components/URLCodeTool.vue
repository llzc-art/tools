<template>
  <div class="tool-panel">
    <h2>URL 编码 / 解码 / 解析</h2>
    <div class="card">
      <div class="form-group">
        <label>输入</label>
        <textarea v-model="input" placeholder="输入 URL 或字符串" class="input-textarea" rows="3"></textarea>
      </div>
      <div class="btn-group">
        <button @click="encodeComp" class="btn btn-primary">组件编码</button>
        <button @click="decodeComp" class="btn btn-secondary">组件解码</button>
        <button @click="parse" class="btn btn-outline">URL 解析</button>
      </div>
      <div v-if="output" class="result-box">
        <div class="result-label">{{ resultLabel }}</div>
        <div v-if="parsed" class="parsed-info">
          <div v-for="(v, k) in parsed" :key="k" class="parsed-row">
            <span class="parsed-key">{{ k }}:</span>
            <span class="parsed-val" @click="copy(String(v))">{{ v }}</span>
          </div>
        </div>
        <pre v-else class="result-value result-pre" @click="copy(output)">{{ output }}</pre>
        <div class="result-hint">点击复制</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject } from 'vue'
import { apiPost, copyToClipboard } from '../api.js'

const showToast = inject('showToast')

function copy(text) {
  copyToClipboard(text).then(ok => showToast(ok ? '已复制到剪贴板' : '复制失败'))
}

const input = ref('')
const output = ref('')
const resultLabel = ref('')
const parsed = ref(null)

async function encodeComp() {
  parsed.value = null
  const res = await apiPost('/api/urlcode/encode', { input: input.value })
  if (res.code === 0) {
    output.value = res.data.output
    resultLabel.value = '编码结果'
  } else showToast(res.message)
}

async function decodeComp() {
  parsed.value = null
  const res = await apiPost('/api/urlcode/decode', { input: input.value })
  if (res.code === 0) {
    output.value = res.data.output
    resultLabel.value = '解码结果'
  } else showToast(res.message)
}

async function parse() {
  const res = await apiPost('/api/urlcode/parse', { url: input.value })
  if (res.code === 0) {
    const d = res.data
    parsed.value = {
      '协议 (Scheme)': d.scheme,
      '主机 (Host)': d.host,
      '端口 (Port)': d.port,
      '路径 (Path)': d.path,
      '查询 (Query)': d.query,
      '片段 (Fragment)': d.fragment,
    }
    output.value = JSON.stringify(d, null, 2)
    resultLabel.value = 'URL 解析结果'
  } else showToast(res.message)
}
</script>
