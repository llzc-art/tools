<template>
  <div class="tool-panel">
    <h2>字符串工具</h2>
    <div class="card">
      <div class="form-group">
        <label>输入字符串</label>
        <textarea v-model="input" placeholder="输入要处理的字符串" class="input-textarea" rows="4"></textarea>
      </div>
      <div class="btn-group">
        <button @click="count" class="btn btn-primary">字符统计</button>
        <button @click="toUpper" class="btn btn-sm btn-outline">转大写</button>
        <button @click="toLower" class="btn btn-sm btn-outline">转小写</button>
        <button @click="toCamel" class="btn btn-sm btn-outline">驼峰</button>
        <button @click="toSnake" class="btn btn-sm btn-outline">下划线</button>
        <button @click="toHex" class="btn btn-sm btn-outline">转 Hex</button>
        <button @click="hexToStr" class="btn btn-sm btn-outline">Hex 转字符串</button>
      </div>
      <div v-if="output" class="result-box">
        <div class="result-label">{{ resultLabel }}</div>
        <pre v-if="countResult" class="parsed-info">
          <div v-for="(v, k) in countResult" :key="k" class="parsed-row">
            <span class="parsed-key">{{ k }}:</span>
            <span class="parsed-val" @click="copy(String(v))">{{ v }}</span>
          </div>
        </pre>
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
const countResult = ref(null)

async function doAction(url, body, label) {
  countResult.value = null
  const res = await apiPost(url, body)
  if (res.code === 0) {
    output.value = typeof res.data.output === 'string' ? res.data.output : JSON.stringify(res.data, null, 2)
    resultLabel.value = label
  } else showToast(res.message)
}

async function count() {
  const res = await apiPost('/api/string/count', { input: input.value })
  if (res.code === 0) {
    const d = res.data
    countResult.value = {
      '字节数': d.byte_count,
      '字符数': d.rune_count,
      '行数': d.line_count,
      '词数': d.word_count,
      '中文字数': d.chinese_count,
    }
    output.value = JSON.stringify(d, null, 2)
    resultLabel.value = '字符统计结果'
  } else showToast(res.message)
}

function toUpper() { doAction('/api/string/to-upper', { input: input.value }, '转大写') }
function toLower() { doAction('/api/string/to-lower', { input: input.value }, '转小写') }
function toCamel() { doAction('/api/string/to-camel', { input: input.value }, '驼峰命名') }
function toSnake() { doAction('/api/string/to-snake', { input: input.value }, '下划线命名') }
function toHex() { doAction('/api/string/to-hex', { input: input.value }, '十六进制') }
function hexToStr() { doAction('/api/hex/to-string', { input: input.value }, 'Hex 转字符串') }
</script>
