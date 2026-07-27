<template>
  <div class="tool-panel">
    <h2>🔠 拼音转换</h2>

    <div class="card">
      <label>输入中文</label>
      <textarea class="input-textarea" v-model="text" rows="5" placeholder="请输入中文文本，例如：你好，世界！"></textarea>

      <div class="form-row opts">
        <div class="form-group">
          <label>声调</label>
          <select class="input-text" v-model="toneType">
            <option value="symbol">带声调符号 (nǐ hǎo)</option>
            <option value="num">数字声调 (ni3 hao3)</option>
            <option value="none">不带声调 (ni hao)</option>
          </select>
        </div>
        <div class="form-group">
          <label>输出格式</label>
          <select class="input-text" v-model="mode">
            <option value="full">完整拼音</option>
            <option value="initial">仅声母</option>
            <option value="final">仅韵母</option>
            <option value="first">首字母</option>
          </select>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>转换结果 <span class="hint-inline">点击复制</span></h3>
      <pre class="result-text" @click="copy(result)">{{ result || '（结果显示在这里）' }}</pre>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, inject } from 'vue'
import { pinyin } from 'pinyin-pro'

const showToast = inject('showToast')
const text = ref('你好，世界！')
const toneType = ref('symbol')
const mode = ref('full')

const result = computed(() => {
  if (!text.value.trim()) return ''
  try {
    const opts = { toneType: toneType.value }
    if (mode.value === 'initial') { opts.pattern = 'initial' }
    else if (mode.value === 'final') { opts.pattern = 'final' }
    else if (mode.value === 'first') { opts.pattern = 'first'; opts.toneType = 'none' }
    return pinyin(text.value, opts)
  } catch (e) {
    return '转换出错：' + e.message
  }
})

function copy(t) {
  if (!t) return
  navigator.clipboard.writeText(t).then(() => showToast('已复制'))
}
</script>

<style scoped>
.opts { margin-top: 0.75rem; }
.hint-inline { font-size: 0.72rem; font-weight: 400; color: var(--text-secondary); margin-left: 0.5rem; }
.result-text {
  background: #f8fafc; border: 1px solid var(--border); border-radius: var(--radius);
  padding: 0.9rem 1rem; font-size: 0.95rem; line-height: 1.7; white-space: pre-wrap;
  word-break: break-word; margin: 0; cursor: pointer; color: var(--text); min-height: 3rem;
}
.result-text:hover { border-color: var(--primary); }
</style>
