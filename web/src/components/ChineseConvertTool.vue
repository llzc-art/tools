<template>
  <div class="tool-panel">
    <h2>🀄 繁简转换</h2>

    <div class="card">
      <div class="form-row">
        <div class="form-group half">
          <label>转换方向</label>
          <select class="input-text" v-model="direction">
            <option value="s2t">简体 → 繁体（台湾）</option>
            <option value="s2hk">简体 → 繁体（香港）</option>
            <option value="t2s">繁体 → 简体</option>
          </select>
        </div>
        <div class="form-group half btn-col">
          <button class="btn-secondary" @click="swap">⇅ 交换并转换</button>
        </div>
      </div>

      <label>输入文本</label>
      <textarea class="input-textarea" v-model="text" rows="6" placeholder="请输入要转换的中文文本"></textarea>
    </div>

    <div class="card">
      <h3>转换结果 <span class="hint-inline">点击复制</span></h3>
      <pre class="result-text" @click="copy(result)">{{ result || '（结果显示在这里）' }}</pre>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, inject } from 'vue'
import * as OpenCC from 'opencc-js'

const showToast = inject('showToast')
const text = ref('汉字繁简转换，一键搞定。')
const direction = ref('s2t')

const converters = {
  s2t: OpenCC.Converter({ from: 'cn', to: 'tw' }),
  s2hk: OpenCC.Converter({ from: 'cn', to: 'hk' }),
  t2s: OpenCC.Converter({ from: 'tw', to: 'cn' }),
}

const result = computed(() => {
  if (!text.value) return ''
  try {
    return converters[direction.value](text.value)
  } catch (e) {
    return '转换出错：' + e.message
  }
})

function swap() {
  if (result.value) text.value = result.value
  direction.value = direction.value === 't2s' ? 's2t' : 't2s'
}

function copy(t) {
  if (!t) return
  navigator.clipboard.writeText(t).then(() => showToast('已复制'))
}
</script>

<style scoped>
.btn-col { display: flex; align-items: flex-end; }
.hint-inline { font-size: 0.72rem; font-weight: 400; color: var(--text-secondary); margin-left: 0.5rem; }
.result-text {
  background: #f8fafc; border: 1px solid var(--border); border-radius: var(--radius);
  padding: 0.9rem 1rem; font-size: 0.95rem; line-height: 1.7; white-space: pre-wrap;
  word-break: break-word; margin: 0; cursor: pointer; color: var(--text); min-height: 3rem;
}
.result-text:hover { border-color: var(--primary); }
</style>
