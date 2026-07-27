<template>
  <div class="tool-panel">
    <h2>🔡 字数统计</h2>

    <div class="card">
      <div class="form-group">
        <label>输入文本</label>
        <textarea class="input-textarea" v-model="text" @input="stat" rows="8" placeholder="粘贴或输入要统计的文本..."></textarea>
      </div>

      <div class="stats-grid" v-if="hasText">
        <div class="stat-item"><div class="stat-num">{{ s.chars }}</div><div class="stat-label">字符数（含空格）</div></div>
        <div class="stat-item"><div class="stat-num">{{ s.charsNoSpace }}</div><div class="stat-label">字符数（不含空格）</div></div>
        <div class="stat-item"><div class="stat-num">{{ s.lines }}</div><div class="stat-label">行数</div></div>
        <div class="stat-item"><div class="stat-num">{{ s.paragraphs }}</div><div class="stat-label">段落数</div></div>
        <div class="stat-item"><div class="stat-num">{{ s.words }}</div><div class="stat-label">词数（中英）</div></div>
        <div class="stat-item"><div class="stat-num">{{ s.minutes }}<span class="unit"> 分钟</span></div><div class="stat-label">预计阅读时长</div></div>
      </div>
      <div class="empty-hint" v-else>输入文本后自动统计</div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, inject } from 'vue'

const showToast = inject('showToast')
const text = ref('')

const hasText = computed(() => text.value.length > 0)

const s = ref({ chars: 0, charsNoSpace: 0, lines: 0, paragraphs: 0, words: 0, minutes: 0 })

function stat() {
  const t = text.value
  const chars = t.length
  const charsNoSpace = t.replace(/\s/g, '').length
  const lines = t === '' ? 0 : t.split('\n').length
  const paragraphs = t.trim() === '' ? 0 : t.split(/\n\s*\n/).filter(p => p.trim()).length
  const cjk = (t.match(/[\u4e00-\u9fff\u3040-\u30ff\uf900-\ufaff]/g) || []).length
  const enWords = (t.replace(/[\u4e00-\u9fff\u3040-\u30ff\uf900-\ufaff]/g, ' ').match(/[A-Za-z0-9]+/g) || []).length
  const words = cjk + enWords
  const minutes = Math.max(1, Math.ceil(words / 300))
  s.value = { chars, charsNoSpace, lines, paragraphs, words, minutes }
}
</script>

<style scoped>
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 0.6rem; margin-top: 0.5rem; }
.stat-item { background: #f8fafc; border: 1px solid var(--border); border-radius: var(--radius); padding: 0.75rem; text-align: center; }
.stat-num { font-size: 1.6rem; font-weight: 800; color: var(--primary); }
.stat-num .unit { font-size: 0.8rem; color: var(--text-secondary); font-weight: 500; }
.stat-label { font-size: 0.72rem; color: var(--text-secondary); margin-top: 0.2rem; }
.empty-hint { color: var(--text-secondary); font-size: 0.85rem; padding: 0.5rem 0; }
</style>
