<template>
  <div class="tool-panel">
    <h2>🎲 随机数 / 抽签</h2>

    <div class="card">
      <div class="tab-row">
        <button :class="['tab', { active: mode === 'num' }]" @click="mode = 'num'">随机数字</button>
        <button :class="['tab', { active: mode === 'draw' }]" @click="mode = 'draw'">名单抽签</button>
        <button :class="['tab', { active: mode === 'shuffle' }]" @click="mode = 'shuffle'">随机洗牌</button>
      </div>

      <!-- 随机数字 -->
      <div v-if="mode === 'num'">
        <div class="form-row">
          <div class="form-group half"><label>最小值</label><input class="input-text" type="number" v-model="rMin" /></div>
          <div class="form-group half"><label>最大值</label><input class="input-text" type="number" v-model="rMax" /></div>
        </div>
        <div class="form-row">
          <div class="form-group half"><label>生成个数</label><input class="input-text" type="number" v-model="rCount" /></div>
          <div class="form-group half"><label>小数位</label>
            <select class="input-select" v-model="rDecimals">
              <option :value="0">整数</option><option :value="1">1 位</option><option :value="2">2 位</option><option :value="3">3 位</option>
            </select>
          </div>
        </div>
        <button class="btn btn-primary" @click="genNumbers">生成</button>
        <div class="result-box" v-if="numResult.length">
          <div class="result-value" @click="copy(numResult.join(', '))">{{ numResult.join(', ') }}</div>
        </div>
      </div>

      <!-- 名单抽签 -->
      <div v-if="mode === 'draw'">
        <div class="form-group">
          <label>候选名单（每行一个或用逗号分隔）</label>
          <textarea class="input-textarea" v-model="nameList" rows="5" placeholder="张三&#10;李四&#10;王五"></textarea>
        </div>
        <div class="form-group">
          <label>抽取人数</label>
          <input class="input-text" type="number" v-model="drawCount" style="max-width:120px" />
        </div>
        <button class="btn btn-primary" @click="draw">开始抽签</button>
        <div class="draw-result" v-if="drawResult.length">
          <div v-for="(w, i) in drawResult" :key="i" class="draw-winner" @click="copy(w)">🎉 {{ w }}</div>
        </div>
      </div>

      <!-- 随机洗牌 -->
      <div v-if="mode === 'shuffle'">
        <div class="form-group">
          <label>待排序内容（每行一个）</label>
          <textarea class="input-textarea" v-model="shuffleList" rows="6" placeholder="一行一项"></textarea>
        </div>
        <button class="btn btn-primary" @click="shuffle">洗牌</button>
        <div class="result-box" v-if="shuffleResult.length">
          <div class="result-pre" @click="copy(shuffleResult.join('\n'))">{{ shuffleResult.join('\n') }}</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject } from 'vue'

const showToast = inject('showToast')
const mode = ref('num')

const rMin = ref(1), rMax = ref(100), rCount = ref(5), rDecimals = ref(0)
const numResult = ref([])

const nameList = ref('张三\n李四\n王五\n赵六\n钱七')
const drawCount = ref(1)
const drawResult = ref([])

const shuffleList = ref('项目 A\n项目 B\n项目 C\n项目 D\n项目 E')
const shuffleResult = ref([])

function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min }

function genNumbers() {
  const min = parseFloat(rMin.value), max = parseFloat(rMax.value)
  const n = Math.min(1000, Math.max(1, parseInt(rCount.value) || 1))
  if (min > max) { showToast('最小值不能大于最大值'); return }
  const arr = []
  for (let i = 0; i < n; i++) {
    const v = min + Math.random() * (max - min)
    arr.push(rDecimals.value > 0 ? v.toFixed(rDecimals.value) : Math.round(v))
  }
  numResult.value = arr
}
function parseNames() {
  return nameList.value.split(/[\n,，、]+/).map(s => s.trim()).filter(s => s)
}
function draw() {
  const names = parseNames()
  const k = Math.min(names.length, Math.max(1, parseInt(drawCount.value) || 1))
  const pool = [...names]
  const winners = []
  for (let i = 0; i < k; i++) {
    const idx = Math.floor(Math.random() * pool.length)
    winners.push(pool.splice(idx, 1)[0])
  }
  drawResult.value = winners
}
function shuffle() {
  const arr = shuffleList.value.split('\n').map(s => s.trim()).filter(s => s)
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[arr[i], arr[j]] = [arr[j], arr[i]]
  }
  shuffleResult.value = arr
}
function copy(text) {
  navigator.clipboard.writeText(String(text)).then(() => showToast('已复制'))
}
</script>

<style scoped>
.tab-row { display: flex; gap: 0.4rem; margin-bottom: 0.85rem; flex-wrap: wrap; }
.tab {
  padding: 0.4rem 0.9rem; border: 1.5px solid var(--border); background: white;
  border-radius: var(--radius); cursor: pointer; font-size: 0.85rem; color: var(--text-secondary);
}
.tab.active { background: var(--primary); color: #fff; border-color: var(--primary); }
.draw-result { margin-top: 0.75rem; display: flex; flex-direction: column; gap: 0.4rem; }
.draw-winner {
  padding: 0.6rem 0.9rem; background: #fef9c3; border: 1px solid #fde047;
  border-radius: var(--radius); font-weight: 700; cursor: pointer; color: #854d0e;
}
</style>
