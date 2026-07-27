<template>
  <div class="tool-panel">
    <h2>🧮 科学计算器</h2>

    <div class="card">
      <div class="calc-display">
        <div class="calc-expr">{{ expr || '0' }}</div>
        <div class="calc-result" v-if="result !== ''">= {{ result }}</div>
      </div>

      <div class="calc-grid">
        <button class="calc-btn func" @click="clear">C</button>
        <button class="calc-btn func" @click="backspace">⌫</button>
        <button class="calc-btn func" @click="append('(')">(</button>
        <button class="calc-btn func" @click="append(')')">)</button>

        <button class="calc-btn func" @click="append('sin(')">sin</button>
        <button class="calc-btn func" @click="append('cos(')">cos</button>
        <button class="calc-btn func" @click="append('tan(')">tan</button>
        <button class="calc-btn op" @click="append('/')">÷</button>

        <button class="calc-btn func" @click="append('sqrt(')">√</button>
        <button class="calc-btn func" @click="append('log(')">log</button>
        <button class="calc-btn func" @click="append('ln(')">ln</button>
        <button class="calc-btn op" @click="append('*')">×</button>

        <button class="calc-btn func" @click="append('pow(')">xʸ</button>
        <button class="calc-btn func" @click="append('pi')">π</button>
        <button class="calc-btn func" @click="append('e')">e</button>
        <button class="calc-btn op" @click="append('-')">−</button>

        <button class="calc-btn num" @click="append('7')">7</button>
        <button class="calc-btn num" @click="append('8')">8</button>
        <button class="calc-btn num" @click="append('9')">9</button>
        <button class="calc-btn op" @click="append('+')">+</button>

        <button class="calc-btn num" @click="append('4')">4</button>
        <button class="calc-btn num" @click="append('5')">5</button>
        <button class="calc-btn num" @click="append('6')">6</button>
        <button class="calc-btn eq" @click="calculate" rowspan="2">=</button>

        <button class="calc-btn num" @click="append('1')">1</button>
        <button class="calc-btn num" @click="append('2')">2</button>
        <button class="calc-btn num" @click="append('3')">3</button>

        <button class="calc-btn num zero" @click="append('0')">0</button>
        <button class="calc-btn num" @click="append('.')">.</button>
        <button class="calc-btn func" @click="append('%')">%</button>
      </div>
      <div class="calc-hint">支持 sin/cos/tan/log/ln/√/π/e 与括号运算，例如 <code>sqrt(16)+pow(2,3)</code></div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject } from 'vue'

const showToast = inject('showToast')
const expr = ref('')
const result = ref('')

function append(t) { expr.value += t }
function clear() { expr.value = ''; result.value = '' }
function backspace() { expr.value = expr.value.slice(0, -1) }

function calculate() {
  const e = expr.value.trim()
  if (!e) { result.value = ''; return }
  try {
    const map = {
      sin: 'Math.sin', cos: 'Math.cos', tan: 'Math.tan',
      asin: 'Math.asin', acos: 'Math.acos', atan: 'Math.atan',
      log: 'Math.log10', ln: 'Math.log', sqrt: 'Math.sqrt',
      abs: 'Math.abs', exp: 'Math.exp', pow: 'Math.pow',
      pi: 'Math.PI', e: 'Math.E'
    }
    let t = e.replace(/\b(sin|cos|tan|asin|acos|atan|log|ln|sqrt|abs|exp|pow|pi|e)\b/g, m => map[m])
    if (!/^[0-9+\-*/().\s,%]+$/.test(t)) throw new Error('非法字符')
    const r = Function('"use strict";return (' + t + ')')()
    if (typeof r !== 'number' || !isFinite(r)) throw new Error('计算错误')
    result.value = formatNum(r)
  } catch (err) {
    result.value = '错误'
    showToast('表达式无法计算')
  }
}

function formatNum(n) {
  if (Number.isInteger(n)) return n.toString()
  return parseFloat(n.toPrecision(12)).toString()
}
</script>

<style scoped>
.calc-display {
  background: #0f172a;
  color: #e2e8f0;
  border-radius: var(--radius);
  padding: 0.85rem 1rem;
  margin-bottom: 0.85rem;
  text-align: right;
  min-height: 64px;
}
.calc-expr {
  font-family: "SF Mono", Monaco, monospace;
  font-size: 1.05rem;
  word-break: break-all;
  min-height: 1.4em;
}
.calc-result {
  font-size: 1.35rem;
  font-weight: 700;
  color: #818cf8;
  margin-top: 0.2rem;
}
.calc-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 0.5rem;
}
.calc-btn {
  padding: 0.7rem 0;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--card-bg);
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s;
  color: var(--text);
}
.calc-btn:hover { background: var(--primary-light); border-color: var(--primary); }
.calc-btn.num { background: #f8fafc; }
.calc-btn.op { background: var(--primary); color: #fff; border-color: var(--primary); }
.calc-btn.op:hover { background: var(--primary-hover); }
.calc-btn.func { background: #eef2ff; color: var(--primary); }
.calc-btn.eq { background: var(--success); color: #fff; border-color: var(--success); grid-row: span 2; }
.calc-btn.eq:hover { filter: brightness(0.95); }
.calc-btn.zero { grid-column: span 1; }
.calc-hint {
  margin-top: 0.75rem;
  font-size: 0.75rem;
  color: var(--text-secondary);
}
.calc-hint code {
  background: #f1f5f9;
  padding: 0.05rem 0.35rem;
  border-radius: 4px;
}
</style>
