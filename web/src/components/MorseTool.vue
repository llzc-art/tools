<template>
  <div class="tool-panel">
    <h2>📻 摩斯密码</h2>

    <div class="card">
      <div class="form-group">
        <label>文本 → 摩斯</label>
        <textarea class="input-textarea" v-model="text" @input="encode" rows="3" placeholder="输入文字，自动转换为摩斯密码"></textarea>
      </div>
      <div class="result-box" v-if="morse">
        <div class="result-value" @click="copy(morse)">{{ morse }}</div>
        <button class="btn btn-primary btn-sm" style="margin-top:0.5rem" @click="play">▶ 播放</button>
      </div>
    </div>

    <div class="card">
      <div class="form-group">
        <label>摩斯 → 文本</label>
        <textarea class="input-textarea" v-model="morseInput" @input="decode" rows="3" placeholder="输入摩斯密码，用空格分隔字母，用 / 分隔单词"></textarea>
      </div>
      <div class="result-box" v-if="decoded">
        <div class="result-value" @click="copy(decoded)">{{ decoded }}</div>
      </div>
      <div class="error-box" v-else-if="decodeError">无法解析的摩斯片段</div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject } from 'vue'

const showToast = inject('showToast')

const MAP = {
  A:'.-',B:'-...',C:'-.-.',D:'-..',E:'.',F:'..-.',G:'--.',H:'....',I:'..',J:'.---',K:'-.-',
  L:'.-..',M:'--',N:'-.',O:'---',P:'.--.',Q:'--.-',R:'.-.',S:'...',T:'-',U:'..-',V:'...-',
  W:'.--',X:'-..-',Y:'-.--',Z:'--..',
  '0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..','9':'----.',
  '.':'.-.-.-',',':'--..--','?':'..--..',"'":'.----.','!':'-.-.--','/':'-..-.','(':'-.--.',')':'-.--.-'
}
const REV = Object.fromEntries(Object.entries(MAP).map(([k,v]) => [v,k]))

const text = ref('SOS')
const morse = ref('')
const morseInput = ref('')
const decoded = ref('')
const decodeError = ref(false)

function encode() {
  morse.value = text.value.toUpperCase().split('').map(ch => {
    if (ch === ' ') return '/'
    return MAP[ch] || ''
  }).filter(p => p !== '').join(' ')
  morseInput.value = morse.value
  decode()
}
function decode() {
  decoded.value = ''
  decodeError.value = false
  const raw = morseInput.value.trim()
  if (!raw) return
  const words = raw.split('/')
  let out = ''
  for (const w of words) {
    const letters = w.trim().split(/\s+/)
    for (const l of letters) {
      if (l === '') continue
      const ch = REV[l]
      if (!ch) { decodeError.value = true; return }
      out += ch
    }
    out += ' '
  }
  decoded.value = out.trim()
}

function play() {
  if (!morse.value) return
  const ctx = new (window.AudioContext || window.webkitAudioContext)()
  const seq = morse.value.replace(/\//g, '   ').split('')
  let t = ctx.currentTime + 0.05
  const dot = 0.08
  for (const c of seq) {
    if (c === '.') {
      beep(ctx, t, dot); t += dot + dot
    } else if (c === '-') {
      beep(ctx, t, dot * 3); t += dot * 3 + dot
    } else {
      t += dot * 2
    }
  }
}
function beep(ctx, start, dur) {
  const osc = ctx.createOscillator()
  const gain = ctx.createGain()
  osc.frequency.value = 620
  osc.connect(gain); gain.connect(ctx.destination)
  gain.gain.setValueAtTime(0.2, start)
  gain.gain.exponentialRampToValueAtTime(0.001, start + dur)
  osc.start(start); osc.stop(start + dur)
}

function copy(text) {
  navigator.clipboard.writeText(String(text)).then(() => showToast('已复制'))
}

encode()
</script>

<style scoped>
</style>
