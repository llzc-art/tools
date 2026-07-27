<template>
  <div class="tool-panel">
    <h2>🔊 文字转语音</h2>

    <div class="card">
      <div class="form-group">
        <label>输入要朗读的文字</label>
        <textarea class="input-textarea" v-model="text" rows="6" placeholder="输入任意文字，点击播放即可朗读..."></textarea>
      </div>

      <div class="form-row">
        <div class="form-group half">
          <label>语音</label>
          <select class="input-select" v-model="voiceURI">
            <option value="">默认语音</option>
            <option v-for="v in voices" :key="v.voiceURI" :value="v.voiceURI">{{ v.name }}（{{ v.lang }}）</option>
          </select>
        </div>
      </div>

      <div class="form-group">
        <label>语速：{{ rate.toFixed(1) }}</label>
        <input type="range" min="0.5" max="2" step="0.1" v-model.number="rate" class="slider" />
      </div>
      <div class="form-group">
        <label>音调：{{ pitch.toFixed(1) }}</label>
        <input type="range" min="0" max="2" step="0.1" v-model.number="pitch" class="slider" />
      </div>

      <div class="btn-group">
        <button class="btn btn-primary" @click="play" :disabled="playing && !paused">▶ 播放</button>
        <button class="btn btn-outline" @click="togglePause" :disabled="!playing">{{ paused ? '▶ 继续' : '⏸ 暂停' }}</button>
        <button class="btn btn-outline" @click="stop" :disabled="!playing">⏹ 停止</button>
      </div>
      <div class="tts-hint" v-if="!supported">当前浏览器不支持语音合成（SpeechSynthesis）</div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, inject } from 'vue'

const showToast = inject('showToast')
const text = ref('你好，欢迎使用攻城师天梯的文字转语音功能。')
const voices = ref([])
const voiceURI = ref('')
const rate = ref(1)
const pitch = ref(1)
const playing = ref(false)   // 是否有朗读任务（含暂停中）
const paused = ref(false)    // 是否处于暂停
const supported = ref(true)
let utter = null

function loadVoices() {
  if (!('speechSynthesis' in window)) { supported.value = false; return }
  voices.value = window.speechSynthesis.getVoices()
}
function play() {
  if (!supported.value) return showToast('浏览器不支持')
  if (!text.value.trim()) return showToast('请输入文字')
  // 暂停中点「播放」= 继续朗读，而不是从头开始
  if (playing.value && paused.value) {
    window.speechSynthesis.resume()
    paused.value = false
    return
  }
  window.speechSynthesis.cancel()
  utter = new SpeechSynthesisUtterance(text.value)
  utter.rate = rate.value
  utter.pitch = pitch.value
  if (voiceURI.value) {
    const v = voices.value.find(x => x.voiceURI === voiceURI.value)
    if (v) utter.voice = v
  }
  utter.onend = () => { playing.value = false; paused.value = false }
  utter.onerror = () => { playing.value = false; paused.value = false }
  window.speechSynthesis.speak(utter)
  playing.value = true
  paused.value = false
}
function togglePause() {
  if (!playing.value) return
  if (paused.value) {
    window.speechSynthesis.resume()
    paused.value = false
  } else {
    window.speechSynthesis.pause()
    paused.value = true
  }
}
function stop() { window.speechSynthesis.cancel(); playing.value = false; paused.value = false }

onMounted(() => {
  loadVoices()
  if ('speechSynthesis' in window) {
    window.speechSynthesis.onvoiceschanged = loadVoices
  }
})
</script>

<style scoped>
.slider { width: 100%; accent-color: var(--primary); }
.tts-hint { margin-top: 0.5rem; font-size: 0.78rem; color: var(--error); }
</style>
