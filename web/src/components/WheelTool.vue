<template>
  <div class="tool-panel">
    <h2>🎯 抽奖转盘</h2>

    <div class="card wheel-card">
      <div class="wheel-wrap">
        <div class="wheel-pointer">▼</div>
        <canvas ref="canvas" width="320" height="320" class="wheel-canvas"></canvas>
      </div>

      <div class="wheel-side">
        <div class="form-group">
          <label>候选项（每行一个）</label>
          <textarea class="input-textarea" v-model="namesText" rows="7" @input="redraw" placeholder="一等奖&#10;二等奖&#10;三等奖&#10;谢谢参与"></textarea>
        </div>
        <button class="btn btn-primary" :disabled="spinning" @click="spin">{{ spinning ? '抽奖中...' : '🎡 开始抽奖' }}</button>
        <div class="winner-box" v-if="winner">
          <div class="winner-label">恭喜抽中</div>
          <div class="winner-name" @click="copy(winner)">{{ winner }}</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, inject } from 'vue'

const showToast = inject('showToast')
const canvas = ref(null)
const namesText = ref('一等奖\n二等奖\n三等奖\n谢谢参与')
const rotation = ref(0)
const spinning = ref(false)
const winner = ref('')

const names = computed(() => namesText.value.split('\n').map(s => s.trim()).filter(s => s))
const COLORS = ['#4f46e5','#ec4899','#10b981','#f59e0b','#06b6d4','#8b5cf6','#ef4444','#14b8a6']

function draw() {
  const cv = canvas.value
  if (!cv) return
  const ctx = cv.getContext('2d')
  const n = names.value.length || 1
  const seg = (Math.PI * 2) / n
  const cx = cv.width / 2, cy = cv.height / 2, r = cv.width / 2 - 4
  ctx.clearRect(0, 0, cv.width, cv.height)
  ctx.save()
  ctx.translate(cx, cy)
  ctx.rotate(rotation.value)
  for (let i = 0; i < n; i++) {
    ctx.beginPath()
    ctx.moveTo(0, 0)
    ctx.arc(0, 0, r, i * seg, (i + 1) * seg)
    ctx.closePath()
    ctx.fillStyle = COLORS[i % COLORS.length]
    ctx.fill()
    ctx.fillStyle = '#fff'
    ctx.font = 'bold 14px sans-serif'
    ctx.textAlign = 'right'
    ctx.textBaseline = 'middle'
    ctx.save()
    ctx.rotate(i * seg + seg / 2)
    ctx.translate(r - 12, 0)
    const label = names.value[i] || ''
    ctx.fillText(label.length > 8 ? label.slice(0, 8) + '…' : label, 0, 0)
    ctx.restore()
  }
  ctx.restore()
  // center hub
  ctx.beginPath()
  ctx.arc(cx, cy, 22, 0, Math.PI * 2)
  ctx.fillStyle = '#fff'
  ctx.fill()
  ctx.strokeStyle = '#ccc'
  ctx.stroke()
}

function redraw() { winner.value = ''; draw() }

function spin() {
  if (spinning.value || names.value.length < 2) { showToast('请至少填写 2 个候选项'); return }
  spinning.value = true
  winner.value = ''
  const n = names.value.length
  const seg = (Math.PI * 2) / n
  const extraSpins = 5 + Math.floor(Math.random() * 5) // 必须为整数圈，否则停止角度会偏移导致指针与结果不一致
  const targetIndex = Math.floor(Math.random() * n)
  // we want sector targetIndex to land at top (-PI/2)
  const targetRot = -Math.PI / 2 - (targetIndex * seg + seg / 2)
  const startRot = rotation.value
  let endRot = startRot + extraSpins * Math.PI * 2
  // align endRot mod 2π to targetRot
  const startMod = ((startRot % (Math.PI * 2)) + Math.PI * 2) % (Math.PI * 2)
  let delta = ((targetRot - startMod) % (Math.PI * 2) + Math.PI * 2) % (Math.PI * 2)
  endRot += delta
  const duration = 3200
  const t0 = performance.now()
  function frame(now) {
    const p = Math.min(1, (now - t0) / duration)
    const eased = 1 - Math.pow(1 - p, 3)
    rotation.value = startRot + (endRot - startRot) * eased
    draw()
    if (p < 1) requestAnimationFrame(frame)
    else {
      rotation.value = ((endRot % (Math.PI * 2)) + Math.PI * 2) % (Math.PI * 2)
      spinning.value = false
      winner.value = names.value[targetIndex]
      draw()
    }
  }
  requestAnimationFrame(frame)
}

function copy(text) {
  navigator.clipboard.writeText(String(text)).then(() => showToast('已复制: ' + text))
}

onMounted(draw)
</script>

<style scoped>
.wheel-card { display: flex; gap: 1.5rem; flex-wrap: wrap; }
.wheel-wrap { position: relative; flex-shrink: 0; }
.wheel-canvas { border-radius: 50%; box-shadow: var(--shadow); display: block; }
.wheel-pointer {
  position: absolute; top: -6px; left: 50%; transform: translateX(-50%);
  font-size: 1.6rem; color: var(--error); z-index: 2; filter: drop-shadow(0 1px 2px rgba(0,0,0,0.3));
}
.wheel-side { flex: 1; min-width: 240px; }
.winner-box { margin-top: 1rem; text-align: center; padding: 0.75rem; background: #fef9c3; border: 1px solid #fde047; border-radius: var(--radius); }
.winner-label { font-size: 0.78rem; color: #854d0e; }
.winner-name { font-size: 1.3rem; font-weight: 800; color: #854d0e; cursor: pointer; }
</style>
