<template>
  <div class="tool-panel">
    <h2>📷 二维码识别</h2>

    <div class="card">
      <div
        class="drop-zone"
        :class="{ dragging }"
        @dragover.prevent="dragging = true"
        @dragleave.prevent="dragging = false"
        @drop.prevent="onDrop"
        @click="$refs.fileInput.click()"
      >
        <input ref="fileInput" type="file" accept="image/*" hidden @change="onSelect" />
        <div class="drop-icon">📁</div>
        <div class="drop-text">点击选择图片，或将二维码图片拖拽到此处</div>
        <div class="drop-hint">支持 PNG / JPG / GIF / WebP，也可粘贴 (Ctrl+V)</div>
      </div>
    </div>

    <div v-if="preview" class="card">
      <h3>预览</h3>
      <img :src="preview" class="preview-img" alt="二维码预览" />
    </div>

    <div v-if="result !== null" class="card">
      <h3>识别结果</h3>
      <div v-if="result" class="result-box">
        <pre class="result-text">{{ result }}</pre>
        <div class="result-actions">
          <button class="btn-primary" @click="copy(result)">复制内容</button>
          <a v-if="isUrl" :href="result" target="_blank" rel="noopener" class="btn-secondary">打开链接</a>
        </div>
      </div>
      <div v-else class="empty-result">未在图片中检测到二维码，请换一张更清晰的图片。</div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, inject, onMounted, onUnmounted } from 'vue'
import jsQR from 'jsqr'

const showToast = inject('showToast')
const dragging = ref(false)
const preview = ref('')
const result = ref(null)

const isUrl = computed(() => /^https?:\/\//i.test(result.value || ''))

function handleFile(file) {
  if (!file || !file.type.startsWith('image/')) { showToast('请选择图片文件'); return }
  const reader = new FileReader()
  reader.onload = e => {
    preview.value = e.target.result
    decode(e.target.result)
  }
  reader.readAsDataURL(file)
}

function decode(dataUrl) {
  const img = new Image()
  img.onload = () => {
    const canvas = document.createElement('canvas')
    canvas.width = img.width
    canvas.height = img.height
    const ctx = canvas.getContext('2d')
    ctx.drawImage(img, 0, 0)
    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height)
    const code = jsQR(imgData.data, imgData.width, imgData.height)
    result.value = code ? code.data : ''
    if (code) showToast('识别成功')
  }
  img.src = dataUrl
}

function onSelect(e) { handleFile(e.target.files[0]) }
function onDrop(e) { dragging.value = false; handleFile(e.dataTransfer.files[0]) }
function onPaste(e) {
  const item = [...(e.clipboardData?.items || [])].find(i => i.type.startsWith('image/'))
  if (item) handleFile(item.getAsFile())
}
function copy(text) { navigator.clipboard.writeText(text).then(() => showToast('已复制')) }

onMounted(() => window.addEventListener('paste', onPaste))
onUnmounted(() => window.removeEventListener('paste', onPaste))
</script>

<style scoped>
.drop-zone {
  border: 2px dashed var(--border); border-radius: var(--radius); padding: 2.5rem 1rem;
  text-align: center; cursor: pointer; transition: all 0.2s; background: #f8fafc;
}
.drop-zone:hover, .drop-zone.dragging { border-color: var(--primary); background: rgba(79,70,229,0.04); }
.drop-icon { font-size: 2.5rem; margin-bottom: 0.5rem; }
.drop-text { font-size: 0.95rem; color: var(--text); font-weight: 500; }
.drop-hint { font-size: 0.78rem; color: var(--text-secondary); margin-top: 0.35rem; }
.preview-img { max-width: 260px; max-height: 260px; border-radius: var(--radius); border: 1px solid var(--border); }
.result-box { display: flex; flex-direction: column; gap: 0.75rem; }
.result-text {
  background: #f8fafc; border: 1px solid var(--border); border-radius: var(--radius);
  padding: 0.9rem 1rem; font-size: 0.9rem; word-break: break-all; white-space: pre-wrap; margin: 0; color: var(--text);
}
.result-actions { display: flex; gap: 0.6rem; }
.empty-result { color: var(--text-secondary); font-size: 0.9rem; }
</style>
