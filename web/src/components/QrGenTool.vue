<template>
  <div class="tool-panel">
    <h2>📱 二维码生成</h2>

    <div class="card">
      <div class="form-group">
        <label>内容（网址 / 文字 / WiFi / 名片 等）</label>
        <textarea class="input-textarea" v-model="content" @input="generate" rows="4" placeholder="https://example.com"></textarea>
      </div>

      <div class="form-row">
        <div class="form-group half">
          <label>尺寸</label>
          <select class="input-select" v-model="size" @change="generate">
            <option :value="160">160 px</option>
            <option :value="256">256 px</option>
            <option :value="320">320 px</option>
            <option :value="512">512 px</option>
          </select>
        </div>
        <div class="form-group half">
          <label>容错级别</label>
          <select class="input-select" v-model="ecl" @change="generate">
            <option value="L">L（7%）</option>
            <option value="M">M（15%）</option>
            <option value="Q">Q（25%）</option>
            <option value="H">H（30%）</option>
          </select>
        </div>
      </div>

      <div class="qr-preview" v-if="dataUrl">
        <img :src="dataUrl" :width="size" :height="size" alt="QR Code" />
      </div>
      <div class="error-box" v-else-if="content">生成失败，请检查内容</div>

      <div class="action-row" v-if="dataUrl">
        <a class="btn btn-primary btn-sm" :href="dataUrl" :download="downloadName">⬇ 下载 PNG</a>
        <button class="btn btn-outline btn-sm" @click="copy(content)">复制内容</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject } from 'vue'
import QRCode from 'qrcode'

const showToast = inject('showToast')
const content = ref('https://github.com')
const size = ref(256)
const ecl = ref('M')
const dataUrl = ref('')
const downloadName = ref('qrcode.png')

async function generate() {
  if (!content.value.trim()) { dataUrl.value = ''; return }
  try {
    dataUrl.value = await QRCode.toDataURL(content.value, {
      errorCorrectionLevel: ecl.value,
      width: size.value,
      margin: 1,
      color: { dark: '#1e293b', light: '#ffffff' }
    })
  } catch (e) {
    dataUrl.value = ''
  }
}
function copy(text) {
  navigator.clipboard.writeText(String(text)).then(() => showToast('已复制'))
}
generate()
</script>

<style scoped>
.qr-preview {
  display: flex; justify-content: center; padding: 1rem;
  background: #f8fafc; border: 1px solid var(--border); border-radius: var(--radius); margin-top: 0.5rem;
}
.qr-preview img { image-rendering: pixelated; border-radius: 4px; }
.action-row { display: flex; gap: 0.6rem; margin-top: 0.75rem; }
</style>
