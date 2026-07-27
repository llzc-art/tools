<template>
  <div class="tool-panel">
    <h2>📸 证件照生成</h2>

    <div class="idphoto-layout">
      <!-- 左侧设置 -->
      <div class="idphoto-settings">
        <div class="card">
          <h3>上传图片</h3>
          <div 
            class="upload-area"
            @click="triggerUpload"
            @dragover.prevent="onDragOver"
            @dragleave="onDragLeave"
            @drop.prevent="onDrop"
            :class="{ 'drag-over': isDragOver }"
          >
            <input 
              ref="fileInput" 
              type="file" 
              accept="image/*" 
              @change="onFileSelect" 
              style="display: none"
            />
            <div v-if="!previewUrl" class="upload-hint">
              <div class="upload-icon">📷</div>
              <p>点击或拖拽上传照片</p>
              <p class="upload-tip">支持 JPG、PNG、WebP 格式</p>
            </div>
            <img v-else :src="previewUrl" class="preview-image" alt="预览" />
          </div>
          <div v-if="previewUrl" class="btn-row">
            <button class="btn btn-outline" @click="resetImage">重新上传</button>
          </div>
        </div>

        <div class="card">
          <h3>证件照规格</h3>
          
          <div class="form-group">
            <label>常见规格</label>
            <select v-model="selectedPreset" class="input-select" @change="applyPreset">
              <option value="">自定义尺寸</option>
              <option value="一寸">一寸 (25mm × 35mm / 295 × 413px)</option>
              <option value="二寸">二寸 (35mm × 49mm / 413 × 579px)</option>
              <option value="小一寸">小一寸 (22mm × 32mm / 260 × 378px)</option>
              <option value="大一寸">大一寸 (26mm × 37mm / 306 × 437px)</option>
              <option value="驾驶证">驾驶证 (22mm × 32mm / 260 × 378px)</option>
              <option value="身份证">身份证 (26mm × 32mm / 358 × 441px)</option>
              <option value="护照">护照 (33mm × 48mm / 354 × 472px)</option>
              <option value="签证">签证 (33mm × 48mm / 354 × 472px)</option>
              <option value="港澳通行证">港澳通行证 (33mm × 48mm / 354 × 472px)</option>
              <option value="考研">考研 (33mm × 48mm / 390 × 567px)</option>
              <option value="公务员">公务员 (35mm × 45mm / 413 × 531px)</option>
            </select>
          </div>

          <div class="form-row">
            <div class="form-group half">
              <label>宽度 (px)</label>
              <input v-model.number="photoWidth" type="number" min="50" max="2000" class="input-text" />
            </div>
            <div class="form-group half">
              <label>高度 (px)</label>
              <input v-model.number="photoHeight" type="number" min="50" max="2000" class="input-text" />
            </div>
          </div>

          <div class="form-group">
            <label>分辨率 (DPI)</label>
            <select v-model.number="dpi" class="input-select">
              <option :value="300">300 DPI（标准印刷）</option>
              <option :value="150">150 DPI（普通打印）</option>
              <option :value="96">96 DPI（屏幕显示）</option>
            </select>
          </div>
        </div>

        <div class="card">
          <h3>背景设置</h3>
          <div class="bg-options">
            <label 
              v-for="bg in backgroundOptions" 
              :key="bg.value"
              :class="['bg-option', { active: backgroundColor === bg.value }]"
            >
              <input type="radio" v-model="backgroundColor" :value="bg.value" />
              <span class="bg-color" :style="{ background: bg.color }"></span>
              <span>{{ bg.label }}</span>
            </label>
          </div>
          
          <div v-if="backgroundColor === 'custom'" class="form-group">
            <label>自定义颜色</label>
            <div class="color-picker">
              <input type="color" v-model="customColor" class="color-input" />
              <input type="text" v-model="customColor" class="input-text" placeholder="#FFFFFF" />
            </div>
          </div>
        </div>

        <div class="card">
          <h3>输出设置</h3>
          <div class="form-group">
            <label>处理引擎</label>
            <select v-model="processMode" class="input-select">
              <option value="frontend">前端AI抠图（推荐）</option>
              <option value="backend">后端算法（快速，无需下载模型）</option>
            </select>
          </div>
          <div class="form-group" v-if="processMode === 'frontend'">
            <label>抠图模型</label>
            <select v-model="modelType" class="input-select">
              <option v-for="m in modelOptions" :key="m.value" :value="m.value">{{ m.label }}</option>
            </select>
            <p class="form-hint">{{ currentModelDesc }}</p>
          </div>
          <div class="form-group" v-if="processMode === 'frontend'">
            <label>模型来源</label>
            <select v-model="modelSource" class="input-select" @change="onModelSourceChange">
              <option value="remote">在线下载（ModelScope）</option>
              <option value="local">本地文件加载</option>
            </select>
          </div>
          <div class="form-group" v-if="processMode === 'frontend' && modelSource === 'remote'">
            <label>模型下载地址（可选）</label>
            <input
              v-model="customModelUrl"
              type="text"
              class="input-text"
              :placeholder="currentModelPlaceholder"
            />
            <p class="form-hint">
              留空则自动从 ModelScope（魔搭社区）下载。如下载失败，可<strong>自行托管模型</strong>后填入地址
            </p>
          </div>
          <div class="form-group" v-if="processMode === 'frontend' && modelSource === 'local'">
            <label>抠图模型文件（.onnx）</label>
            <div class="local-file-row">
              <input
                ref="modelFileInput"
                type="file"
                accept=".onnx"
                @change="onModelFileSelect"
                style="display: none"
              />
              <button class="btn btn-outline btn-sm" @click="triggerModelFileSelect">
                📁 选择文件
              </button>
              <span class="file-name" :class="{ 'file-set': !!localModelFile }">
                {{ localModelFile ? localModelFile.name : '未选择文件' }}
              </span>
            </div>
            <p class="form-hint">
              选择本地下载好的 <strong>.onnx</strong> 模型文件，跳过网络下载
            </p>
          </div>
          <div class="form-group" v-if="processMode === 'frontend' && modelSource === 'local'">
            <label>SCRFD-10G-BNKPS 人脸检测模型（可选，.onnx）</label>
            <div class="local-file-row">
              <input
                ref="faceModelFileInput"
                type="file"
                accept=".onnx"
                @change="onFaceModelFileSelect"
                style="display: none"
              />
              <button class="btn btn-outline btn-sm" @click="triggerFaceModelFileSelect">
                📁 选择文件
              </button>
              <span class="file-name" :class="{ 'file-set': !!localFaceModelFile }">
                {{ localFaceModelFile ? localFaceModelFile.name : '未选择（将从在线下载）' }}
              </span>
            </div>
            <p class="form-hint">
              可选。不选则自动从在线下载 SCRFD-10G-BNKPS 模型（~17MB）
            </p>
          </div>
          <div class="form-group" v-if="processMode === 'frontend'">
            <label>人脸矫正</label>
            <select v-model="alignFace" class="input-select">
              <option :value="true">启用 SCRFD-10G-BNKPS 人脸检测+旋转矫正（推荐）</option>
              <option :value="false">关闭（跳过旋转矫正，速度更快）</option>
            </select>
            <p class="form-hint">
              基于 SCRFD-10G-BNKPS 检测人脸 5 关键点，矫正倾斜头部。模型仅 ~17MB，对加载速度影响极小
            </p>
          </div>
          <div class="form-group">
            <label>输出格式</label>
            <select v-model="outputFormat" class="input-select">
              <option value="jpeg">JPEG（推荐，体积小）</option>
              <option value="png">PNG（无损，支持透明）</option>
            </select>
          </div>
          <div class="form-group">
            <label>边缘羽化</label>
            <select v-model.number="feathering" class="input-select">
              <option :value="0">无羽化</option>
              <option :value="1">轻微</option>
              <option :value="2">适中（推荐）</option>
              <option :value="3">较强</option>
              <option :value="4">强</option>
              <option :value="5">最强</option>
            </select>
          </div>
        </div>

        <div class="btn-row">
          <button class="btn btn-primary" @click="generatePhoto" :disabled="!previewUrl || loading">
            <span v-if="loading" class="loading-text">
              {{ stageLabels[progressStage] || '处理中' }}...
              <span v-if="progressPercent > 0" class="progress-badge">{{ progressPercent }}%</span>
            </span>
            <span v-else>🔧 生成证件照</span>
          </button>
        </div>
      </div>

      <!-- 右侧预览 -->
      <div class="idphoto-preview">
        <div class="card preview-card">
          <h3>预览效果</h3>
          <div class="preview-container" :style="previewStyle">
            <canvas ref="canvas" :width="photoWidth" :height="photoHeight"></canvas>
          </div>
          <div class="preview-info">
            <p>{{ photoWidth }} × {{ photoHeight }} px | {{ dpi }} DPI | {{ outputFormat.toUpperCase() }}</p>
          </div>
        </div>

        <div v-if="generatedUrl" class="card download-card">
          <h3>生成结果</h3>
          <div class="result-actions">
            <div class="download-preview">
              <img :src="generatedUrl" alt="生成结果" />
            </div>
            <div class="btn-column">
              <button class="btn btn-primary" @click="downloadPhoto">
                📥 下载证件照
              </button>
              <button class="btn btn-outline" @click="showPrintLayout = true">
                🖨️ 排版打印
              </button>
            </div>
          </div>
        </div>

        <!-- 排版打印弹窗 -->
        <div v-if="showPrintLayout" class="modal-overlay" @click.self="showPrintLayout = false">
          <div class="modal-content card">
            <div class="modal-header">
              <h3>🖨️ 排版打印</h3>
              <button class="modal-close" @click="showPrintLayout = false">✕</button>
            </div>
            <div class="modal-body">
              <div class="form-group">
                <label>相纸尺寸</label>
                <select v-model="printConfig.paperSize" class="input-select">
                  <option value="5inch">5寸 (3.5 × 5 英寸)</option>
                  <option value="6inch">6寸 (4 × 6 英寸)</option>
                  <option value="A4">A4 (8.27 × 11.69 英寸)</option>
                </select>
              </div>
              <div class="form-row">
                <div class="form-group half">
                  <label>列数</label>
                  <input v-model.number="printConfig.columns" type="number" min="1" max="10" class="input-text" placeholder="自动" />
                </div>
                <div class="form-group half">
                  <label>行数</label>
                  <input v-model.number="printConfig.rows" type="number" min="1" max="10" class="input-text" placeholder="自动" />
                </div>
              </div>
              <div class="form-group">
                <label>间距 (px)</label>
                <input v-model.number="printConfig.gap" type="number" min="0" max="100" class="input-text" />
              </div>
              <div class="print-preview-hint">
                <p v-if="printConfig.paperSize === '5inch'">5寸相纸: 1500 × 1050 px (300DPI)</p>
                <p v-else-if="printConfig.paperSize === '6inch'">6寸相纸: 1800 × 1200 px (300DPI)</p>
                <p v-else>A4相纸: 2480 × 3508 px (300DPI)</p>
                <p class="hint-sub">留空列数/行数将自动计算最优排版</p>
              </div>
              <div class="btn-row">
                <button class="btn btn-primary" @click="generatePrintLayout" :disabled="printLoading">
                  <span v-if="printLoading">生成中...</span>
                  <span v-else>生成排版图</span>
                </button>
              </div>
            </div>

            <div v-if="printResultUrl" class="print-result">
              <div class="download-preview">
                <img :src="printResultUrl" alt="排版结果" />
              </div>
              <div class="btn-row">
                <button class="btn btn-primary" @click="downloadPrintLayout">
                  📥 下载排版图
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, inject } from 'vue'
import { apiPost } from '../api.js'
import { 
  generateIDPhoto, 
  generatePrintLayout as generatePrintLayoutFrontend,
  MODEL_CONFIGS,
} from '../idphotoProcessor.js'

const showToast = inject('showToast')

// 上传相关
const fileInput = ref(null)
const previewUrl = ref('')
const isDragOver = ref(false)
const selectedFile = ref(null)
const loading = ref(false)

// 处理模式：frontend=前端AI抠图, backend=后端处理
const processMode = ref('frontend')

// 处理进度
const progressStage = ref('')
const progressPercent = ref(0)

// 尺寸设置
const selectedPreset = ref('')
const photoWidth = ref(295)
const photoHeight = ref(413)
const dpi = ref(300)

// 背景设置
const backgroundColor = ref('white')
const customColor = ref('#FFFFFF')
const backgroundOptions = [
  { label: '白色', value: 'white', color: '#FFFFFF' },
  { label: '蓝色', value: 'blue', color: '#439BDB' },
  { label: '红色', value: 'red', color: '#E66464' },
  { label: '深蓝', value: 'blue3', color: '#3575BB' },
  { label: '浅灰', value: 'gray', color: '#E6E6E6' },
  { label: '自定义', value: 'custom', color: '' },
]

// 输出设置
const outputFormat = ref('jpeg')
const feathering = ref(2)

// 模型设置
const modelType = ref('modnet')
const customModelUrl = ref('')
const alignFace = ref(true)
const modelSource = ref('remote') // 'remote' = 在线下载, 'local' = 本地文件
const localModelFile = ref(null)       // 本地抠图模型文件
const localFaceModelFile = ref(null)   // 本地 SCRFD-10G-BNKPS 人脸检测模型文件（可选）
const modelFileInput = ref(null)
const faceModelFileInput = ref(null)
const modelOptions = Object.entries(MODEL_CONFIGS).map(([value, config]) => ({
  value,
  label: config.label,
  desc: config.desc,
}))
const currentModelDesc = computed(() => {
  return MODEL_CONFIGS[modelType.value]?.desc || ''
})
const currentModelPlaceholder = computed(() => {
  const cfg = MODEL_CONFIGS[modelType.value]
  return cfg?.urls?.[0] || '请输入模型文件的直链下载地址'
})

// 生成结果
const canvas = ref(null)
const generatedUrl = ref('')
const generatedImageBase64 = ref('')

// 排版打印
const showPrintLayout = ref(false)
const printLoading = ref(false)
const printResultUrl = ref('')
const printConfig = ref({
  paperSize: '5inch',
  columns: 0,
  rows: 0,
  gap: 20,
})

const previewStyle = computed(() => ({
  width: Math.min(photoWidth.value, 300) + 'px',
  height: Math.min(photoHeight.value, 400) + 'px',
}))

// 进度文案映射
const stageLabels = {
  downloading_model: '下载模型中',
  loading_model: '加载模型中',
  face_detect: '人脸检测中',
  removing_bg: 'AI 抠图中',
  cropping: '智能裁剪中',
  compositing: '合成背景中',
  encoding: '编码输出中',
  done: '完成',
}

function triggerUpload() {
  fileInput.value?.click()
}

function onFileSelect(e) {
  const file = e.target.files?.[0]
  if (file) handleFile(file)
}

function onDragOver(e) {
  isDragOver.value = true
}

function onDragLeave() {
  isDragOver.value = false
}

function onDrop(e) {
  isDragOver.value = false
  const file = e.dataTransfer.files?.[0]
  if (file && file.type.startsWith('image/')) {
    handleFile(file)
  }
}

function handleFile(file) {
  selectedFile.value = file
  const reader = new FileReader()
  reader.onload = (e) => {
    previewUrl.value = e.target.result
    generatedUrl.value = ''
    generatedImageBase64.value = ''
  }
  reader.readAsDataURL(file)
}

function resetImage() {
  previewUrl.value = ''
  generatedUrl.value = ''
  generatedImageBase64.value = ''
  printResultUrl.value = ''
  progressStage.value = ''
  progressPercent.value = 0
  selectedFile.value = null
  selectedPreset.value = ''
  fileInput.value.value = ''
}

function applyPreset() {
  const presets = {
    '一寸': { width: 295, height: 413 },
    '二寸': { width: 413, height: 579 },
    '小一寸': { width: 260, height: 378 },
    '大一寸': { width: 306, height: 437 },
    '驾驶证': { width: 260, height: 378 },
    '身份证': { width: 358, height: 441 },
    '护照': { width: 354, height: 472 },
    '签证': { width: 354, height: 472 },
    '港澳通行证': { width: 354, height: 472 },
    '考研': { width: 390, height: 567 },
    '公务员': { width: 413, height: 531 },
  }
  const preset = presets[selectedPreset.value]
  if (preset) {
    photoWidth.value = preset.width
    photoHeight.value = preset.height
  }
}

// 本地模型文件选择
function triggerModelFileSelect() {
  modelFileInput.value?.click()
}

function onModelFileSelect(e) {
  const file = e.target.files?.[0]
  if (!file) return
  if (!file.name.toLowerCase().endsWith('.onnx')) {
    showToast('请选择 .onnx 格式的模型文件')
    return
  }
  localModelFile.value = file
  showToast(`已选择抠图模型: ${file.name}`)
}

function triggerFaceModelFileSelect() {
  faceModelFileInput.value?.click()
}

function onFaceModelFileSelect(e) {
  const file = e.target.files?.[0]
  if (!file) return
  if (!file.name.toLowerCase().endsWith('.onnx')) {
    showToast('请选择 .onnx 格式的模型文件')
    return
  }
  localFaceModelFile.value = file
  showToast(`已选择人脸检测模型(SCRFD-10G-BNKPS): ${file.name}`)
}

// 切换模型来源时清除已选文件
function onModelSourceChange() {
  if (modelSource.value === 'remote') {
    localModelFile.value = null
    localFaceModelFile.value = null
  }
}

async function generatePhoto() {
  if (!selectedFile.value) return

  loading.value = true
  progressStage.value = 'removing_bg'
  progressPercent.value = 0

  try {
    if (processMode.value === 'frontend') {
      await generatePhotoFrontend()
    } else {
      await generatePhotoBackend()
    }
  } catch (error) {
    console.error('处理失败:', error)
    // 前端AI失败时自动回退到后端
    if (processMode.value === 'frontend') {
      showToast('前端AI处理失败，自动切换到后端处理')
      try {
        await generatePhotoBackend()
      } catch (e2) {
        showToast('处理失败，请重试')
      }
    } else {
      showToast('处理失败，请重试')
    }
  } finally {
    loading.value = false
    progressStage.value = ''
    progressPercent.value = 0
  }
}

// 前端 AI 抠图流程
async function generatePhotoFrontend() {
  // 本地文件模式校验
  if (modelSource.value === 'local' && !localModelFile.value) {
    showToast('请先选择本地抠图模型文件（.onnx）')
    return
  }

  // BiRefNet-RMBG2 (~366MB INT8) 在浏览器 wasm 中无法加载（OOM），
  // 直接走 Go 后端 ONNX Runtime 推理
  if (modelType.value === 'birefnet') {
    showToast('BiRefNet-RMBG2 由后端 ONNX Runtime 推理中（约 10-30 秒）...')
    return await generatePhotoBackend()
  }

  const result = await generateIDPhoto(selectedFile.value, {
    width: photoWidth.value,
    height: photoHeight.value,
    background: backgroundColor.value,
    customColor: customColor.value,
    feathering: feathering.value,
    outputFormat: outputFormat.value,
    modelType: modelType.value,
    modelUrl: modelSource.value === 'remote' ? (customModelUrl.value || undefined) : undefined,
    modelFile: modelSource.value === 'local' ? localModelFile.value : undefined,
    faceModelFile: modelSource.value === 'local' ? (localFaceModelFile.value || undefined) : undefined,
    alignFace: alignFace.value,
    onProgress: ({ stage, progress }) => {
      progressStage.value = stage
      progressPercent.value = Math.round(progress * 100)
    },
  })

  generatedUrl.value = result.dataUrl
  generatedImageBase64.value = result.base64
  showToast('证件照生成成功（前端AI抠图）')

  // 更新 Canvas 预览
  updateCanvasPreview(result.dataUrl)
}

// 后端处理流程（备选）
async function generatePhotoBackend() {
  progressStage.value = 'backend'
  progressPercent.value = 50

  const formData = new FormData()
  formData.append('image', selectedFile.value)
  formData.append('width', photoWidth.value.toString())
  formData.append('height', photoHeight.value.toString())
  formData.append('background', backgroundColor.value)
  formData.append('custom_color', customColor.value)
  formData.append('dpi', dpi.value.toString())
  formData.append('output_format', outputFormat.value)
  formData.append('feathering', feathering.value.toString())
  // BiRefNet-RMBG2 高精发丝级模型：前端 wasm 无法运行 ~350MB 大模型，
  // 必须走 Go 后端 ONNX Runtime 推理
  formData.append('use_birefnet', modelType.value === 'birefnet' ? 'true' : 'false')

  const response = await fetch('/api/idphoto/process', {
    method: 'POST',
    body: formData,
  })

  const result = await response.json()

  if (result.code === 0) {
    const mimeType = result.data.format === 'png' ? 'image/png' : 'image/jpeg'
    generatedUrl.value = `data:${mimeType};base64,${result.data.image}`
    generatedImageBase64.value = result.data.image
    showToast('证件照生成成功（后端处理）')
    updateCanvasPreview(generatedUrl.value)
  } else {
    throw new Error(result.message || '处理失败')
  }
}

// 更新 Canvas 预览
function updateCanvasPreview(dataUrl) {
  if (!canvas.value) return
  const ctx = canvas.value.getContext('2d')
  const img = new Image()
  img.onload = () => {
    canvas.value.width = photoWidth.value
    canvas.value.height = photoHeight.value
    ctx.drawImage(img, 0, 0, photoWidth.value, photoHeight.value)
  }
  img.src = dataUrl
}

// 排版打印 - 前端 Canvas 实现
async function generatePrintLayout() {
  if (!generatedUrl.value) {
    showToast('请先生成证件照')
    return
  }

  printLoading.value = true
  printResultUrl.value = ''

  try {
    const result = await generatePrintLayoutFrontend(generatedUrl.value, {
      photoWidth: photoWidth.value,
      photoHeight: photoHeight.value,
      paperSize: printConfig.value.paperSize,
      columns: printConfig.value.columns || 0,
      rows: printConfig.value.rows || 0,
      gap: printConfig.value.gap,
    })

    printResultUrl.value = result.dataUrl
    showToast('排版图生成成功')
  } catch (error) {
    console.error('排版失败:', error)
    // 前端失败时回退到后端
    try {
      await generatePrintLayoutBackend()
    } catch (e2) {
      showToast('排版失败，请重试')
    }
  } finally {
    printLoading.value = false
  }
}

// 排版打印 - 后端实现（备选）
async function generatePrintLayoutBackend() {
  const result = await apiPost('/api/idphoto/print-layout', {
    image: generatedImageBase64.value,
    photo_width: photoWidth.value,
    photo_height: photoHeight.value,
    paper_size: printConfig.value.paperSize,
    columns: printConfig.value.columns || 0,
    rows: printConfig.value.rows || 0,
    gap: printConfig.value.gap,
  })

  if (result.code === 0) {
    printResultUrl.value = `data:image/jpeg;base64,${result.data.image}`
    showToast('排版图生成成功')
  } else {
    throw new Error(result.message || '排版失败')
  }
}

function downloadPhoto() {
  if (!generatedUrl.value) return
  
  const ext = outputFormat.value === 'png' ? 'png' : 'jpg'
  const link = document.createElement('a')
  link.download = `证件照_${photoWidth.value}x${photoHeight.value}.${ext}`
  link.href = generatedUrl.value
  link.click()
  showToast('下载成功')
}

function downloadPrintLayout() {
  if (!printResultUrl.value) return
  
  const link = document.createElement('a')
  link.download = `证件照排版_${printConfig.value.paperSize}.jpg`
  link.href = printResultUrl.value
  link.click()
  showToast('下载成功')
}
</script>

<style scoped>
.idphoto-layout {
  display: flex;
  gap: 1.5rem;
  flex: 1;
}

.idphoto-settings {
  width: 340px;
  flex-shrink: 0;
  overflow-y: auto;
  max-height: calc(100vh - 160px);
}

.idphoto-preview {
  flex: 1;
  min-width: 0;
}

.upload-area {
  border: 2px dashed var(--border);
  border-radius: 8px;
  padding: 2rem;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s;
  min-height: 200px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.upload-area:hover,
.upload-area.drag-over {
  border-color: var(--primary);
  background: var(--primary-light);
}

.upload-hint {
  color: var(--text-secondary);
}

.upload-icon {
  font-size: 3rem;
  margin-bottom: 0.5rem;
}

.upload-tip {
  font-size: 0.78rem;
  margin-top: 0.5rem;
}

.preview-image {
  max-width: 100%;
  max-height: 180px;
  object-fit: contain;
  border-radius: 4px;
}

.btn-row {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.75rem;
  justify-content: center;
}

.btn-column {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.bg-options {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.bg-option {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.5rem 0.75rem;
  border: 2px solid var(--border);
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.15s;
  font-size: 0.85rem;
}

.bg-option input {
  display: none;
}

.bg-option.active {
  border-color: var(--primary);
  background: var(--primary-light);
}

.bg-color {
  width: 20px;
  height: 20px;
  border-radius: 4px;
  border: 1px solid var(--border);
}

.color-picker {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

.color-input {
  width: 50px;
  height: 38px;
  padding: 2px;
  border: 1px solid var(--border);
  border-radius: 6px;
  cursor: pointer;
}

.preview-card {
  text-align: center;
}

.preview-container {
  margin: 1rem auto;
  border: 1px solid var(--border);
  border-radius: 4px;
  overflow: hidden;
  background: repeating-conic-gradient(#f0f0f0 0% 25%, #fff 0% 50%) 50% / 20px 20px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.preview-container canvas {
  max-width: 100%;
  max-height: 100%;
}

.preview-info {
  font-size: 0.78rem;
  color: var(--text-secondary);
  margin-top: 0.5rem;
}

.download-card {
  margin-top: 1rem;
}

.result-actions {
  display: flex;
  gap: 1rem;
  align-items: center;
}

.download-preview {
  flex: 1;
  background: repeating-conic-gradient(#f0f0f0 0% 25%, #fff 0% 50%) 50% / 16px 16px;
  border-radius: 4px;
  padding: 1rem;
  text-align: center;
  min-height: 120px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.download-preview img {
  max-width: 200px;
  max-height: 280px;
  border-radius: 4px;
  box-shadow: var(--shadow);
}

/* 模态框 */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: var(--bg);
  border-radius: 12px;
  width: 90%;
  max-width: 560px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
}

.modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1rem;
}

.modal-header h3 {
  margin: 0;
}

.modal-close {
  background: none;
  border: none;
  font-size: 1.2rem;
  cursor: pointer;
  color: var(--text-secondary);
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  transition: all 0.15s;
}

.modal-close:hover {
  background: var(--border);
}

.modal-body {
  padding: 0;
}

.print-preview-hint {
  font-size: 0.8rem;
  color: var(--text-secondary);
  margin: 0.75rem 0;
  padding: 0.75rem;
  background: var(--primary-light);
  border-radius: 6px;
}

.print-preview-hint p {
  margin: 0.2rem 0;
}

.hint-sub {
  font-style: italic;
  opacity: 0.8;
}

.print-result {
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border);
}

.loading-text {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
}

.progress-badge {
  display: inline-block;
  background: rgba(255, 255, 255, 0.3);
  border-radius: 4px;
  padding: 0 0.4rem;
  font-size: 0.75rem;
  font-weight: 600;
  min-width: 2.5rem;
  text-align: center;
}

.form-hint {
  font-size: 0.75rem;
  color: var(--text-secondary);
  margin-top: 0.3rem;
  margin-bottom: 0;
}

.local-file-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.btn-sm {
  padding: 0.35rem 0.75rem;
  font-size: 0.8rem;
  white-space: nowrap;
  flex-shrink: 0;
}

.file-name {
  font-size: 0.8rem;
  color: var(--text-secondary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
}

.file-name.file-set {
  color: var(--primary);
  font-weight: 500;
}

@media (max-width: 768px) {
  .idphoto-layout {
    flex-direction: column;
  }
  
  .idphoto-settings {
    width: 100%;
    max-height: none;
  }

  .result-actions {
    flex-direction: column;
  }
}
</style>
