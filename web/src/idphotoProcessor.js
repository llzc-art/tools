/**
 * 证件照前端处理器
 *
 * 完整前端流程（模型串联逻辑）：
 *   上传原图 → YuNet人脸检测(5关键点) → 旋转矫正 → 人像抠图(MODNet/BiRefNet)
 *   → Canvas合成纯色背景 → 按国标比例裁切 → 输出300DPI高清PNG
 *
 * 抠图引擎: onnxruntime-web + WebWorker
 *   - MODNet (512x512, INT8~6.6MB): 轻量快速，适合移动端/H5
 *   - BiRefNet-portrait (1024x1024, FP16~490MB): 高精发丝级，适合打印/政务标准
 *   - YuNet (320x320, ~233KB): 人脸检测+5关键点，用于旋转矫正和头部定位
 *
 * Canvas API 负责: 裁剪/缩放/合成背景/Alpha精修/颜色去污染
 *
 * 避坑建议：
 *   - 所有模型优先使用量化版本(INT8/FP16)，体积减半、速度翻倍
 *   - 模型放 Web Worker 推理，避免阻塞页面渲染
 *   - 模型文件用 IndexedDB 缓存，二次访问无需重新下载
 */

// 预设背景色
export const BG_COLORS = {
  white:  { r: 255, g: 255, b: 255, hex: '#FFFFFF' },
  blue:   { r: 67,  g: 155, b: 219, hex: '#439BDB' },
  red:    { r: 230, g: 100, b: 100, hex: '#E66464' },
  blue3:  { r: 53,  g: 117, b: 187, hex: '#3575BB' },
  gray:   { r: 230, g: 230, b: 230, hex: '#E6E6E6' },
}

/**
 * 模型类型及下载配置
 *
 * 下载源：ModelScope（魔搭社区），国内访问速度快、稳定
 * ModelScope URL 格式: https://www.modelscope.cn/models/{owner}/{model}/resolve/master/{path}
 *
 * 模型选型遵循参考资料：
 *   - 方案A(移动端): MODNet INT8量化 ~6.6MB，加载快、手机不卡顿
 *   - 方案B(PC端): BiRefNet-portrait FP16 ~490MB，发丝细节完美
 *
 * 可在界面输入自定义 URL 覆盖默认下载地址。
 */
export const MODEL_CONFIGS = {
  modnet: {
    label: 'MODNet（轻量快速）',
    desc: '512px, ~6.6MB(INT8量化), 适合手机/H5快速出图',
    size: 512,
    // ModelScope: Xenova/modnet 仓库，提供 INT8/FP16/FP32 多种量化版本
    urls: [
      'https://www.modelscope.cn/models/Xenova/modnet/resolve/master/onnx/model_quantized.onnx',
      'https://www.modelscope.cn/models/Xenova/modnet/resolve/master/onnx/model_fp16.onnx',
      'https://www.modelscope.cn/models/Xenova/modnet/resolve/master/onnx/model.onnx',
    ],
  },
  birefnet: {
    label: 'BiRefNet-RMBG2（高精发丝级）',
    desc: '1024px, ~490MB(FP16), 发丝细节完美，适合打印/标准证件照',
    size: 1024,
    // ModelScope: onnx-community/BiRefNet-portrait-ONNX (FP16/FP32)
    urls: [
      'https://www.modelscope.cn/models/onnx-community/BiRefNet-portrait-ONNX/resolve/master/onnx/model_fp16.onnx',
      'https://www.modelscope.cn/models/onnx-community/BiRefNet-portrait-ONNX/resolve/master/onnx/model.onnx',
      'https://www.modelscope.cn/models/AI-ModelScope/RMBG-2.0/resolve/master/onnx/model.onnx',
    ],
  },
}

/**
 * YuNet 人脸检测模型配置
 *
 * 用途：检测人脸 + 5关键点（右眼、左眼、鼻尖、右嘴角、左嘴角）
 *       → 矫正旋转（基于双眼连线角度）→ 计算头部区域
 *
 * 注意：YuNet ONNX 暂未上架 ModelScope，使用 HuggingFace 国内镜像(hf-mirror.com)。
 *       模型仅 ~233KB，对下载速度和流量无影响。
 */
export const FACE_MODEL_CONFIG = {
  label: 'YuNet 人脸检测',
  size: 320,
  urls: [
    'https://hf-mirror.com/opencv/face_detection_yunet/resolve/main/face_detection_yunet_2023mar.onnx',
    'https://hf-mirror.com/opencv/face_detection_yunet/resolve/main/face_detection_yunet_2023mar_int8.onnx',
  ],
}

// ========== WebWorker 管理 ==========

let workerInstance = null
let workerReady = false
let workerModelType = null
let workerPendingResolve = null
let workerPendingReject = null
let workerOnProgress = null

/**
 * 获取或创建 Worker 实例
 */
function getWorker() {
  if (!workerInstance) {
    workerInstance = new Worker(
      new URL('./workers/idphotoWorker.js', import.meta.url),
      { type: 'module' }
    )
    workerInstance.onmessage = handleWorkerMessage
    workerInstance.onerror = (err) => {
      console.error('Worker error:', err)
      if (workerPendingReject) {
        workerPendingReject(new Error('Worker 异常: ' + (err.message || '未知错误')))
        workerPendingReject = null
        workerPendingResolve = null
      }
    }
  }
  return workerInstance
}

function handleWorkerMessage(event) {
  const { type, progress, stage, fromCache, maskImageBitmap, originalWidth, originalHeight, error, message } = event.data

  switch (type) {
    case 'progress': {
      if (workerOnProgress) {
        if (stage === 'download') {
          workerOnProgress(progress, fromCache ? 'using_cache' : 'downloading_model')
        } else {
          workerOnProgress(progress * 0.3 + 0.7, 'inference') // 推理占后70%
        }
      }
      break
    }

    case 'modelLoaded': {
      workerReady = true
      break
    }

    case 'maskReady': {
      if (workerPendingResolve && maskImageBitmap) {
        // 将 ImageBitmap 转换为 HTMLImageElement
        const canvas = document.createElement('canvas')
        canvas.width = originalWidth
        canvas.height = originalHeight
        const ctx = canvas.getContext('2d')
        ctx.drawImage(maskImageBitmap, 0, 0)
        maskImageBitmap.close() // 释放 ImageBitmap
        
        const dataUrl = canvas.toDataURL('image/png')
        loadImage(dataUrl).then(img => {
          const resolve = workerPendingResolve
          workerPendingResolve = null
          workerPendingReject = null
          resolve(img)
        })
      }
      break
    }

    case 'error': {
      if (workerPendingReject) {
        const reject = workerPendingReject
        workerPendingResolve = null
        workerPendingReject = null
        reject(new Error(message || error || '未知错误'))
      }
      break
    }
  }
}

/**
 * 确保模型已加载到 Worker
 * 同时加载抠图模型和人脸检测模型(YuNet)，YuNet加载失败不影响抠图
 * @param {string} modelType - 'modnet' | 'birefnet'
 * @param {string} [modelUrl] - 自定义模型 URL
 * @param {Function} [onProgress] - 进度回调 (0~1)
 * @returns {Promise<void>}
 */
export async function ensureModelLoaded(modelType = 'modnet', modelUrl, onProgress) {
  const config = MODEL_CONFIGS[modelType] || MODEL_CONFIGS.modnet
  
  // 如果用户提供了自定义 URL，替换 urls 列表的第一个
  let urls = [...config.urls]
  if (modelUrl) {
    urls = [modelUrl, ...config.urls]
  }

  // 如果同模型已加载，直接返回
  if (workerReady && workerModelType === modelType) return

  // 如果模型不同，需要销毁重建 Worker
  if (workerInstance && workerModelType !== modelType) {
    destroyWorker()
  }

  workerOnProgress = onProgress || null
  const worker = getWorker()

  return new Promise((resolve, reject) => {
    const checkReady = () => {
      if (workerReady) {
        resolve()
        return
      }
      // 等待 modelLoaded 消息
      const origHandler = worker.onmessage
      worker.onmessage = (event) => {
        if (event.data.type === 'modelLoaded') {
          workerReady = true
          workerModelType = modelType
          worker.onmessage = origHandler
          resolve()
        } else if (event.data.type === 'error') {
          worker.onmessage = origHandler
          reject(new Error(event.data.message || '模型加载失败'))
        } else if (event.data.type === 'progress') {
          // 进度透传
          if (workerOnProgress) {
            const p = event.data.progress * 0.3 // 模型下载占总进度的前30%
            workerOnProgress(p, event.data.stage)
          }
        }
      }
    }

    // 同时传递抠图模型和人脸检测模型(YuNet)的下载地址
    worker.postMessage({
      type: 'loadModel',
      modelType,
      urls,
      faceModelUrls: FACE_MODEL_CONFIG.urls,
    })
    
    // 超时处理（每个 URL 尝试 30s，总共最多）
    const timeout = setTimeout(() => {
      if (!workerReady) {
        reject(new Error('模型加载超时，请检查网络或尝试换一个地址'))
      }
    }, Math.max(60000, urls.length * 30000))

    checkReady()
    // fallback: 如果 modelLoaded 到达时 checkReady 还没解除
    const interval = setInterval(() => {
      if (workerReady) {
        clearTimeout(timeout)
        clearInterval(interval)
        resolve()
      }
    }, 200)
  })
}

/**
 * 从本地文件加载模型到 Worker
 *
 * 用途：用户通过文件选择器选择本地 .onnx 文件后，读取为 ArrayBuffer 传入 Worker，
 *       跳过网络下载，适合内网/离线环境或已手动下载好模型的场景。
 *
 * @param {string} modelType - 'modnet' | 'birefnet'（仅用于标记当前加载的模型类型）
 * @param {File|ArrayBuffer} modelFile - 抠图模型文件（.onnx）
 * @param {File|ArrayBuffer} [faceModelFile] - YuNet 人脸检测模型文件（可选，省略则自动从 URL 下载）
 * @param {Function} [onProgress] - 进度回调 (0~1)
 * @returns {Promise<void>}
 */
export async function ensureModelLoadedFromFile(modelType = 'modnet', modelFile, faceModelFile, onProgress) {
  // 如果同模型已加载，直接返回
  if (workerReady && workerModelType === modelType) return

  // 如果模型不同，需要销毁重建 Worker
  if (workerInstance && workerModelType !== modelType) {
    destroyWorker()
  }

  workerOnProgress = onProgress || null
  const worker = getWorker()

  // 读取文件为 ArrayBuffer（如果传入的已经是 ArrayBuffer 则直接使用）
  const modelBuffer = modelFile instanceof ArrayBuffer ? modelFile : await modelFile.arrayBuffer()

  // YuNet 模型文件（可选）
  let faceModelBuffer = null
  if (faceModelFile) {
    faceModelBuffer = faceModelFile instanceof ArrayBuffer ? faceModelFile : await faceModelFile.arrayBuffer()
  }

  return new Promise((resolve, reject) => {
    const origHandler = worker.onmessage
    worker.onmessage = (event) => {
      if (event.data.type === 'modelLoaded') {
        workerReady = true
        workerModelType = modelType
        worker.onmessage = origHandler
        resolve()
      } else if (event.data.type === 'error') {
        worker.onmessage = origHandler
        reject(new Error(event.data.message || '本地模型加载失败'))
      } else if (event.data.type === 'progress') {
        if (workerOnProgress) {
          // 本地加载无下载步骤，进度直接映射到前30%
          workerOnProgress(event.data.progress * 0.3, event.data.stage)
        }
      }
    }

    // 传输 ArrayBuffer 的所有权给 Worker（零拷贝）
    const transferList = [modelBuffer]
    if (faceModelBuffer) transferList.push(faceModelBuffer)

    worker.postMessage(
      {
        type: 'loadModelFromBuffer',
        modelBuffer,
        faceModelBuffer,
      },
      transferList
    )

    // 超时处理（本地文件加载通常很快，给 60s 余量）
    const timeout = setTimeout(() => {
      if (!workerReady) {
        worker.onmessage = origHandler
        reject(new Error('本地模型加载超时，请检查文件是否为有效的 ONNX 模型'))
      }
    }, 60000)

    // fallback 轮询
    const interval = setInterval(() => {
      if (workerReady) {
        clearTimeout(timeout)
        clearInterval(interval)
        worker.onmessage = origHandler
        resolve()
      }
    }, 200)
  })
}

/**
 * 销毁 Worker 实例
 */
export function destroyWorker() {
  if (workerInstance) {
    workerInstance.terminate()
    workerInstance = null
    workerReady = false
    workerModelType = null
    workerPendingResolve = null
    workerPendingReject = null
    workerOnProgress = null
  }
}

/**
 * 步骤1: AI 抠图 - 通过 WebWorker + onnxruntime-web 移除背景
 * 内部流程：YuNet人脸检测 → 旋转矫正 → MODNet/BiRefNet抠图推理
 * @param {File|Blob} imageFile - 原始图片文件
 * @param {Function} onProgress - 进度回调 (0~1)
 * @param {object} [options] - { modelType: 'modnet'|'birefnet', alignFace: boolean }
 * @returns {Promise<HTMLImageElement>} 透明背景的人像图片
 */
export async function removeImageBackground(imageFile, onProgress, options = {}) {
  const { modelType = 'modnet', alignFace = true } = options

  if (!workerReady) {
    throw new Error('模型尚未加载，请先调用 ensureModelLoaded()')
  }

  workerOnProgress = onProgress || null

  // 将 File/Blob 转为 ImageBitmap
  const blob = imageFile instanceof Blob ? imageFile : new Blob([imageFile])
  const imageBitmap = await createImageBitmap(blob)

  const worker = getWorker()

  return new Promise((resolve, reject) => {
    workerPendingResolve = resolve
    workerPendingReject = reject

    worker.postMessage(
      {
        type: 'removeBackground',
        imageBitmap,
        modelType,
        alignFace,
      },
      [imageBitmap] // transfer ownership
    )
  })
}

/**
 * 分析Alpha通道，找到人像的包围盒（bounding box）
 * 只在透明背景（AI抠图后）的图像上有效
 * @param {HTMLCanvasElement|HTMLImageElement} source - 含Alpha通道的图像
 * @returns {{ minX:number, minY:number, maxX:number, maxY:number, width:number, height:number, cx:number, cy:number }}
 */
function findPortraitBounds(source) {
  const w = source.naturalWidth || source.width
  const h = source.naturalHeight || source.height

  // 渲染到canvas获取像素数据
  const canvas = document.createElement('canvas')
  canvas.width = w
  canvas.height = h
  const ctx = canvas.getContext('2d')
  ctx.drawImage(source, 0, 0)
  const imageData = ctx.getImageData(0, 0, w, h)
  const pixels = imageData.data
  const alphaThreshold = 25

  let minX = w, minY = h, maxX = 0, maxY = 0
  let pixelCount = 0

  // 隔行扫描以提升性能（大图时）
  const step = w * h > 2000000 ? 2 : 1
  for (let y = 0; y < h; y += step) {
    for (let x = 0; x < w; x += step) {
      const idx = (y * w + x) * 4
      if (pixels[idx + 3] > alphaThreshold) {
        if (x < minX) minX = x
        if (x > maxX) maxX = x
        if (y < minY) minY = y
        if (y > maxY) maxY = y
        pixelCount++
      }
    }
  }

  // 如果没找到有效像素，返回全图范围
  if (pixelCount === 0) {
    return { minX: 0, minY: 0, maxX: w - 1, maxY: h - 1, width: w, height: h, cx: w / 2, cy: h / 2 }
  }

  // 扩大一点边界，避免切到人像边缘
  const marginX = Math.ceil((maxX - minX) * 0.03)
  const marginY = Math.ceil((maxY - minY) * 0.02)
  minX = Math.max(0, minX - marginX)
  maxX = Math.min(w - 1, maxX + marginX)
  minY = Math.max(0, minY - marginY)
  maxY = Math.min(h - 1, maxY + marginY)

  return {
    minX, minY, maxX, maxY,
    width: maxX - minX + 1,
    height: maxY - minY + 1,
    cx: (minX + maxX) / 2,
    cy: (minY + maxY) / 2,
  }
}

/**
 * 通过分析每行的水平跨度，检测肩部/颈部位置
 * 颈部：上半身区域水平跨度最窄的行
 * 肩部：颈部下方水平跨度显著增宽并趋于稳定的区域
 * @param {HTMLCanvasElement} canvas - 已渲染好的透明背景人像画布
 * @param {object} portrait - findPortraitBounds 的返回结果
 * @returns {number} 建议的裁剪底部 Y 坐标（肩部下方合适位置）
 */
function detectShoulderY(canvas, portrait) {
  const w = canvas.width
  const ctx = canvas.getContext('2d')
  const imageData = ctx.getImageData(0, 0, w, canvas.height)
  const pixels = imageData.data
  const alphaThreshold = 30

  // 计算每行的前景像素水平跨度
  const rows = []
  for (let y = portrait.minY; y <= portrait.maxY; y++) {
    if (y >= canvas.height) break
    let leftX = -1, rightX = -1
    for (let x = 0; x < w; x++) {
      if (pixels[(y * w + x) * 4 + 3] > alphaThreshold) {
        if (leftX < 0) leftX = x
        rightX = x
      }
    }
    rows.push({ y, span: leftX >= 0 ? rightX - leftX : 0, leftX, rightX })
  }

  if (rows.length < 10) return portrait.maxY

  const totalRows = rows.length
  const portraitHeight = portrait.maxY - portrait.minY

  // 上部区域（头部+颈部大约在人像上方的45%）
  const upperEnd = Math.floor(totalRows * 0.5)

  // 在中上部找最窄的行（候选颈部）
  let neckIdx = -1
  let minSpan = Infinity
  const searchStart = Math.floor(totalRows * 0.08) // 跳过头顶
  const searchEnd = Math.min(Math.floor(totalRows * 0.55), upperEnd + 5)

  for (let i = searchStart; i < searchEnd; i++) {
    if (rows[i].span > 5 && rows[i].span < minSpan) {
      minSpan = rows[i].span
      neckIdx = i
    }
  }

  if (neckIdx < 0) return portrait.maxY

  // 从颈部往下找肩部：跨度开始显著增宽并趋于稳定
  let shoulderIdx = neckIdx
  let maxSpanAfterNeck = 0
  let maxSpanIdx = neckIdx

  const shoulderSearchEnd = Math.min(totalRows - 1, Math.floor(totalRows * 0.8))

  for (let i = neckIdx + 1; i < shoulderSearchEnd; i++) {
    if (rows[i].span > maxSpanAfterNeck) {
      maxSpanAfterNeck = rows[i].span
      maxSpanIdx = i
    }
  }

  // 从最大跨度处继续向下，找到趋于稳定的行
  shoulderIdx = maxSpanIdx
  const stableThreshold = maxSpanAfterNeck * 0.9
  for (let i = maxSpanIdx + 1; i < shoulderSearchEnd; i++) {
    if (rows[i].span >= stableThreshold) {
      shoulderIdx = i
    } else if (rows[i].span < stableThreshold * 0.7) {
      // 跨度显著下降，可能到了身体结束
      break
    }
  }

  // 肩部下方增加一点留白
  const shoulderPadding = Math.floor(portraitHeight * 0.06)
  const candidateY = rows[shoulderIdx] ? rows[shoulderIdx].y + shoulderPadding : portrait.maxY

  // 合理性检查：不能裁得太少（至少保留人像高度的35%）
  const minValidY = portrait.minY + portraitHeight * 0.35
  return Math.max(candidateY, minValidY)
}

/**
 * 步骤2: 智能裁剪缩放 - 基于Alpha通道分析，人像居中并适配证件照比例
 * 自动检测人像位置，水平居中，垂直偏上（头部在上方合适位置）
 * 可选检测肩部位置，裁剪掉肩部以下多余身体部分
 * @param {HTMLImageElement} img - 透明背景人像图
 * @param {number} targetW - 目标宽度
 * @param {number} targetH - 目标高度
 * @param {object} [options] - 可选配置
 * @param {boolean} [options.detectShoulders=true] - 是否检测肩部裁剪
 * @returns {HTMLCanvasElement} 裁剪缩放后的画布
 */
export function smartCropAndResize(img, targetW, targetH, options = {}) {
  const { detectShoulders = true } = options
  const origW = img.naturalWidth || img.width
  const origH = img.naturalHeight || img.height

  // 1. 渲染原图到临时 Canvas 用于像素分析
  const tempCanvas = document.createElement('canvas')
  tempCanvas.width = origW
  tempCanvas.height = origH
  const tempCtx = tempCanvas.getContext('2d')
  tempCtx.drawImage(img, 0, 0)

  // 2. 找到人像包围盒
  const portrait = findPortraitBounds(tempCanvas)

  // 3. 可选：检测肩部位置
  let cropBottom = portrait.maxY
  if (detectShoulders) {
    const shoulderY = detectShoulderY(tempCanvas, portrait)
    const minValidH = portrait.minY + portrait.height * 0.4
    if (shoulderY >= minValidH) {
      cropBottom = shoulderY
    }
  }

  // 4. 人像内容区域
  const contentHeight = cropBottom - portrait.minY + 1
  const contentWidth = portrait.maxX - portrait.minX + 1
  const contentCX = (portrait.minX + portrait.maxX) / 2

  // 5. 证件照构图规则
  const verticalFillRatio = 0.75
  const horizontalFillRatio = 0.82
  const topSpaceBias = 0.25
  const maxScale = 3.5

  // 6. 关键：使用 MAX scale（紧贴人像）确保人像在画面中有足够大的占比
  //    min scale 会造成裁剪区过大，人像无法居中
  const scaleForY = (targetH * verticalFillRatio) / contentHeight
  const scaleForX = (targetW * horizontalFillRatio) / contentWidth
  let scale = Math.max(scaleForX, scaleForY)

  // 确保裁剪区不会超出原图范围（水平居中检查）
  const halfCropW = (targetW / scale) / 2
  const distToLeftEdge = contentCX
  const distToRightEdge = origW - contentCX
  if (halfCropW > distToLeftEdge || halfCropW > distToRightEdge) {
    // 无法居中，加大 scale 缩小裁剪区
    const maxHalfCropW = Math.min(distToLeftEdge, distToRightEdge)
    scale = Math.max(scale, targetW / (2 * maxHalfCropW))
  }

  // 确保裁剪区不会超出原图范围（垂直检查）
  const halfCropH = (targetH / scale) / 2
  const portraitCY = portrait.minY + (cropBottom - portrait.minY) * 0.45
  const distToTopEdge = portraitCY
  const distToBottomEdge = origH - portraitCY
  if (halfCropH > distToTopEdge || halfCropH > distToBottomEdge) {
    const maxHalfCropH = Math.min(distToTopEdge, distToBottomEdge)
    scale = Math.max(scale, targetH / (2 * maxHalfCropH))
  }

  // 限制最大放大倍数
  scale = Math.min(scale, maxScale)

  // 7. 重新计算裁剪区域
  const srcW = targetW / scale
  const srcH = targetH / scale
  const extraVSpace = srcH - contentHeight

  // 水平：严格居中
  let srcX = contentCX - srcW / 2

  // 垂直：偏上构图
  let srcY = portrait.minY - extraVSpace * topSpaceBias

  // 8. 边界钳制
  srcX = Math.round(Math.max(0, Math.min(srcX, origW - srcW)))
  srcY = Math.round(Math.max(0, Math.min(srcY, origH - srcH)))

  // 确保不越界
  if (srcX + srcW > origW) srcX = Math.floor(origW - srcW)
  if (srcY + srcH > origH) srcY = Math.floor(origH - srcH)
  if (srcX < 0) srcX = 0
  if (srcY < 0) srcY = 0

  // 9. 绘制结果
  const canvas = document.createElement('canvas')
  canvas.width = targetW
  canvas.height = targetH
  const ctx = canvas.getContext('2d')

  ctx.drawImage(
    tempCanvas,
    Math.round(srcX), Math.round(srcY), Math.round(srcW), Math.round(srcH),
    0, 0, targetW, targetH
  )

  return canvas
}

/**
 * Alpha通道形态学精修 - 填充抠图产生的空洞，去除噪点
 * 对标 HivisionIDPhotos 的后处理思路，解决"人像后面出现白斑"问题
 * @param {HTMLCanvasElement} fgCanvas - 抠图后的透明前景画布
 * @param {object} [options] - 可选参数
 * @param {number} [options.closeRadius=4] - 闭运算半径（填充空洞），越大填充越多
 * @param {number} [options.openRadius=1] - 开运算半径（去除噪点）
 * @returns {HTMLCanvasElement} 精修后的画布
 */
function refineAlphaMatte(fgCanvas, options = {}) {
  const { closeRadius = 4, openRadius = 1 } = options
  const w = fgCanvas.width
  const h = fgCanvas.height
  const ctx = fgCanvas.getContext('2d')
  const imageData = ctx.getImageData(0, 0, w, h)
  const pixels = imageData.data
  const totalPixels = w * h

  // 提取 alpha 通道
  const alpha = new Uint8Array(totalPixels)
  for (let i = 0; i < totalPixels; i++) {
    alpha[i] = pixels[i * 4 + 3]
  }

  // 1. 生成二值蒙版（alpha > 128 视为前景）
  const binaryMask = new Uint8Array(totalPixels)
  let fgCount = 0
  for (let i = 0; i < totalPixels; i++) {
    binaryMask[i] = alpha[i] > 128 ? 1 : 0
    if (binaryMask[i]) fgCount++
  }

  // 2. 形态学闭运算（先膨胀后腐蚀）：填充前景中的小空洞
  if (closeRadius > 0 && fgCount > 0) {
    const dilated = separableDilate(binaryMask, w, h, closeRadius)
    const closed = separableErode(dilated, w, h, closeRadius)
    // 将闭运算后"新出现"的前景像素 alpha 值提升
    for (let i = 0; i < totalPixels; i++) {
      if (binaryMask[i] === 0 && closed[i] === 1) {
        // 原本是背景/空洞，闭运算后变为前景 → 提高其 alpha
        alpha[i] = Math.min(255, alpha[i] + 200)
      }
    }
  }

  // 3. 形态学开运算（先腐蚀后膨胀）：去除孤立噪点
  if (openRadius > 0 && fgCount > 0) {
    const eroded = separableErode(binaryMask, w, h, openRadius)
    const opened = separableDilate(eroded, w, h, openRadius)
    for (let i = 0; i < totalPixels; i++) {
      if (binaryMask[i] === 1 && opened[i] === 0) {
        // 原本是前景噪点，开运算后移除 → 降低 alpha
        alpha[i] = 0
      }
    }
  }

  // 写回像素
  for (let i = 0; i < totalPixels; i++) {
    pixels[i * 4 + 3] = alpha[i]
  }

  const resultCanvas = document.createElement('canvas')
  resultCanvas.width = w
  resultCanvas.height = h
  const resultCtx = resultCanvas.getContext('2d')
  resultCtx.putImageData(imageData, 0, 0)
  return resultCanvas
}

/**
 * 可分离膨胀（水平+垂直两次pass），比二维核更高效
 */
function separableDilate(mask, w, h, radius) {
  const temp = new Uint8Array(w * h)
  // Horizontal pass
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      if (mask[y * w + x]) {
        const left = Math.max(0, x - radius)
        const right = Math.min(w - 1, x + radius)
        for (let nx = left; nx <= right; nx++) {
          temp[y * w + nx] = 1
        }
      }
    }
  }
  const result = new Uint8Array(w * h)
  // Vertical pass
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      if (temp[y * w + x]) {
        const top = Math.max(0, y - radius)
        const bottom = Math.min(h - 1, y + radius)
        for (let ny = top; ny <= bottom; ny++) {
          result[ny * w + x] = 1
        }
      }
    }
  }
  return result
}

/**
 * 可分离腐蚀
 */
function separableErode(mask, w, h, radius) {
  const temp = new Uint8Array(w * h)
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const left = Math.max(0, x - radius)
      const right = Math.min(w - 1, x + radius)
      let allFg = true
      for (let nx = left; nx <= right; nx++) {
        if (!mask[y * w + nx]) { allFg = false; break }
      }
      if (allFg) temp[y * w + x] = 1
    }
  }
  const result = new Uint8Array(w * h)
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const top = Math.max(0, y - radius)
      const bottom = Math.min(h - 1, y + radius)
      let allFg = true
      for (let ny = top; ny <= bottom; ny++) {
        if (!temp[ny * w + x]) { allFg = false; break }
      }
      if (allFg) result[y * w + x] = 1
    }
  }
  return result
}

/**
 * 颜色去污染 - 消除半透明边缘的背景色残留
 * 对标 BiRefNet/RMBG-2 后处理：半透明边缘像素中混入了原图背景色，
 * 直接合成到新背景时会出现白边/灰边，需要先"去污染"
 * @param {HTMLCanvasElement} fgCanvas - 透明前景画布
 * @param {object} assumedBg - 假设的原图背景色 {r, g, b}，默认浅灰白
 * @returns {HTMLCanvasElement} 去污染后的画布
 */
function decontaminateEdgeColors(fgCanvas, assumedBg = { r: 240, g: 240, b: 240 }) {
  const w = fgCanvas.width
  const h = fgCanvas.height
  const ctx = fgCanvas.getContext('2d')
  const imageData = ctx.getImageData(0, 0, w, h)
  const pixels = imageData.data
  const totalPixels = w * h

  for (let i = 0; i < totalPixels; i++) {
    const idx = i * 4
    const alpha = pixels[idx + 3]

    // 只处理半透明边缘（alpha 在 20~240 之间）
    if (alpha > 20 && alpha < 240) {
      const a = alpha / 255

      // 假设原图背景为浅色，按比例从前景色中减去背景污染
      // 公式：foreground_clean = (observed - (1-alpha)*background) / alpha
      // 钳制到有效范围
      const r = Math.round(Math.max(0, Math.min(255,
        (pixels[idx] - (1 - a) * assumedBg.r) / a)))
      const g = Math.round(Math.max(0, Math.min(255,
        (pixels[idx + 1] - (1 - a) * assumedBg.g) / a)))
      const b = Math.round(Math.max(0, Math.min(255,
        (pixels[idx + 2] - (1 - a) * assumedBg.b) / a)))

      pixels[idx] = r
      pixels[idx + 1] = g
      pixels[idx + 2] = b
    }
  }

  const resultCanvas = document.createElement('canvas')
  resultCanvas.width = w
  resultCanvas.height = h
  const resultCtx = resultCanvas.getContext('2d')
  resultCtx.putImageData(imageData, 0, 0)
  return resultCanvas
}

/**
 * 步骤3: 合成背景色 - 将透明人像合成到纯色背景上
 * 包含 Alpha 精修 + 颜色去污染 + 边缘羽化的完整管线
 * @param {HTMLCanvasElement} fgCanvas - 前景画布（含alpha通道）
 * @param {object} bgColor - 背景色 {r, g, b}
 * @param {number} feathering - 羽化程度 0-5
 * @returns {HTMLCanvasElement} 合成后的画布
 */
export function compositeWithBackground(fgCanvas, bgColor, feathering = 2) {
  const w = fgCanvas.width
  const h = fgCanvas.height

  // 1. Alpha 通道形态学精修（填充空洞）
  let processedCanvas = refineAlphaMatte(fgCanvas, {
    closeRadius: 4,
    openRadius: 1,
  })

  // 2. 颜色去污染（消除半透明边缘的白边残留）
  processedCanvas = decontaminateEdgeColors(processedCanvas, {
    r: 240, g: 240, b: 240,
  })

  // 3. 边缘羽化（可选）
  if (feathering > 0) {
    processedCanvas = applyEdgeFeathering(processedCanvas, feathering)
  }

  // 4. 合成到纯色背景
  const resultCanvas = document.createElement('canvas')
  resultCanvas.width = w
  resultCanvas.height = h
  const ctx = resultCanvas.getContext('2d')

  ctx.fillStyle = `rgb(${bgColor.r},${bgColor.g},${bgColor.b})`
  ctx.fillRect(0, 0, w, h)

  ctx.drawImage(processedCanvas, 0, 0)

  return resultCanvas
}

/**
 * 边缘羽化 - 只对真人像边缘区域做柔和过渡，避免全图模糊
 * @param {HTMLCanvasElement} srcCanvas
 * @param {number} radius - 羽化半径 1-5
 * @returns {HTMLCanvasElement}
 */
function applyEdgeFeathering(srcCanvas, radius) {
  const w = srcCanvas.width
  const h = srcCanvas.height
  const ctx = srcCanvas.getContext('2d')
  const srcData = ctx.getImageData(0, 0, w, h)
  const srcPixels = srcData.data
  const totalPixels = w * h

  // 找到所有边缘像素（alpha 在过渡区间的像素及其邻域）
  const edgeMask = new Uint8Array(totalPixels)
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const idx = y * w + x
      const alpha = srcPixels[idx * 4 + 3]
      if (alpha > 5 && alpha < 250) {
        edgeMask[idx] = 1
      }
    }
  }

  // 扩展边缘区域
  const expandedMask = separableDilate(edgeMask, w, h, radius)

  // 对 alpha 通道在边缘区域做盒式滤波（近似羽化）
  const smoothedAlpha = new Float32Array(totalPixels)

  // 先用原始 alpha 初始化
  for (let i = 0; i < totalPixels; i++) {
    smoothedAlpha[i] = srcPixels[i * 4 + 3]
  }

  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const idx = y * w + x
      if (!expandedMask[idx]) continue

      // 盒式滤波采样邻域 alpha
      let sum = 0
      let count = 0
      const yMin = Math.max(0, y - radius)
      const yMax = Math.min(h - 1, y + radius)
      const xMin = Math.max(0, x - radius)
      const xMax = Math.min(w - 1, x + radius)

      for (let ny = yMin; ny <= yMax; ny++) {
        for (let nx = xMin; nx <= xMax; nx++) {
          sum += srcPixels[(ny * w + nx) * 4 + 3]
          count++
        }
      }

      smoothedAlpha[idx] = Math.round(sum / count)
    }
  }

  // 写回
  const resultData = ctx.createImageData(w, h)
  const resultPixels = resultData.data
  for (let i = 0; i < totalPixels; i++) {
    const idx = i * 4
    resultPixels[idx] = srcPixels[idx]
    resultPixels[idx + 1] = srcPixels[idx + 1]
    resultPixels[idx + 2] = srcPixels[idx + 2]
    resultPixels[idx + 3] = Math.round(smoothedAlpha[i])
  }

  const resultCanvas = document.createElement('canvas')
  resultCanvas.width = w
  resultCanvas.height = h
  const resultCtx = resultCanvas.getContext('2d')
  resultCtx.putImageData(resultData, 0, 0)
  return resultCanvas
}

/**
 * 完整的证件照生成流程
 * @param {File} imageFile - 原始图片文件
 * @param {object} options - 配置选项
 * @param {number} [options.width=295] - 输出宽度
 * @param {number} [options.height=413] - 输出高度
 * @param {string} [options.background='white'] - 背景色预设
 * @param {string} [options.customColor='#FFFFFF'] - 自定义背景色
 * @param {number} [options.feathering=2] - 边缘羽化程度 0-5
 * @param {string} [options.outputFormat='jpeg'] - 输出格式 jpeg|png
 * @param {string} [options.modelType='modnet'] - 抠图模型类型 modnet|birefnet
 * @param {string} [options.modelUrl] - 自定义模型下载 URL
 * @param {File|ArrayBuffer} [options.modelFile] - 本地模型文件（优先于 modelUrl）
 * @param {File|ArrayBuffer} [options.faceModelFile] - 本地 YuNet 人脸检测模型文件
 * @param {boolean} [options.alignFace=true] - 是否启用人脸矫正
 * @param {Function} [options.onProgress] - 进度回调 ({stage, progress})
 * @returns {Promise<{dataUrl: string, base64: string, width: number, height: number}>}
 */
export async function generateIDPhoto(imageFile, options = {}) {
  const {
    width = 295,
    height = 413,
    background = 'white',
    customColor = '#FFFFFF',
    feathering = 2,
    outputFormat = 'jpeg',
    modelType = 'modnet',
    modelUrl,
    modelFile,
    faceModelFile,
    alignFace = true,
    onProgress,
  } = options

  // 1. 确保模型已加载（含 YuNet 人脸检测模型）
  //    优先级：本地文件 > 自定义URL > 默认ModelScope地址
  if (onProgress) onProgress({ stage: 'loading_model', progress: 0 })
  const modelLoadProgress = (p, stage) => {
    if (onProgress) {
      onProgress({
        stage: stage === 'downloading_model' ? 'downloading_model' : 'loading_model',
        progress: p * 0.3, // 模型加载占前30%
      })
    }
  }

  if (modelFile) {
    // 从本地文件加载模型（无需网络下载）
    await ensureModelLoadedFromFile(modelType, modelFile, faceModelFile, modelLoadProgress)
  } else {
    // 从 URL 下载加载模型
    await ensureModelLoaded(modelType, modelUrl, modelLoadProgress)
  }

  // 2. AI抠图（内部含 YuNet 人脸检测 + 旋转矫正 + 抠图推理）
  if (onProgress) onProgress({ stage: 'removing_bg', progress: 0.3 })
  const transparentImg = await removeImageBackground(imageFile, (p) => {
    if (onProgress) {
      onProgress({ stage: 'removing_bg', progress: 0.3 + p * 0.35 })
    }
  }, { modelType, alignFace })

  // 3. 智能裁剪缩放
  if (onProgress) onProgress({ stage: 'cropping', progress: 0.65 })
  const croppedCanvas = smartCropAndResize(transparentImg, width, height)

  // 4. 合成背景色
  if (onProgress) onProgress({ stage: 'compositing', progress: 0.8 })
  const bgColor = resolveBgColor(background, customColor)
  const resultCanvas = compositeWithBackground(croppedCanvas, bgColor, feathering)

  // 5. 导出结果
  if (onProgress) onProgress({ stage: 'encoding', progress: 0.9 })
  const mimeType = outputFormat === 'png' ? 'image/png' : 'image/jpeg'
  const quality = outputFormat === 'png' ? undefined : 0.95

  const dataUrl = canvasToDataUrl(resultCanvas, mimeType, quality)
  const base64 = dataUrl.split(',')[1]

  if (onProgress) onProgress({ stage: 'done', progress: 1 })

  return {
    dataUrl,
    base64,
    width,
    height,
    format: outputFormat === 'png' ? 'png' : 'jpeg',
  }
}

/**
 * 解析背景色
 */
function resolveBgColor(background, customColor) {
  if (background === 'custom' && customColor) {
    return hexToRgb(customColor)
  }
  return BG_COLORS[background] || BG_COLORS.white
}

/**
 * Hex 转 RGB
 */
function hexToRgb(hex) {
  hex = hex.replace('#', '')
  if (hex.length === 3) {
    hex = hex.split('').map(c => c + c).join('')
  }
  return {
    r: parseInt(hex.substring(0, 2), 16),
    g: parseInt(hex.substring(2, 4), 16),
    b: parseInt(hex.substring(4, 6), 16),
  }
}

/**
 * Canvas 导出 DataURL
 */
function canvasToDataUrl(canvas, mimeType, quality) {
  return canvas.toDataURL(mimeType, quality)
}

/**
 * 加载图片为 HTMLImageElement
 */
function loadImage(url) {
  return new Promise((resolve, reject) => {
    const img = new Image()
    img.crossOrigin = 'anonymous'
    img.onload = () => resolve(img)
    img.onerror = reject
    img.src = url
  })
}

/**
 * 排版打印 - 在前端用 Canvas 排列多张证件照
 * @param {string} photoDataUrl - 证件照的 data URL
 * @param {object} options - 排版配置
 * @returns {Promise<{dataUrl: string, base64: string}>}
 */
export async function generatePrintLayout(photoDataUrl, options = {}) {
  const {
    photoWidth = 295,
    photoHeight = 413,
    paperSize = '5inch',
    columns = 0,
    rows = 0,
    gap = 20,
  } = options

  // 相纸尺寸
  const paperSizes = {
    '5inch': { w: 1500, h: 1050 },
    '6inch': { w: 1800, h: 1200 },
    'A4':    { w: 2480, h: 3508 },
  }
  const paper = paperSizes[paperSize] || paperSizes['5inch']

  // 自动计算行列
  let cols = columns
  let rows_ = rows
  if (cols <= 0 || rows_ <= 0) {
    cols = Math.floor((paper.w + gap) / (photoWidth + gap))
    rows_ = Math.floor((paper.h + gap) / (photoHeight + gap))
    if (cols <= 0) cols = 1
    if (rows_ <= 0) rows_ = 1
  }

  // 缩放照片以适应
  const totalW = cols * photoWidth + (cols + 1) * gap
  const totalH = rows_ * photoHeight + (rows_ + 1) * gap
  let scale = 1
  if (totalW > paper.w) scale = Math.min(scale, (paper.w - 20) / totalW)
  if (totalH > paper.h) scale = Math.min(scale, (paper.h - 20) / totalH)

  const pw = Math.round(photoWidth * scale)
  const ph = Math.round(photoHeight * scale)
  const gp = Math.round(gap * scale)

  // 加载证件照
  const photoImg = await loadImage(photoDataUrl)

  // 创建画布
  const canvas = document.createElement('canvas')
  canvas.width = paper.w
  canvas.height = paper.h
  const ctx = canvas.getContext('2d')

  // 白色背景
  ctx.fillStyle = '#FFFFFF'
  ctx.fillRect(0, 0, paper.w, paper.h)

  // 计算布局起始位置（居中）
  const layoutW = cols * pw + (cols - 1) * gp
  const layoutH = rows_ * ph + (rows_ - 1) * gp
  const startX = Math.round((paper.w - layoutW) / 2)
  const startY = Math.round((paper.h - layoutH) / 2)

  // 粘贴照片
  for (let row = 0; row < rows_; row++) {
    for (let col = 0; col < cols; col++) {
      const x = startX + col * (pw + gp)
      const y = startY + row * (ph + gp)
      ctx.drawImage(photoImg, x, y, pw, ph)
    }
  }

  const resultDataUrl = canvas.toDataURL('image/jpeg', 0.95)
  const base64 = resultDataUrl.split(',')[1]

  return {
    dataUrl: resultDataUrl,
    base64,
    width: paper.w,
    height: paper.h,
  }
}
