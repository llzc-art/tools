/**
 * 证件照抠图 WebWorker
 *
 * 基于 onnxruntime-web 实现完整的前端证件照抠图流水线：
 *   1. SCRFD-10G-BNKPS 人脸检测（5关键点）→ 计算双眼连线角度
 *   2. 旋转矫正 → 使双眼水平
 *   3. MODNet / BiRefNet 人像抠图 → 生成透明 Alpha 蒙版
 *
 * 模型通过 IndexedDB 缓存，二次访问无需重新下载
 *
 * 消息协议：
 *   主线程 → Worker:
 *     - { type: 'loadModel', urls: string[], faceModelUrls?: string[] }
 *         从 URL 下载加载抠图模型 + SCRFD 人脸检测模型
 *     - { type: 'loadModelFromBuffer', modelBuffer: ArrayBuffer, faceModelBuffer?: ArrayBuffer }
 *         从本地文件 ArrayBuffer 加载模型（无需网络下载）
 *     - { type: 'removeBackground', imageBitmap, modelType, alignFace }
 *         执行抠图推理（含可选的人脸检测+旋转矫正）
 *
 *   Worker → 主线程:
 *     - { type: 'progress', stage, progress }  - 模型下载/推理进度
 *     - { type: 'modelLoaded' }                 - 模型加载完成
 *     - { type: 'maskReady', maskImageBitmap, originalWidth, originalHeight }
 *         抠图结果 (ImageBitmap)
 *     - { type: 'error', message }              - 错误信息
 */

// ========== IndexedDB 模型缓存 ==========

const DB_NAME = 'idphoto-models'
const DB_VERSION = 1
const STORE_NAME = 'models'

function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)
    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME)
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

async function getCachedModel(url) {
  const db = await openDB()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly')
    const store = tx.objectStore(STORE_NAME)
    const req = store.get(url)
    req.onsuccess = () => {
      db.close()
      resolve(req.result || null)
    }
    req.onerror = () => {
      db.close()
      reject(req.error)
    }
  })
}

async function cacheModel(url, buffer) {
  const db = await openDB()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite')
    const store = tx.objectStore(STORE_NAME)
    store.put(buffer, url)
    tx.oncomplete = () => {
      db.close()
      resolve()
    }
    tx.onerror = () => {
      db.close()
      reject(tx.error)
    }
  })
}

// ========== 模型下载（多 URL 回退） ==========

/**
 * 从多个 URL 中下载模型，按顺序尝试，第一个成功即返回
 * @param {string[]} urls - 候选下载地址列表
 * @returns {Promise<{buffer: Uint8Array, url: string}>}
 */
async function downloadModel(urls) {
  // 1. 检查 IndexedDB 缓存（用所有 url 尝试命中缓存）
  for (const url of urls) {
    const cached = await getCachedModel(url)
    if (cached) {
      self.postMessage({ 
        type: 'progress', stage: 'download', progress: 1, fromCache: true,
        message: `命中缓存: ${new URL(url).hostname}`,
      })
      return { buffer: cached, url }
    }
  }

  // 2. 按顺序尝试下载
  const errors = []
  for (let i = 0; i < urls.length; i++) {
    const url = urls[i]
    const hostname = new URL(url).hostname
    self.postMessage({ 
      type: 'progress', stage: 'download', progress: 0,
      message: `尝试下载 (${i + 1}/${urls.length}): ${hostname}`,
    })

    try {
      const buffer = await downloadFromUrl(url)
      self.postMessage({ type: 'progress', stage: 'download', progress: 1, fromCache: false })
      return { buffer, url }
    } catch (err) {
      console.warn(`下载失败 [${hostname}]:`, err.message)
      errors.push(`${hostname}: ${err.message}`)
      
      // 通知主线程切换地址
      self.postMessage({
        type: 'progress', stage: 'download', progress: (i + 1) / urls.length,
        message: `${hostname} 下载失败，尝试备用地址...`,
      })
    }
  }

  // 所有 URL 都失败
  throw new Error(`所有下载地址均失败:\n${errors.map((e, i) => `  ${i + 1}. ${e}`).join('\n')}`)
}

/**
 * 从单个 URL 流式下载模型
 *
 * 特殊处理：ModelScope 上的大模型使用 Git LFS 存储，
 *           直接 fetch URL 返回的是 HTML 重定向页（包含 `<a href="...">Found</a>`），
 *           需要从中提取真实 LFS CDN 链接后再次下载。
 */
async function downloadFromUrl(url) {
  let actualUrl = url
  let response = await fetch(actualUrl, { signal: AbortSignal.timeout(30000) })

  // 检查是否是 ModelScope LFS HTML 重定向页
  const contentType = response.headers.get('content-type') || ''
  if (contentType.includes('text/html')) {
    const html = await response.text()
    // 提取 `<a href="...">Found</a>` 中的真实链接
    const m = html.match(/<a\s+href=["']([^"']+)["']\s*>[^<]*Found<\/a>/i)
    if (m && m[1]) {
      const realUrl = m[1].replace(/&amp;/g, '&')
      console.log('[ORT] ModelScope LFS 重定向到:', realUrl)
      response = await fetch(realUrl, { signal: AbortSignal.timeout(30000) })
      actualUrl = realUrl
    }
  }

  if (!response.ok) throw new Error(`HTTP ${response.status}`)

  const contentLength = response.headers.get('content-length')
  const total = contentLength ? parseInt(contentLength, 10) : 0
  const reader = response.body.getReader()
  const chunks = []

  let received = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(value)
    received += value.length
    if (total > 0) {
      self.postMessage({ type: 'progress', stage: 'download', progress: received / total })
    }
  }

  const buffer = new Uint8Array(received)
  let offset = 0
  for (const chunk of chunks) {
    buffer.set(chunk, offset)
    offset += chunk.length
  }

  // 缓存到 IndexedDB（用原始 URL 作 key，避免 LFS 临时 auth_key 失效）
  try {
    await cacheModel(url, buffer)
  } catch {
    // IndexedDB 缓存失败不影响使用
  }

  return buffer
}

// ========== ONNX Runtime 初始化 ==========

let ortSession = null      // 抠图模型会话 (MODNet / BiRefNet)
let yunetSession = null    // 人脸检测模型会话 (SCRFD-10G-BNKPS)
// 为兼容旧引用同步保留变量名（实际指向 SCRFD 模型）
let scrfdSession = null

// ort 实例缓存，避免重复 import() 带来的开销
let _ortInstance = null
let _ortConfigured = false

/**
 * 配置 ONNX Runtime 运行环境
 *
 * 关键配置项说明：
 *  - wasmPaths:  显式指向 /assets/ 目录，Vite build 已把 ort-wasm-*.wasm
 *                复制到 dist/assets/，Go 后端从该路径托管。
 *                配合 static.go 的 application/wasm MIME 修复，
 *                可让 WebAssembly.compileStreaming() 成功走流式编译。
 *  - proxy:      false，Worker 中无跨域需求
 *  - numThreads: 1，单线程（Web Worker 中多线程反而引入 SharedArrayBuffer 复杂度）
 *  - simd:       true，启用 SIMD 加速
 *  - logLevel:   'warning'，避免 ort 内部刷屏
 *  - enableCpuMemArena: false，关闭 CPU 内存池预分配（默认会预分配 ~1GB，
 *                在 wasm32 浏览器中容易触发 OOM），改为按需分配
 *
 * @param {typeof import('onnxruntime-web')} ort
 */
function configureOrt(ort) {
  if (_ortConfigured) return
  _ortConfigured = true

  // 1. wasm 路径：仅生产环境显式指定
  //    dev 环境保持 ORT 默认（import.meta.url 推断），避免覆盖 Vite dev 的相对路径解析
  //    typeof 防御 import.meta.env 不存在的打包场景
  const isProd = typeof import.meta !== 'undefined'
    && import.meta.env
    && import.meta.env.PROD === true

  if (isProd) {
    ort.env.wasm.wasmPaths = '/assets/'
  }

  // 2. Worker 中不需要 JS 代理
  ort.env.wasm.proxy = false

  // 3. 单线程 + SIMD
  ort.env.wasm.numThreads = 1
  ort.env.wasm.simd = true

  // 4. 调整日志级别：error 必显示，warning 默认，info 关闭
  ort.env.logLevel = 'warning'

  // 5. 关闭冗余的 webgl 日志（用不到）
  if (ort.env.webgl) ort.env.webgl.disableWarnings = true

  // 6. 关闭 CPU 内存池预分配：默认会预分配 ~1GB 内存池，
  //    在 wasm32 浏览器（Chrome 桌面）容易触发 OOM，错误码约为 0x2D9A0540 (764MB)
  //    关闭后 ORT 会按需分配内存，代价是频繁分配/释放会慢一点
  try {
    ort.env.wasm.enableCpuMemArena = false
  } catch (err) {
    // 部分版本 API 名称不同（enableMemoryPattern），忽略
  }

  // 7. 限制 wasm memory growth：默认不限制 maximum，
  //    显式限制到 2GB 避免某些浏览器触发 "Cannot enlarge memory arrays" 错误
  try {
    ort.env.wasm.maximumMemory = 2 * 1024 * 1024 * 1024  // 2GB
  } catch (err) {
    // 部分版本无此 API
  }

  // 8. 关闭内存模式优化（与 enableCpuMemArena=false 配合，进一步减少预分配）
  try {
    ort.env.wasm.enableMemoryPattern = false
  } catch (err) {
    // 部分版本无此 API
  }
}

/**
 * 动态导入 onnxruntime-web（带缓存与配置）
 * @returns {Promise<typeof import('onnxruntime-web')>}
 */
async function importOrt() {
  if (_ortInstance) return _ortInstance
  _ortInstance = await import('onnxruntime-web')
  configureOrt(_ortInstance)
  return _ortInstance
}

/**
 * 统一的 Session 创建工厂
 * - 优先 wasm 后端
 * - 失败时回退 cpu
 * - 启用全部图优化
 *
 * @param {ArrayBuffer} buffer
 * @returns {Promise<import('onnxruntime-web').InferenceSession>}
 */
async function createOrtSession(buffer) {
  const ort = await importOrt()
  // 尝试多个 executionProviders 顺序：wasm → cpu
  // graphOptimizationLevel 选用 'basic'：
  //   - 'all' / 'extended' 会做算子融合、layout 转换，对 DynamicQuantizeLinear
  //     等动态算子可能不兼容，导致 wasm 端 OOM
  //   - 'basic' 只做常量折叠等最基础优化，最兼容但速度略慢
  const providerChain = ['wasm', 'cpu']
  let lastError = null
  for (const ep of providerChain) {
    try {
      return await ort.InferenceSession.create(buffer, {
        executionProviders: [ep],
        graphOptimizationLevel: 'basic',
      })
    } catch (e) {
      // ONNX Runtime wasm 抛出的可能是 emscripten 原始错误码（数字），
      // 也可能是 Error 对象，也可能是特殊代理对象——逐个兼容提取信息
      const typeOf = typeof e
      const ctorName = e?.constructor?.name
      const ownKeys = (e && typeof e === 'object')
        ? Object.getOwnPropertyNames(e)
        : []
      // 直接序列化整个对象（避免 JSON.stringify 漏掉原型链上的字段）
      let serialized = '<unserializable>'
      try {
        serialized = JSON.stringify(e, Object.getOwnPropertyNames(e || {}))
      } catch {}

      const info = {
        ep,
        typeOf,
        ctorName,
        ownKeys,
        serialized,
        // 转十六进制便于看是否是 emscripten 错误码
        hexValue: typeof e === 'number' ? '0x' + (e >>> 0).toString(16).toUpperCase() : undefined,
        // String(e) - 这是用户实际看到的错误码
        toString: (() => { try { return String(e) } catch { return '<unstringifiable>' } })(),
      }
      console.warn(`[ORT] ${ep} backend failed (raw):`, info)
      // 同时打印原始 error 对象（DevTools 可以展开查看）
      console.warn(`[ORT] ${ep} raw error object:`, e)
      lastError = e
    }
  }
  // 友好的最终错误消息（包含可操作建议）
  const bufMB = (buffer.byteLength / 1024 / 1024).toFixed(2)
  const isLargeModel = buffer.byteLength > 500 * 1024 * 1024
  const hint = isLargeModel
    ? '\n\n可能原因：模型文件过大（>500MB），浏览器 wasm 内存不足。' +
      '建议：\n' +
      '  1. 改用 MODNet（轻量快速，6.6MB）\n' +
      '  2. 使用 INT8 量化版 BiRefNet（~250MB）\n' +
      '  3. 通过后端 ONNX Runtime Python 做服务端推理'
    : '\n\n建议：检查模型文件是否为有效的 ONNX 格式（用 Netron / onnx.checker 验证）'
  throw new Error(
    `所有 ONNX Runtime 后端均加载失败（wasm/cpu）。模型大小=${bufMB}MB。` +
    `最后错误: ${
      lastError?.message || String(lastError) || '未知错误'
    }` +
    hint
  )
}

/**
 * 加载 ONNX 模型
 * 同时加载抠图模型和人脸检测模型(SCRFD-10G-BNKPS)
 * SCRFD 加载失败不影响抠图功能，仅跳过旋转矫正
 * @param {string[]} urls - 抠图模型候选下载地址列表
 * @param {string[]} [faceModelUrls] - SCRFD 人脸检测模型候选下载地址列表
 */
async function loadModel(urls, faceModelUrls) {
  // ---- 抠图模型 ----
  if (!ortSession) {
    self.postMessage({ type: 'progress', stage: 'download', progress: 0 })
    const { buffer: modelBuffer } = await downloadModel(urls)

    // 提前 importOrt()，触发 wasm 加载并暴露错误
    // 防止到 InferenceSession.create 才发现 wasm 未就绪
    await importOrt()

    self.postMessage({ type: 'progress', stage: 'load', progress: 0 })
    ortSession = await createOrtSession(modelBuffer)
  }

  // ---- SCRFD 人脸检测模型（可选，加载失败不阻塞） ----
  if (!yunetSession && !scrfdSession && faceModelUrls && faceModelUrls.length > 0) {
    try {
      const { buffer: faceBuffer } = await downloadModel(faceModelUrls)
      const session = await createOrtSession(faceBuffer)
      yunetSession = session
      scrfdSession = session
      console.log('SCRFD-10G-BNKPS 人脸检测模型加载成功')
    } catch (e) {
      console.warn('SCRFD 加载失败，将跳过旋转矫正:', e.message)
    }
  }

  self.postMessage({ type: 'modelLoaded' })
}

/**
 * 从本地文件 Buffer 加载模型（无需网络下载）
 *
 * 用途：用户通过文件选择器选择本地 .onnx 文件后，直接将 ArrayBuffer 传入
 *       跳过下载流程，适合内网/离线环境或已下载好模型的场景
 *
 * @param {ArrayBuffer} modelBuffer - 抠图模型文件的 ArrayBuffer
 * @param {ArrayBuffer} [faceModelBuffer] - SCRFD 人脸检测模型文件的 ArrayBuffer（可选）
 */
async function loadModelFromBuffer(modelBuffer, faceModelBuffer) {
  // ---- 抠图模型 ----
  if (!ortSession) {
    self.postMessage({ type: 'progress', stage: 'init', progress: 0.3 })
    await importOrt()
    self.postMessage({ type: 'progress', stage: 'load', progress: 0.6 })
    ortSession = await createOrtSession(modelBuffer)
  }

  // ---- SCRFD 人脸检测模型（可选，加载失败不阻塞） ----
  if (!yunetSession && !scrfdSession && faceModelBuffer) {
    try {
      const session = await createOrtSession(faceModelBuffer)
      yunetSession = session
      scrfdSession = session
      console.log('SCRFD-10G-BNKPS 人脸检测模型（本地文件）加载成功')
    } catch (e) {
      console.warn('SCRFD 本地文件加载失败，将跳过旋转矫正:', e.message)
    }
  }

  self.postMessage({ type: 'modelLoaded' })
}

// ========== 图像预处理 ==========

/**
 * MODNet 预处理
 *   - 输入: RGB 图片，缩放到 512x512
 *   - 归一化: (pixel / 255 - 0.5) / 0.5 → 范围 [-1, 1]
 *   - 格式: NCHW float32
 */
function preprocessMODNet(imageData, targetSize = 512) {
  const { data, width, height } = imageData
  
  // 创建离屏 canvas 进行缩放
  const canvas = new OffscreenCanvas(targetSize, targetSize)
  const ctx = canvas.getContext('2d')
  
  // 渲染原图到 OffscreenCanvas
  const tmpCanvas = new OffscreenCanvas(width, height)
  const tmpCtx = tmpCanvas.getContext('2d')
  tmpCtx.putImageData(imageData, 0, 0)
  
  ctx.drawImage(tmpCanvas, 0, 0, targetSize, targetSize)
  
  const resized = ctx.getImageData(0, 0, targetSize, targetSize)
  const pixels = resized.data
  
  // NCHW float32, normalized to [-1, 1]
  const input = new Float32Array(1 * 3 * targetSize * targetSize)
  const planeSize = targetSize * targetSize
  
  for (let i = 0; i < planeSize; i++) {
    const idx = i * 4
    // (pixel / 255 - 0.5) / 0.5 = pixel / 127.5 - 1
    input[i] = pixels[idx] / 127.5 - 1           // R
    input[planeSize + i] = pixels[idx + 1] / 127.5 - 1  // G
    input[2 * planeSize + i] = pixels[idx + 2] / 127.5 - 1  // B
  }
  
  return input
}

/**
 * BiRefNet / RMBG-2 预处理
 *   - 输入: RGB 图片，缩放到 1024x1024
 *   - 归一化: (pixel / 255 - mean) / std
 *   - 格式: NCHW float32
 */
function preprocessBiRefNet(imageData, targetSize = 1024) {
  const { data, width, height } = imageData
  
  const canvas = new OffscreenCanvas(targetSize, targetSize)
  const ctx = canvas.getContext('2d')
  
  const tmpCanvas = new OffscreenCanvas(width, height)
  const tmpCtx = tmpCanvas.getContext('2d')
  tmpCtx.putImageData(imageData, 0, 0)
  
  ctx.drawImage(tmpCanvas, 0, 0, targetSize, targetSize)
  
  const resized = ctx.getImageData(0, 0, targetSize, targetSize)
  const pixels = resized.data
  
  // Normalize with ImageNet stats: (x/255 - mean) / std
  const mean = [0.485, 0.456, 0.406]
  const std = [0.229, 0.224, 0.225]
  
  const input = new Float32Array(1 * 3 * targetSize * targetSize)
  const planeSize = targetSize * targetSize
  
  for (let i = 0; i < planeSize; i++) {
    const idx = i * 4
    input[i] = (pixels[idx] / 255 - mean[0]) / std[0]                    // R
    input[planeSize + i] = (pixels[idx + 1] / 255 - mean[1]) / std[1]    // G
    input[2 * planeSize + i] = (pixels[idx + 2] / 255 - mean[2]) / std[2]  // B
  }
  
  return input
}

// ========== SCRFD-10G-BNKPS 人脸检测 ==========

/**
 * SCRFD 预处理
 *   - 输入: 原图缩放到 inputSize × inputSize（默认 640，SCRFD-10G 标准）
 *   - 颜色格式: BGR（注意！与 MODNet/BiRefNet 的 RGB 不同）
 *   - 归一化: 原始像素值 [0, 255]，模型内部含归一化层
 *   - 格式: NCHW float32
 *   - 来源: insightface scrfd_10g_bnkps (CVHub520/modelscope 镜像)
 */
function preprocessSCRFD(imageData, inputSize = 640) {
  const { width, height } = imageData

  const canvas = new OffscreenCanvas(inputSize, inputSize)
  const ctx = canvas.getContext('2d')

  const tmpCanvas = new OffscreenCanvas(width, height)
  const tmpCtx = tmpCanvas.getContext('2d')
  tmpCtx.putImageData(imageData, 0, 0)

  ctx.drawImage(tmpCanvas, 0, 0, inputSize, inputSize)

  const resized = ctx.getImageData(0, 0, inputSize, inputSize)
  const pixels = resized.data

  // NCHW float32, BGR 通道顺序，像素值 [0, 255]
  const input = new Float32Array(1 * 3 * inputSize * inputSize)
  const planeSize = inputSize * inputSize

  for (let i = 0; i < planeSize; i++) {
    const idx = i * 4
    input[i]                     = pixels[idx + 2] // B
    input[planeSize + i]         = pixels[idx + 1] // G
    input[2 * planeSize + i]     = pixels[idx]     // R
  }

  return input
}

/**
 * 非极大值抑制 (NMS)
 * @param {Array} detections - 检测结果数组
 * @param {number} iouThreshold - IoU 阈值
 * @returns {Array} 过滤后的检测结果
 */
function nms(detections, iouThreshold = 0.3) {
  if (detections.length === 0) return []

  // 按分数降序排列
  const sorted = [...detections].sort((a, b) => b.score - a.score)
  const keep = []
  const suppressed = new Array(sorted.length).fill(false)

  for (let i = 0; i < sorted.length; i++) {
    if (suppressed[i]) continue
    keep.push(sorted[i])

    for (let j = i + 1; j < sorted.length; j++) {
      if (suppressed[j]) continue
      const iou = computeIoU(sorted[i].bbox, sorted[j].bbox)
      if (iou > iouThreshold) {
        suppressed[j] = true
      }
    }
  }

  return keep
}

/**
 * 计算两个 bbox 的 IoU
 */
function computeIoU(box1, box2) {
  const x1 = Math.max(box1.x1, box2.x1)
  const y1 = Math.max(box1.y1, box2.y1)
  const x2 = Math.min(box1.x2, box2.x2)
  const y2 = Math.min(box1.y2, box2.y2)

  const interArea = Math.max(0, x2 - x1) * Math.max(0, y2 - y1)
  const area1 = (box1.x2 - box1.x1) * (box1.y2 - box1.y1)
  const area2 = (box2.x2 - box2.x1) * (box2.y2 - box2.y1)
  const unionArea = area1 + area2 - interArea

  return unionArea > 0 ? interArea / unionArea : 0
}

/**
 * SCRFD 后处理 - 解码模型输出，返回人脸检测结果
 *
 * SCRFD 10G-BNKPS 模型有 9 个输出（3 个 stride × 3 个输出）:
 *   每个 stride: cls(置信度, channel=1), bbox(bbox, channel=4), kps(关键点, channel=10)
 *   输出形状示例: [1, H*W*2, 1] / [1, H*W*2, 4] / [1, H*W*2, 10]
 *   （其中 2 = num_anchors_per_location，10G-BNKPS 默认 anchor=2）
 *
 * 关键差异（SCRFD 自身特性）:
 *   - SCRFD 的 bbox/kps 输出已经预乘 stride 系数
 *   - 因此解码时不再乘以 inputSize/outputSize 缩放比，直接使用即可
 *
 * bbox 解码:
 *   x1 = anchor_cx - bbox[0], y1 = anchor_cy - bbox[1]
 *   x2 = anchor_cx + bbox[2], y2 = anchor_cy + bbox[3]
 *
 * 关键点解码:
 *   landmark[i].x = anchor_cx + kps[2*i], landmark[i].y = anchor_cy + kps[2*i+1]
 *   5 个关键点: 右眼, 左眼, 鼻尖, 右嘴角, 左嘴角
 *
 * @param {object} results - ONNX 推理结果
 * @param {string[]} outputNames - 输出节点名称列表
 * @param {number} inputSize - 模型输入尺寸
 * @param {number} origWidth - 原图宽度（用于坐标缩放）
 * @param {number} origHeight - 原图高度（用于坐标缩放）
 * @returns {object|null} 最佳人脸检测结果 { bbox, landmarks, score }
 */
function postprocessSCRFD(results, outputNames, inputSize, origWidth, origHeight) {
  const scoreThreshold = 0.5
  const nmsThreshold = 0.3
  const strides = [8, 16, 32]
  const anchorsPerLoc = 2

  // 按通道数识别输出类型: 1=cls, 4=bbox, 10=kps
  // 同一 stride 的输出具有相同的 H×W 空间维度
  const clsOutputs = []
  const bboxOutputs = []
  const kpsOutputs = []

  for (const name of outputNames) {
    const tensor = results[name]
    if (!tensor) continue
    const dims = tensor.dims
    let c = 0
    // 取最后一维作为通道数
    if (dims.length >= 1) c = dims[dims.length - 1]

    if (c === 1) clsOutputs.push(tensor)
    else if (c === 4) bboxOutputs.push(tensor)
    else if (c === 10) kpsOutputs.push(tensor)
  }

  if (clsOutputs.length === 0 || bboxOutputs.length === 0) return null

  // SCRFD 模型有 3 个 stride 级别的输出，需要按 stride 分组
  // 同一 stride 的 cls/bbox/kps 张量具有相同 H×W
  // 实现策略：按 H*W 空间尺寸对 9 个张量分组（每组 3 个张量）
  const grouped = groupByStride(clsOutputs, bboxOutputs, kpsOutputs, strides, anchorsPerLoc, inputSize)
  if (!grouped) return null

  const detections = []
  const scaleX = origWidth / inputSize
  const scaleY = origHeight / inputSize

  for (let s = 0; s < grouped.length; s++) {
    const stride = strides[s]
    const { clsTensor, bboxTensor, kpsTensor } = grouped[s]

    // SCRFD 的输出形状常见为 [1, H*W*2, C]
    // data 长度 = H*W*2*C；每个位置有 2 个 anchor
    const numLocs = clsTensor.data.length / anchorsPerLoc

    for (let i = 0; i < numLocs; i++) {
      for (let a = 0; a < anchorsPerLoc; a++) {
        const idx = i * anchorsPerLoc + a

        const score = clsTensor.data[idx]
        if (score < scoreThreshold) continue

        // 中心点 (i 是展开后的位置索引，需还原为 (col, row))
        // numLocs = numH * numW
        const numW = Math.floor(inputSize / stride)
        const numH = Math.floor(inputSize / stride)
        const col = i % numW
        const row = Math.floor(i / numW)
        const cx = (col + 0.5) * stride
        const cy = (row + 0.5) * stride

        // bbox 解码（SCRFD 已预乘 stride）
        const x1 = (cx - bboxTensor.data[idx * 4 + 0]) * scaleX
        const y1 = (cy - bboxTensor.data[idx * 4 + 1]) * scaleY
        const x2 = (cx + bboxTensor.data[idx * 4 + 2]) * scaleX
        const y2 = (cy + bboxTensor.data[idx * 4 + 3]) * scaleY

        // 关键点解码（顺序：右眼、左眼、鼻、右嘴角、左嘴角，与原版一致）
        const landmarks = []
        if (kpsTensor) {
          for (let j = 0; j < 5; j++) {
            landmarks.push({
              x: (cx + kpsTensor.data[idx * 10 + j * 2 + 0]) * scaleX,
              y: (cy + kpsTensor.data[idx * 10 + j * 2 + 1]) * scaleY,
            })
          }
        }

        detections.push({
          bbox: { x1, y1, x2, y2 },
          landmarks,
          score,
        })
      }
    }
  }

  // NMS 去重
  const keep = nms(detections, nmsThreshold)
  if (keep.length === 0) return null

  // 返回置信度最高的检测结果
  keep.sort((a, b) => b.score - a.score)
  return keep[0]
}

/**
 * 将 SCRFD 9 个张量按 stride 分组。
 * 分组依据：同一 stride 的 cls/bbox/kps 张量具有相同 H*W*2 = data.length / channel
 * 应对各种命名（output_0~8 / cls_8 / stride_8_cls / ...）的鲁棒分组。
 */
function groupByStride(clsOutputs, bboxOutputs, kpsOutputs, strides, anchorsPerLoc, inputSize) {
  const grouped = []

  for (const stride of strides) {
    // 该 stride 下 H*W 的位置数
    // 数据中每个位置 anchorsPerLoc=2 个 anchor，因此 numLocs*anchorsPerLoc = data.length/channel
    // 我们用 channel=1 的 cls 张量长度来推断 numLocs
    // 但我们事先不知道哪个 stride 属于哪个张量，所以需要匹配：

    // 找 cls 张量中 numLocs 与当前 stride 匹配的那个
    // 期望 numLocs = (inputSize/stride)^2
    // 但我们没法直接拿到 inputSize，只能根据 data.length 反推

    // 简化策略：data.length / channel = numLocs * anchorsPerLoc
    // 对 inputSize=640, stride=8:  numLocs = 80*80=6400  → data.length(1ch) = 12800
    // 对 inputSize=640, stride=16: numLocs = 40*40=1600  → data.length(1ch) = 3200
    // 对 inputSize=640, stride=32: numLocs = 20*20=400   → data.length(1ch) = 800
    // （inputSize=320 时对应的 numLocs=1600/400/100，data.length=3200/800/200）

    const hw = Math.floor(inputSize / stride)
    const expectedClsLen = hw * hw * anchorsPerLoc
    const expectedBboxLen = expectedClsLen * 4
    const expectedKpsLen = expectedClsLen * 10

    const clsTensor = clsOutputs.find(t => t.data.length === expectedClsLen)
    const bboxTensor = bboxOutputs.find(t => t.data.length === expectedBboxLen)
    const kpsTensor = kpsOutputs.length > 0
      ? kpsOutputs.find(t => t.data.length === expectedKpsLen)
      : null

    if (!clsTensor || !bboxTensor) return null
    grouped.push({ clsTensor, bboxTensor, kpsTensor })
  }

  return grouped
}

/**
 * 人脸检测 - 运行 SCRFD 推理并返回检测结果
 * @param {ImageData} imageData - 原始图像数据
 * @returns {Promise<object|null>} 人脸检测结果
 */
async function detectFace(imageData) {
  if (!yunetSession) return null

  const inputSize = 640
  const origWidth = imageData.width
  const origHeight = imageData.height

  // 预处理（BGR 格式，640×640）
  const inputData = preprocessSCRFD(imageData, inputSize)

  const ort = await importOrt()
  const inputName = yunetSession.inputNames[0]
  const tensor = new ort.Tensor('float32', inputData, [1, 3, inputSize, inputSize])

  // 推理
  const feeds = { [inputName]: tensor }
  const results = await yunetSession.run(feeds)

  // 后处理（返回 {bbox, landmarks, score}）
  return postprocessSCRFD(results, yunetSession.outputNames, inputSize, origWidth, origHeight)
}

/**
 * 人脸对齐 - 基于双眼关键点计算旋转角度，旋转图像使双眼水平
 *
 * SCRFD 关键点顺序: [0]右眼, [1]左眼, [2]鼻尖, [3]右嘴角, [4]左嘴角
 * 旋转角度 = atan2(leftEye.y - rightEye.y, leftEye.x - rightEye.x)
 *
 * @param {OffscreenCanvas} srcCanvas - 源画布
 * @param {object} faceDetection - 人脸检测结果
 * @returns {OffscreenCanvas} 旋转后的画布
 */
function alignFaceRotation(srcCanvas, faceDetection) {
  if (!faceDetection || !faceDetection.landmarks || faceDetection.landmarks.length < 2) {
    return srcCanvas
  }
  
  const rightEye = faceDetection.landmarks[0]
  const leftEye = faceDetection.landmarks[1]
  
  // 计算双眼连线角度
  const dx = leftEye.x - rightEye.x
  const dy = leftEye.y - rightEye.y
  let angle = Math.atan2(dy, dx) * 180 / Math.PI
  
  // 角度过小（< 2度）不旋转，避免不必要的插值损失
  if (Math.abs(angle) < 2) return srcCanvas
  
  // 限制最大旋转角度，避免过度矫正
  angle = Math.max(-15, Math.min(15, angle))
  
  const w = srcCanvas.width
  const h = srcCanvas.height
  
  // 计算旋转后的画布尺寸（保持原图大小，可能裁切边角）
  const rotatedCanvas = new OffscreenCanvas(w, h)
  const ctx = rotatedCanvas.getContext('2d')
  
  // 以画面中心为旋转中心
  ctx.translate(w / 2, h / 2)
  ctx.rotate(angle * Math.PI / 180)
  ctx.translate(-w / 2, -h / 2)
  
  ctx.drawImage(srcCanvas, 0, 0)
  
  return rotatedCanvas
}

/**
 * 从 ONNX 输出生成 alpha 蒙版
 * 输出: [1, 1, H, W] float32
 *   - MODNet 输出已为 [0, 1] 概率值，无需后处理
 *   - BiRefNet / RMBG-2.0 输出为 raw logits，需要 sigmoid 转换到 [0, 1]
 * 返回: OffscreenCanvas 包含 RGBA 图片（原始颜色 + 推理出的 alpha）
 */
function postprocessMask(ortOutput, originalImageData, modelType) {
  const outputData = ortOutput.data // Float32Array
  const modelSize = modelType === 'modnet' ? 512 : 1024
  // MODNet 输出已 sigmoid 过；BiRefNet/RMBG-2.0 输出是 raw logits
  const needSigmoid = modelType !== 'modnet'

  // 创建 alpha mask 的 ImageData
  const maskImageData = new ImageData(modelSize, modelSize)
  const maskPixels = maskImageData.data

  // 将模型输出映射到 0-255 alpha 值
  for (let i = 0; i < modelSize * modelSize; i++) {
    let val = outputData[i]
    if (needSigmoid) {
      // sigmoid: 1 / (1 + e^-x)，对负值大输入做数值稳定处理
      val = val >= 0 ? 1 / (1 + Math.exp(-val)) : Math.exp(val) / (1 + Math.exp(val))
    }
    // 钳制到 [0, 1]，映射到 [0, 255]
    const alpha = Math.round(Math.max(0, Math.min(1, val)) * 255)
    maskPixels[i * 4] = 255     // R (白色蒙版)
    maskPixels[i * 4 + 1] = 255 // G
    maskPixels[i * 4 + 2] = 255 // B
    maskPixels[i * 4 + 3] = alpha
  }

  return maskImageData
}

// ========== 背景移除 ==========

/**
 * 执行抠图推理
 * 完整流程：SCRFD人脸检测 → 旋转矫正 → MODNet/BiRefNet抠图推理 → Alpha蒙版合成
 * @param {ImageBitmap} imageBitmap - 输入图片（从主线程传过来的）
 * @param {object} options - { modelType: 'modnet'|'birefnet', alignFace: boolean }
 */
async function removeBackground(imageBitmap, options = {}) {
  const { modelType = 'modnet', alignFace = true } = options

  if (!ortSession) {
    throw new Error('模型未加载，请先调用 loadModel')
  }

  let origWidth = imageBitmap.width
  let origHeight = imageBitmap.height
  const modelSize = modelType === 'modnet' ? 512 : 1024

  // 1. 获取原图 ImageData
  const origCanvas = new OffscreenCanvas(origWidth, origHeight)
  const origCtx = origCanvas.getContext('2d')
  origCtx.drawImage(imageBitmap, 0, 0)
  let origImageData = origCtx.getImageData(0, 0, origWidth, origHeight)

  // 2. 人脸检测 + 旋转矫正（SCRFD 加载成功且启用时执行）
  if (alignFace && yunetSession) {
    self.postMessage({ type: 'progress', stage: 'face_detect', progress: 0.1 })
    try {
      const faceDetection = await detectFace(origImageData)
      if (faceDetection) {
        const alignedCanvas = alignFaceRotation(origCanvas, faceDetection)
        if (alignedCanvas !== origCanvas) {
          // 旋转后的画布尺寸可能与原图不同，更新尺寸
          origWidth = alignedCanvas.width
          origHeight = alignedCanvas.height
          const alignedCtx = alignedCanvas.getContext('2d')
          origImageData = alignedCtx.getImageData(0, 0, origWidth, origHeight)
          console.log(`人脸对齐: 旋转 ${faceDetection.score.toFixed(2)} 置信度, ${faceDetection.landmarks.length} 关键点`)
        }
      }
    } catch (e) {
      console.warn('人脸检测失败，跳过旋转矫正:', e.message)
    }
  }
  
  // 3. 预处理
  self.postMessage({ type: 'progress', stage: 'preprocess', progress: 0.2 })
  let inputTensor
  if (modelType === 'modnet') {
    inputTensor = preprocessMODNet(origImageData, modelSize)
  } else {
    inputTensor = preprocessBiRefNet(origImageData, modelSize)
  }
  
  // 4. 创建 ONNX Tensor
  const ort = await importOrt()
  const inputName = ortSession.inputNames[0]
  const tensor = new ort.Tensor('float32', inputTensor, [1, 3, modelSize, modelSize])
  
  // 5. 执行推理
  self.postMessage({ type: 'progress', stage: 'inference', progress: 0.5 })
  const feeds = { [inputName]: tensor }
  const results = await ortSession.run(feeds)
  
  const outputName = ortSession.outputNames[0]
  const output = results[outputName]
  
  // 6. 生成 alpha 蒙版
  self.postMessage({ type: 'progress', stage: 'postprocess', progress: 0.8 })
  const maskImageData = postprocessMask(output, origImageData, modelType)
  
  // 7. 将蒙版应用到原图
  const resultCanvas = new OffscreenCanvas(origWidth, origHeight)
  const resultCtx = resultCanvas.getContext('2d')
  
  // 先绘制蒙版到 modelSize 大小的 canvas
  const maskCanvas = new OffscreenCanvas(modelSize, modelSize)
  const maskCtx = maskCanvas.getContext('2d')
  maskCtx.putImageData(maskImageData, 0, 0)
  
  // 将蒙版缩放绘制到原图大小（会进行双线性插值平滑 alpha）
  resultCtx.drawImage(maskCanvas, 0, 0, origWidth, origHeight)
  
  // 取蒙版的 alpha 通道
  const maskResultData = resultCtx.getImageData(0, 0, origWidth, origHeight)
  const maskResultPixels = maskResultData.data
  
  // 将原始 RGB + 推理出的 alpha 合成最终图片
  const finalImageData = new ImageData(origWidth, origHeight)
  const finalPixels = finalImageData.data
  
  for (let y = 0; y < origHeight; y++) {
    for (let x = 0; x < origWidth; x++) {
      const idx = (y * origWidth + x) * 4
      // 使用原始颜色（可能是旋转矫正后的颜色）
      finalPixels[idx] = origImageData.data[idx]         // R
      finalPixels[idx + 1] = origImageData.data[idx + 1] // G
      finalPixels[idx + 2] = origImageData.data[idx + 2] // B
      // 使用推理出的 alpha
      finalPixels[idx + 3] = maskResultPixels[idx + 3]   // A
    }
  }
  
  resultCtx.putImageData(finalImageData, 0, 0)
  
  // 8. 返回 ImageBitmap（零拷贝传输回主线程）
  const resultBitmap = await createImageBitmap(resultCanvas)
  self.postMessage({ 
    type: 'maskReady', 
    maskImageBitmap: resultBitmap,
    originalWidth: origWidth,
    originalHeight: origHeight,
  }, [resultBitmap]) // transfer
}

// ========== 消息处理 ==========

self.onmessage = async (event) => {
  const { type } = event.data
  
  try {
    switch (type) {
      case 'loadModel': {
        const { urls, faceModelUrls } = event.data
        await loadModel(urls, faceModelUrls)
        break
      }
      
      case 'loadModelFromBuffer': {
        const { modelBuffer, faceModelBuffer } = event.data
        if (!modelBuffer) throw new Error('缺少模型文件数据')
        await loadModelFromBuffer(modelBuffer, faceModelBuffer)
        break
      }
      
      case 'removeBackground': {
        const { imageBitmap, modelType, alignFace } = event.data
        if (!imageBitmap) throw new Error('缺少图片数据')
        await removeBackground(imageBitmap, { modelType, alignFace })
        break
      }
      
      default:
        console.warn('未知 Worker 消息类型:', type)
    }
  } catch (error) {
    self.postMessage({ type: 'error', message: error.message || String(error) })
  }
}