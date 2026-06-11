/**
 * 证件照前端处理器
 * 集成 @imgly/background-removal (AI抠图) + Canvas API (合成/裁剪/缩放)
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
 * 步骤1: AI 抠图 - 使用 @imgly/background-removal 移除背景
 * @param {File|Blob} imageFile - 原始图片文件
 * @param {Function} onProgress - 进度回调 (0~1)
 * @returns {Promise<HTMLImageElement>} 透明背景的人像图片
 */
export async function removeImageBackground(imageFile, onProgress) {
  // 动态导入，避免首屏加载大体积的 ONNX Runtime
  const { removeBackground: aiRemoveBackground } = await import('@imgly/background-removal')
  
  const blob = await aiRemoveBackground(imageFile, {
    model: 'medium',       // small/medium/large - medium 平衡速度与质量
    output: {
      format: 'image/png',
      quality: 0.9,
    },
    progress: (key, current, total) => {
      if (onProgress && total > 0) {
        onProgress(current / total)
      }
    },
  })

  const url = URL.createObjectURL(blob)
  return loadImage(url)
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
 * 步骤3: 合成背景色 - 将透明人像合成到纯色背景上
 * @param {HTMLCanvasElement} fgCanvas - 前景画布（含alpha通道）
 * @param {object} bgColor - 背景色 {r, g, b}
 * @param {number} feathering - 羽化程度 0-5
 * @returns {HTMLCanvasElement} 合成后的画布
 */
export function compositeWithBackground(fgCanvas, bgColor, feathering = 2) {
  const w = fgCanvas.width
  const h = fgCanvas.height

  const resultCanvas = document.createElement('canvas')
  resultCanvas.width = w
  resultCanvas.height = h
  const ctx = resultCanvas.getContext('2d')

  // 1. 填充纯色背景
  ctx.fillStyle = `rgb(${bgColor.r},${bgColor.g},${bgColor.b})`
  ctx.fillRect(0, 0, w, h)

  // 2. 可选羽化处理：对前景alpha通道做模糊
  if (feathering > 0) {
    const featheredCanvas = applyFeathering(fgCanvas, feathering)
    ctx.drawImage(featheredCanvas, 0, 0)
  } else {
    ctx.drawImage(fgCanvas, 0, 0)
  }

  return resultCanvas
}

/**
 * 对前景进行边缘羽化处理
 * 使用 Canvas filter 的 blur 来模糊 alpha 通道边缘
 * @param {HTMLCanvasElement} srcCanvas
 * @param {number} radius - 羽化半径 0-5
 * @returns {HTMLCanvasElement}
 */
function applyFeathering(srcCanvas, radius) {
  const w = srcCanvas.width
  const h = srcCanvas.height

  // 先提取alpha通道边缘区域
  const srcCtx = srcCanvas.getContext('2d')
  const srcData = srcCtx.getImageData(0, 0, w, h)
  const srcPixels = srcData.data

  // 创建边缘蒙版：只对前景/背景边界区域做模糊
  const edgeMask = new Uint8Array(w * h)
  const threshold = 10 // alpha阈值，用于检测边缘

  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const idx = (y * w + x) * 4
      const alpha = srcPixels[idx + 3]
      // 检测是否是边缘像素（alpha在0~255之间的过渡区域）
      if (alpha > threshold && alpha < 255 - threshold) {
        edgeMask[y * w + x] = 1
      }
    }
  }

  // 扩展边缘蒙版（膨胀操作，使羽化区域更宽）
  const blurRadius = radius
  const expandedMask = dilateMask(edgeMask, w, h, blurRadius * 2)

  // 使用 Canvas blur 做高斯模糊
  const blurCanvas = document.createElement('canvas')
  blurCanvas.width = w
  blurCanvas.height = h
  const blurCtx = blurCanvas.getContext('2d')
  blurCtx.filter = `blur(${radius}px)`
  blurCtx.drawImage(srcCanvas, 0, 0)
  blurCtx.filter = 'none'

  // 取模糊后的像素
  const blurData = blurCtx.getImageData(0, 0, w, h)
  const blurPixels = blurData.data

  // 混合：边缘区域用模糊后的alpha，非边缘区域用原始alpha
  const resultCanvas = document.createElement('canvas')
  resultCanvas.width = w
  resultCanvas.height = h
  const resultCtx = resultCanvas.getContext('2d')
  const resultData = resultCtx.createImageData(w, h)
  const resultPixels = resultData.data

  for (let i = 0; i < w * h; i++) {
    const idx = i * 4
    resultPixels[idx] = srcPixels[idx]       // R
    resultPixels[idx + 1] = srcPixels[idx + 1] // G
    resultPixels[idx + 2] = srcPixels[idx + 2] // B

    if (expandedMask[i]) {
      // 边缘区域：使用模糊后的alpha
      resultPixels[idx + 3] = blurPixels[idx + 3]
    } else {
      // 非边缘区域：使用原始alpha
      resultPixels[idx + 3] = srcPixels[idx + 3]
    }
  }

  resultCtx.putImageData(resultData, 0, 0)
  return resultCanvas
}

/**
 * 膨胀蒙版
 */
function dilateMask(mask, w, h, radius) {
  const result = new Uint8Array(w * h)
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      if (mask[y * w + x]) {
        for (let dy = -radius; dy <= radius; dy++) {
          for (let dx = -radius; dx <= radius; dx++) {
            const nx = x + dx
            const ny = y + dy
            if (nx >= 0 && nx < w && ny >= 0 && ny < h) {
              result[ny * w + nx] = 1
            }
          }
        }
      }
    }
  }
  return result
}

/**
 * 完整的证件照生成流程
 * @param {File} imageFile - 原始图片文件
 * @param {object} options - 配置选项
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
    onProgress,
  } = options

  // 1. AI抠图
  if (onProgress) onProgress({ stage: 'removing_bg', progress: 0 })
  const transparentImg = await removeImageBackground(imageFile, (p) => {
    if (onProgress) onProgress({ stage: 'removing_bg', progress: p * 0.6 })
  })

  // 2. 智能裁剪缩放
  if (onProgress) onProgress({ stage: 'cropping', progress: 0.6 })
  const croppedCanvas = smartCropAndResize(transparentImg, width, height)

  // 3. 合成背景色
  if (onProgress) onProgress({ stage: 'compositing', progress: 0.8 })
  const bgColor = resolveBgColor(background, customColor)
  const resultCanvas = compositeWithBackground(croppedCanvas, bgColor, feathering)

  // 4. 导出结果
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
