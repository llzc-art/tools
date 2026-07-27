package service

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"

	"github.com/disintegration/imaging"

	"lelezc.com/tools/internal/onnx"
)

// IDPhotoConfig 证件照配置
type IDPhotoConfig struct {
	Width       int     `json:"width"`
	Height      int     `json:"height"`
	Background  string  `json:"background"`  // white, blue, red, custom
	CustomColor string  `json:"custom_color"`
	DPI         int     `json:"dpi"`
	OutputFormat string `json:"output_format"` // jpeg, png
	Feathering  int     `json:"feathering"`   // 边缘羽化程度 0-5

	// UseBiRefNet 是否使用 BiRefNet-RMBG2 服务端推理（默认 false）
	// 浏览器前端因 wasm memory 限制无法运行 ~350MB 的大模型，故改用 Go 后端
	// 实现。模型 INT8 量化版 ~366MB，首次调用时自动下载到 data/onnxruntime/models/
	UseBiRefNet bool `json:"use_birefnet"`
}

// IDPhotoResult 证件照处理结果
type IDPhotoResult struct {
	Image  string `json:"image"` // base64 编码的图片
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Format string `json:"format"`
}

// PrintLayoutConfig 排版打印配置
type PrintLayoutConfig struct {
	PhotoWidth  int `json:"photo_width"`  // 单张证件照宽度
	PhotoHeight int `json:"photo_height"` // 单张证件照高度
	PaperWidth  int `json:"paper_width"`  // 相纸宽度(px) 默认5寸 1500x1050
	PaperHeight int `json:"paper_height"` // 相纸高度(px)
	Columns     int `json:"columns"`      // 列数
	Rows        int `json:"rows"`         // 行数
	Gap         int `json:"gap"`          // 间距(px)
}

// weightedSample 加权颜色采样
type weightedSample struct {
	c      color.NRGBA
	weight float64
}

// BGColors 预设背景色
var BGColors = map[string]color.NRGBA{
	"white":  {R: 255, G: 255, B: 255, A: 255},
	"blue":   {R: 67, G: 155, B: 219, A: 255},   // #439BDB 标准蓝
	"red":    {R: 230, G: 100, B: 100, A: 255},   // #E66464 标准红
	"blue2":  {R: 0, G: 130, B: 200, A: 255},     // #0082C8 身份证蓝
	"blue3":  {R: 53, G: 117, B: 187, A: 255},    // #3575BB 深蓝(护照)
	"gray":   {R: 230, G: 230, B: 230, A: 255},   // #E6E6E6 浅灰
}

// ProcessIDPhoto 处理证件照（改进版：先分析人像位置再精确居中裁剪）
func ProcessIDPhoto(file multipart.File, filename string, config *IDPhotoConfig) (*IDPhotoResult, error) {
	// 解码图片
	img, format, err := image.Decode(file)
	if err != nil {
		return nil, errors.New("无法解析图片: " + err.Error())
	}

	bounds := img.Bounds()
	origWidth := bounds.Dx()
	origHeight := bounds.Dy()

	// 计算目标尺寸
	targetWidth := config.Width
	targetHeight := config.Height
	if targetWidth <= 0 {
		targetWidth = 295
	}
	if targetHeight <= 0 {
		targetHeight = 413
	}

	// 如果启用 BiRefNet 服务端推理，先抠出透明背景人像
	// （浏览器前端因 wasm memory 限制无法运行 ~350MB 的大模型）
	if config.UseBiRefNet {
		birefnetResult, err := onnx.RunBiRefNet(img)
		if err != nil {
			return nil, fmt.Errorf("BiRefNet 服务端推理失败: %w", err)
		}
		// 用 BiRefNet 输出替代原图，后续流程基于透明背景分析
		img = birefnetResult.MaskImage
		bounds = img.Bounds()
		origWidth = bounds.Dx()
		origHeight = bounds.Dy()
	}

	// 获取背景色
	bgColor := color.NRGBA{R: 255, G: 255, B: 255, A: 255}
	if config.Background != "" && config.Background != "custom" {
		if c, ok := BGColors[config.Background]; ok {
			bgColor = c
		}
	} else if config.CustomColor != "" {
		bgColor = parseColorFromString(config.CustomColor)
	}

	// 缩放到工作尺寸进行人像分析（最长边不超过 800px）
	workW, workH := origWidth, origHeight
	if origWidth > 800 || origHeight > 800 {
		scale := 800.0 / math.Max(float64(origWidth), float64(origHeight))
		workW = int(float64(origWidth) * scale)
		workH = int(float64(origHeight) * scale)
	}
	workImg := imaging.Resize(img, workW, workH, imaging.Lanczos)

	// 分析人像位置：找前景包围盒 + 肩部检测
	portraitBounds := findPortraitBounds(workImg, workW, workH)
	shoulderY := detectShoulderYFromImage(workImg, workW, workH, portraitBounds)

	// 基于人像位置计算精确裁剪区域

	// 将工作图上的坐标映射回原图
	scaleBack := float64(origWidth) / float64(workW)
	portMinX := int(float64(portraitBounds.minX) * scaleBack)
	portMaxX := int(float64(portraitBounds.maxX) * scaleBack)
	portMinY := int(float64(portraitBounds.minY) * scaleBack)
	cropBottom := int(float64(shoulderY) * scaleBack)
	if cropBottom > origHeight-1 {
		cropBottom = origHeight - 1
	}

	contentW := portMaxX - portMinX + 1
	contentH := cropBottom - portMinY + 1
	contentCX := float64(portMinX+portMaxX) / 2.0

	// 证件照构图规则
	verticalFill := 0.75  // 人像占画面高度75%
	horizontalFill := 0.82
	topBias := 0.30       // 上方留白比例

	scaleY := float64(targetHeight) * verticalFill / float64(contentH)
	scaleX := float64(targetWidth) * horizontalFill / float64(contentW)
	cropScale := math.Min(scaleX, scaleY)
	if cropScale > 3.5 {
		cropScale = 3.5
	}

	srcW := int(float64(targetWidth) / cropScale)
	srcH := int(float64(targetHeight) / cropScale)

	extraVSpace := float64(srcH) - float64(contentH)
	srcX := contentCX - float64(srcW)/2.0
	srcY := float64(portMinY) - extraVSpace*topBias

	// 边界钳制
	if srcX < 0 {
		srcX = 0
	}
	if srcY < 0 {
		srcY = 0
	}
	if srcX+float64(srcW) > float64(origWidth) {
		srcX = float64(origWidth - srcW)
	}
	if srcY+float64(srcH) > float64(origHeight) {
		srcY = float64(origHeight - srcH)
	}

	// 裁剪原图
	croppedRect := image.Rect(int(srcX), int(srcY), int(srcX)+srcW, int(srcY)+srcH)
	croppedImg := imaging.Crop(img, croppedRect)

	// 缩放到目标尺寸
	resized := imaging.Resize(croppedImg, targetWidth, targetHeight, imaging.Lanczos)

	// 人像提取并替换背景
	feathering := config.Feathering
	if feathering < 0 {
		feathering = 2
	}
	if feathering > 5 {
		feathering = 5
	}
	result := extractAndReplaceBG(resized, bgColor, feathering)

	// 编码结果
	outputFormat := config.OutputFormat
	if outputFormat == "" {
		outputFormat = "jpeg"
	}

	var buf bytes.Buffer
	switch strings.ToLower(outputFormat) {
	case "png":
		format = "png"
		err = png.Encode(&buf, result)
	default:
		format = "jpeg"
		err = encodeJPEGWithDPI(&buf, result, 95, config.DPI)
	}
	if err != nil {
		return nil, errors.New("编码图片失败: " + err.Error())
	}

	return &IDPhotoResult{
		Image:  base64.StdEncoding.EncodeToString(buf.Bytes()),
		Width:  targetWidth,
		Height: targetHeight,
		Format: format,
	}, nil
}

// portraitBounds 人像包围盒
type portraitBounds struct {
	minX, minY, maxX, maxY int
	width, height          int
}

// findPortraitBounds 通过背景色对比找到人像包围盒
func findPortraitBounds(img image.Image, w, h int) portraitBounds {
	bgRef := sampleBackground(img, w, h)
	tolerance := calcBgTolerance(img, bgRef, w, h) * 1.3

	minX, minY := w, h
	maxX, maxY := 0, 0

	step := 1
	if w*h > 2000000 {
		step = 2
	}

	for y := 0; y < h; y += step {
		for x := 0; x < w; x += step {
			pixel := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA)
			if colorDist(pixel, bgRef) > tolerance {
				if x < minX {
					minX = x
				}
				if x > maxX {
					maxX = x
				}
				if y < minY {
					minY = y
				}
				if y > maxY {
					maxY = y
				}
			}
		}
	}

	// 没找到有效像素
	if minX > maxX || minY > maxY {
		return portraitBounds{minX: 0, minY: 0, maxX: w - 1, maxY: h - 1, width: w, height: h}
	}

	// 扩大边界
	marginX := (maxX - minX) * 3 / 100
	marginY := (maxY - minY) * 2 / 100
	minX -= marginX
	maxX += marginX
	minY -= marginY
	maxY += marginY

	if minX < 0 {
		minX = 0
	}
	if minY < 0 {
		minY = 0
	}
	if maxX >= w {
		maxX = w - 1
	}
	if maxY >= h {
		maxY = h - 1
	}

	return portraitBounds{
		minX: minX, minY: minY, maxX: maxX, maxY: maxY,
		width: maxX - minX + 1, height: maxY - minY + 1,
	}
}

// rowSpan 记录每行的前景跨度
type rowSpan struct {
	y, span int
}

// detectShoulderYFromImage 检测肩部位置 Y 坐标
func detectShoulderYFromImage(img image.Image, w, h int, portrait portraitBounds) int {
	bgRef := sampleBackground(img, w, h)
	baseTol := calcBgTolerance(img, bgRef, w, h)
	tolerance := baseTol * 1.3

	var rows []rowSpan
	for y := portrait.minY; y <= portrait.maxY; y++ {
		leftX, rightX := -1, -1
		for x := 0; x < w; x++ {
			pixel := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA)
			if colorDist(pixel, bgRef) > tolerance {
				if leftX < 0 {
					leftX = x
				}
				rightX = x
			}
		}
		span := 0
		if leftX >= 0 {
			span = rightX - leftX
		}
		rows = append(rows, rowSpan{y: y, span: span})
	}

	if len(rows) < 10 {
		return portrait.maxY
	}

	totalRows := len(rows)
	portraitHeight := portrait.maxY - portrait.minY

	// 在中上部分找最窄行（候选颈部）
	neckIdx := -1
	minSpan := 999999
	searchStart := totalRows * 8 / 100
	searchEnd := totalRows * 55 / 100

	if searchEnd > totalRows-1 {
		searchEnd = totalRows - 1
	}

	for i := searchStart; i < searchEnd; i++ {
		if rows[i].span > 5 && rows[i].span < minSpan {
			minSpan = rows[i].span
			neckIdx = i
		}
	}

	if neckIdx < 0 {
		return portrait.maxY
	}

	// 从颈部往下找肩部最大跨度
	shoulderSearchEnd := totalRows * 80 / 100
	if shoulderSearchEnd >= totalRows {
		shoulderSearchEnd = totalRows - 1
	}

	maxSpan := 0
	maxSpanIdx := neckIdx
	for i := neckIdx + 1; i < shoulderSearchEnd; i++ {
		if rows[i].span > maxSpan {
			maxSpan = rows[i].span
			maxSpanIdx = i
		}
	}

	// 从最大跨度处继续向下找稳定区域
	shoulderIdx := maxSpanIdx
	stableThreshold := int(float64(maxSpan) * 0.9)
	for i := maxSpanIdx + 1; i < shoulderSearchEnd; i++ {
		if rows[i].span >= stableThreshold {
			shoulderIdx = i
		} else if rows[i].span < int(float64(stableThreshold)*0.7) {
			break
		}
	}

	// 肩部下方留白
	padding := portraitHeight * 6 / 100
	candidateY := rows[shoulderIdx].y + padding

	// 合理性检查
	minValidY := portrait.minY + portraitHeight*35/100
	if candidateY < minValidY {
		candidateY = portrait.maxY
	}

	return candidateY
}

// smartCropAndResize 智能裁剪和缩放（保留用于向后兼容）
func smartCropAndResize(img image.Image, origW, origH, targetW, targetH int) *image.NRGBA {
	// 证件照中人脸通常在上方1/3区域，裁剪时优先保留上方
	targetRatio := float64(targetW) / float64(targetH)
	origRatio := float64(origW) / float64(origH)

	var resized *image.NRGBA

	if origRatio > targetRatio {
		// 原图更宽，以高度为基准缩放，然后水平裁剪
		newHeight := targetH
		newWidth := int(float64(targetH) * origRatio)
		if newWidth < 1 {
			newWidth = 1
		}
		resized = imaging.Resize(img, newWidth, newHeight, imaging.Lanczos)

		// 水平居中裁剪
		x := (newWidth - targetW) / 2
		if x < 0 {
			x = 0
		}
		return imaging.Crop(resized, image.Rect(x, 0, x+targetW, targetH))
	} else {
		// 原图更高，以宽度为基准缩放，然后垂直裁剪
		// 证件照特殊处理：人脸在上方，裁剪时偏上
		newWidth := targetW
		newHeight := int(float64(targetW) / origRatio)
		if newHeight < 1 {
			newHeight = 1
		}
		resized = imaging.Resize(img, newWidth, newHeight, imaging.Lanczos)

		// 垂直裁剪，偏上方（保留人脸区域）
		y := 0
		excess := newHeight - targetH
		if excess > 0 {
			// 人脸通常在上方1/3处，裁掉下方2/3的多余部分
			y = excess / 4 // 偏上裁剪
			if y+targetH > newHeight {
				y = newHeight - targetH
			}
			if y < 0 {
				y = 0
			}
		}
		return imaging.Crop(resized, image.Rect(0, y, targetW, y+targetH))
	}
}

// extractAndReplaceBG 提取人像并替换背景（改进版：基于连通区域的flood-fill算法 + image/draw合成）
func extractAndReplaceBG(src image.Image, bgColor color.NRGBA, feathering int) *image.NRGBA {
	bounds := src.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	// 1. 采样背景参考颜色
	bgRef := sampleBackground(src, width, height)

	// 2. 计算自适应容差
	tolerance := calcBgTolerance(src, bgRef, width, height)

	// 3. flood-fill 从边缘检测背景区域（使用扩大容差的多轮策略）
	bgMask := floodFillBackground(src, bgRef, tolerance, width, height)

	// 4. 角落二次清理：对四角区域用更大容差重新检测
	cleanCorners(bgMask, src, bgRef, tolerance, width, height)

	// 5. 肤色保护 + 深色区域保护（避免衣服/头发被误判为背景）
	protectSkinColor(bgMask, src, width, height)
	protectDarkRegions(bgMask, src, width, height)

	// 6. 形态学后处理：填充前景中的小空洞（半径缩小到1，减少边缘侵蚀）
	fgMask := invertMask(bgMask, width, height)
	fgMask = morphClose(fgMask, width, height, 1)
	bgMask = invertMask(fgMask, width, height)

	// 7. 边缘强制背景：确保最外圈1-2像素全部标记为背景
	forceBorderBackground(bgMask, width, height)

	// 8. 生成alpha蒙版：前景=1.0，背景=0.0
	alphaMask := binaryToAlpha(bgMask, width, height)

	// 9. 应用边缘羽化
	if feathering > 0 {
		alphaMask = blurMask(alphaMask, width, height, feathering)
	}

	// 10. 使用 image/draw 进行高效合成
	// 创建纯色背景层
	bgLayer := image.NewNRGBA(image.Rect(0, 0, width, height))
	draw.Draw(bgLayer, bgLayer.Bounds(), &image.Uniform{bgColor}, image.Point{}, draw.Src)

	// 创建前景层（原图），根据alpha蒙版调整每个像素的透明度
	fgLayer := image.NewNRGBA(image.Rect(0, 0, width, height))
	draw.Draw(fgLayer, fgLayer.Bounds(), src, bounds.Min, draw.Src)

	// 根据alpha蒙版设置前景层的Alpha通道
	for py := 0; py < height; py++ {
		for px := 0; px < width; px++ {
			c := fgLayer.NRGBAAt(px, py)
			alpha := alphaMask[py][px]
			if alpha < 0 {
				alpha = 0
			}
			if alpha > 1 {
				alpha = 1
			}
			c.A = uint8(alpha*255 + 0.5)
			fgLayer.SetNRGBA(px, py, c)
		}
	}

	// 使用 draw.Over 将前景叠加到背景上
	draw.Draw(bgLayer, bgLayer.Bounds(), fgLayer, image.Point{}, draw.Over)

	return bgLayer
}

// cleanCorners 对四个角落区域用更大容差重新检测背景
func cleanCorners(bgMask [][]bool, src image.Image, bgRef color.NRGBA, baseTol float64, w, h int) {
	// 角落区域大小
	cornerSize := int(math.Min(float64(w), float64(h)) * 0.15)
	if cornerSize < 20 {
		cornerSize = 20
	}
	// 角落使用1.3倍容差（从2.0降低，避免误吞边缘像素）
	cornerTol := baseTol * 1.3

	corners := [4][2]int{
		{0, 0},             // 左上
		{w - cornerSize, 0}, // 右上
		{0, h - cornerSize}, // 左下
		{w - cornerSize, h - cornerSize}, // 右下
	}

	for _, c := range corners {
		x0, y0 := c[0], c[1]
		for dy := 0; dy < cornerSize && y0+dy < h; dy++ {
			for dx := 0; dx < cornerSize && x0+dx < w; dx++ {
				px, py := x0+dx, y0+dy
				if bgMask[py][px] {
					continue // 已经是背景
				}
				pixel := color.NRGBAModel.Convert(src.At(px, py)).(color.NRGBA)
				dist := colorDist(pixel, bgRef)
				if dist <= cornerTol {
					bgMask[py][px] = true
				}
			}
		}
	}
}

// forceBorderBackground 强制将最外圈像素标记为背景
// 仅标记极边缘（1px），避免吃掉紧贴边缘的人像
func forceBorderBackground(bgMask [][]bool, w, h int) {
	border := 1
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if x < border || x >= w-border || y < border || y >= h-border {
				bgMask[y][x] = true
			}
		}
	}
}

// sampleBackground 从图像边缘多个位置采样，计算背景参考颜色
// 增加四角采样权重，因为角落几乎一定是背景
func sampleBackground(src image.Image, w, h int) color.NRGBA {
	type samplePoint struct{ x, y int; weight float64 }
	var points []samplePoint

	margin := 3

	// 四角区域密集采样（高权重，因为角落一定是背景）
	cornerR := int(math.Min(float64(w), float64(h)) * 0.08)
	if cornerR < 10 {
		cornerR = 10
	}
	cornerPts := [][2]int{
		{margin, margin}, {w - margin - 1, margin},
		{margin, h - margin - 1}, {w - margin - 1, h - margin - 1},
	}
	for _, cp := range cornerPts {
		// 在角落实采多个点
		for dy := -cornerR; dy <= cornerR; dy += 4 {
			for dx := -cornerR; dx <= cornerR; dx += 4 {
				px, py := cp[0]+dx, cp[1]+dy
				if px >= 0 && px < w && py >= 0 && py < h {
					points = append(points, samplePoint{px, py, 3.0})
				}
			}
		}
	}

	// 四边中点
	points = append(points,
		samplePoint{w / 2, margin, 1.0}, samplePoint{w / 2, h - margin - 1, 1.0},
		samplePoint{margin, h / 2, 1.0}, samplePoint{w - margin - 1, h / 2, 1.0},
	)

	// 四边1/4点
	points = append(points,
		samplePoint{w / 4, margin, 1.0}, samplePoint{3 * w / 4, margin, 1.0},
		samplePoint{w / 4, h - margin - 1, 1.0}, samplePoint{3 * w / 4, h - margin - 1, 1.0},
		samplePoint{margin, h / 4, 1.0}, samplePoint{margin, 3 * h / 4, 1.0},
		samplePoint{w - margin - 1, h / 4, 1.0}, samplePoint{w - margin - 1, 3 * h / 4, 1.0},
	)

	// 采集颜色
	var samples []weightedSample
	for _, p := range points {
		if p.x >= 0 && p.x < w && p.y >= 0 && p.y < h {
			c := sampleArea(src, p.x, p.y, 3, w, h)
			samples = append(samples, weightedSample{c, p.weight})
		}
	}

	return findDominantBGColorWeighted(samples)
}

// calcBgTolerance 根据背景颜色的一致性计算自适应容差
func calcBgTolerance(src image.Image, bgRef color.NRGBA, w, h int) float64 {
	// 采集边缘像素与bgRef的距离，取P90作为容差参考
	var dists []float64
	step := 4 // 每隔几个像素采样一次，提高性能

	for x := 0; x < w; x += step {
		c := color.NRGBAModel.Convert(src.At(x, 0)).(color.NRGBA)
		dists = append(dists, colorDist(c, bgRef))
		c = color.NRGBAModel.Convert(src.At(x, h-1)).(color.NRGBA)
		dists = append(dists, colorDist(c, bgRef))
	}
	for y := 0; y < h; y += step {
		c := color.NRGBAModel.Convert(src.At(0, y)).(color.NRGBA)
		dists = append(dists, colorDist(c, bgRef))
		c = color.NRGBAModel.Convert(src.At(w-1, y)).(color.NRGBA)
		dists = append(dists, colorDist(c, bgRef))
	}

	if len(dists) == 0 {
		return 30.0
	}

	// 排序取P80（不是P90，因为边缘可能包含人像部分）
	sortFloats(dists)
	p80Idx := int(float64(len(dists)) * 0.8)
	if p80Idx >= len(dists) {
		p80Idx = len(dists) - 1
	}
	baseTol := dists[p80Idx]

	// 容差范围：25~60（收窄，避免误吞人像边缘）
	if baseTol < 25 {
		baseTol = 25
	}
	if baseTol > 60 {
		baseTol = 60
	}

	return baseTol
}

// floodFillBackground 从图像边缘开始flood-fill，检测与边缘连通的背景区域
// 使用八邻域BFS + 角落优先策略
func floodFillBackground(src image.Image, bgRef color.NRGBA, tolerance float64, w, h int) [][]bool {
	bgMask := make([][]bool, h)
	for y := 0; y < h; y++ {
		bgMask[y] = make([]bool, w)
	}

	visited := make([][]bool, h)
	for y := 0; y < h; y++ {
		visited[y] = make([]bool, w)
	}

	type point struct{ x, y int }

	// 使用环形队列优化BFS性能
	queueCap := (w + h) * 2
	queue := make([]point, 0, queueCap)

	// 优先将四角像素加入队列（角落是背景的概率最高）
	queue = append(queue,
		point{0, 0}, point{w - 1, 0},
		point{0, h - 1}, point{w - 1, h - 1},
	)

	// 然后加入边缘像素
	for x := 1; x < w-1; x++ {
		queue = append(queue, point{x, 0}, point{x, h - 1})
	}
	for y := 1; y < h-1; y++ {
		queue = append(queue, point{0, y}, point{w - 1, y})
	}

	// 八邻域方向（包括对角线，更好覆盖角落）
	dirs := [8]point{
		{0, -1}, {0, 1}, {-1, 0}, {1, 0},
		{-1, -1}, {-1, 1}, {1, -1}, {1, 1},
	}

	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]

		if p.x < 0 || p.x >= w || p.y < 0 || p.y >= h {
			continue
		}
		if visited[p.y][p.x] {
			continue
		}
		visited[p.y][p.x] = true

		c := color.NRGBAModel.Convert(src.At(p.x, p.y)).(color.NRGBA)
		dist := colorDist(c, bgRef)

		if dist <= tolerance {
			bgMask[p.y][p.x] = true
			for _, d := range dirs {
				nx, ny := p.x+d.x, p.y+d.y
				if nx >= 0 && nx < w && ny >= 0 && ny < h && !visited[ny][nx] {
					queue = append(queue, point{nx, ny})
				}
			}
		}
	}

	return bgMask
}

// protectSkinColor 保护肤色区域不被误判为背景
func protectSkinColor(bgMask [][]bool, src image.Image, w, h int) {
	for py := 0; py < h; py++ {
		for px := 0; px < w; px++ {
			c := color.NRGBAModel.Convert(src.At(px, py)).(color.NRGBA)
			if isSkinColor(c) && bgMask[py][px] {
				bgMask[py][px] = false
			}
		}
	}
}

// protectDarkRegions 保护深色区域（衣服、头发等）不被误判为背景
// 策略：如果一个像素与周围4邻域中有前景像素相邻，且颜色较深，则保留为前景
func protectDarkRegions(bgMask [][]bool, src image.Image, w, h int) {
	dirs := [][2]int{{0, -1}, {0, 1}, {-1, 0}, {1, 0}}

	for py := 1; py < h-1; py++ {
		for px := 1; px < w-1; px++ {
			if !bgMask[py][px] {
				continue // 已经是前景，跳过
			}

			c := color.NRGBAModel.Convert(src.At(px, py)).(color.NRGBA)
			brightness := float64(c.R)*0.299 + float64(c.G)*0.587 + float64(c.B)*0.114

			// 非常暗的像素（亮度 < 60）可能是深色衣服/头发，不应轻易判为背景
			if brightness > 80 {
				continue
			}

			// 检查周围是否有前景像素（说明这个像素在人像边缘内部）
			hasFgNeighbor := false
			for _, d := range dirs {
				nx, ny := px+d[0], py+d[1]
				if nx >= 0 && nx < w && ny >= 0 && ny < h && !bgMask[ny][nx] {
					hasFgNeighbor = true
					break
				}
			}

			if hasFgNeighbor {
				bgMask[py][px] = false
			}
		}
	}
}

// morphClose 形态学闭运算：填充人像区域中的小空洞
func morphClose(mask [][]bool, w, h, radius int) [][]bool {
	// 先膨胀（dilate）：背景区域扩展
	dilated := dilateMask(mask, w, h, radius)
	// 再腐蚀（erode）：背景区域收缩
	return erodeMask(dilated, w, h, radius)
}

// dilateMask 膨胀背景区域
func dilateMask(mask [][]bool, w, h, radius int) [][]bool {
	result := make([][]bool, h)
	for y := 0; y < h; y++ {
		result[y] = make([]bool, w)
	}

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if mask[y][x] {
				// 扩展半径内的像素
				for dy := -radius; dy <= radius; dy++ {
					for dx := -radius; dx <= radius; dx++ {
						nx, ny := x+dx, y+dy
						if nx >= 0 && nx < w && ny >= 0 && ny < h {
							result[ny][nx] = true
						}
					}
				}
			}
		}
	}
	return result
}

// erodeMask 腐蚀背景区域
func erodeMask(mask [][]bool, w, h, radius int) [][]bool {
	result := make([][]bool, h)
	for y := 0; y < h; y++ {
		result[y] = make([]bool, w)
	}

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			// 检查半径内是否全部是背景
			allBg := true
			for dy := -radius; dy <= radius && allBg; dy++ {
				for dx := -radius; dx <= radius && allBg; dx++ {
					nx, ny := x+dx, y+dy
					if nx >= 0 && nx < w && ny >= 0 && ny < h {
						if !mask[ny][nx] {
							allBg = false
						}
					}
				}
			}
			result[y][x] = allBg
		}
	}
	return result
}

// binaryToAlpha 将二值蒙版转换为alpha蒙版（前景=1.0，背景=0.0）
func binaryToAlpha(bgMask [][]bool, w, h int) [][]float64 {
	alphaMask := make([][]float64, h)
	for y := 0; y < h; y++ {
		alphaMask[y] = make([]float64, w)
		for x := 0; x < w; x++ {
			if bgMask[y][x] {
				alphaMask[y][x] = 0.0 // 背景
			} else {
				alphaMask[y][x] = 1.0 // 前景（人像）
			}
		}
	}
	return alphaMask
}

// invertMask 反转蒙版
func invertMask(mask [][]bool, w, h int) [][]bool {
	result := make([][]bool, h)
	for y := 0; y < h; y++ {
		result[y] = make([]bool, w)
		for x := 0; x < w; x++ {
			result[y][x] = !mask[y][x]
		}
	}
	return result
}

// sortFloats 对float64切片进行简单排序（冒泡排序，小数组足够快）
func sortFloats(a []float64) {
	n := len(a)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if a[j] > a[j+1] {
				a[j], a[j+1] = a[j+1], a[j]
			}
		}
	}
}

// clampFloat 将浮点数限制在0~255并转为uint8
func clampFloat(v float64) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v + 0.5)
}

// sampleArea 采样一个区域的平均颜色
func sampleArea(src image.Image, cx, cy, radius, imgW, imgH int) color.NRGBA {
	var sumR, sumG, sumB float64
	count := 0

	for dy := -radius; dy <= radius; dy++ {
		for dx := -radius; dx <= radius; dx++ {
			x := cx + dx
			y := cy + dy
			if x < 0 || x >= imgW || y < 0 || y >= imgH {
				continue
			}
			c := color.NRGBAModel.Convert(src.At(x, y)).(color.NRGBA)
			sumR += float64(c.R)
			sumG += float64(c.G)
			sumB += float64(c.B)
			count++
		}
	}

	if count == 0 {
		return color.NRGBA{R: 255, G: 255, B: 255, A: 255}
	}

	return color.NRGBA{
		R: uint8(sumR / float64(count)),
		G: uint8(sumG / float64(count)),
		B: uint8(sumB / float64(count)),
		A: 255,
	}
}

// colorDist 计算两个颜色之间的欧氏距离
func colorDist(c1, c2 color.NRGBA) float64 {
	dr := float64(c1.R) - float64(c2.R)
	dg := float64(c1.G) - float64(c2.G)
	db := float64(c1.B) - float64(c2.B)
	return math.Sqrt(dr*dr + dg*dg + db*db)
}

// findDominantBGColor 从采样中找出主导背景色
func findDominantBGColor(samples []color.NRGBA) color.NRGBA {
	weighted := make([]weightedSample, len(samples))
	for i, s := range samples {
		weighted[i] = weightedSample{s, 1.0}
	}
	return findDominantBGColorWeighted(weighted)
}

// findDominantBGColorWeighted 从加权采样中找出主导背景色
func findDominantBGColorWeighted(samples []weightedSample) color.NRGBA {
	// 计算加权平均值
	var sumR, sumG, sumB, totalW float64
	for _, s := range samples {
		w := s.weight
		sumR += float64(s.c.R) * w
		sumG += float64(s.c.G) * w
		sumB += float64(s.c.B) * w
		totalW += w
	}
	if totalW == 0 {
		return color.NRGBA{R: 255, G: 255, B: 255, A: 255}
	}

	avg := color.NRGBA{
		R: uint8(sumR / totalW),
		G: uint8(sumG / totalW),
		B: uint8(sumB / totalW),
		A: 255,
	}

	// 筛选与加权平均值接近的采样点
	var closeR, closeG, closeB, closeW float64
	for _, s := range samples {
		if colorDist(s.c, avg) < 60 {
			w := s.weight
			closeR += float64(s.c.R) * w
			closeG += float64(s.c.G) * w
			closeB += float64(s.c.B) * w
			closeW += w
		}
	}

	if closeW == 0 {
		return avg
	}

	return color.NRGBA{
		R: uint8(closeR / closeW),
		G: uint8(closeG / closeW),
		B: uint8(closeB / closeW),
		A: 255,
	}
}

// isSkinColor 判断是否为肤色（YCbCr色彩空间）
func isSkinColor(c color.NRGBA) bool {
	r, g, b := float64(c.R), float64(c.G), float64(c.B)

	// RGB 规则快速筛选
	if r < 60 || g < 40 || b < 20 {
		return false
	}
	if r < g || r < b {
		return false
	}

	// 转换到 YCbCr 空间进行更精确的判断
	y := 0.299*r + 0.587*g + 0.114*b
	cb := 128 - 0.168736*r - 0.331264*g + 0.5*b
	cr := 128 + 0.5*r - 0.418688*g - 0.081312*b

	// 肤色在 YCbCr 空间的典型范围
	// 支持各种肤色
	return y > 80 && cb > 77 && cb < 127 && cr > 133 && cr < 173
}

// blurMask 对蒙版进行简单的高斯模糊
func blurMask(mask [][]float64, w, h, radius int) [][]float64 {
	// 使用两次box blur近似高斯模糊
	result := make([][]float64, h)
	for y := 0; y < h; y++ {
		result[y] = make([]float64, w)
		copy(result[y], mask[y])
	}

	// 两次水平+垂直box blur
	for pass := 0; pass < 2; pass++ {
		temp := make([][]float64, h)
		for y := 0; y < h; y++ {
			temp[y] = make([]float64, w)
		}

		// 水平模糊
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				var sum float64
				count := 0
				for dx := -radius; dx <= radius; dx++ {
					nx := x + dx
					if nx >= 0 && nx < w {
						sum += result[y][nx]
						count++
					}
				}
				temp[y][x] = sum / float64(count)
			}
		}

		// 垂直模糊
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				var sum float64
				count := 0
				for dy := -radius; dy <= radius; dy++ {
					ny := y + dy
					if ny >= 0 && ny < h {
						sum += temp[ny][x]
						count++
					}
				}
				result[y][x] = sum / float64(count)
			}
		}
	}

	return result
}

// GeneratePrintLayout 生成排版打印图
func GeneratePrintLayout(photoImage string, config *PrintLayoutConfig) (*IDPhotoResult, error) {
	// 解码证件照
	imgData, err := base64.StdEncoding.DecodeString(photoImage)
	if err != nil {
		return nil, errors.New("无法解码图片数据: " + err.Error())
	}

	photo, _, err := image.Decode(bytes.NewReader(imgData))
	if err != nil {
		return nil, errors.New("无法解析证件照: " + err.Error())
	}

	// 默认5寸相纸
	paperW := config.PaperWidth
	paperH := config.PaperHeight
	if paperW <= 0 {
		paperW = 1500 // 5寸 5x3.5 inches at 300dpi
	}
	if paperH <= 0 {
		paperH = 1050
	}

	cols := config.Columns
	rows := config.Rows
	if cols <= 0 {
		cols = 2
	}
	if rows <= 0 {
		rows = 2
	}

	gap := config.Gap
	if gap < 0 {
		gap = 20
	}

	photoW := config.PhotoWidth
	photoH := config.PhotoHeight
	if photoW <= 0 {
		photoW = 295
	}
	if photoH <= 0 {
		photoH = 413
	}

	// 计算缩放比例使照片能放下
	totalW := cols*photoW + (cols+1)*gap
	totalH := rows*photoH + (rows+1)*gap

	// 如果照片太大，缩放照片
	scale := 1.0
	if totalW > paperW {
		scale = math.Min(scale, float64(paperW-20)/float64(totalW))
	}
	if totalH > paperH {
		scale = math.Min(scale, float64(paperH-20)/float64(totalH))
	}

	if scale < 1.0 {
		photoW = int(float64(photoW) * scale)
		photoH = int(float64(photoH) * scale)
		gap = int(float64(gap) * scale)
	}

	// 缩放证件照到目标尺寸
	resizedPhoto := imaging.Resize(photo, photoW, photoH, imaging.Lanczos)

	// 创建相纸画布（白色背景）
	canvas := imaging.New(paperW, paperH, color.NRGBA{R: 255, G: 255, B: 255, A: 255})

	// 计算整体排版区域的起始位置（居中）
	layoutW := cols*photoW + (cols-1)*gap
	layoutH := rows*photoH + (rows-1)*gap
	startX := (paperW - layoutW) / 2
	startY := (paperH - layoutH) / 2

	// 粘贴照片
	for row := 0; row < rows; row++ {
		for col := 0; col < cols; col++ {
			x := startX + col*(photoW+gap)
			y := startY + row*(photoH+gap)
			canvas = imaging.Paste(canvas, resizedPhoto, image.Pt(x, y))
		}
	}

	// 编码
	var buf bytes.Buffer
	err = jpeg.Encode(&buf, canvas, &jpeg.Options{Quality: 95})
	if err != nil {
		return nil, errors.New("编码排版图失败: " + err.Error())
	}

	return &IDPhotoResult{
		Image:  base64.StdEncoding.EncodeToString(buf.Bytes()),
		Width:  paperW,
		Height: paperH,
		Format: "jpeg",
	}, nil
}

// encodeJPEGWithDPI 以指定DPI编码JPEG
func encodeJPEGWithDPI(w io.Writer, img image.Image, quality int, dpi int) error {
	if dpi <= 0 {
		dpi = 300
	}

	// 先编码到buffer
	var buf bytes.Buffer
	err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality})
	if err != nil {
		return err
	}

	// JPEG DPI 存储在 JFIF/EXIF 中
	// 修改JFIF header中的DPI信息
	data := buf.Bytes()

	// 查找JFIF marker (FF E0) 并修改DPI
	// JFIF segment: FF E0 [len_hi] [len_lo] 4A 46 49 46 00 ...
	// Offset 7-8: units (01=inches, 02=cm)
	// Offset 9-10: X density
	// Offset 11-12: Y density
	result := make([]byte, len(data))
	copy(result, data)

	// 查找 JFIF 标识
	for i := 0; i < len(result)-20; i++ {
		if result[i] == 0xFF && result[i+1] == 0xE0 {
			// 检查 JFIF 标识
			if i+9 < len(result) && result[i+4] == 0x4A && result[i+5] == 0x46 &&
				result[i+6] == 0x49 && result[i+7] == 0x46 {
				// 设置单位为英寸
				result[i+9] = 0x01
				// 设置X密度 (big-endian)
				result[i+10] = byte(dpi >> 8)
				result[i+11] = byte(dpi & 0xFF)
				// 设置Y密度 (big-endian)
				result[i+12] = byte(dpi >> 8)
				result[i+13] = byte(dpi & 0xFF)
				break
			}
		}
	}

	_, err = w.Write(result)
	return err
}

// parseColorFromString 解析颜色字符串
func parseColorFromString(hex string) color.NRGBA {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) == 6 {
		r, _ := strconv.ParseUint(hex[0:2], 16, 8)
		g, _ := strconv.ParseUint(hex[2:4], 16, 8)
		b, _ := strconv.ParseUint(hex[4:6], 16, 8)
		return color.NRGBA{R: uint8(r), G: uint8(g), B: uint8(b), A: 255}
	}
	if len(hex) == 8 {
		r, _ := strconv.ParseUint(hex[0:2], 16, 8)
		g, _ := strconv.ParseUint(hex[2:4], 16, 8)
		b, _ := strconv.ParseUint(hex[4:6], 16, 8)
		a, _ := strconv.ParseUint(hex[6:8], 16, 8)
		return color.NRGBA{R: uint8(r), G: uint8(g), B: uint8(b), A: uint8(a)}
	}
	return color.NRGBA{R: 255, G: 255, B: 255, A: 255}
}

// GetIDPhotoPresets 获取证件照预设
func GetIDPhotoPresets() map[string]map[string]interface{} {
	return map[string]map[string]interface{}{
		"一寸":     {"width": 295, "height": 413, "desc": "25mm × 35mm"},
		"二寸":     {"width": 413, "height": 579, "desc": "35mm × 49mm"},
		"小一寸":   {"width": 260, "height": 378, "desc": "22mm × 32mm"},
		"大一寸":   {"width": 306, "height": 437, "desc": "26mm × 37mm"},
		"驾驶证":   {"width": 260, "height": 378, "desc": "22mm × 32mm"},
		"身份证":   {"width": 358, "height": 441, "desc": "26mm × 32mm"},
		"护照":     {"width": 354, "height": 472, "desc": "33mm × 48mm"},
		"签证":     {"width": 354, "height": 472, "desc": "33mm × 48mm"},
		"港澳通行证": {"width": 354, "height": 472, "desc": "33mm × 48mm"},
		"考研":     {"width": 390, "height": 567, "desc": "33mm × 48mm"},
		"公务员":   {"width": 413, "height": 531, "desc": "35mm × 45mm"},
	}
}

// ValidateImageFormat 验证图片格式
func ValidateImageFormat(filename string, contentType string) bool {
	validExts := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".webp": true,
	}

	validTypes := map[string]bool{
		"image/jpeg": true,
		"image/png":  true,
		"image/webp": true,
	}

	ext := strings.ToLower(filename)
	for k := range validExts {
		if strings.HasSuffix(ext, k) {
			return true
		}
	}

	return validTypes[contentType]
}

// RemoveBG 调用 remove.bg API 进行精确抠图
func RemoveBG(apiKey string, file multipart.File) ([]byte, error) {
	req, err := http.NewRequest("POST", "https://api.remove.bg/v1.0/removebg", file)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Api-Key", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("remove.bg API 返回错误")
	}

	return io.ReadAll(resp.Body)
}

// GetImageInfo 获取图片信息
func GetImageInfo(file multipart.File) (width, height int, format string, err error) {
	cfg, format, err := image.DecodeConfig(file)
	if err != nil {
		return 0, 0, "", err
	}
	return cfg.Width, cfg.Height, format, nil
}
