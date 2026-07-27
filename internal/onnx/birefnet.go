// BiRefNet-RMBG2 后端推理实现
//
// 模型：RMBG-2.0 INT8 动态量化版（AI-ModelScope/RMBG-2.0 model_int8.onnx）
// 大小：~366MB（FP32 版 ~976MB 浏览器 wasm 装不下，INT8 版服务端可运行）
// 输入：[1, 3, 1024, 1024] float32, RGB, ImageNet normalize（mean=[0.485,0.456,0.406], std=[0.229,0.224,0.225]）
// 输出：[1, 1, 1024, 1024] float32, raw logits（需 sigmoid 转换到 [0,1]）
//
// 完整流程：
//  1. 原图 → resize 到 1024×1024（保持宽高比，padding 到正方形）
//  2. RGB 归一化（ImageNet）
//  3. ORT 推理
//  4. mask 后处理：sigmoid → 缩放回原图尺寸 → alpha 合成（与前端 postprocessMask 等价）

package onnx

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"math"
	"os"
	"path/filepath"
	"sync"

	ort "github.com/yalue/onnxruntime_go"
)

const (
	// BiRefNet 模型固定输入尺寸
	birefnetInputSize = 1024

	// 模型下载 URL（INT8 动态量化版，与前端预处理兼容）
	birefnetModelURL = "https://www.modelscope.cn/models/AI-ModelScope/RMBG-2.0/resolve/master/onnx/model_int8.onnx"

	// 本地缓存路径（相对于项目根）
	birefnetModelRelPath = "data/onnxruntime/models/birefnet_int8.onnx"
)

var (
	birefnetMu     sync.Mutex
	birefnetLoaded bool
	birefnetSess   *ort.DynamicAdvancedSession
)

// ensureBiRefNetLoaded 懒加载 BiRefNet 模型（首次调用时下载）
// 进程内并发安全。
//
// 模型加载优先级：
//  1. BIREFNET_MODEL_PATH 环境变量指定的路径（最高优先级，便于部署/集成）
//  2. ./data/onnxruntime/models/birefnet_int8.onnx 项目本地缓存
//  3. 从 ModelScope 自动下载到本地缓存（首次启动需要 2-5 分钟）
func ensureBiRefNetLoaded() error {
	if birefnetLoaded && birefnetSess != nil {
		return nil
	}

	birefnetMu.Lock()
	defer birefnetMu.Unlock()

	if birefnetLoaded && birefnetSess != nil {
		return nil
	}

	// 确保模型文件存在（不存在则下载）
	modelPath, err := ensureModelFile()
	if err != nil {
		return fmt.Errorf("准备模型文件失败: %w", err)
	}

	// 确保环境已初始化
	if !IsInitialized() {
		if err := InitOnce(); err != nil {
			return fmt.Errorf("初始化 ONNX Runtime 失败: %w", err)
		}
	}

	// 创建 DynamicAdvancedSession（输入/输出在 Run 时指定，灵活）
	sess, err := ort.NewDynamicAdvancedSession(
		modelPath,
		[]string{"pixel_values"}, // input names
		[]string{"output"},       // output names
		nil, // 默认 SessionOptions
	)
	if err != nil {
		return fmt.Errorf("创建 BiRefNet session 失败 (model=%s): %w", modelPath, err)
	}

	birefnetSess = sess
	birefnetLoaded = true

	// 打印加载成功的日志（含模型路径和大小）
	if info, err := os.Stat(modelPath); err == nil {
		fmt.Printf("[BiRefNet] 模型加载成功: %s (%.1f MB)\n", modelPath, float64(info.Size())/1024/1024)
	} else {
		fmt.Printf("[BiRefNet] 模型加载成功: %s\n", modelPath)
	}
	return nil
}

// ensureModelFile 确保本地有模型文件，没有则下载
//
// 模型路径查找优先级：
//  1. BIREFNET_MODEL_PATH 环境变量（用户指定，绝对/相对路径均可）
//  2. ./data/onnxruntime/models/birefnet_int8.onnx 项目本地缓存
//  3. 从 ModelScope 自动下载到本地缓存
func ensureModelFile() (string, error) {
	// 1. 环境变量 BIREFNET_MODEL_PATH（最高优先级，便于集成/部署）
	if customPath := os.Getenv("BIREFNET_MODEL_PATH"); customPath != "" {
		if info, err := os.Stat(customPath); err == nil && info.Size() > 100*1024*1024 {
			return customPath, nil
		} else if err == nil {
			return "", fmt.Errorf("BIREFNET_MODEL_PATH 指定的文件 %q 大小异常（%d 字节），请检查文件是否完整",
				customPath, info.Size())
		} else {
			return "", fmt.Errorf("BIREFNET_MODEL_PATH 指定的路径 %q 无效: %w", customPath, err)
		}
	}

	cwd, _ := os.Getwd()
	modelPath := filepath.Join(cwd, birefnetModelRelPath)

	// 2. 项目本地缓存已存在
	if info, err := os.Stat(modelPath); err == nil && info.Size() > 100*1024*1024 {
		return modelPath, nil
	}

	// 3. 自动下载（注意：ModelScope LFS URL 实际是 HTML 重定向，需要 curl 跟随）
	if err := os.MkdirAll(filepath.Dir(modelPath), 0755); err != nil {
		return "", err
	}
	if err := downloadModel(modelPath); err != nil {
		return "", err
	}
	return modelPath, nil
}

func downloadModel(destPath string) error {
	// 使用 curl 跟随 HTML 重定向（ModelScope LFS 存储）
	tmpPath := destPath + ".download"
	cmd := fmt.Sprintf(`curl -L --fail --silent --show-error -o %q '%s'`, tmpPath, birefnetModelURL)
	if err := runShell(cmd); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("下载模型失败: %w (提示：请检查网络或手动下载 %s 到 %s)", err, birefnetModelURL, destPath)
	}

	// 校验：文件至少 100MB（避免下载到 HTML 错误页）
	info, err := os.Stat(tmpPath)
	if err != nil {
		return err
	}
	if info.Size() < 100*1024*1024 {
		os.Remove(tmpPath)
		return fmt.Errorf("下载文件过小（%d 字节），可能不是有效的 ONNX 模型", info.Size())
	}

	// 重命名为正式名
	return os.Rename(tmpPath, destPath)
}

// BiRefNetResult BiRefNet 推理结果
type BiRefNetResult struct {
	// MaskImage 是已扣出人像后的透明 PNG，尺寸与原图一致
	MaskImage *image.NRGBA
}

// RunBiRefNet 对输入图片运行 BiRefNet-RMBG2 推理，返回扣出人像后的透明背景图
//
// 参数：
//   - src: 输入图片（任意常见格式）
//
// 返回：
//   - *image.NRGBA: 透明背景的人像图，尺寸与原图相同
//   - error: 错误
func RunBiRefNet(src image.Image) (*BiRefNetResult, error) {
	if err := ensureBiRefNetLoaded(); err != nil {
		return nil, err
	}

	bounds := src.Bounds()
	origW := bounds.Dx()
	origH := bounds.Dy()

	// 1. 预处理：resize 到 1024×1024（保持宽高比，padding 到正方形）
	inputData, scaleX, scaleY, padLeft, padTop := preprocessForBiRefNet(src, birefnetInputSize)
	inputShape := ort.NewShape(1, 3, birefnetInputSize, birefnetInputSize)
	inputTensor, err := ort.NewTensor(inputShape, inputData)
	if err != nil {
		return nil, fmt.Errorf("创建输入 tensor 失败: %w", err)
	}
	defer inputTensor.Destroy()

	// 2. 推理（输出形状 [1, 1, 1024, 1024]）
	// 创建输出 tensor（预分配，ORT 会写入）
	outputShape := ort.NewShape(1, 1, birefnetInputSize, birefnetInputSize)
	outputTensor, err := ort.NewEmptyTensor[float32](outputShape)
	if err != nil {
		return nil, fmt.Errorf("创建输出 tensor 失败: %w", err)
	}
	defer outputTensor.Destroy()

	if err := birefnetSess.Run(
		[]ort.Value{inputTensor},
		[]ort.Value{outputTensor},
	); err != nil {
		return nil, fmt.Errorf("推理失败: %w", err)
	}
	maskData := outputTensor.GetData()
	modelSize := birefnetInputSize

	// 3. 后处理：sigmoid → 取有效区域（去掉 padding）→ 缩放回原图
	mask := postprocessMask(maskData, modelSize, origW, origH, scaleX, scaleY, padLeft, padTop)

	// 4. alpha 合成到原图（与前端 postprocessMask 一致）
	out := image.NewNRGBA(image.Rect(0, 0, origW, origH))
	for y := 0; y < origH; y++ {
		for x := 0; x < origW; x++ {
			alpha := mask[y*origW+x]
			srcR, srcG, srcB, _ := src.At(x+bounds.Min.X, y+bounds.Min.Y).RGBA()
			// RGBA() 返回 0~65535 的预乘 alpha 值，需要转换
			out.SetNRGBA(x, y, color.NRGBA{
				R: uint8(srcR >> 8),
				G: uint8(srcG >> 8),
				B: uint8(srcB >> 8),
				A: alpha,
			})
		}
	}
	return &BiRefNetResult{MaskImage: out}, nil
}

// preprocessForBiRefNet 图像预处理
//
// 返回：
//   - inputData: NCHW float32, RGB, ImageNet normalized
//   - scaleX/Y: 原图到 1024×1024 的缩放比（考虑 padding）
//   - padLeft/Top: 1024×1024 中有效区域的左上角偏移
func preprocessForBiRefNet(src image.Image, targetSize int) (inputData []float32, scaleX, scaleY float64, padLeft, padTop int) {
	// 1. Resize 保持宽高比
	bounds := src.Bounds()
	srcW := bounds.Dx()
	srcH := bounds.Dy()

	scale := float64(targetSize) / math.Max(float64(srcW), float64(srcH))
	resizeW := int(float64(srcW) * scale)
	resizeH := int(float64(srcH) * scale)
	padLeft = (targetSize - resizeW) / 2
	padTop = (targetSize - resizeH) / 2

	// 实际有效区域的缩放比
	scaleX = float64(resizeW) / float64(srcW)
	scaleY = float64(resizeH) / float64(srcH)

	// 2. 用 imaging resize（已在依赖中）
	resized := imagingResize(src, resizeW, resizeH)

	// 3. 创建 1024×1024 画布，先填充 padding 区域为黑色（normalize 后为 (-mean/std)）
	canvas := image.NewNRGBA(image.Rect(0, 0, targetSize, targetSize))
	draw.Draw(canvas, canvas.Bounds(), &image.Uniform{C: color.Black}, image.Point{}, draw.Src)
	draw.Draw(canvas, image.Rect(padLeft, padTop, padLeft+resizeW, padTop+resizeH),
		resized, image.Point{}, draw.Over)

	// 4. NCHW float32 + ImageNet normalize
	mean := [3]float32{0.485, 0.456, 0.406}
	std := [3]float32{0.229, 0.224, 0.225}

	planeSize := targetSize * targetSize
	inputData = make([]float32, 1*3*planeSize)

	for i := 0; i < planeSize; i++ {
		idx := i * 4
		r := float32(canvas.Pix[idx]) / 255.0
		g := float32(canvas.Pix[idx+1]) / 255.0
		b := float32(canvas.Pix[idx+2]) / 255.0
		inputData[i] = (r - mean[0]) / std[0]                       // R
		inputData[planeSize+i] = (g - mean[1]) / std[1]             // G
		inputData[2*planeSize+i] = (b - mean[2]) / std[2]           // B
	}
	return inputData, scaleX, scaleY, padLeft, padTop
}

// postprocessMask mask 后处理：sigmoid + 裁剪 padding + resize 回原图
//
// 参数 maskData: 1×1×1024×1024 float32 模型的 raw logits
// 返回：原图尺寸的 alpha 数组（0~255 uint8）
func postprocessMask(maskData []float32, modelSize, origW, origH int,
	scaleX, scaleY float64, padLeft, padTop int) []uint8 {
	// 1. sigmoid + 裁剪掉 padding 区域
	resizedW := int(float64(origW) * scaleX)
	resizedH := int(float64(origH) * scaleY)
	alphaResized := make([]uint8, resizedW*resizedH)

	for y := 0; y < resizedH; y++ {
		sy := padTop + y
		for x := 0; x < resizedW; x++ {
			sx := padLeft + x
			idx := sy*modelSize + sx
			val := float64(maskData[idx])
			// sigmoid
			if val >= 0 {
				val = 1.0 / (1.0 + math.Exp(-val))
			} else {
				ev := math.Exp(val)
				val = ev / (1.0 + ev)
			}
			// clamp 到 [0,1] → [0,255]
			if val < 0 {
				val = 0
			}
			if val > 1 {
				val = 1
			}
			alphaResized[y*resizedW+x] = uint8(val * 255)
		}
	}

	// 2. resize alpha 回原图尺寸（最近邻插值，简单快速）
	alphaOrig := make([]uint8, origW*origH)
	for y := 0; y < origH; y++ {
		sy := int(float64(y) / scaleY)
		if sy >= resizedH {
			sy = resizedH - 1
		}
		for x := 0; x < origW; x++ {
			sx := int(float64(x) / scaleX)
			if sx >= resizedW {
				sx = resizedW - 1
			}
			alphaOrig[y*origW+x] = alphaResized[sy*resizedW+sx]
		}
	}
	return alphaOrig
}