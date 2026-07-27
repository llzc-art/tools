package handler

import (
	"encoding/json"
	"strconv"

	"lelezc.com/tools/internal/service"
	"github.com/valyala/fasthttp"
)

// IDPhotoProcess 处理证件照
func IDPhotoProcess(ctx *fasthttp.RequestCtx) {
	// 获取上传的文件
	file, err := ctx.FormFile("image")
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		json.NewEncoder(ctx.Response.BodyWriter()).Encode(map[string]interface{}{
			"code":    400,
			"message": "请上传图片文件",
		})
		return
	}

	// 验证文件格式
	contentType := string(ctx.Request.Header.ContentType())
	if !service.ValidateImageFormat(file.Filename, contentType) {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		json.NewEncoder(ctx.Response.BodyWriter()).Encode(map[string]interface{}{
			"code":    400,
			"message": "只支持 JPG、PNG、WebP 格式的图片",
		})
		return
	}

	// 从 FormData 获取参数
	width := getFormInt(ctx, "width", 295)
	height := getFormInt(ctx, "height", 413)
	background := getFormValue(ctx, "background", "white")
	customColor := getFormValue(ctx, "custom_color", "#FFFFFF")
	dpi := getFormInt(ctx, "dpi", 300)
	outputFormat := getFormValue(ctx, "output_format", "jpeg")
	feathering := getFormInt(ctx, "feathering", 2)
	// use_birefnet: 前端是否使用 BiRefNet-RMBG2 高精发丝级模型（服务端推理）
	// 浏览器 wasm 因 memory 限制无法运行 ~350MB 的大模型，必须走后端
	useBiRefNet := getFormValue(ctx, "use_birefnet", "") == "true" || getFormValue(ctx, "use_birefnet", "") == "1"

	// 打开文件
	f, err := file.Open()
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		json.NewEncoder(ctx.Response.BodyWriter()).Encode(map[string]interface{}{
			"code":    500,
			"message": "无法读取文件: " + err.Error(),
		})
		return
	}
	defer f.Close()

	// 处理证件照
	config := &service.IDPhotoConfig{
		Width:        width,
		Height:       height,
		Background:   background,
		CustomColor:  customColor,
		DPI:          dpi,
		OutputFormat: outputFormat,
		Feathering:   feathering,
		UseBiRefNet:  useBiRefNet,
	}

	result, err := service.ProcessIDPhoto(f, file.Filename, config)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		json.NewEncoder(ctx.Response.BodyWriter()).Encode(map[string]interface{}{
			"code":    500,
			"message": "处理失败: " + err.Error(),
		})
		return
	}

	// 返回结果
	json.NewEncoder(ctx.Response.BodyWriter()).Encode(map[string]interface{}{
		"code":    0,
		"message": "success",
		"data":    result,
	})
}

// IDPhotoPrintLayout 生成排版打印图
func IDPhotoPrintLayout(ctx *fasthttp.RequestCtx) {
	// 解析请求参数
	var req struct {
		Image       string `json:"image"`        // base64 编码的证件照
		PhotoWidth  int    `json:"photo_width"`  // 证件照宽度
		PhotoHeight int    `json:"photo_height"` // 证件照高度
		PaperSize   string `json:"paper_size"`   // 相纸尺寸: 5inch, 6inch, A4
		Columns     int    `json:"columns"`      // 列数
		Rows        int    `json:"rows"`         // 行数
		Gap         int    `json:"gap"`          // 间距
	}

	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		json.NewEncoder(ctx.Response.BodyWriter()).Encode(map[string]interface{}{
			"code":    400,
			"message": "参数错误: " + err.Error(),
		})
		return
	}

	if req.Image == "" {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		json.NewEncoder(ctx.Response.BodyWriter()).Encode(map[string]interface{}{
			"code":    400,
			"message": "请提供证件照图片数据",
		})
		return
	}

	// 根据相纸尺寸设置默认值
	paperW, paperH := 1500, 1050 // 默认5寸
	switch req.PaperSize {
	case "6inch":
		paperW, paperH = 1800, 1200
	case "A4":
		paperW, paperH = 2480, 3508 // A4 at 300dpi
	default: // 5inch
		paperW, paperH = 1500, 1050
	}

	// 自动计算行列数
	cols := req.Columns
	rows := req.Rows
	if cols <= 0 && rows <= 0 {
		// 自动计算：尽量多放
		photoW := req.PhotoWidth
		photoH := req.PhotoHeight
		if photoW <= 0 {
			photoW = 295
		}
		if photoH <= 0 {
			photoH = 413
		}
		gap := 20
		if req.Gap > 0 {
			gap = req.Gap
		}
		cols = (paperW - gap) / (photoW + gap)
		rows = (paperH - gap) / (photoH + gap)
		if cols < 1 {
			cols = 1
		}
		if rows < 1 {
			rows = 1
		}
	} else {
		if cols <= 0 {
			cols = 2
		}
		if rows <= 0 {
			rows = 2
		}
	}

	gap := req.Gap
	if gap < 0 {
		gap = 20
	}

	config := &service.PrintLayoutConfig{
		PhotoWidth:  req.PhotoWidth,
		PhotoHeight: req.PhotoHeight,
		PaperWidth:  paperW,
		PaperHeight: paperH,
		Columns:     cols,
		Rows:        rows,
		Gap:         gap,
	}

	result, err := service.GeneratePrintLayout(req.Image, config)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		json.NewEncoder(ctx.Response.BodyWriter()).Encode(map[string]interface{}{
			"code":    500,
			"message": "排版失败: " + err.Error(),
		})
		return
	}

	json.NewEncoder(ctx.Response.BodyWriter()).Encode(map[string]interface{}{
		"code":    0,
		"message": "success",
		"data":    result,
	})
}

// getFormValue 获取 Form 参数值
func getFormValue(ctx *fasthttp.RequestCtx, key, defaultVal string) string {
	val := ctx.FormValue(key)
	if len(val) == 0 {
		return defaultVal
	}
	return string(val)
}

// getFormInt 获取 Form 参数整数值
func getFormInt(ctx *fasthttp.RequestCtx, key string, defaultVal int) int {
	val := ctx.FormValue(key)
	if len(val) == 0 {
		return defaultVal
	}
	intVal, err := strconv.Atoi(string(val))
	if err != nil {
		return defaultVal
	}
	return intVal
}

// IDPhotoPresets 获取证件照预设
func IDPhotoPresets(ctx *fasthttp.RequestCtx) {
	presets := service.GetIDPhotoPresets()

	json.NewEncoder(ctx.Response.BodyWriter()).Encode(map[string]interface{}{
		"code":    0,
		"message": "success",
		"data":    presets,
	})
}
