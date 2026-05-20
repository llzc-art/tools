package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/response"
)

var dataConvertSvc = service.NewDataConvertService()

// DataConvertDetect 自动检测数据格式
func DataConvertDetect(ctx *fasthttp.RequestCtx) {
	var req struct {
		Input string `json:"input"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" {
		response.Error(ctx, 1001, "请输入数据")
		return
	}

	format := dataConvertSvc.DetectFormat(req.Input)
	if format == "" {
		response.Error(ctx, 2001, "无法识别数据格式")
		return
	}

	response.Success(ctx, map[string]string{"format": format})
}

// DataConvert 数据格式转换
func DataConvert(ctx *fasthttp.RequestCtx) {
	var req struct {
		Input        string `json:"input"`
		SourceFormat string `json:"source_format"`
		TargetFormat string `json:"target_format"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" {
		response.Error(ctx, 1001, "请输入数据")
		return
	}
	if req.TargetFormat == "" {
		response.Error(ctx, 1001, "请指定目标格式")
		return
	}

	result := dataConvertSvc.Convert(req.Input, req.SourceFormat, req.TargetFormat)
	response.Success(ctx, result)
}
