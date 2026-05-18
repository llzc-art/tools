package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

var jsonSvc = service.NewJSONService()

type jsonFormatReq struct {
	Input  string `json:"input"`
	Indent int    `json:"indent"`
}

func JSONFormat(ctx *fasthttp.RequestCtx) {
	var req jsonFormatReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" {
		response.Error(ctx, 1001, "input 参数不能为空")
		return
	}
	result, err := jsonSvc.Format(req.Input, req.Indent)
	if err != nil {
		logger.Errorc("JSONFormat", "JSON 格式化失败: "+err.Error())
		response.Error(ctx, 2004, "JSON 格式化失败: "+err.Error())
		return
	}
	response.Success(ctx, result)
}

type jsonCompressReq struct {
	Input string `json:"input"`
}

func JSONCompress(ctx *fasthttp.RequestCtx) {
	var req jsonCompressReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" {
		response.Error(ctx, 1001, "input 参数不能为空")
		return
	}
	result, err := jsonSvc.Compress(req.Input)
	if err != nil {
		logger.Errorc("JSONCompress", "JSON 压缩失败: "+err.Error())
		response.Error(ctx, 2004, "JSON 压缩失败: "+err.Error())
		return
	}
	response.Success(ctx, result)
}
