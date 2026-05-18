package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

var base64Svc = service.NewBase64Service()

type base64Req struct {
	Input    string `json:"input"`
	Encoding string `json:"encoding"` // standard, url, raw, url_raw
}

func Base64Encode(ctx *fasthttp.RequestCtx) {
	var req base64Req
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" {
		response.Error(ctx, 1001, "input 参数不能为空")
		return
	}
	if req.Encoding == "" {
		req.Encoding = "standard"
	}
	result := base64Svc.Encode(req.Input, req.Encoding)
	response.Success(ctx, result)
}

func Base64Decode(ctx *fasthttp.RequestCtx) {
	var req base64Req
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" {
		response.Error(ctx, 1001, "input 参数不能为空")
		return
	}
	if req.Encoding == "" {
		req.Encoding = "standard"
	}
	result, err := base64Svc.Decode(req.Input, req.Encoding)
	if err != nil {
		logger.Errorc("Base64Decode", "Base64 解码失败: "+err.Error())
		response.Error(ctx, 2001, "Base64 解码失败: "+err.Error())
		return
	}
	response.Success(ctx, result)
}
