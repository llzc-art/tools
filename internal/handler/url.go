package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

var urlSvc = service.NewURLService()

type urlReq struct {
	Input string `json:"input"`
}

func URLEncode(ctx *fasthttp.RequestCtx) {
	var req urlReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" {
		response.Error(ctx, 1001, "input 参数不能为空")
		return
	}
	result := urlSvc.Encode(req.Input)
	response.Success(ctx, result)
}

func URLDecode(ctx *fasthttp.RequestCtx) {
	var req urlReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" {
		response.Error(ctx, 1001, "input 参数不能为空")
		return
	}
	result, err := urlSvc.Decode(req.Input)
	if err != nil {
		logger.Errorc("URLDecode", "URL 解码失败: "+err.Error())
		response.Error(ctx, 2003, "URL 解码失败")
		return
	}
	response.Success(ctx, result)
}
