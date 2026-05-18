package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

var stringSvc = service.NewStringService()

type stringReq struct {
	Input string `json:"input"`
}

func StringCount(ctx *fasthttp.RequestCtx) {
	var req stringReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	result := stringSvc.Count(req.Input)
	response.Success(ctx, result)
}

func StringToUpper(ctx *fasthttp.RequestCtx) {
	var req stringReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	result := stringSvc.ToUpper(req.Input)
	response.Success(ctx, result)
}

func StringToLower(ctx *fasthttp.RequestCtx) {
	var req stringReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	result := stringSvc.ToLower(req.Input)
	response.Success(ctx, result)
}

type stringCaseReq struct {
	Input string `json:"input"`
}

func StringToCamel(ctx *fasthttp.RequestCtx) {
	var req stringCaseReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	result := stringSvc.ToCamel(req.Input)
	response.Success(ctx, result)
}

func StringToSnake(ctx *fasthttp.RequestCtx) {
	var req stringCaseReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	result := stringSvc.ToSnake(req.Input)
	response.Success(ctx, result)
}

func StringToHex(ctx *fasthttp.RequestCtx) {
	var req stringReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	result := stringSvc.StringToHex(req.Input)
	response.Success(ctx, result)
}

func HexToString(ctx *fasthttp.RequestCtx) {
	var req stringReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	result, err := stringSvc.HexToString(req.Input)
	if err != nil {
		logger.Errorc("HexToString", "十六进制解码失败: "+err.Error())
		response.Error(ctx, 2008, "十六进制解码失败: "+err.Error())
		return
	}
	response.Success(ctx, result)
}
