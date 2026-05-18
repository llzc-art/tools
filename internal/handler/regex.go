package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

var regexSvc = service.NewRegexService()

type regexMatchReq struct {
	Pattern string `json:"pattern"`
	Input   string `json:"input"`
}

func RegexMatch(ctx *fasthttp.RequestCtx) {
	var req regexMatchReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Pattern == "" || req.Input == "" {
		response.Error(ctx, 1001, "pattern 和 input 参数不能为空")
		return
	}
	result, err := regexSvc.Match(req.Pattern, req.Input)
	if err != nil {
		logger.Errorc("RegexMatch", "正则匹配失败: "+err.Error())
		response.Error(ctx, 2007, "正则表达式错误: "+err.Error())
		return
	}
	response.Success(ctx, result)
}

type regexReplaceReq struct {
	Pattern string `json:"pattern"`
	Input   string `json:"input"`
	Replace string `json:"replace"`
}

func RegexReplace(ctx *fasthttp.RequestCtx) {
	var req regexReplaceReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Pattern == "" || req.Input == "" {
		response.Error(ctx, 1001, "pattern 和 input 参数不能为空")
		return
	}
	result, err := regexSvc.Replace(req.Pattern, req.Input, req.Replace)
	if err != nil {
		logger.Errorc("RegexReplace", "正则替换失败: "+err.Error())
		response.Error(ctx, 2007, "正则表达式错误: "+err.Error())
		return
	}
	response.Success(ctx, result)
}
