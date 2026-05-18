package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

var urlCodeSvc = service.NewURLCodeService()

type urlCodeReq struct {
	Input string `json:"input"`
}

func URLEncodeComponent(ctx *fasthttp.RequestCtx) {
	var req urlCodeReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" {
		response.Error(ctx, 1001, "input 参数不能为空")
		return
	}
	result := urlCodeSvc.EncodeComponent(req.Input)
	response.Success(ctx, result)
}

func URLDecodeComponent(ctx *fasthttp.RequestCtx) {
	var req urlCodeReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" {
		response.Error(ctx, 1001, "input 参数不能为空")
		return
	}
	result, err := urlCodeSvc.DecodeComponent(req.Input)
	if err != nil {
		logger.Errorc("URLDecodeComponent", "URL 组件解码失败: "+err.Error())
		response.Error(ctx, 2003, "URL 组件解码失败")
		return
	}
	response.Success(ctx, result)
}

type urlParseReq struct {
	URL string `json:"url"`
}

func URLParse(ctx *fasthttp.RequestCtx) {
	var req urlParseReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.URL == "" {
		response.Error(ctx, 1001, "url 参数不能为空")
		return
	}
	result, err := urlCodeSvc.Parse(req.URL)
	if err != nil {
		logger.Errorc("URLParse", "URL 解析失败: "+err.Error())
		response.Error(ctx, 2003, "URL 解析失败")
		return
	}
	response.Success(ctx, result)
}

type urlBuildReq struct {
	Scheme   string `json:"scheme"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	Path     string `json:"path"`
	Query    string `json:"query"`
	Fragment string `json:"fragment"`
}

func URLBuild(ctx *fasthttp.RequestCtx) {
	var req urlBuildReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	result := urlCodeSvc.Build(req.Scheme, req.Host, req.Port, req.Path, req.Query, req.Fragment)
	response.Success(ctx, result)
}

type unicodeReq struct {
	Input string `json:"input"`
}

func UnicodeEncode(ctx *fasthttp.RequestCtx) {
	var req unicodeReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" {
		response.Error(ctx, 1001, "input 参数不能为空")
		return
	}
	result := urlCodeSvc.UnicodeEncode(req.Input)
	response.Success(ctx, result)
}

func UnicodeDecode(ctx *fasthttp.RequestCtx) {
	var req unicodeReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" {
		response.Error(ctx, 1001, "input 参数不能为空")
		return
	}
	result, err := urlCodeSvc.UnicodeDecode(req.Input)
	if err != nil {
		logger.Errorc("UnicodeDecode", "Unicode 解码失败: "+err.Error())
		response.Error(ctx, 2005, "Unicode 解码失败")
		return
	}
	response.Success(ctx, result)
}
