package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/response"
)

var keygenSvc = service.NewKeyGenService()

type keygenReq struct {
	Type string `json:"type"`
	Bits int    `json:"bits"`
}

func KeyGenGenerate(ctx *fasthttp.RequestCtx) {
	var req keygenReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Type == "" {
		req.Type = "rsa"
	}
	result, err := keygenSvc.Generate(req.Type, req.Bits)
	if err != nil {
		response.Error(ctx, 1002, err.Error())
		return
	}
	response.Success(ctx, result)
}

func KeyGenTypes(ctx *fasthttp.RequestCtx) {
	response.Success(ctx, keygenSvc.SupportedTypes())
}
