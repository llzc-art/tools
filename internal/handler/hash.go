package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/response"
)

var hashSvc = service.NewHashService()

type hashReq struct {
	Input string `json:"input"`
	Algo  string `json:"algo"`
}

func HashCompute(ctx *fasthttp.RequestCtx) {
	var req hashReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" {
		response.Error(ctx, 1001, "input 参数不能为空")
		return
	}
	if req.Algo == "" {
		req.Algo = "md5"
	}

	var result *service.HashResult
	switch req.Algo {
	case "md5":
		result = hashSvc.MD5(req.Input)
	case "sha1":
		result = hashSvc.SHA1(req.Input)
	case "sha256":
		result = hashSvc.SHA256(req.Input)
	case "sha512":
		result = hashSvc.SHA512(req.Input)
	default:
		response.Error(ctx, 1001, "不支持的算法，可选: md5, sha1, sha256, sha512")
		return
	}
	response.Success(ctx, result)
}
