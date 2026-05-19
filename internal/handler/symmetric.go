package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/response"
)

var symmetricSvc = service.NewSymmetricService()

type symmetricReq struct {
	Algo       string `json:"algo"`
	Mode       string `json:"mode"`
	Operation  string `json:"operation"` // encrypt / decrypt
	Input      string `json:"input"`
	Key        string `json:"key"`
	KeyFormat  string `json:"keyFormat"` // text / hex，默认 text
	Padding    string `json:"padding"`   // pkcs7 / zero / none，默认 pkcs7
	IV         string `json:"iv"`        // 初始向量，hex 格式，可选
}

func SymmetricCompute(ctx *fasthttp.RequestCtx) {
	var req symmetricReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" {
		response.Error(ctx, 1001, "input 参数不能为空")
		return
	}
	if req.Key == "" {
		response.Error(ctx, 1001, "key 参数不能为空")
		return
	}
	if req.Algo == "" {
		req.Algo = "aes"
	}
	if req.Mode == "" {
		req.Mode = "cbc"
	}
	if req.Operation == "" {
		req.Operation = "encrypt"
	}

	if req.KeyFormat == "" {
		req.KeyFormat = "text"
	}
	if req.Padding == "" {
		req.Padding = "pkcs7"
	}

	var result *service.SymmetricResult
	var err error
	switch req.Operation {
	case "encrypt":
		result, err = symmetricSvc.Encrypt(req.Algo, req.Mode, req.Input, req.Key, req.KeyFormat, req.Padding, req.IV)
	case "decrypt":
		result, err = symmetricSvc.Decrypt(req.Algo, req.Mode, req.Input, req.Key, req.KeyFormat, req.Padding, req.IV)
	default:
		response.Error(ctx, 1001, "不支持的操作，可选: encrypt, decrypt")
		return
	}
	if err != nil {
		response.Error(ctx, 1002, err.Error())
		return
	}
	response.Success(ctx, result)
}

func SymmetricKeySizes(ctx *fasthttp.RequestCtx) {
	response.Success(ctx, symmetricSvc.KeySizes())
}
