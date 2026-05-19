package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/response"
)

var asymmetricSvc = service.NewAsymmetricService()

type asymmetricEncryptReq struct {
	Algo    string `json:"algo"`
	Input   string `json:"input"`
	KeyType string `json:"keyType"` // publicKey / privateKey
	Key     string `json:"key"`
	Padding string `json:"padding"` // pkcs1v15 / oaep，默认 pkcs1v15
}

type asymmetricDecryptReq struct {
	Algo    string `json:"algo"`
	Input   string `json:"input"`
	Key     string `json:"key"`
	Padding string `json:"padding"` // pkcs1v15 / oaep，默认 pkcs1v15
}

type asymmetricSignReq struct {
	Algo    string `json:"algo"`
	Input   string `json:"input"`
	Key     string `json:"key"`
	Padding string `json:"padding"` // pkcs1v15 / pss，默认 pkcs1v15
}

type asymmetricVerifyReq struct {
	Algo      string `json:"algo"`
	Input     string `json:"input"`
	Signature string `json:"signature"`
	Key       string `json:"key"`
	Padding   string `json:"padding"` // pkcs1v15 / pss，默认 pkcs1v15
}

func AsymmetricEncrypt(ctx *fasthttp.RequestCtx) {
	var req asymmetricEncryptReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" || req.Key == "" {
		response.Error(ctx, 1001, "input 和 key 参数不能为空")
		return
	}
	if req.Algo == "" {
		req.Algo = "rsa"
	}
	if req.Padding == "" {
		req.Padding = "pkcs1v15"
	}
	result, err := asymmetricSvc.Encrypt(req.Algo, req.Input, req.Key, req.Padding)
	if err != nil {
		response.Error(ctx, 1002, err.Error())
		return
	}
	response.Success(ctx, result)
}

func AsymmetricDecrypt(ctx *fasthttp.RequestCtx) {
	var req asymmetricDecryptReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" || req.Key == "" {
		response.Error(ctx, 1001, "input 和 key 参数不能为空")
		return
	}
	if req.Algo == "" {
		req.Algo = "rsa"
	}
	if req.Padding == "" {
		req.Padding = "pkcs1v15"
	}
	result, err := asymmetricSvc.Decrypt(req.Algo, req.Input, req.Key, req.Padding)
	if err != nil {
		response.Error(ctx, 1002, err.Error())
		return
	}
	response.Success(ctx, result)
}

func AsymmetricSign(ctx *fasthttp.RequestCtx) {
	var req asymmetricSignReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" || req.Key == "" {
		response.Error(ctx, 1001, "input 和 key 参数不能为空")
		return
	}
	if req.Algo == "" {
		req.Algo = "rsa"
	}
	if req.Padding == "" {
		req.Padding = "pkcs1v15"
	}
	result, err := asymmetricSvc.Sign(req.Algo, req.Input, req.Key, req.Padding)
	if err != nil {
		response.Error(ctx, 1002, err.Error())
		return
	}
	response.Success(ctx, result)
}

func AsymmetricVerify(ctx *fasthttp.RequestCtx) {
	var req asymmetricVerifyReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Input == "" || req.Signature == "" || req.Key == "" {
		response.Error(ctx, 1001, "input、signature 和 key 参数不能为空")
		return
	}
	if req.Algo == "" {
		req.Algo = "rsa"
	}
	if req.Padding == "" {
		req.Padding = "pkcs1v15"
	}
	result, err := asymmetricSvc.Verify(req.Algo, req.Input, req.Signature, req.Key, req.Padding)
	if err != nil {
		response.Error(ctx, 1002, err.Error())
		return
	}
	response.Success(ctx, result)
}
