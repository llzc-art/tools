package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/response"
)

var jwtSvc = service.NewJWTService()

type jwtDecodeReq struct {
	Token string `json:"token"`
}

func JWTDecode(ctx *fasthttp.RequestCtx) {
	var req jwtDecodeReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Token == "" {
		response.Error(ctx, 1001, "token 参数不能为空")
		return
	}
	result := jwtSvc.Decode(req.Token)
	response.Success(ctx, result)
}
