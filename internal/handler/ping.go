package handler

import (
	"time"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/pkg/response"
)

func Ping(ctx *fasthttp.RequestCtx) {
	response.Success(ctx, map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().Unix(),
	})
}
