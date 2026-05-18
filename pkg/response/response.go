package response

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
)

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

func Success(ctx *fasthttp.RequestCtx, data interface{}) {
	resp := Response{
		Code:    0,
		Message: "success",
		Data:    data,
	}
	writeJSON(ctx, resp)
}

func Error(ctx *fasthttp.RequestCtx, code int, message string) {
	resp := Response{
		Code:    code,
		Message: message,
		Data:    nil,
	}
	writeJSON(ctx, resp)
}

func writeJSON(ctx *fasthttp.RequestCtx, v interface{}) {
	ctx.SetContentType("application/json; charset=utf-8")
	ctx.SetStatusCode(200)
	data, _ := json.Marshal(v)
	ctx.SetBody(data)
}
