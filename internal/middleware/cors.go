package middleware

import "github.com/valyala/fasthttp"

var corsAllowHeaders = "Content-Type, Authorization"
var corsAllowMethods = "GET, POST, OPTIONS"
var corsAllowOrigin = "*"

func CORS(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		ctx.Response.Header.Set("Access-Control-Allow-Origin", corsAllowOrigin)
		ctx.Response.Header.Set("Access-Control-Allow-Headers", corsAllowHeaders)
		ctx.Response.Header.Set("Access-Control-Allow-Methods", corsAllowMethods)

		if string(ctx.Method()) == "OPTIONS" {
			ctx.SetStatusCode(204)
			return
		}

		next(ctx)
	}
}
