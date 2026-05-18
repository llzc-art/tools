package middleware

import (
	"runtime/debug"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

func Recovery(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		defer func() {
			if r := recover(); r != nil {
				logger.WithFields(logger.ERROR, "RECOVERY", "panic recovered", map[string]interface{}{
					"error":  r,
					"stack":  string(debug.Stack()),
					"path":   string(ctx.Path()),
					"method": string(ctx.Method()),
				})
				response.Error(ctx, 5000, "服务器内部错误")
			}
		}()
		next(ctx)
	}
}
