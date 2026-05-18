package middleware

import (
	"time"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/pkg/logger"
)

func Logger(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		start := time.Now()
		next(ctx)
		duration := time.Since(start)

		logger.WithFields(logger.INFO, "HTTP", "", map[string]interface{}{
			"method":   string(ctx.Method()),
			"path":     string(ctx.Path()),
			"status":   ctx.Response.StatusCode(),
			"duration": duration.String(),
			"ip":       ctx.RemoteIP().String(),
		})
	}
}
