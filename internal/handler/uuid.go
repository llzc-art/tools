package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/response"
)

var randomGenSvc = service.NewRandomGenService()

func RandomGenerate(ctx *fasthttp.RequestCtx) {
	var req service.RandomGenParams
	body := ctx.PostBody()
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			response.Error(ctx, 1001, "参数错误")
			return
		}
	}
	if req.Count <= 0 {
		req.Count = 1
	}
	if req.Mode == "" {
		req.Mode = "uuid"
	}
	result := randomGenSvc.Generate(req)
	response.Success(ctx, result)
}

// 兼容旧路由
func UUIDGenerate(ctx *fasthttp.RequestCtx) {
	var req struct {
		Count int `json:"count"`
	}
	body := ctx.PostBody()
	if len(body) > 0 {
		json.Unmarshal(body, &req)
	}
	if req.Count <= 0 {
		req.Count = 1
	}
	result := randomGenSvc.Generate(service.RandomGenParams{
		Count: req.Count,
		Mode:  "uuid",
	})
	// 返回兼容旧格式
	type compatResult struct {
		UUIDs []string `json:"uuids"`
		Count int      `json:"count"`
	}
	response.Success(ctx, &compatResult{
		UUIDs: result.Items,
		Count: result.Count,
	})
}
