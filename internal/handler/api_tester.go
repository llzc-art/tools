package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/database"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

// APITesterStateGet 获取 API 测试器完整状态
func APITesterStateGet(ctx *fasthttp.RequestCtx) {
	state, err := database.GetAPITesterState()
	if err != nil {
		logger.Errorc("APITesterStateGet", "查询失败: "+err.Error())
		response.Error(ctx, 5000, "查询失败")
		return
	}
	response.Success(ctx, state)
}

// APITesterStateSave 保存 API 测试器完整状态
func APITesterStateSave(ctx *fasthttp.RequestCtx) {
	var state map[string]interface{}
	if err := json.Unmarshal(ctx.PostBody(), &state); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}

	if err := database.SaveAPITesterState(state); err != nil {
		logger.Errorc("APITesterStateSave", "保存失败: "+err.Error())
		response.Error(ctx, 5000, "保存失败")
		return
	}
	response.Success(ctx, nil)
}
