package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

var timeFormatSvc = service.NewTimeFormatService()

type timeFormatConvertReq struct {
	Time       string `json:"time"`
	FromFormat string `json:"from_format"`
	ToFormat   string `json:"to_format"`
	FromTZ     string `json:"from_tz"`
	ToTZ       string `json:"to_tz"`
}

func TimeFormatConvert(ctx *fasthttp.RequestCtx) {
	var req timeFormatConvertReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Time == "" || req.FromFormat == "" || req.ToFormat == "" {
		response.Error(ctx, 1001, "time、from_format、to_format 参数不能为空")
		return
	}
	result, err := timeFormatSvc.Convert(req.Time, req.FromFormat, req.ToFormat, req.FromTZ, req.ToTZ)
	if err != nil {
		logger.Errorc("TimeFormatConvert", "时间格式转换失败: "+err.Error())
		response.Error(ctx, 2002, "时间格式解析失败")
		return
	}
	response.Success(ctx, result)
}
