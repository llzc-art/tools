package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

var timestampSvc = service.NewTimestampService()

func TimestampNow(ctx *fasthttp.RequestCtx) {
	unit := string(ctx.QueryArgs().Peek("unit"))
	result := timestampSvc.Now(unit)
	response.Success(ctx, result)
}

type timestampToTimeReq struct {
	Timestamp int64  `json:"timestamp"`
	Unit      string `json:"unit"`
	Format    string `json:"format"`
	Timezone  string `json:"timezone"`
}

func TimestampToTime(ctx *fasthttp.RequestCtx) {
	var req timestampToTimeReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Timestamp == 0 {
		response.Error(ctx, 1001, "timestamp 参数不能为空")
		return
	}
	result, err := timestampSvc.ToTime(req.Timestamp, req.Unit, req.Format, req.Timezone)
	if err != nil {
		logger.Errorc("TimestampToTime", "时间戳转换失败: "+err.Error())
		response.Error(ctx, 2002, "时间格式解析失败")
		return
	}
	response.Success(ctx, result)
}

type timestampFromTimeReq struct {
	Time     string `json:"time"`
	Format   string `json:"format"`
	Timezone string `json:"timezone"`
}

func TimestampFromTime(ctx *fasthttp.RequestCtx) {
	var req timestampFromTimeReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Time == "" {
		response.Error(ctx, 1001, "time 参数不能为空")
		return
	}
	result, err := timestampSvc.FromTime(req.Time, req.Format, req.Timezone)
	if err != nil {
		logger.Errorc("TimestampFromTime", "时间转时间戳失败: "+err.Error())
		response.Error(ctx, 2002, "时间格式解析失败")
		return
	}
	response.Success(ctx, result)
}
