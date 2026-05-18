package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

var ipSvc = service.NewIPService()

type ipLookupReq struct {
	IP string `json:"ip"`
}

func IPLookup(ctx *fasthttp.RequestCtx) {
	var req ipLookupReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.IP == "" {
		response.Error(ctx, 1001, "ip 参数不能为空")
		return
	}
	result, err := ipSvc.Lookup(req.IP)
	if err != nil {
		logger.Errorc("IPLookup", "IP 查询失败: "+err.Error())
		response.Error(ctx, 2006, "IP 查询失败: "+err.Error())
		return
	}
	response.Success(ctx, result)
}

type ipCIDRReq struct {
	CIDR string `json:"cidr"`
}

func IPCIDR(ctx *fasthttp.RequestCtx) {
	var req ipCIDRReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.CIDR == "" {
		response.Error(ctx, 1001, "cidr 参数不能为空")
		return
	}
	result, err := ipSvc.CIDR(req.CIDR)
	if err != nil {
		logger.Errorc("IPCIDR", "CIDR 解析失败: "+err.Error())
		response.Error(ctx, 2006, "CIDR 解析失败: "+err.Error())
		return
	}
	response.Success(ctx, result)
}
