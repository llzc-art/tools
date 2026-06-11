package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

var ddlParserSvc = service.NewDDLParserService()

type ddlParseReq struct {
	DDL string `json:"ddl"`
}

// DDLParse 解析DDL，生成UML类图和表结构表格
func DDLParse(ctx *fasthttp.RequestCtx) {
	var req ddlParseReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.DDL == "" {
		response.Error(ctx, 1001, "DDL 语句不能为空")
		return
	}

	result, err := ddlParserSvc.Parse(req.DDL)
	if err != nil {
		logger.Errorc("DDLParse", "DDL解析失败: "+err.Error())
		response.Error(ctx, 2002, err.Error())
		return
	}

	response.Success(ctx, result)
}
