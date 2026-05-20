package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/database"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

var linuxCommandSvc = service.NewLinuxCommandService()

// LinuxCommandList 获取所有 Linux 命令
func LinuxCommandList(ctx *fasthttp.RequestCtx) {
	cmds, err := database.ListLinuxCommands()
	if err != nil {
		logger.Errorc("LinuxCommandList", "查询失败: "+err.Error())
		response.Error(ctx, 5000, "查询失败")
		return
	}
	if cmds == nil {
		cmds = []database.LinuxCommand{}
	}
	response.Success(ctx, cmds)
}

// LinuxCommandSearch 搜索 Linux 命令
func LinuxCommandSearch(ctx *fasthttp.RequestCtx) {
	var req struct {
		Keyword string `json:"keyword"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Keyword == "" {
		response.Error(ctx, 1001, "搜索关键词不能为空")
		return
	}

	cmds, err := database.SearchLinuxCommands(req.Keyword)
	if err != nil {
		logger.Errorc("LinuxCommandSearch", "搜索失败: "+err.Error())
		response.Error(ctx, 5000, "搜索失败")
		return
	}
	if cmds == nil {
		cmds = []database.LinuxCommand{}
	}
	response.Success(ctx, cmds)
}

// LinuxCommandGet 获取单个命令
func LinuxCommandGet(ctx *fasthttp.RequestCtx) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}

	cmd, err := database.GetLinuxCommand(req.ID)
	if err != nil {
		logger.Errorc("LinuxCommandGet", "查询失败: "+err.Error())
		response.Error(ctx, 5000, "查询失败")
		return
	}
	if cmd == nil {
		response.Error(ctx, 2001, "命令不存在")
		return
	}
	response.Success(ctx, cmd)
}

// LinuxCommandCreate 创建 Linux 命令
func LinuxCommandCreate(ctx *fasthttp.RequestCtx) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Usage       string `json:"usage"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Name == "" {
		response.Error(ctx, 1001, "命令名称不能为空")
		return
	}

	c := &database.LinuxCommand{
		Name:        req.Name,
		Description: req.Description,
		Usage:       req.Usage,
	}
	if err := database.CreateLinuxCommand(c); err != nil {
		logger.Errorc("LinuxCommandCreate", "创建失败: "+err.Error())
		response.Error(ctx, 5000, "创建失败，命令名可能已存在")
		return
	}
	response.Success(ctx, c)
}

// LinuxCommandUpdate 更新 Linux 命令
func LinuxCommandUpdate(ctx *fasthttp.RequestCtx) {
	var req struct {
		ID          int64  `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Usage       string `json:"usage"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.ID == 0 {
		response.Error(ctx, 1001, "ID 不能为空")
		return
	}
	if req.Name == "" {
		response.Error(ctx, 1001, "命令名称不能为空")
		return
	}

	c := &database.LinuxCommand{
		ID:          req.ID,
		Name:        req.Name,
		Description: req.Description,
		Usage:       req.Usage,
	}
	if err := database.UpdateLinuxCommand(c); err != nil {
		logger.Errorc("LinuxCommandUpdate", "更新失败: "+err.Error())
		response.Error(ctx, 5000, "更新失败")
		return
	}
	response.Success(ctx, nil)
}

// LinuxCommandDelete 删除 Linux 命令
func LinuxCommandDelete(ctx *fasthttp.RequestCtx) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if err := database.DeleteLinuxCommand(req.ID); err != nil {
		logger.Errorc("LinuxCommandDelete", "删除失败: "+err.Error())
		response.Error(ctx, 5000, "删除失败")
		return
	}
	response.Success(ctx, nil)
}

// LinuxCommandHelp 通过系统命令获取帮助信息
func LinuxCommandHelp(ctx *fasthttp.RequestCtx) {
	var req struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Command == "" {
		response.Error(ctx, 1001, "命令名称不能为空")
		return
	}

	result := linuxCommandSvc.GetCommandHelp(req.Command)
	response.Success(ctx, result)
}
