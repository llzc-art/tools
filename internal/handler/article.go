package handler

import (
	"encoding/json"
	"strconv"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/response"
)

var articleSvc = service.NewArticleService()

// ArticleList 文章列表
func ArticleList(ctx *fasthttp.RequestCtx) {
	result, err := articleSvc.List()
	if err != nil {
		response.Error(ctx, 500, err.Error())
		return
	}
	response.Success(ctx, result)
}

// ArticleGet 获取文章详情
func ArticleGet(ctx *fasthttp.RequestCtx) {
	idStr := string(ctx.QueryArgs().Peek("id"))
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		response.Error(ctx, 400, "参数错误：id 无效")
		return
	}

	article, err := articleSvc.Get(id)
	if err != nil {
		response.Error(ctx, 500, err.Error())
		return
	}
	if article == nil {
		response.Error(ctx, 404, "文章不存在")
		return
	}
	response.Success(ctx, article)
}

// ArticleCreate 创建文章
func ArticleCreate(ctx *fasthttp.RequestCtx) {
	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 400, "参数错误: "+err.Error())
		return
	}

	article, err := articleSvc.Create(req.Title, req.Content)
	if err != nil {
		response.Error(ctx, 500, err.Error())
		return
	}
	response.Success(ctx, article)
}

// ArticleUpdate 更新文章
func ArticleUpdate(ctx *fasthttp.RequestCtx) {
	var req struct {
		ID      int64  `json:"id"`
		Title   string `json:"title"`
		Content string `json:"content"`
		Status  string `json:"status"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 400, "参数错误: "+err.Error())
		return
	}
	if req.ID <= 0 {
		response.Error(ctx, 400, "参数错误：id 无效")
		return
	}

	article, err := articleSvc.Update(req.ID, req.Title, req.Content, req.Status)
	if err != nil {
		response.Error(ctx, 500, err.Error())
		return
	}
	response.Success(ctx, article)
}

// ArticleDelete 删除文章
func ArticleDelete(ctx *fasthttp.RequestCtx) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 400, "参数错误: "+err.Error())
		return
	}
	if req.ID <= 0 {
		response.Error(ctx, 400, "参数错误：id 无效")
		return
	}

	if err := articleSvc.Delete(req.ID); err != nil {
		response.Error(ctx, 500, err.Error())
		return
	}
	response.Success(ctx, nil)
}

// ArticleChannelList 渠道列表
func ArticleChannelList(ctx *fasthttp.RequestCtx) {
	result, err := articleSvc.ListChannels()
	if err != nil {
		response.Error(ctx, 500, err.Error())
		return
	}
	response.Success(ctx, result)
}

// ArticleChannelCreate 创建渠道
func ArticleChannelCreate(ctx *fasthttp.RequestCtx) {
	var req struct {
		Name        string `json:"name"`
		ChannelType string `json:"channel_type"`
		Config      string `json:"config"` // JSON 字符串
		Enabled     bool   `json:"enabled"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 400, "参数错误: "+err.Error())
		return
	}
	if req.Name == "" || req.ChannelType == "" {
		response.Error(ctx, 400, "名称和渠道类型不能为空")
		return
	}

	channel, err := articleSvc.CreateChannel(req.Name, req.ChannelType, req.Config, req.Enabled)
	if err != nil {
		response.Error(ctx, 500, err.Error())
		return
	}
	response.Success(ctx, channel)
}

// ArticleChannelUpdate 更新渠道
func ArticleChannelUpdate(ctx *fasthttp.RequestCtx) {
	var req struct {
		ID          int64  `json:"id"`
		Name        string `json:"name"`
		ChannelType string `json:"channel_type"`
		Config      string `json:"config"`
		Enabled     bool   `json:"enabled"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 400, "参数错误: "+err.Error())
		return
	}
	if req.ID <= 0 {
		response.Error(ctx, 400, "参数错误：id 无效")
		return
	}

	channel, err := articleSvc.UpdateChannel(req.ID, req.Name, req.ChannelType, req.Config, req.Enabled)
	if err != nil {
		response.Error(ctx, 500, err.Error())
		return
	}
	response.Success(ctx, channel)
}

// ArticleChannelDelete 删除渠道
func ArticleChannelDelete(ctx *fasthttp.RequestCtx) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 400, "参数错误: "+err.Error())
		return
	}
	if req.ID <= 0 {
		response.Error(ctx, 400, "参数错误：id 无效")
		return
	}

	if err := articleSvc.DeleteChannel(req.ID); err != nil {
		response.Error(ctx, 500, err.Error())
		return
	}
	response.Success(ctx, nil)
}

// ArticlePublish 发布文章
func ArticlePublish(ctx *fasthttp.RequestCtx) {
	var req service.PublishRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 400, "参数错误: "+err.Error())
		return
	}
	if req.ArticleID <= 0 {
		response.Error(ctx, 400, "参数错误：article_id 无效")
		return
	}
	if len(req.ChannelIDs) == 0 {
		response.Error(ctx, 400, "请至少选择一个发布渠道")
		return
	}

	result, err := articleSvc.Publish(&req)
	if err != nil {
		response.Error(ctx, 500, err.Error())
		return
	}
	response.Success(ctx, result)
}

// ArticlePublishLogs 获取发布日志
func ArticlePublishLogs(ctx *fasthttp.RequestCtx) {
	idStr := string(ctx.QueryArgs().Peek("article_id"))
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		response.Error(ctx, 400, "参数错误：article_id 无效")
		return
	}

	result, err := articleSvc.GetPublishLogs(id)
	if err != nil {
		response.Error(ctx, 500, err.Error())
		return
	}
	response.Success(ctx, result)
}
