package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/database"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

// LLM 配置 CRUD

type llmConfigReq struct {
	ID               int64   `json:"id"`
	Name             string  `json:"name"`
	BaseURL          string  `json:"base_url"`
	APIKey           string  `json:"api_key"`
	Model            string  `json:"model"`
	Temperature      float64 `json:"temperature"`
	TopP             float64 `json:"top_p"`
	MaxTokens        int     `json:"max_tokens"`
	Stream           bool    `json:"stream"`
	PresencePenalty  float64 `json:"presence_penalty"`
	FrequencyPenalty float64 `json:"frequency_penalty"`
	ResponseFormat   string  `json:"response_format"`
	Stop             []string `json:"stop"`
	IsDefault        bool    `json:"is_default"`
}

func toLLMConfig(req *llmConfigReq) *database.LLMConfig {
	stopJSON := ""
	if len(req.Stop) > 0 {
		b, _ := json.Marshal(req.Stop)
		stopJSON = string(b)
	}
	return &database.LLMConfig{
		ID:               req.ID,
		Name:             req.Name,
		BaseURL:          req.BaseURL,
		APIKey:           req.APIKey,
		Model:            req.Model,
		Temperature:      req.Temperature,
		TopP:             req.TopP,
		MaxTokens:        req.MaxTokens,
		Stream:           req.Stream,
		PresencePenalty:  req.PresencePenalty,
		FrequencyPenalty: req.FrequencyPenalty,
		ResponseFormat:   req.ResponseFormat,
		Stop:             stopJSON,
		IsDefault:        req.IsDefault,
	}
}

// LLMConfigList 获取所有 LLM 配置
func LLMConfigList(ctx *fasthttp.RequestCtx) {
	configs, err := database.ListLLMConfigs()
	if err != nil {
		logger.Errorc("LLMConfigList", "查询失败: "+err.Error())
		response.Error(ctx, 5000, "查询失败")
		return
	}
	if configs == nil {
		configs = []database.LLMConfig{}
	}
	response.Success(ctx, configs)
}

// LLMConfigGet 获取单个 LLM 配置
func LLMConfigGet(ctx *fasthttp.RequestCtx) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}

	config, err := database.GetLLMConfig(req.ID)
	if err != nil {
		logger.Errorc("LLMConfigGet", "查询失败: "+err.Error())
		response.Error(ctx, 5000, "查询失败")
		return
	}
	if config == nil {
		response.Error(ctx, 2001, "配置不存在")
		return
	}
	response.Success(ctx, config)
}

// LLMConfigGetDefault 获取默认配置
func LLMConfigGetDefault(ctx *fasthttp.RequestCtx) {
	config, err := database.GetDefaultLLMConfig()
	if err != nil {
		logger.Errorc("LLMConfigGetDefault", "查询失败: "+err.Error())
		response.Error(ctx, 5000, "查询失败")
		return
	}
	if config == nil {
		response.Success(ctx, nil)
		return
	}
	response.Success(ctx, config)
}

// LLMConfigCreate 创建 LLM 配置
func LLMConfigCreate(ctx *fasthttp.RequestCtx) {
	var req llmConfigReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}

	c := toLLMConfig(&req)
	if err := database.CreateLLMConfig(c); err != nil {
		logger.Errorc("LLMConfigCreate", "创建失败: "+err.Error())
		response.Error(ctx, 5000, "创建失败")
		return
	}
	response.Success(ctx, c)
}

// LLMConfigUpdate 更新 LLM 配置
func LLMConfigUpdate(ctx *fasthttp.RequestCtx) {
	var req llmConfigReq
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.ID == 0 {
		response.Error(ctx, 1001, "ID 不能为空")
		return
	}

	c := toLLMConfig(&req)
	if err := database.UpdateLLMConfig(c); err != nil {
		logger.Errorc("LLMConfigUpdate", "更新失败: "+err.Error())
		response.Error(ctx, 5000, "更新失败")
		return
	}
	response.Success(ctx, nil)
}

// LLMConfigDelete 删除 LLM 配置
func LLMConfigDelete(ctx *fasthttp.RequestCtx) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if err := database.DeleteLLMConfig(req.ID); err != nil {
		logger.Errorc("LLMConfigDelete", "删除失败: "+err.Error())
		response.Error(ctx, 5000, "删除失败")
		return
	}
	response.Success(ctx, nil)
}

// LLMConfigSetDefault 设置默认配置
func LLMConfigSetDefault(ctx *fasthttp.RequestCtx) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if err := database.SetDefaultLLMConfig(req.ID); err != nil {
		logger.Errorc("LLMConfigSetDefault", "设置失败: "+err.Error())
		response.Error(ctx, 5000, "设置失败")
		return
	}
	response.Success(ctx, nil)
}

// --- LLM Messages ---

// LLMMessagesGet 获取消息列表
func LLMMessagesGet(ctx *fasthttp.RequestCtx) {
	var req struct {
		ConfigID int64 `json:"config_id"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}

	msgs, err := database.ListLLMMessages(req.ConfigID)
	if err != nil {
		logger.Errorc("LLMMessagesGet", "查询失败: "+err.Error())
		response.Error(ctx, 5000, "查询失败")
		return
	}
	if msgs == nil {
		msgs = []database.LLMMessage{}
	}
	response.Success(ctx, msgs)
}

// LLMMessagesSave 保存消息列表
func LLMMessagesSave(ctx *fasthttp.RequestCtx) {
	var req struct {
		ConfigID int64                 `json:"config_id"`
		Messages []database.LLMMessage  `json:"messages"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}

	if err := database.SaveLLMMessages(req.ConfigID, req.Messages); err != nil {
		logger.Errorc("LLMMessagesSave", "保存失败: "+err.Error())
		response.Error(ctx, 5000, "保存失败")
		return
	}
	response.Success(ctx, nil)
}

// LLMMessagesClear 清空消息
func LLMMessagesClear(ctx *fasthttp.RequestCtx) {
	var req struct {
		ConfigID int64 `json:"config_id"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}

	if err := database.ClearLLMMessages(req.ConfigID); err != nil {
		logger.Errorc("LLMMessagesClear", "清空失败: "+err.Error())
		response.Error(ctx, 5000, "清空失败")
		return
	}
	response.Success(ctx, nil)
}
