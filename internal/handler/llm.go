package handler

import (
	"bufio"
	"encoding/json"
	"fmt"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/config"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

var llmSvc = service.NewLLMService()

// 内联响应函数（供 llm 和 api_proxy 等使用）
func responseSuccess(ctx *fasthttp.RequestCtx, data interface{}) {
	resp := map[string]interface{}{
		"code":    0,
		"message": "success",
		"data":    data,
	}
	ctx.SetContentType("application/json; charset=utf-8")
	ctx.SetStatusCode(200)
	jsonData, _ := json.Marshal(resp)
	ctx.SetBody(jsonData)
}

func responseError(ctx *fasthttp.RequestCtx, code int, message string) {
	resp := map[string]interface{}{
		"code":    code,
		"message": message,
		"data":    nil,
	}
	ctx.SetContentType("application/json; charset=utf-8")
	ctx.SetStatusCode(200)
	jsonData, _ := json.Marshal(resp)
	ctx.SetBody(jsonData)
}

// LLMChatRequest LLM 对话请求（对齐 OpenAI Chat Completions API）
type LLMChatRequest struct {
	BaseURL          string                  `json:"base_url"`
	APIKey           string                  `json:"api_key"`
	Model            string                  `json:"model"`
	Messages         []service.ChatMessage   `json:"messages"`
	Stream           bool                    `json:"stream"`
	MaxTokens        int                     `json:"max_tokens,omitempty"`
	Temperature      float64                 `json:"temperature,omitempty"`
	TopP             float64                 `json:"top_p,omitempty"`
	N                int                     `json:"n,omitempty"`
	Stop             []string                `json:"stop,omitempty"`
	PresencePenalty  float64                 `json:"presence_penalty,omitempty"`
	FrequencyPenalty float64                 `json:"frequency_penalty,omitempty"`
	ResponseFormat   *service.ResponseFormat `json:"response_format,omitempty"`
}

// LLMChat 对话接口（支持流式和非流式）
func LLMChat(ctx *fasthttp.RequestCtx) {
	var req LLMChatRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		logger.Errorc("LLMChat", "参数解析失败: "+err.Error())
		response.Error(ctx, 1001, "参数错误")
		return
	}

	if req.BaseURL == "" {
		response.Error(ctx, 1001, "API 地址不能为空")
		return
	}
	if req.Model == "" {
		response.Error(ctx, 1001, "模型 ID 不能为空")
		return
	}
	if len(req.Messages) == 0 {
		response.Error(ctx, 1001, "消息列表不能为空")
		return
	}

	if req.Stream {
		handleStreamChat(ctx, &req)
		return
	}

	// 非流式
	chatReq := &service.ChatRequest{
		BaseURL:          req.BaseURL,
		APIKey:           req.APIKey,
		Model:            req.Model,
		Messages:         req.Messages,
		Stream:           false,
		MaxTokens:        req.MaxTokens,
		Temperature:      req.Temperature,
		TopP:             req.TopP,
		N:                req.N,
		Stop:             req.Stop,
		PresencePenalty:  req.PresencePenalty,
		FrequencyPenalty: req.FrequencyPenalty,
		ResponseFormat:   req.ResponseFormat,
		ChatTimeout:      config.C.LLM.ChatTimeout,
		StreamTimeout:    config.C.LLM.StreamTimeout,
	}

	result, err := llmSvc.Chat(chatReq)
	if err != nil {
		logger.Errorc("LLMChat", "非流式对话失败: "+err.Error())
		response.Error(ctx, 2009, err.Error())
		return
	}

	response.Success(ctx, result)
}

// handleStreamChat 使用 SetBodyStreamWriter 实现 SSE 流式推送
func handleStreamChat(ctx *fasthttp.RequestCtx, req *LLMChatRequest) {
	// 设置 SSE 响应头
	ctx.SetContentType("text/event-stream; charset=utf-8")
	ctx.Response.Header.Set("Cache-Control", "no-cache")
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetStatusCode(200)

	// 使用 SetBodyStreamWriter 进行流式写入
	ctx.SetBodyStreamWriter(func(w *bufio.Writer) {
		chatReq := &service.ChatRequest{
			BaseURL:          req.BaseURL,
			APIKey:           req.APIKey,
			Model:            req.Model,
			Messages:         req.Messages,
			Stream:           true,
			MaxTokens:        req.MaxTokens,
			Temperature:      req.Temperature,
			TopP:             req.TopP,
			N:                req.N,
			Stop:             req.Stop,
			PresencePenalty:  req.PresencePenalty,
			FrequencyPenalty: req.FrequencyPenalty,
			ResponseFormat:   req.ResponseFormat,
			ChatTimeout:      config.C.LLM.ChatTimeout,
			StreamTimeout:    config.C.LLM.StreamTimeout,
		}

		err := llmSvc.ChatStream(chatReq, func(chunk *service.StreamChunk) error {
			data, _ := json.Marshal(chunk)
			sseData := fmt.Sprintf("data: %s\n\n", data)
			if _, writeErr := w.WriteString(sseData); writeErr != nil {
				return writeErr
			}
			return w.Flush()
		})

		if err != nil {
			logger.Errorc("LLMChat", "流式对话失败: "+err.Error())
			// 发送错误事件
			errData, _ := json.Marshal(map[string]interface{}{
				"error": map[string]string{
					"message": err.Error(),
					"type":   "api_error",
				},
			})
			w.WriteString(fmt.Sprintf("data: %s\n\n", errData))
			w.Flush()
		}

		// 发送结束事件
		w.WriteString("data: [DONE]\n\n")
		w.Flush()
	})
}
