package service

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"lelezc.com/tools/pkg/logger"
)

// LLMService LLM 对话服务
type LLMService struct{}

// NewLLMService 创建 LLM 服务实例
func NewLLMService() *LLMService {
	return &LLMService{}
}

// ========== 请求/响应结构（对齐 OpenAI Chat Completions API） ==========

// ChatMessage 对话消息
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest 对话请求（扩展支持更多 OpenAI 参数）
type ChatRequest struct {
	BaseURL            string        `json:"base_url"`
	APIKey             string        `json:"api_key"`
	Model              string        `json:"model"`
	Messages           []ChatMessage `json:"messages"`
	Stream             bool          `json:"stream"`
	MaxTokens          int           `json:"max_tokens"`
	Temperature        float64       `json:"temperature"`
	TopP               float64       `json:"top_p"`
	N                  int           `json:"n"`
	Stop               []string      `json:"stop"`
	PresencePenalty    float64       `json:"presence_penalty"`
	FrequencyPenalty   float64       `json:"frequency_penalty"`
	ResponseFormat     *ResponseFormat `json:"response_format,omitempty"`
	ChatTimeout        int           `json:"chat_timeout"`
	StreamTimeout      int           `json:"stream_timeout"`
}

// ResponseFormat 响应格式
type ResponseFormat struct {
	Type string `json:"type"` // "text" 或 "json_object"
}

// ChatResponse 对话响应（非流式，对齐 OpenAI 格式）
type ChatResponse struct {
	ID                string         `json:"id"`
	Object            string         `json:"object"`              // "chat.completion"
	Created           int64          `json:"created"`             // Unix 时间戳
	Model             string         `json:"model"`
	Choices           []ChatChoice   `json:"choices"`
	Usage             *TokenUsage    `json:"usage,omitempty"`
	SystemFingerprint string         `json:"system_fingerprint,omitempty"`
}

// ChatChoice 对话选择项
type ChatChoice struct {
	Index         int         `json:"index"`
	Message       ChatMessage `json:"message"`
	FinishReason  string      `json:"finish_reason"` // "stop", "length", "content_filter"
}

// TokenUsage token 使用量
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// StreamChunk 流式响应块（对齐 OpenAI 格式）
type StreamChunk struct {
	ID                string              `json:"id"`
	Object            string              `json:"object"`               // "chat.completion.chunk"
	Created           int64               `json:"created"`
	Model             string              `json:"model"`
	Choices           []StreamChoice      `json:"choices"`
	SystemFingerprint string              `json:"system_fingerprint,omitempty"`
}

// StreamChoice 流式选择项
type StreamChoice struct {
	Index        int            `json:"index"`
	Delta        StreamDelta    `json:"delta"`
	FinishReason *string        `json:"finish_reason"` // nil 表示未结束，"stop"/"length" 表示结束
}

// StreamDelta 流式增量
type StreamDelta struct {
	Role    string `json:"role,omitempty"`
	Content string `json:"content,omitempty"`
}

// ========== OpenAI 兼容 API 内部结构 ==========

type openaiRequest struct {
	Model             string          `json:"model"`
	Messages          []ChatMessage   `json:"messages"`
	Stream            bool            `json:"stream"`
	MaxTokens         int             `json:"max_tokens,omitempty"`
	Temperature       float64         `json:"temperature,omitempty"`
	TopP              float64         `json:"top_p,omitempty"`
	N                 int             `json:"n,omitempty"`
	Stop              []string        `json:"stop,omitempty"`
	PresencePenalty   float64         `json:"presence_penalty,omitempty"`
	FrequencyPenalty  float64         `json:"frequency_penalty,omitempty"`
	ResponseFormat    *ResponseFormat `json:"response_format,omitempty"`
}

type openaiResponse struct {
	ID                string `json:"id"`
	Object            string `json:"object"`
	Created           int64  `json:"created"`
	Model             string `json:"model"`
	Choices           []struct {
		Index        int    `json:"index"`
		Message      struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	SystemFingerprint string `json:"system_fingerprint,omitempty"`
}

type openaiStreamResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int    `json:"index"`
		Delta        struct {
			Role    string `json:"role,omitempty"`
			Content string `json:"content,omitempty"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
	SystemFingerprint string `json:"system_fingerprint,omitempty"`
}

// ========== 核心方法 ==========

// Chat 非流式对话
func (s *LLMService) Chat(req *ChatRequest) (*ChatResponse, error) {
	if req.BaseURL == "" {
		return nil, fmt.Errorf("API 地址不能为空")
	}
	if req.Model == "" {
		return nil, fmt.Errorf("模型 ID 不能为空")
	}
	if len(req.Messages) == 0 {
		return nil, fmt.Errorf("消息列表不能为空")
	}

	// 构建请求
	oaiReq := openaiRequest{
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
	}

	body, err := json.Marshal(oaiReq)
	if err != nil {
		logger.Errorc("LLMService.Chat", "构建请求失败: "+err.Error())
		return nil, fmt.Errorf("构建请求失败: %v", err)
	}

	url := strings.TrimRight(req.BaseURL, "/") + "/chat/completions"
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		logger.Errorc("LLMService.Chat", "创建请求失败: "+err.Error())
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if req.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+req.APIKey)
	}

	timeout := 120
	if req.ChatTimeout > 0 {
		timeout = req.ChatTimeout
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		logger.Errorc("LLMService.Chat", "请求失败: "+err.Error())
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorc("LLMService.Chat", "读取响应失败: "+err.Error())
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		logger.WithFields(logger.ERROR, "LLMService.Chat", "API 返回错误", map[string]interface{}{
			"status_code": resp.StatusCode,
			"response":    string(respBody),
		})
		return nil, fmt.Errorf("API 返回错误 (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var oaiResp openaiResponse
	if err := json.Unmarshal(respBody, &oaiResp); err != nil {
		logger.Errorc("LLMService.Chat", "解析响应失败: "+err.Error())
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	if len(oaiResp.Choices) == 0 {
		return nil, fmt.Errorf("API 未返回内容")
	}

	result := &ChatResponse{
		ID:                oaiResp.ID,
		Object:            oaiResp.Object,
		Created:           oaiResp.Created,
		Model:             oaiResp.Model,
		Choices:           make([]ChatChoice, len(oaiResp.Choices)),
		SystemFingerprint: oaiResp.SystemFingerprint,
		Usage: &TokenUsage{
			PromptTokens:     oaiResp.Usage.PromptTokens,
			CompletionTokens: oaiResp.Usage.CompletionTokens,
			TotalTokens:      oaiResp.Usage.TotalTokens,
		},
	}

	for i, c := range oaiResp.Choices {
		result.Choices[i] = ChatChoice{
			Index: c.Index,
			Message: ChatMessage{
				Role:    c.Message.Role,
				Content: c.Message.Content,
			},
			FinishReason: c.FinishReason,
		}
	}

	return result, nil
}

// ChatStream 流式对话，通过 callback 逐块返回
func (s *LLMService) ChatStream(req *ChatRequest, onChunk func(*StreamChunk) error) error {
	if req.BaseURL == "" {
		return fmt.Errorf("API 地址不能为空")
	}
	if req.Model == "" {
		return fmt.Errorf("模型 ID 不能为空")
	}
	if len(req.Messages) == 0 {
		return fmt.Errorf("消息列表不能为空")
	}

	oaiReq := openaiRequest{
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
	}

	body, err := json.Marshal(oaiReq)
	if err != nil {
		logger.Errorc("LLMService.ChatStream", "构建请求失败: "+err.Error())
		return fmt.Errorf("构建请求失败: %v", err)
	}

	url := strings.TrimRight(req.BaseURL, "/") + "/chat/completions"
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		logger.Errorc("LLMService.ChatStream", "创建请求失败: "+err.Error())
		return fmt.Errorf("创建请求失败: %v", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if req.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+req.APIKey)
	}

	timeout := 300
	if req.StreamTimeout > 0 {
		timeout = req.StreamTimeout
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		logger.Errorc("LLMService.ChatStream", "请求失败: "+err.Error())
		return fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		logger.WithFields(logger.ERROR, "LLMService.ChatStream", "API 返回错误", map[string]interface{}{
			"status_code": resp.StatusCode,
			"response":    string(respBody),
		})
		return fmt.Errorf("API 返回错误 (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	// 跟踪是否已收到过 finish_reason（模型可能返回 "stop" 或 "length" 等）
	var gotFinishReason bool

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			// 只有在模型未主动发送 finish_reason 时，才补发 "stop"
			if !gotFinishReason {
				doneReason := "stop"
				onChunk(&StreamChunk{
					Object:  "chat.completion.chunk",
					Choices: []StreamChoice{{Index: 0, FinishReason: &doneReason}},
				})
			}
			break
		}

		var streamResp openaiStreamResponse
		if err := json.Unmarshal([]byte(data), &streamResp); err != nil {
			continue
		}

		if len(streamResp.Choices) > 0 {
			chunk := &StreamChunk{
				ID:                streamResp.ID,
				Object:            streamResp.Object,
				Created:           streamResp.Created,
				Model:             streamResp.Model,
				SystemFingerprint: streamResp.SystemFingerprint,
				Choices:           make([]StreamChoice, len(streamResp.Choices)),
			}

			for i, c := range streamResp.Choices {
				chunk.Choices[i] = StreamChoice{
					Index: c.Index,
					Delta: StreamDelta{
						Role:    c.Delta.Role,
						Content: c.Delta.Content,
					},
					FinishReason: c.FinishReason,
				}
				// 记录是否已收到过结束原因
				if c.FinishReason != nil && *c.FinishReason != "" {
					gotFinishReason = true
				}
			}

			if err := onChunk(chunk); err != nil {
				return err
			}
		}
	}

	if err := scanner.Err(); err != nil {
		logger.Errorc("LLMService.ChatStream", "读取流式响应失败: "+err.Error())
		return fmt.Errorf("读取流式响应失败: %v", err)
	}

	return nil
}
