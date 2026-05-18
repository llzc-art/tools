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

// ChatMessage 对话消息
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest 对话请求
type ChatRequest struct {
	BaseURL        string        `json:"base_url"`         // API 基础地址
	APIKey         string        `json:"api_key"`          // API Key
	Model          string        `json:"model"`            // 模型 ID
	Messages       []ChatMessage `json:"messages"`         // 对话消息列表
	Stream         bool          `json:"stream"`           // 是否流式
	MaxTokens      int           `json:"max_tokens"`       // 最大 token 数
	Temperature    float64       `json:"temperature"`      // 温度
	ChatTimeout    int           `json:"chat_timeout"`     // 非流式超时（秒）
	StreamTimeout  int           `json:"stream_timeout"`   // 流式超时（秒）
}

// ChatResponse 对话响应（非流式）
type ChatResponse struct {
	ID      string      `json:"id"`
	Model   string      `json:"model"`
	Content string      `json:"content"`
	Usage   *TokenUsage `json:"usage,omitempty"`
}

// TokenUsage token 使用量
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// StreamChunk 流式响应块
type StreamChunk struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Content string `json:"content"`
	Finish  bool   `json:"finish"`
}

// openAI 兼容 API 的请求/响应结构
type openaiRequest struct {
	Model       string        `json:"model"`
	Messages    []ChatMessage `json:"messages"`
	Stream      bool          `json:"stream"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature,omitempty"`
}

type openaiResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
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
}

type openaiStreamResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Delta struct {
			Role    string `json:"role,omitempty"`
			Content string `json:"content,omitempty"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
}

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
		Model:       req.Model,
		Messages:    req.Messages,
		Stream:      false,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
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
		ID:      oaiResp.ID,
		Model:   oaiResp.Model,
		Content: oaiResp.Choices[0].Message.Content,
		Usage: &TokenUsage{
			PromptTokens:     oaiResp.Usage.PromptTokens,
			CompletionTokens: oaiResp.Usage.CompletionTokens,
			TotalTokens:      oaiResp.Usage.TotalTokens,
		},
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
		Model:       req.Model,
		Messages:    req.Messages,
		Stream:      true,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
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

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			onChunk(&StreamChunk{Finish: true})
			break
		}

		var streamResp openaiStreamResponse
		if err := json.Unmarshal([]byte(data), &streamResp); err != nil {
			continue
		}

		if len(streamResp.Choices) > 0 {
			chunk := &StreamChunk{
				ID:    streamResp.ID,
				Model: streamResp.Model,
			}
			choice := streamResp.Choices[0]
			chunk.Content = choice.Delta.Content
			chunk.Finish = choice.FinishReason != nil

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
