package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type JWTService struct{}

func NewJWTService() *JWTService {
	return &JWTService{}
}

type JWTDecodeResult struct {
	Token      string                 `json:"token"`
	Header     map[string]interface{} `json:"header"`
	Payload    map[string]interface{} `json:"payload"`
	Signature  string                 `json:"signature"`
	SignInput  string                 `json:"signInput"` // header.payload 原文
	Valid      bool                   `json:"valid"`
	Error      string                 `json:"error,omitempty"`
	Format     string                 `json:"format"` // "url" or "standard"
	TimeFields map[string]string      `json:"timeFields,omitempty"` // 时间戳字段格式化
}

func (s *JWTService) Decode(token string) *JWTDecodeResult {
	result := &JWTDecodeResult{Token: token}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		result.Valid = false
		result.Error = "无效的 JWT 格式，应为三段以 . 分隔"
		return result
	}

	result.SignInput = parts[0] + "." + parts[1]

	// 判断编码格式：URL-safe 字符集 vs 标准
	format := "url"
	if strings.ContainsAny(parts[0], "+/") {
		format = "standard"
	}
	result.Format = format

	// Decode header
	header, err := decodeJWTPart(parts[0])
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("Header 解码失败: %v", err)
		return result
	}
	result.Header = header

	// Decode payload
	payload, err := decodeJWTPart(parts[1])
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("Payload 解码失败: %v", err)
		return result
	}
	result.Payload = payload

	// Signature 部分：解码为 hex 显示
	sigBytes, err := decodeJWTPartBytes(parts[2])
	if err == nil {
		result.Signature = fmt.Sprintf("%x", sigBytes)
	} else {
		result.Signature = parts[2]
	}

	// 格式化常见时间戳字段
	result.TimeFields = formatTimeFields(payload)

	result.Valid = true
	return result
}

// decodeJWTPart 解码 JWT 的一个部分为 map
func decodeJWTPart(part string) (map[string]interface{}, error) {
	decoded, err := decodeJWTPartBytes(part)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(decoded, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// decodeJWTPartBytes 解码 JWT 的一个部分为字节
// 依次尝试：Base64URL (Raw) → Base64URL (with padding) → Standard Base64
func decodeJWTPartBytes(part string) ([]byte, error) {
	// 1. 尝试 Base64URL Raw（JWT 规范编码，无填充）
	if decoded, err := base64.RawURLEncoding.DecodeString(part); err == nil {
		return decoded, nil
	}

	// 2. 尝试 Base64URL with padding
	padded := padBase64(part)
	if decoded, err := base64.URLEncoding.DecodeString(padded); err == nil {
		return decoded, nil
	}

	// 3. 尝试标准 Base64（带 +/ 和可选填充）
	if decoded, err := base64.StdEncoding.DecodeString(padded); err == nil {
		return decoded, nil
	}

	// 4. 尝试标准 Base64 Raw
	if decoded, err := base64.RawStdEncoding.DecodeString(part); err == nil {
		return decoded, nil
	}

	return nil, fmt.Errorf("无法解码: %s", truncate(part, 20))
}

// padBase64 补全 base64 padding
func padBase64(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	default:
		return s
	}
}

// truncate 截断字符串
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// formatTimeFields 格式化 JWT 中的常见时间戳字段
func formatTimeFields(payload map[string]interface{}) map[string]string {
	timeFields := map[string]string{}
	timeKeys := []string{"iat", "exp", "nbf", "auth_time"}

	for _, key := range timeKeys {
		if val, ok := payload[key]; ok {
			var ts int64
			switch v := val.(type) {
			case float64:
				ts = int64(v)
			case json.Number:
				if n, err := v.Int64(); err == nil {
					ts = n
				}
			}
			if ts > 0 {
				t := time.Unix(ts, 0)
				timeFields[key] = t.Format("2006-01-02 15:04:05")
			}
		}
	}

	return timeFields
}
