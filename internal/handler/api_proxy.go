package handler

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/pkg/logger"
)

// APIProxyRequest API 代理请求
type APIProxyRequest struct {
	Method        string            `json:"method"`
	URL           string            `json:"url"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body"`
	BodyType      string            `json:"body_type,omitempty"`       // none/json/form/multipart/raw
	FormData      []KVPair          `json:"form_data,omitempty"`       // form-data 字段
	MultipartFiles []MultipartFile  `json:"multipart_files,omitempty"` // 文件上传
	Timeout       int               `json:"timeout,omitempty"`
}

// KVPair 键值对
type KVPair struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Enabled bool   `json:"enabled"`
	Type    string `json:"type,omitempty"` // text/file（multipart 时用）
}

// MultipartFile 文件上传参数
type MultipartFile struct {
	Fieldname   string `json:"fieldname"`            // 表单字段名
	Filename    string `json:"filename"`             // 文件名
	Content     string `json:"content"`              // base64 编码的文件内容
	ContentType string `json:"content_type,omitempty"` // MIME 类型
}

// APIProxyResponse API 代理响应
type APIProxyResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Size       int               `json:"size"`
	Duration   int64             `json:"duration"`
}

// APIProxy 代理发送 HTTP 请求，避免浏览器跨域限制
func APIProxy(ctx *fasthttp.RequestCtx) {
	var req APIProxyRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		responseError(ctx, 1001, "参数错误")
		return
	}

	if req.URL == "" {
		responseError(ctx, 1001, "URL 不能为空")
		return
	}

	if req.Method == "" {
		req.Method = "GET"
	}
	req.Method = strings.ToUpper(req.Method)

	// 构建请求体
	var bodyReader io.Reader
	var contentType string

	if req.BodyType == "multipart" && (req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH") {
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)

		// 添加文本字段
		for _, f := range req.FormData {
			if !f.Enabled || f.Key == "" || f.Type == "file" {
				continue
			}
			_ = writer.WriteField(f.Key, f.Value)
		}

		// 添加文件字段
		for _, file := range req.MultipartFiles {
			if file.Fieldname == "" {
				continue
			}
			fileContent, err := base64.StdEncoding.DecodeString(file.Content)
			if err != nil {
				logger.Errorc("APIProxy", "文件内容解码失败: "+err.Error())
				continue
			}

			mimeType := file.ContentType
			if mimeType == "" {
				mimeType = "application/octet-stream"
			}

			h := make(textproto.MIMEHeader)
			h.Set("Content-Disposition",
				fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
					escapeQuotes(file.Fieldname), escapeQuotes(file.Filename)))
			h.Set("Content-Type", mimeType)

			part, err := writer.CreatePart(h)
			if err != nil {
				logger.Errorc("APIProxy", "创建 multipart part 失败: "+err.Error())
				continue
			}
			part.Write(fileContent)
		}

		writer.Close()
		bodyReader = &buf
		contentType = writer.FormDataContentType()
	} else if req.Body != "" && (req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH") {
		bodyReader = bytes.NewReader([]byte(req.Body))
	}

	httpReq, err := http.NewRequest(req.Method, req.URL, bodyReader)
	if err != nil {
		logger.Errorc("APIProxy", "创建请求失败: "+err.Error())
		responseError(ctx, 1001, "URL 格式错误: "+err.Error())
		return
	}

	// 设置请求头
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// multipart 时设置 Content-Type
	if contentType != "" {
		httpReq.Header.Set("Content-Type", contentType)
	}

	// 超时
	timeout := 30
	if req.Timeout > 0 {
		timeout = req.Timeout
		if timeout > 300 {
			timeout = 300
		}
	}
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	resp, err := client.Do(httpReq)
	duration := time.Since(start).Milliseconds()

	if err != nil {
		logger.Errorc("APIProxy", "请求失败: "+err.Error())
		responseError(ctx, 2001, "请求失败: "+err.Error())
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorc("APIProxy", "读取响应失败: "+err.Error())
		responseError(ctx, 2002, "读取响应失败: "+err.Error())
		return
	}

	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[k] = strings.Join(v, ", ")
		}
	}

	result := &APIProxyResponse{
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		Body:       string(respBody),
		Size:       len(respBody),
		Duration:   duration,
	}

	responseSuccess(ctx, result)
}

// quoteEscaper 用于 multipart 文件名转义
var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}
