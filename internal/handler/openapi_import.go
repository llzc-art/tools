package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/pkg/logger"
)

// OpenAPIImportRequest OpenAPI 导入请求
type OpenAPIImportRequest struct {
	Content string `json:"content"` // OpenAPI JSON/YAML 内容
	URL     string `json:"url"`     // 或从 URL 拉取
}

// ImportedAPI 导入后的 API 项
type ImportedAPI struct {
	ID          string            `json:"id"`
	Group       string            `json:"group"`
	Name        string            `json:"name"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Summary     string            `json:"summary"`
	Description string            `json:"description"`
	Headers     []KVPair          `json:"headers"`
	Params      []KVPair          `json:"params"`
	BodyType    string            `json:"body_type"`
	Body        string            `json:"body"`
	AuthType    string            `json:"auth_type"`
	AuthToken   string            `json:"auth_token"`
}

// ImportedGroup 导入后的分组
type ImportedGroup struct {
	Name     string            `json:"name"`
	BaseURL  string            `json:"base_url"`
	Headers  []KVPair          `json:"headers"`
	AuthType string            `json:"auth_type"`
	AuthToken string           `json:"auth_token"`
	APIs     []ImportedAPI     `json:"apis"`
}

// OpenAPIImportResponse 导入响应
type OpenAPIImportResponse struct {
	Title   string          `json:"title"`
	Version string          `json:"version"`
	Groups  []ImportedGroup `json:"groups"`
}

// OpenAPIImport 导入 OpenAPI/Swagger 规范
func OpenAPIImport(ctx *fasthttp.RequestCtx) {
	var req OpenAPIImportRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		responseError(ctx, 1001, "参数错误")
		return
	}

	content := req.Content
	if content == "" && req.URL != "" {
		// 从 URL 拉取
		fetched, err := fetchURL(req.URL)
		if err != nil {
			responseError(ctx, 2001, "拉取 OpenAPI 文档失败: "+err.Error())
			return
		}
		content = fetched
	}

	if content == "" {
		responseError(ctx, 1001, "请提供 OpenAPI 文档内容或 URL")
		return
	}

	result, err := parseOpenAPIDoc(content)
	if err != nil {
		logger.Errorc("OpenAPIImport", "解析失败: "+err.Error())
		responseError(ctx, 2002, "解析 OpenAPI 文档失败: "+err.Error())
		return
	}

	responseSuccess(ctx, result)
}

// fetchURL 简单 HTTP GET
func fetchURL(url string) (string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Accept", "application/json, application/yaml, text/yaml, */*")

	resp, err := client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// parseOpenAPIDoc 解析 OpenAPI 文档（支持 2.0/3.0）
func parseOpenAPIDoc(content string) (*OpenAPIImportResponse, error) {
	content = strings.TrimSpace(content)

	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		return nil, fmt.Errorf("JSON 解析失败: %v", err)
	}

	// 判断版本
	swagger, _ := doc["swagger"].(string)
	openapi, _ := doc["openapi"].(string)

	if swagger == "2.0" {
		return parseSwagger2(doc)
	} else if strings.HasPrefix(openapi, "3.") {
		return parseOpenAPI3(doc)
	}

	return nil, fmt.Errorf("不支持的 OpenAPI 版本: swagger=%s, openapi=%s", swagger, openapi)
}

// parseSwagger2 解析 Swagger 2.0
func parseSwagger2(doc map[string]interface{}) (*OpenAPIImportResponse, error) {
	title, _ := doc["info"].(map[string]interface{})["title"].(string)
	version, _ := doc["info"].(map[string]interface{})["version"].(string)
	host, _ := doc["host"].(string)
	basePath, _ := doc["basePath"].(string)

	baseURL := ""
	if host != "" {
		schemes, _ := doc["schemes"].([]interface{})
		scheme := "https"
		if len(schemes) > 0 {
			if s, ok := schemes[0].(string); ok {
				scheme = s
			}
		}
		baseURL = scheme + "://" + host + basePath
	}

	// 全局安全定义
	globalHeaders := []KVPair{}
	globalAuthType := "none"
	globalAuthToken := ""

	if secDefs, ok := doc["securityDefinitions"].(map[string]interface{}); ok {
		for name, def := range secDefs {
			d, _ := def.(map[string]interface{})
			switch d["type"] {
			case "apiKey":
				in, _ := d["in"].(string)
				keyName, _ := d["name"].(string)
				if in == "header" {
					globalHeaders = append(globalHeaders, KVPair{Key: keyName, Value: fmt.Sprintf("{{%s}}", name), Enabled: true})
				}
			case "bearer":
				globalAuthType = "bearer"
				globalAuthToken = fmt.Sprintf("{{%s}}", name)
			case "basic":
				globalAuthType = "basic"
			}
		}
	}

	groups := []ImportedGroup{}
	paths, _ := doc["paths"].(map[string]interface{})

	for path, methods := range paths {
		methodsMap, _ := methods.(map[string]interface{})
		for method, detail := range methodsMap {
			d, _ := detail.(map[string]interface{})
			method = strings.ToUpper(method)
			if method == "PARAMETERS" {
				continue
			}

			summary, _ := d["summary"].(string)
			desc, _ := d["description"].(string)
			tag := "默认"
			if tags, ok := d["tags"].([]interface{}); ok && len(tags) > 0 {
				if t, ok := tags[0].(string); ok {
					tag = t
				}
			}

			params := []KVPair{}
			headers := []KVPair{}
			bodyType := "none"
			bodyContent := ""

			if parameters, ok := d["parameters"].([]interface{}); ok {
				for _, p := range parameters {
					param, _ := p.(map[string]interface{})
					pName, _ := param["name"].(string)
					pIn, _ := param["in"].(string)
					pRequired, _ := param["required"].(bool)
					pDesc, _ := param["description"].(string)
					_ = pDesc

					switch pIn {
					case "query":
						params = append(params, KVPair{Key: pName, Value: "", Enabled: pRequired})
					case "header":
						headers = append(headers, KVPair{Key: pName, Value: "", Enabled: pRequired})
					case "path":
						params = append(params, KVPair{Key: pName, Value: fmt.Sprintf("{{%s}}", pName), Enabled: true})
					case "body":
						bodyType = "json"
						if schema, ok := param["schema"].(map[string]interface{}); ok {
							example := generateExampleFromSchema(schema)
							if example != "" {
								bodyContent = example
							}
						}
					case "formData":
						bodyType = "form"
						params = append(params, KVPair{Key: pName, Value: "", Enabled: pRequired})
					}
				}
			}

			api := ImportedAPI{
				ID:          fmt.Sprintf("%s_%s", method, path),
				Group:       tag,
				Name:        summary,
				Method:      method,
				Path:        path,
				Summary:     summary,
				Description: desc,
				Headers:     headers,
				Params:      params,
				BodyType:    bodyType,
				Body:        bodyContent,
				AuthType:    globalAuthType,
				AuthToken:   globalAuthToken,
			}

			// 查找或创建分组
			found := false
			for i, g := range groups {
				if g.Name == tag {
					groups[i].APIs = append(groups[i].APIs, api)
					found = true
					break
				}
			}
			if !found {
				groups = append(groups, ImportedGroup{
					Name:      tag,
					BaseURL:   baseURL,
					Headers:   append([]KVPair{}, globalHeaders...),
					AuthType:  globalAuthType,
					AuthToken: globalAuthToken,
					APIs:      []ImportedAPI{api},
				})
			}
		}
	}

	return &OpenAPIImportResponse{
		Title:   title,
		Version: version,
		Groups:  groups,
	}, nil
}

// parseOpenAPI3 解析 OpenAPI 3.0
func parseOpenAPI3(doc map[string]interface{}) (*OpenAPIImportResponse, error) {
	info, _ := doc["info"].(map[string]interface{})
	title, _ := info["title"].(string)
	version, _ := info["version"].(string)

	// 从 servers 获取 base URL
	baseURL := ""
	if servers, ok := doc["servers"].([]interface{}); ok && len(servers) > 0 {
		if s, ok := servers[0].(map[string]interface{}); ok {
			baseURL, _ = s["url"].(string)
		}
	}

	// 全局安全
	globalHeaders := []KVPair{}
	globalAuthType := "none"
	globalAuthToken := ""

	if secSchemes, ok := doc["components"].(map[string]interface{})["securitySchemes"].(map[string]interface{}); ok {
		for name, def := range secSchemes {
			d, _ := def.(map[string]interface{})
			switch d["type"] {
			case "apiKey":
				in, _ := d["in"].(string)
				keyName, _ := d["name"].(string)
				if in == "header" {
					globalHeaders = append(globalHeaders, KVPair{Key: keyName, Value: fmt.Sprintf("{{%s}}", name), Enabled: true})
				}
			case "http":
				scheme, _ := d["scheme"].(string)
				if scheme == "bearer" {
					globalAuthType = "bearer"
					globalAuthToken = fmt.Sprintf("{{%s}}", name)
				} else if scheme == "basic" {
					globalAuthType = "basic"
				}
			}
		}
	}

	groups := []ImportedGroup{}
	paths, _ := doc["paths"].(map[string]interface{})

	for path, methods := range paths {
		methodsMap, _ := methods.(map[string]interface{})
		for method, detail := range methodsMap {
			d, _ := detail.(map[string]interface{})
			method = strings.ToUpper(method)
			if method == "PARAMETERS" || method == "SUMMARY" || method == "DESCRIPTION" {
				continue
			}

			summary, _ := d["summary"].(string)
			desc, _ := d["description"].(string)
			tag := "默认"
			if tags, ok := d["tags"].([]interface{}); ok && len(tags) > 0 {
				if t, ok := tags[0].(string); ok {
					tag = t
				}
			}

			params := []KVPair{}
			headers := []KVPair{}
			bodyType := "none"
			bodyContent := ""

			// 解析 parameters
			if parameters, ok := d["parameters"].([]interface{}); ok {
				for _, p := range parameters {
					param, _ := p.(map[string]interface{})
					pName, _ := param["name"].(string)
					pIn, _ := param["in"].(string)
					pRequired, _ := param["required"].(bool)

					switch pIn {
					case "query":
						params = append(params, KVPair{Key: pName, Value: "", Enabled: pRequired})
					case "header":
						headers = append(headers, KVPair{Key: pName, Value: "", Enabled: pRequired})
					case "path":
						params = append(params, KVPair{Key: pName, Value: fmt.Sprintf("{{%s}}", pName), Enabled: true})
					case "cookie":
						headers = append(headers, KVPair{Key: "Cookie", Value: fmt.Sprintf("%s={{%s}}", pName, pName), Enabled: true})
					}
				}
			}

			// 解析 requestBody (OpenAPI 3.0)
			if rb, ok := d["requestBody"].(map[string]interface{}); ok {
				if content, ok := rb["content"].(map[string]interface{}); ok {
					if jsonContent, ok := content["application/json"].(map[string]interface{}); ok {
						bodyType = "json"
						if schema, ok := jsonContent["schema"].(map[string]interface{}); ok {
							example := generateExampleFromSchema(schema)
							if example != "" {
								bodyContent = example
							}
						}
					} else if formContent, ok := content["application/x-www-form-urlencoded"].(map[string]interface{}); ok {
						bodyType = "form"
						if schema, ok := formContent["schema"].(map[string]interface{}); ok {
							if props, ok := schema["properties"].(map[string]interface{}); ok {
								for k := range props {
									params = append(params, KVPair{Key: k, Value: "", Enabled: true})
								}
							}
						}
					} else if multiContent, ok := content["multipart/form-data"].(map[string]interface{}); ok {
						bodyType = "multipart"
						if schema, ok := multiContent["schema"].(map[string]interface{}); ok {
							if props, ok := schema["properties"].(map[string]interface{}); ok {
								for k, v := range props {
									prop, _ := v.(map[string]interface{})
									pType := "text"
									if fmt.Sprintf("%v", prop["type"]) == "string" && fmt.Sprintf("%v", prop["format"]) == "binary" {
										pType = "file"
									}
									params = append(params, KVPair{Key: k, Value: "", Enabled: true, Type: pType})
								}
							}
						}
					}
				}
			}

			api := ImportedAPI{
				ID:          fmt.Sprintf("%s_%s", method, path),
				Group:       tag,
				Name:        summary,
				Method:      method,
				Path:        path,
				Summary:     summary,
				Description: desc,
				Headers:     headers,
				Params:      params,
				BodyType:    bodyType,
				Body:        bodyContent,
				AuthType:    globalAuthType,
				AuthToken:   globalAuthToken,
			}

			found := false
			for i, g := range groups {
				if g.Name == tag {
					groups[i].APIs = append(groups[i].APIs, api)
					found = true
					break
				}
			}
			if !found {
				groups = append(groups, ImportedGroup{
					Name:      tag,
					BaseURL:   baseURL,
					Headers:   append([]KVPair{}, globalHeaders...),
					AuthType:  globalAuthType,
					AuthToken: globalAuthToken,
					APIs:      []ImportedAPI{api},
				})
			}
		}
	}

	return &OpenAPIImportResponse{
		Title:   title,
		Version: version,
		Groups:  groups,
	}, nil
}

// generateExampleFromSchema 从 JSON Schema 生成示例 JSON
func generateExampleFromSchema(schema map[string]interface{}) string {
	// 先尝试用 example
	if ex, ok := schema["example"]; ok {
		data, _ := json.MarshalIndent(ex, "", "  ")
		return string(data)
	}

	schemaType, _ := schema["type"].(string)

	switch schemaType {
	case "object":
		result := map[string]interface{}{}
		if props, ok := schema["properties"].(map[string]interface{}); ok {
			for k, v := range props {
				prop, _ := v.(map[string]interface{})
				result[k] = getDefaultValue(prop)
			}
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		return string(data)
	case "array":
		if items, ok := schema["items"].(map[string]interface{}); ok {
			data, _ := json.MarshalIndent([]interface{}{getDefaultValue(items)}, "", "  ")
			return string(data)
		}
		return "[]"
	case "string":
		return ""
	case "integer", "number":
		return "0"
	case "boolean":
		return "false"
	}

	return ""
}

// getDefaultValue 获取属性的默认值
func getDefaultValue(prop map[string]interface{}) interface{} {
	// 先看 example
	if ex, ok := prop["example"]; ok {
		return ex
	}

	propType, _ := prop["type"].(string)
	switch propType {
	case "string":
		return ""
	case "integer", "number":
		return 0
	case "boolean":
		return false
	case "array":
		return []interface{}{}
	case "object":
		result := map[string]interface{}{}
		if props, ok := prop["properties"].(map[string]interface{}); ok {
			for k, v := range props {
				p, _ := v.(map[string]interface{})
				result[k] = getDefaultValue(p)
			}
		}
		return result
	}

	return ""
}
