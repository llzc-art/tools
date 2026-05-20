package service

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// IntegrationService 应用对接服务
type IntegrationService struct {
	cloudPlatforms        []PlatformDef
	wechatAPIs            WechatConfig
	wecomAPIs             WechatConfig
	feishuAPIs            WechatConfig
	tencentServiceMappings  map[string]struct{ service, host string }
	aliyunHostMappings      map[string]string
	awsServiceMappings      map[string]struct{ service, hostTmpl string }
}

// NewIntegrationService 创建应用对接服务
func NewIntegrationService() *IntegrationService {
	s := &IntegrationService{}
	s.loadConfigs()
	return s
}

// ============================================================
// 配置文件加载
// ============================================================

// CloudConfigFile 云平台配置文件结构
type CloudConfigFile struct {
	Platforms []PlatformDef `yaml:"platforms"`
}

// TencentServiceMapping 腾讯云 Action -> 服务/主机映射
type TencentServiceMapping struct {
	Action  string `yaml:"action"`
	Service string `yaml:"service"`
	Host    string `yaml:"host"`
}

// AliyunHostMapping 阿里云 Action -> 主机映射
type AliyunHostMapping struct {
	Action string `yaml:"action"`
	Host   string `yaml:"host"`
}

// AWSServiceMapping AWS Category -> 服务/主机映射
type AWSServiceMapping struct {
	Category   string `yaml:"category"`
	Service    string `yaml:"service"`
	HostTmpl   string `yaml:"host_template"`
}

// WechatConfig 微信/企业微信/飞书配置文件结构
type WechatConfig struct {
	BaseURL    string        `yaml:"base_url" json:"base_url"`
	AuthFields []AuthField   `yaml:"auth_fields" json:"auth_fields"`
	APIs       []PlatformAPI `yaml:"apis" json:"apis"`
}

// loadConfigs 从配置文件加载所有平台定义
func (s *IntegrationService) loadConfigs() {
	configDir := "config/integration"

	// 加载云平台配置
	s.cloudPlatforms = s.loadCloudConfig(filepath.Join(configDir, "cloud.yaml"))

	// 加载微信配置
	s.wechatAPIs = s.loadWechatConfig(filepath.Join(configDir, "wechat.yaml"))

	// 加载企业微信配置
	s.wecomAPIs = s.loadWechatConfig(filepath.Join(configDir, "wecom.yaml"))

	// 加载飞书配置
	s.feishuAPIs = s.loadWechatConfig(filepath.Join(configDir, "feishu.yaml"))
}

func (s *IntegrationService) loadCloudConfig(path string) []PlatformDef {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("[WARN] 加载云平台配置失败 %s: %v，使用默认配置\n", path, err)
		s.loadDefaultMappings()
		return defaultCloudPlatforms()
	}
	var cfg CloudConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Printf("[WARN] 解析云平台配置失败 %s: %v，使用默认配置\n", path, err)
		s.loadDefaultMappings()
		return defaultCloudPlatforms()
	}
	if len(cfg.Platforms) == 0 {
		s.loadDefaultMappings()
		return defaultCloudPlatforms()
	}
	// 加载服务映射配置
	s.loadServiceMappings(cfg.Platforms)
	// 确保 nil slice 序列化为 [] 而非 null
	for i := range cfg.Platforms {
		if cfg.Platforms[i].APIs == nil {
			cfg.Platforms[i].APIs = []PlatformAPI{}
		}
		if cfg.Platforms[i].AuthFields == nil {
			cfg.Platforms[i].AuthFields = []AuthField{}
		}
		if cfg.Platforms[i].Regions == nil {
			cfg.Platforms[i].Regions = []RegionOption{}
		}
	}
	return cfg.Platforms
}

// loadServiceMappings 加载服务映射配置
func (s *IntegrationService) loadServiceMappings(platforms []PlatformDef) {
	// 初始化映射表
	s.tencentServiceMappings = make(map[string]struct{ service, host string })
	s.aliyunHostMappings = make(map[string]string)
	s.awsServiceMappings = make(map[string]struct{ service, hostTmpl string })

	for _, p := range platforms {
		switch p.ID {
		case "tencent":
			for _, m := range p.TencentServiceMappings {
				s.tencentServiceMappings[m.Action] = struct{ service, host string }{m.Service, m.Host}
			}
		case "aliyun":
			for _, m := range p.AliyunHostMappings {
				s.aliyunHostMappings[m.Action] = m.Host
			}
		case "aws":
			for _, m := range p.AWSServiceMappings {
				s.awsServiceMappings[m.Category] = struct{ service, hostTmpl string }{m.Service, m.HostTmpl}
			}
		}
	}
}

// loadDefaultMappings 加载默认映射配置
func (s *IntegrationService) loadDefaultMappings() {
	s.tencentServiceMappings = map[string]struct{ service, host string }{
		"DescribeInstances":      {"cvm", "cvm.tencentcloudapi.com"},
		"DescribeZones":         {"cvm", "cvm.tencentcloudapi.com"},
		"DescribeDisks":         {"cbs", "cbs.tencentcloudapi.com"},
		"DescribeLoadBalancers": {"clb", "clb.tencentcloudapi.com"},
		"DescribeClusters":      {"tke", "tke.tencentcloudapi.com"},
		"DescribeDBInstances":   {"cdb", "cdb.tencentcloudapi.com"},
	}
	s.aliyunHostMappings = map[string]string{
		"DescribeInstances":     "ecs.aliyuncs.com",
		"DescribeZones":          "ecs.aliyuncs.com",
		"DescribeDisks":          "ecs.aliyuncs.com",
		"DescribeDBInstances":    "rds.aliyuncs.com",
		"DescribeLoadBalancers":  "slb.aliyuncs.com",
		"DescribeClusters":       "cs.aliyuncs.com",
	}
	s.awsServiceMappings = map[string]struct{ service, hostTmpl string }{
		"S3":     {"s3", "s3.%s.amazonaws.com"},
		"RDS":    {"rds", "rds.%s.amazonaws.com"},
		"ELB":    {"elasticloadbalancing", "elasticloadbalancing.%s.amazonaws.com"},
		"Lambda": {"lambda", "lambda.%s.amazonaws.com"},
		"EKS":    {"eks", "eks.%s.amazonaws.com"},
	}
}

func (s *IntegrationService) loadWechatConfig(path string) WechatConfig {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("[WARN] 加载配置失败 %s: %v\n", path, err)
		return WechatConfig{APIs: []PlatformAPI{}, AuthFields: []AuthField{}}
	}
	var cfg WechatConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Printf("[WARN] 解析配置失败 %s: %v\n", path, err)
		return WechatConfig{APIs: []PlatformAPI{}, AuthFields: []AuthField{}}
	}
	// 确保 nil slice 序列化为 [] 而非 null
	if cfg.APIs == nil {
		cfg.APIs = []PlatformAPI{}
	}
	if cfg.AuthFields == nil {
		cfg.AuthFields = []AuthField{}
	}
	return cfg
}

// ============================================================
// 默认配置（配置文件加载失败时的兜底）
// ============================================================

func defaultCloudPlatforms() []PlatformDef {
	return []PlatformDef{
		{
			ID: "tencent", Name: "腾讯云", BaseURL: "https://cvm.tencentcloudapi.com",
			SignMethod: "tc3-hmac-sha256", Region: "ap-guangzhou",
			Regions: []RegionOption{
				{Value: "ap-guangzhou", Label: "华南地区(广州)"},
				{Value: "ap-shanghai", Label: "华东地区(上海)"},
				{Value: "ap-beijing", Label: "华北地区(北京)"},
				{Value: "ap-chengdu", Label: "西南地区(成都)"},
				{Value: "ap-hongkong", Label: "港澳台地区(中国香港)"},
				{Value: "ap-singapore", Label: "东南亚地区(新加坡)"},
				{Value: "ap-tokyo", Label: "亚太地区(东京)"},
				{Value: "na-siliconvalley", Label: "美国西部(硅谷)"},
				{Value: "eu-frankfurt", Label: "欧洲地区(法兰克福)"},
			},
			AuthFields: []AuthField{
				{Key: "secret_id", Label: "SecretId", Type: "text", Placeholder: "AKIDz8krbsJ5...", Required: true},
				{Key: "secret_key", Label: "SecretKey", Type: "password", Placeholder: "Gu5t9xG...", Required: true},
			},
		},
		{
			ID: "aliyun", Name: "阿里云", BaseURL: "https://ecs.aliyuncs.com",
			SignMethod: "aliyun-hmac-sha1", Region: "cn-hangzhou",
			Regions: []RegionOption{
				{Value: "cn-hangzhou", Label: "华东1(杭州)"},
				{Value: "cn-shanghai", Label: "华东2(上海)"},
				{Value: "cn-qingdao", Label: "华北1(青岛)"},
				{Value: "cn-beijing", Label: "华北2(北京)"},
				{Value: "cn-shenzhen", Label: "华南1(深圳)"},
				{Value: "cn-chengdu", Label: "西南1(成都)"},
				{Value: "cn-hongkong", Label: "中国香港)"},
				{Value: "ap-southeast-1", Label: "亚太东南1(新加坡)"},
				{Value: "us-west-1", Label: "美国西部(硅谷)"},
				{Value: "eu-central-1", Label: "欧洲中部(法兰克福)"},
			},
			AuthFields: []AuthField{
				{Key: "access_key_id", Label: "AccessKey ID", Type: "text", Placeholder: "LTAI5t...", Required: true},
				{Key: "access_key_secret", Label: "AccessKey Secret", Type: "password", Placeholder: "Bf4J7x...", Required: true},
			},
		},
		{
			ID: "aws", Name: "AWS", BaseURL: "https://ec2.amazonaws.com",
			SignMethod: "aws-sigv4", Region: "us-east-1",
			Regions: []RegionOption{
				{Value: "us-east-1", Label: "US East (N. Virginia)"},
				{Value: "us-east-2", Label: "US East (Ohio)"},
				{Value: "us-west-1", Label: "US West (N. California)"},
				{Value: "us-west-2", Label: "US West (Oregon)"},
				{Value: "ap-east-1", Label: "Asia Pacific (Hong Kong)"},
				{Value: "ap-southeast-1", Label: "Asia Pacific (Singapore)"},
				{Value: "ap-northeast-1", Label: "Asia Pacific (Tokyo)"},
				{Value: "eu-west-1", Label: "EU (Ireland)"},
				{Value: "eu-central-1", Label: "EU (Frankfurt)"},
			},
			AuthFields: []AuthField{
				{Key: "access_key_id", Label: "Access Key ID", Type: "text", Placeholder: "AKIAIOSFODNN7...", Required: true},
				{Key: "secret_access_key", Label: "Secret Access Key", Type: "password", Placeholder: "wJalrXUtnFEMI...", Required: true},
			},
		},
		{
			ID: "huawei", Name: "华为云", BaseURL: "https://ecs.cn-north-1.myhuaweicloud.com",
			SignMethod: "huawei-hmac-sha256", Region: "cn-north-1",
			Regions: []RegionOption{
				{Value: "cn-north-1", Label: "华北-北京一"},
				{Value: "cn-north-4", Label: "华北-北京四"},
				{Value: "cn-east-2", Label: "华东-上海二"},
				{Value: "cn-east-3", Label: "华东-上海一"},
				{Value: "cn-south-1", Label: "华南-广州"},
				{Value: "ap-southeast-1", Label: "中国香港"},
				{Value: "ap-southeast-2", Label: "亚太-曼谷"},
				{Value: "ap-southeast-3", Label: "亚太-新加坡"},
			},
			AuthFields: []AuthField{
				{Key: "access_key_id", Label: "AK", Type: "text", Placeholder: "UGQOBN...", Required: true},
				{Key: "secret_access_key", Label: "SK", Type: "password", Placeholder: "dGOXVx...", Required: true},
				{Key: "project_id", Label: "Project ID", Type: "text", Placeholder: "0aa8...", Required: true},
			},
		},
	}
}

// ============================================================
// 数据结构定义
// ============================================================

// PlatformAPI 平台 API 定义
type PlatformAPI struct {
	ID           string `yaml:"id" json:"id"`
	Name         string `yaml:"name" json:"name"`
	Method       string `yaml:"method" json:"method"`
	Path         string `yaml:"path" json:"path"`
	Description  string `yaml:"description" json:"description"`
	Category     string `yaml:"category" json:"category"`
	BodyTemplate string `yaml:"body_template" json:"body_template,omitempty"`
	QueryParams  string `yaml:"query_params" json:"query_params,omitempty"`
}

// PlatformDef 平台定义
// RegionOption 区域选项
type RegionOption struct {
	Value string `yaml:"value" json:"value"`
	Label string `yaml:"label" json:"label"`
}

type PlatformDef struct {
	ID                      string         `yaml:"id" json:"id"`
	Name                    string         `yaml:"name" json:"name"`
	BaseURL                 string         `yaml:"base_url" json:"base_url"`
	SignMethod              string         `yaml:"sign_method" json:"sign_method"`
	Region                  string         `yaml:"region" json:"region"`
	Regions                 []RegionOption `yaml:"regions" json:"regions"`
	APIs                    []PlatformAPI  `yaml:"apis" json:"apis"`
	AuthFields              []AuthField    `yaml:"auth_fields" json:"auth_fields"`
	TencentServiceMappings  []TencentServiceMapping `yaml:"tencent_service_mappings"`
	AliyunHostMappings      []AliyunHostMapping     `yaml:"aliyun_host_mappings"`
	AWSServiceMappings      []AWSServiceMapping     `yaml:"aws_service_mappings"`
}

// AuthField 认证字段定义
type AuthField struct {
	Key         string `yaml:"key" json:"key"`
	Label       string `yaml:"label" json:"label"`
	Type        string `yaml:"type" json:"type"`
	Placeholder string `yaml:"placeholder" json:"placeholder"`
	Required    bool   `yaml:"required" json:"required"`
}

// ============================================================
// 获取 API 定义（从加载的配置中读取）
// ============================================================

// GetCloudPlatforms 获取云平台列表及预定义 API
func (s *IntegrationService) GetCloudPlatforms() []PlatformDef {
	return s.cloudPlatforms
}

// GetWeChatAPIs 获取微信开放平台 API 列表
func (s *IntegrationService) GetWeChatAPIs() WechatConfig {
	return s.wechatAPIs
}

// GetWeComAPIs 获取企业微信 API 列表
func (s *IntegrationService) GetWeComAPIs() WechatConfig {
	return s.wecomAPIs
}

// GetFeishuAPIs 获取飞书开放平台 API 列表
func (s *IntegrationService) GetFeishuAPIs() WechatConfig {
	return s.feishuAPIs
}

// ============================================================
// 云平台 API 签名调用
// ============================================================

// CloudCallRequest 云平台 API 调用请求
type CloudCallRequest struct {
	PlatformID string            `json:"platform_id"`
	APIID      string            `json:"api_id"`
	Auth       map[string]string `json:"auth"`
	Body       string            `json:"body"`
	Timeout    int               `json:"timeout"`
}

// CallAPIResponse API 调用响应
type CallAPIResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Size       int               `json:"size"`
	Duration   int64             `json:"duration"`
}

// CloudCall 云平台签名调用
func (s *IntegrationService) CloudCall(req *CloudCallRequest) (*CallAPIResponse, error) {
	platforms := s.cloudPlatforms
	var platform *PlatformDef
	var api *PlatformAPI
	for i := range platforms {
		if platforms[i].ID == req.PlatformID {
			platform = &platforms[i]
			for j := range platforms[i].APIs {
				if platforms[i].APIs[j].ID == req.APIID {
					api = &platforms[i].APIs[j]
					break
				}
			}
			break
		}
	}
	if platform == nil {
		return nil, fmt.Errorf("未找到平台: %s", req.PlatformID)
	}
	if api == nil {
		return nil, fmt.Errorf("未找到API: %s", req.APIID)
	}

	// 替换模板变量
	body := replaceTemplateVars(req.Body, req.Auth)
	apiPath := replaceTemplateVars(api.Path, req.Auth)

	switch platform.SignMethod {
	case "tc3-hmac-sha256":
		return s.callTencentCloud(platform, api, apiPath, body, req.Auth, req.Timeout)
	case "aliyun-hmac-sha1":
		return s.callAliyunCloud(platform, api, apiPath, body, req.Auth, req.Timeout)
	case "aws-sigv4":
		return s.callAWS(platform, api, apiPath, body, req.Auth, req.Timeout)
	case "huawei-hmac-sha256":
		return s.callHuaweiCloud(platform, api, apiPath, body, req.Auth, req.Timeout)
	default:
		return nil, fmt.Errorf("不支持的签名方法: %s", platform.SignMethod)
	}
}

// ============================================================
// 腾讯云 TC3-HMAC-SHA256 签名
// ============================================================

func (s *IntegrationService) callTencentCloud(platform *PlatformDef, api *PlatformAPI, apiPath, body string, auth map[string]string, timeout int) (*CallAPIResponse, error) {
	secretID := auth["secret_id"]
	secretKey := auth["secret_key"]
	region := auth["region"]
	if region == "" {
		region = "ap-guangzhou"
	}

	service := "cvm"
	host := "cvm.tencentcloudapi.com"
	now := time.Now().UTC()
	timestamp := now.Unix()
	date := now.Format("2006-01-02")

	// 解析 Action 从 body，并移除公共参数（POST JSON 模式下公共参数走 Header）
	actionName := api.Description
	version := "2017-03-12"
	if body != "" {
		var bodyMap map[string]interface{}
		if err := json.Unmarshal([]byte(body), &bodyMap); err == nil {
			if a, ok := bodyMap["Action"].(string); ok {
				actionName = a
			}
			if v, ok := bodyMap["Version"].(string); ok {
				version = v
			}
			if r, ok := bodyMap["Region"].(string); ok {
				region = r
			}
			service, host = s.inferTencentService(actionName)
			// POST JSON 模式下，公共参数必须通过 Header 传递，从 body 中移除
			delete(bodyMap, "Action")
			delete(bodyMap, "Version")
			delete(bodyMap, "Region")
			cleanBody, _ := json.Marshal(bodyMap)
			body = string(cleanBody)
		}
	}

	// Step 1: 拼接规范请求串
	contentType := "application/json; charset=utf-8"
	payload := body
	if payload == "" {
		payload = "{}"
	}
	payloadHash := sha256Hex(payload)

	canonicalHeaders := fmt.Sprintf("content-type:%s\nhost:%s\nx-tc-action:%s\n", contentType, host, strings.ToLower(actionName))
	signedHeaders := "content-type;host;x-tc-action"
	canonicalRequest := fmt.Sprintf("POST\n/\n\n%s\n%s\n%s", canonicalHeaders, signedHeaders, payloadHash)

	// Step 2: 拼接待签名字符串
	credentialScope := fmt.Sprintf("%s/%s/tc3_request", date, service)
	stringToSign := fmt.Sprintf("TC3-HMAC-SHA256\n%d\n%s\n%s", timestamp, credentialScope, sha256Hex(canonicalRequest))

	// Step 3: 计算签名
	secretDate := hmacSha256Hex([]byte("TC3"+secretKey), date)
	secretService := hmacSha256Hex(secretDate, service)
	secretSigning := hmacSha256Hex(secretService, "tc3_request")
	signature := hmacSha256HexHex(secretSigning, stringToSign)

	// Step 4: 构建 Authorization
	authorization := fmt.Sprintf("TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		secretID, credentialScope, signedHeaders, signature)

	// 发送请求
	urlStr := fmt.Sprintf("https://%s/", host)
	headers := map[string]string{
		"Content-Type":   contentType,
		"Host":           host,
		"X-TC-Action":    actionName,
		"X-TC-Version":  version,
		"X-TC-Region":   region,
		"X-TC-Timestamp": fmt.Sprintf("%d", timestamp),
		"Authorization":  authorization,
	}

	return doHTTPRequest("POST", urlStr, headers, payload, timeout)
}

// inferTencentService 根据 Action 推断腾讯云服务和主机
func (s *IntegrationService) inferTencentService(action string) (string, string) {
	if s.tencentServiceMappings == nil {
		s.loadDefaultMappings()
	}
	if m, ok := s.tencentServiceMappings[action]; ok {
		return m.service, m.host
	}
	return "cvm", "cvm.tencentcloudapi.com"
}

// ============================================================
// 阿里云 HMAC-SHA1 签名
// ============================================================

func (s *IntegrationService) callAliyunCloud(platform *PlatformDef, api *PlatformAPI, apiPath, body string, auth map[string]string, timeout int) (*CallAPIResponse, error) {
	accessKeyID := auth["access_key_id"]
	accessKeySecret := auth["access_key_secret"]
	region := auth["region"]
	if region == "" {
		region = "cn-hangzhou"
	}

	// 构建公共参数
	params := map[string]string{
		"Format":           "JSON",
		"Version":          "2014-05-26",
		"AccessKeyId":      accessKeyID,
		"SignatureMethod":  "HMAC-SHA1",
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"SignatureVersion": "1.0",
		"SignatureNonce":   fmt.Sprintf("%d", time.Now().UnixNano()),
	}

	// 解析 QueryParams
	if api.QueryParams != "" {
		qp := replaceTemplateVars(api.QueryParams, auth)
		for _, pair := range strings.Split(qp, "&") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				params[kv[0]] = kv[1]
			}
		}
	}

	// 从 QueryParams 覆盖 Version
	if v, ok := params["Version"]; ok {
		_ = v
	}

	// 构造签名字符串
	var sortedKeys []string
	for k := range params {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	var queryParts []string
	for _, k := range sortedKeys {
		queryParts = append(queryParts, urlEncode(k)+"="+urlEncode(params[k]))
	}
	canonicalQuery := strings.Join(queryParts, "&")

	stringToSign := "GET&" + urlEncode("/") + "&" + urlEncode(canonicalQuery)

	// 计算签名
	signature := hmacSha1Base64(accessKeySecret+"&", stringToSign)

	// 构建最终 URL
	finalQuery := canonicalQuery + "&Signature=" + urlEncode(signature)

	// 根据 Action 推断 host
	host := "ecs.aliyuncs.com"
	if action, ok := params["Action"]; ok {
		host = s.inferAliyunHost(action)
	}

	urlStr := fmt.Sprintf("https://%s/?%s", host, finalQuery)

	return doHTTPRequest("GET", urlStr, nil, "", timeout)
}

func (s *IntegrationService) inferAliyunHost(action string) string {
	if s.aliyunHostMappings == nil {
		s.loadDefaultMappings()
	}
	if h, ok := s.aliyunHostMappings[action]; ok {
		return h
	}
	return "ecs.aliyuncs.com"
}

// ============================================================
// AWS Signature Version 4
// ============================================================

func (s *IntegrationService) callAWS(platform *PlatformDef, api *PlatformAPI, apiPath, body string, auth map[string]string, timeout int) (*CallAPIResponse, error) {
	accessKeyID := auth["access_key_id"]
	secretAccessKey := auth["secret_access_key"]
	region := auth["region"]
	if region == "" {
		region = "us-east-1"
	}

	service := "ec2"
	host := "ec2." + region + ".amazonaws.com"

	// 根据 API 推断服务
	if api.Category != "" {
		svc, h := s.inferAWSService(api.Category, region)
		service = svc
		host = h
	}

	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	payload := body
	if payload == "" {
		payload = ""
	}
	payloadHash := sha256Hex(payload)

	contentType := "application/x-www-form-urlencoded"
	if api.Method == "GET" {
		contentType = ""
	}

	canonicalHeaders := fmt.Sprintf("content-type:%s\nhost:%s\nx-amz-date:%s\n", contentType, host, amzDate)
	signedHeaders := "content-type;host;x-amz-date"
	if contentType == "" {
		canonicalHeaders = fmt.Sprintf("host:%s\nx-amz-date:%s\n", host, amzDate)
		signedHeaders = "host;x-amz-date"
	}

	canonicalRequest := fmt.Sprintf("%s\n%s\n\n%s\n%s\n%s",
		api.Method, apiPath, canonicalHeaders, signedHeaders, payloadHash)

	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", amzDate, credentialScope, sha256Hex(canonicalRequest))

	signingKey := hmacSha256Bytes([]byte("AWS4"+secretAccessKey), dateStamp)
	signingKey = hmacSha256Bytes(signingKey, region)
	signingKey = hmacSha256Bytes(signingKey, service)
	signingKey = hmacSha256Bytes(signingKey, "aws4_request")
	signature := hex.EncodeToString(hmacSha256Bytes(signingKey, stringToSign))

	authorization := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKeyID, credentialScope, signedHeaders, signature)

	urlStr := fmt.Sprintf("https://%s%s", host, apiPath)
	headers := map[string]string{
		"X-Amz-Date":   amzDate,
		"Authorization": authorization,
	}
	if contentType != "" {
		headers["Content-Type"] = contentType
	}

	return doHTTPRequest(api.Method, urlStr, headers, payload, timeout)
}

func (s *IntegrationService) inferAWSService(category, region string) (string, string) {
	if s.awsServiceMappings == nil {
		s.loadDefaultMappings()
	}
	if m, ok := s.awsServiceMappings[category]; ok {
		return m.service, fmt.Sprintf(m.hostTmpl, region)
	}
	return "ec2", fmt.Sprintf("ec2.%s.amazonaws.com", region)
}

// ============================================================
// 华为云 HMAC-SHA256 签名
// ============================================================

func (s *IntegrationService) callHuaweiCloud(platform *PlatformDef, api *PlatformAPI, apiPath, body string, auth map[string]string, timeout int) (*CallAPIResponse, error) {
	ak := auth["access_key_id"]
	sk := auth["secret_access_key"]
	projectID := auth["project_id"]
	region := auth["region"]
	if region == "" {
		region = "cn-north-1"
	}

	host := fmt.Sprintf("ecs.%s.myhuaweicloud.com", region)
	now := time.Now().UTC()
	date := now.Format("20060102T150405Z")

	payload := body
	if payload == "" {
		payload = ""
	}
	payloadHash := sha256Hex(payload)

	contentType := "application/json"
	canonicalHeaders := fmt.Sprintf("content-type:%s\nhost:%s\nx-sdk-date:%s\n", contentType, host, date)
	signedHeaders := "content-type;host;x-sdk-date"

	canonicalRequest := fmt.Sprintf("%s\n%s\n\n%s\n%s\n%s",
		api.Method, apiPath, canonicalHeaders, signedHeaders, payloadHash)

	stringToSign := fmt.Sprintf("SDK-HMAC-SHA256\n%s\n%s", date, sha256Hex(canonicalRequest))
	signature := hmacSha256HexString(sk, stringToSign)

	authorization := fmt.Sprintf("SDK-HMAC-SHA256 Access=%s, SignedHeaders=%s, Signature=%s", ak, signedHeaders, signature)

	urlStr := fmt.Sprintf("https://%s%s", host, apiPath)
	headers := map[string]string{
		"Content-Type":  contentType,
		"Host":          host,
		"X-Sdk-Date":    date,
		"Authorization": authorization,
	}
	if projectID != "" {
		headers["X-Project-Id"] = projectID
	}

	return doHTTPRequest(api.Method, urlStr, headers, payload, timeout)
}

// ============================================================
// 微信/企业微信/飞书 - 通用 API 调用代理
// ============================================================

// WeChatTokenRequest 微信获取Token请求
type WeChatTokenRequest struct {
	AppID  string `json:"app_id"`
	Secret string `json:"secret"`
}

// GetWeChatAccessToken 获取微信公众号/小程序 Access Token
func (s *IntegrationService) GetWeChatAccessToken(appID, secret string) (*CallAPIResponse, error) {
	if appID == "" || secret == "" {
		return nil, fmt.Errorf("appid 和 secret 不能为空")
	}
	tokenURL := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=%s&secret=%s",
		url.QueryEscape(appID), url.QueryEscape(secret))
	return doHTTPRequest("GET", tokenURL, nil, "", 10)
}

// GetWeComAccessToken 获取企业微信 Access Token
func (s *IntegrationService) GetWeComAccessToken(corpID, corpSecret string) (*CallAPIResponse, error) {
	if corpID == "" || corpSecret == "" {
		return nil, fmt.Errorf("corpid 和 corpsecret 不能为空")
	}
	tokenURL := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%s&corpsecret=%s",
		url.QueryEscape(corpID), url.QueryEscape(corpSecret))
	return doHTTPRequest("GET", tokenURL, nil, "", 10)
}

// FeishuTokenRequest 飞书获取Token请求
type FeishuTokenRequest struct {
	AppID     string `json:"app_id"`
	AppSecret string `json:"app_secret"`
}

// GetFeishuAccessToken 获取飞书 Tenant Access Token
func (s *IntegrationService) GetFeishuAccessToken(appID, appSecret string) (*CallAPIResponse, error) {
	if appID == "" || appSecret == "" {
		return nil, fmt.Errorf("app_id 和 app_secret 不能为空")
	}
	bodyMap := map[string]string{"app_id": appID, "app_secret": appSecret}
	bodyJSON, _ := json.Marshal(bodyMap)
	return doHTTPRequest("POST", "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
		map[string]string{"Content-Type": "application/json; charset=utf-8"}, string(bodyJSON), 10)
}

// SimpleCall 简单代理调用（微信/企业微信/飞书等带 Token 的请求）
func (s *IntegrationService) SimpleCall(method, urlStr, body string, headers map[string]string, timeout int) (*CallAPIResponse, error) {
	return doHTTPRequest(method, urlStr, headers, body, timeout)
}

// ============================================================
// 通用 HTTP 请求
// ============================================================

func doHTTPRequest(method, urlStr string, headers map[string]string, body string, timeout int) (*CallAPIResponse, error) {
	if urlStr == "" {
		return nil, fmt.Errorf("URL 不能为空")
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("URL 格式无效: %v", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("只支持 http/https 协议")
	}
	host := parsedURL.Hostname()
	if isPrivateIP(host) {
		return nil, fmt.Errorf("不允许访问内网地址")
	}

	if method == "" {
		method = "GET"
	}
	method = strings.ToUpper(method)

	var bodyReader io.Reader
	if body != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		bodyReader = bytes.NewReader([]byte(body))
	}

	httpReq, err := http.NewRequest(method, urlStr, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}

	if timeout <= 0 {
		timeout = 30
	}
	if timeout > 120 {
		timeout = 120
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
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[k] = strings.Join(v, ", ")
		}
	}

	return &CallAPIResponse{
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		Body:       string(respBody),
		Size:       len(respBody),
		Duration:   duration,
	}, nil
}

// ============================================================
// 签名辅助函数
// ============================================================

func sha256Hex(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func hmacSha256Hex(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func hmacSha256HexHex(key []byte, data string) string {
	return hex.EncodeToString(hmacSha256Hex(key, data))
}

func hmacSha1Base64(key, data string) string {
	h := hmac.New(sha1.New, []byte(key))
	h.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func hmacSha256Bytes(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func hmacSha256HexString(key, data string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func urlEncode(s string) string {
	return url.QueryEscape(s)
}

// replaceTemplateVars 替换模板变量 {{key}}
func replaceTemplateVars(tmpl string, vars map[string]string) string {
	result := tmpl
	for k, v := range vars {
		result = strings.ReplaceAll(result, "{{"+k+"}}", v)
	}
	return result
}

// isPrivateIP 检查是否为内网地址
func isPrivateIP(host string) bool {
	privatePrefixes := []string{"10.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
		"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.", "127.", "0."}
	lowerHost := strings.ToLower(host)
	for _, prefix := range privatePrefixes {
		if strings.HasPrefix(lowerHost, prefix) {
			return true
		}
	}
	if lowerHost == "localhost" || lowerHost == "::1" {
		return true
	}
	return false
}
