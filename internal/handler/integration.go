package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/response"
)

var integrationSvc = service.NewIntegrationService()

// IntegrationCloudPlatforms 获取云平台列表
func IntegrationCloudPlatforms(ctx *fasthttp.RequestCtx) {
	platforms := integrationSvc.GetCloudPlatforms()
	response.Success(ctx, platforms)
}

// IntegrationCloudCall 云平台 API 签名调用
func IntegrationCloudCall(ctx *fasthttp.RequestCtx) {
	var req service.CloudCallRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.PlatformID == "" {
		response.Error(ctx, 1001, "请选择云平台")
		return
	}
	if req.APIID == "" {
		response.Error(ctx, 1001, "请选择API接口")
		return
	}

	result, err := integrationSvc.CloudCall(&req)
	if err != nil {
		response.Error(ctx, 2001, err.Error())
		return
	}
	response.Success(ctx, result)
}

// IntegrationWeChatAPIs 获取微信 API 列表
func IntegrationWeChatAPIs(ctx *fasthttp.RequestCtx) {
	apis := integrationSvc.GetWeChatAPIs()
	response.Success(ctx, apis)
}

// IntegrationWeChatToken 获取微信 Access Token
func IntegrationWeChatToken(ctx *fasthttp.RequestCtx) {
	var req service.WeChatTokenRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.AppID == "" || req.Secret == "" {
		response.Error(ctx, 1001, "appid 和 secret 不能为空")
		return
	}

	result, err := integrationSvc.GetWeChatAccessToken(req.AppID, req.Secret)
	if err != nil {
		response.Error(ctx, 2001, err.Error())
		return
	}
	response.Success(ctx, result)
}

// IntegrationWeChatCall 微信 API 调用代理
func IntegrationWeChatCall(ctx *fasthttp.RequestCtx) {
	var req struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
		Timeout int               `json:"timeout"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.URL == "" {
		response.Error(ctx, 1001, "URL 不能为空")
		return
	}

	result, err := integrationSvc.SimpleCall(req.Method, req.URL, req.Body, req.Headers, req.Timeout)
	if err != nil {
		response.Error(ctx, 2001, err.Error())
		return
	}
	response.Success(ctx, result)
}

// IntegrationWeComAPIs 获取企业微信 API 列表
func IntegrationWeComAPIs(ctx *fasthttp.RequestCtx) {
	apis := integrationSvc.GetWeComAPIs()
	response.Success(ctx, apis)
}

// IntegrationWeComToken 获取企业微信 Access Token
func IntegrationWeComToken(ctx *fasthttp.RequestCtx) {
	var req struct {
		CorpID     string `json:"corp_id"`
		CorpSecret string `json:"corp_secret"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.CorpID == "" || req.CorpSecret == "" {
		response.Error(ctx, 1001, "corpid 和 corpsecret 不能为空")
		return
	}

	result, err := integrationSvc.GetWeComAccessToken(req.CorpID, req.CorpSecret)
	if err != nil {
		response.Error(ctx, 2001, err.Error())
		return
	}
	response.Success(ctx, result)
}

// IntegrationWeComCall 企业微信 API 调用代理
func IntegrationWeComCall(ctx *fasthttp.RequestCtx) {
	var req struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
		Timeout int               `json:"timeout"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.URL == "" {
		response.Error(ctx, 1001, "URL 不能为空")
		return
	}

	result, err := integrationSvc.SimpleCall(req.Method, req.URL, req.Body, req.Headers, req.Timeout)
	if err != nil {
		response.Error(ctx, 2001, err.Error())
		return
	}
	response.Success(ctx, result)
}

// IntegrationFeishuAPIs 获取飞书 API 列表
func IntegrationFeishuAPIs(ctx *fasthttp.RequestCtx) {
	apis := integrationSvc.GetFeishuAPIs()
	response.Success(ctx, apis)
}

// IntegrationFeishuToken 获取飞书 Tenant Access Token
func IntegrationFeishuToken(ctx *fasthttp.RequestCtx) {
	var req service.FeishuTokenRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.AppID == "" || req.AppSecret == "" {
		response.Error(ctx, 1001, "app_id 和 app_secret 不能为空")
		return
	}

	result, err := integrationSvc.GetFeishuAccessToken(req.AppID, req.AppSecret)
	if err != nil {
		response.Error(ctx, 2001, err.Error())
		return
	}
	response.Success(ctx, result)
}

// IntegrationFeishuCall 飞书 API 调用代理
func IntegrationFeishuCall(ctx *fasthttp.RequestCtx) {
	var req struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
		Timeout int               `json:"timeout"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.URL == "" {
		response.Error(ctx, 1001, "URL 不能为空")
		return
	}

	result, err := integrationSvc.SimpleCall(req.Method, req.URL, req.Body, req.Headers, req.Timeout)
	if err != nil {
		response.Error(ctx, 2001, err.Error())
		return
	}
	response.Success(ctx, result)
}
