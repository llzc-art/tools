package handler

import (
	"encoding/json"
	"net"
	"strings"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

var networkSvc = service.NewNetworkService()

// NetworkPing 批量 Ping 测试
func NetworkPing(ctx *fasthttp.RequestCtx) {
	var req struct {
		IPs     string `json:"ips"`
		Count   int    `json:"count"`
		Timeout int    `json:"timeout"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.IPs == "" {
		response.Error(ctx, 1001, "请输入 IP 地址列表")
		return
	}

	ips := splitLines(req.IPs)
	if len(ips) == 0 {
		response.Error(ctx, 1001, "请输入至少一个 IP 地址")
		return
	}
	if len(ips) > 100 {
		response.Error(ctx, 1001, "单次最多支持 100 个 IP 地址")
		return
	}

	results := networkSvc.Ping(ips, req.Count, req.Timeout)
	response.Success(ctx, results)
}

// NetworkPortProbe 批量端口探测
func NetworkPortProbe(ctx *fasthttp.RequestCtx) {
	var req struct {
		Addresses string `json:"addresses"`
		Timeout   int    `json:"timeout"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Addresses == "" {
		response.Error(ctx, 1001, "请输入地址列表")
		return
	}

	addresses := splitLines(req.Addresses)
	if len(addresses) == 0 {
		response.Error(ctx, 1001, "请输入至少一个地址")
		return
	}
	if len(addresses) > 100 {
		response.Error(ctx, 1001, "单次最多支持 100 个地址")
		return
	}

	results := networkSvc.PortProbe(addresses, req.Timeout)
	response.Success(ctx, results)
}

// NetworkSSHProbe SSH 连通性探测
func NetworkSSHProbe(ctx *fasthttp.RequestCtx) {
	var req struct {
		Host       string `json:"host"`
		Port       int    `json:"port"`
		Username   string `json:"username"`
		AuthType   string `json:"auth_type"`
		Password   string `json:"password"`
		PrivateKey string `json:"private_key"`
		Timeout    int    `json:"timeout"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Host == "" {
		response.Error(ctx, 1001, "请输入主机地址")
		return
	}

	// 安全校验：host 只允许域名和 IP 格式
	if !isValidHost(req.Host) {
		response.Error(ctx, 1001, "主机地址格式无效")
		return
	}

	// 如果提供了用户名，auth_type 默认为 password
	if req.Username != "" && req.AuthType == "" {
		req.AuthType = "password"
	}

	result := networkSvc.SSHProbe(req.Host, req.Port, req.Username, req.AuthType, req.Password, req.PrivateKey, req.Timeout)
	response.Success(ctx, result)
}

// splitLines 将多行文本分割为字符串数组，去除空行和前后空格
func splitLines(text string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// isValidHost 检查主机地址是否合法（IP 或域名）
func isValidHost(host string) bool {
	// 检查是否为合法 IP（IPv4/IPv6）
	if net.ParseIP(host) != nil {
		return true
	}
	// 检查是否为域名格式
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for i, c := range host {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
		if c == '-' && (i == 0 || i == len(host)-1) {
			return false
		}
	}
	return true
}

// init 避免未使用导入
func init() {
	_ = logger.Info
}
