package service

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// NetworkService 网络探测服务
type NetworkService struct{}

// NewNetworkService 创建网络探测服务
func NewNetworkService() *NetworkService {
	return &NetworkService{}
}

// PingResult Ping 测试结果
type PingResult struct {
	IP      string `json:"ip"`
	Alive   bool   `json:"alive"`
	Latency string `json:"latency,omitempty"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}

// PortProbeResult 端口探测结果
type PortProbeResult struct {
	Address string `json:"address"`
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Latency string `json:"latency,omitempty"`
	Error   string `json:"error,omitempty"`
}

// SSHProbeResult SSH 探测结果
type SSHProbeResult struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Reachable bool   `json:"reachable"`
	AuthOK    bool   `json:"auth_ok,omitempty"`
	Banner    string `json:"banner,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Ping 批量 Ping 测试
func (s *NetworkService) Ping(ips []string, count int, timeout int) []PingResult {
	if count <= 0 {
		count = 3
	}
	if count > 10 {
		count = 10
	}
	if timeout <= 0 {
		timeout = 5
	}
	if timeout > 30 {
		timeout = 30
	}

	results := make([]PingResult, len(ips))
	type indexedResult struct {
		idx int
		res PingResult
	}

	ch := make(chan indexedResult, len(ips))
	for i, ip := range ips {
		go func(idx int, target string) {
			ch <- indexedResult{idx: idx, res: s.pingSingle(target, count, timeout)}
		}(i, ip)
	}

	for i := 0; i < len(ips); i++ {
		r := <-ch
		results[r.idx] = r.res
	}
	return results
}

func (s *NetworkService) pingSingle(ip string, count, timeout int) PingResult {
	result := PingResult{IP: ip}

	// 安全校验：IP 格式检查
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		result.Error = "无效的 IP 地址"
		return result
	}

	// 使用系统 ping 命令
	args := []string{"-c", fmt.Sprintf("%d", count), "-W", fmt.Sprintf("%d", timeout), ip}
	output, err := executeCommand("ping", args, time.Duration(timeout+5)*time.Second)

	result.Output = output
	if err != nil {
		result.Alive = false
		result.Error = "Ping 失败: " + err.Error()
		return result
	}

	// 解析输出判断是否通
	if strings.Contains(output, "0 packets received") || strings.Contains(output, "100% packet loss") {
		result.Alive = false
	} else {
		result.Alive = true
	}

	// 尝试提取延迟
	latencyRe := regexp.MustCompile(`min/avg/max/(?:stddev|msdev)\s*=\s*[\d.]+/([\d.]+)/[\d.]+/[\d.]+\s*ms`)
	matches := latencyRe.FindStringSubmatch(output)
	if len(matches) >= 2 {
		result.Latency = matches[1] + "ms"
	} else {
		// 尝试另一种格式：rtt min/avg/max/mdev = x/x/x/x ms
		latencyRe2 := regexp.MustCompile(`rtt min/avg/max/mdev\s*=\s*[\d.]+/([\d.]+)/[\d.]+/[\d.]+\s*ms`)
		matches2 := latencyRe2.FindStringSubmatch(output)
		if len(matches2) >= 2 {
			result.Latency = matches2[1] + "ms"
		}
	}

	return result
}

// PortProbe 批量端口探测
func (s *NetworkService) PortProbe(addresses []string, timeout int) []PortProbeResult {
	if timeout <= 0 {
		timeout = 5
	}
	if timeout > 30 {
		timeout = 30
	}

	results := make([]PortProbeResult, len(addresses))
	type indexedResult struct {
		idx int
		res PortProbeResult
	}

	ch := make(chan indexedResult, len(addresses))
	for i, addr := range addresses {
		go func(idx int, target string) {
			ch <- indexedResult{idx: idx, res: s.portProbeSingle(target, timeout)}
		}(i, addr)
	}

	for i := 0; i < len(addresses); i++ {
		r := <-ch
		results[r.idx] = r.res
	}
	return results
}

func (s *NetworkService) portProbeSingle(address string, timeout int) PortProbeResult {
	result := PortProbeResult{Address: address}

	address = strings.TrimSpace(address)
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// 尝试作为 host:port 解析
		result.Error = "地址格式错误，请使用 IP:Port 格式"
		return result
	}

	result.IP = host
	var portInt int
	fmt.Sscanf(port, "%d", &portInt)
	result.Port = portInt

	if portInt <= 0 || portInt > 65535 {
		result.Error = "端口号无效（1-65535）"
		return result
	}

	startTime := time.Now()
	conn, err := net.DialTimeout("tcp", address, time.Duration(timeout)*time.Second)
	elapsed := time.Since(startTime)

	if err != nil {
		result.Open = false
		result.Error = "连接失败: " + err.Error()
		return result
	}
	conn.Close()
	result.Open = true
	result.Latency = fmt.Sprintf("%.1fms", float64(elapsed.Milliseconds()))

	return result
}

// SSHProbe SSH 连通性探测
func (s *NetworkService) SSHProbe(host string, port int, username string, authType string, password string, privateKey string, timeout int) SSHProbeResult {
	if port <= 0 {
		port = 22
	}
	if timeout <= 0 {
		timeout = 10
	}
	if timeout > 60 {
		timeout = 60
	}

	result := SSHProbeResult{
		Host: host,
		Port: port,
	}

	// 第一步：测试 TCP 端口是否可达
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	startTime := time.Now()
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		result.Reachable = false
		result.Error = "TCP 连接失败: " + err.Error()
		return result
	}

	// 先读取 SSH Banner
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	banner, _ := reader.ReadString('\n')
	if banner != "" {
		result.Banner = strings.TrimSpace(banner)
	}
	conn.Close()

	result.Reachable = true

	// 如果没有提供认证信息，只测试端口可达性
	if username == "" {
		return result
	}

	// 第二步：尝试 SSH 认证
	var sshAuth []ssh.AuthMethod

	switch authType {
	case "password":
		if password != "" {
			sshAuth = append(sshAuth, ssh.Password(password))
		}
	case "key":
		if privateKey != "" {
			signer, err := ssh.ParsePrivateKey([]byte(privateKey))
			if err != nil {
				result.Error = "解析私钥失败: " + err.Error()
				return result
			}
			sshAuth = append(sshAuth, ssh.PublicKeys(signer))
		}
	default:
		// 默认尝试 password
		if password != "" {
			sshAuth = append(sshAuth, ssh.Password(password))
		}
	}

	if len(sshAuth) == 0 {
		return result
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            sshAuth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(timeout) * time.Second,
	}

	elapsed := time.Since(startTime)
	_ = elapsed

	sshConn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		result.AuthOK = false
		result.Error = "SSH 认证失败: " + err.Error()
		return result
	}
	sshConn.Close()
	result.AuthOK = true

	return result
}

// executeCommand 安全执行系统命令
func executeCommand(name string, args []string, timeout time.Duration) (string, error) {
	// 安全校验：命令名只允许字母数字下划线横线
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return "", fmt.Errorf("命令名包含非法字符")
		}
	}

	var stdout, stderr strings.Builder
	cmd := createCommand(name, args)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case err := <-done:
		output := stdout.String()
		errOutput := stderr.String()
		if err != nil {
			if output != "" {
				return output, nil
			}
			return "", fmt.Errorf("%s", errOutput)
		}
		return output, nil
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return "", fmt.Errorf("命令执行超时")
	}
}
