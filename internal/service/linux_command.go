package service

import (
	"bytes"
	"os/exec"
	"strings"
	"time"
)

// LinuxCommandService Linux 命令查询服务
type LinuxCommandService struct{}

// NewLinuxCommandService 创建 Linux 命令查询服务
func NewLinuxCommandService() *LinuxCommandService {
	return &LinuxCommandService{}
}

// CommandHelpResult 命令帮助结果
type CommandHelpResult struct {
	Command   string `json:"command"`
	HelpText  string `json:"help_text"`
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
}

// GetCommandHelp 执行命令 --help 获取帮助信息
func (s *LinuxCommandService) GetCommandHelp(command string) *CommandHelpResult {
	result := &CommandHelpResult{
		Command: command,
	}

	// 安全检查：只允许字母、数字、下划线、横线
	for _, c := range command {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			result.Error = "命令名包含非法字符"
			return result
		}
	}

	// 检查命令是否存在
	path, err := exec.LookPath(command)
	if err != nil {
		result.Available = false
		result.Error = "系统中未找到该命令"
		return result
	}
	result.Available = true
	_ = path

	// 尝试执行 --help
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(command, "--help")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = 5 * time.Second

	if err := cmd.Run(); err != nil {
		// 有些命令 --help 返回非0退出码但仍有输出
		output := strings.TrimSpace(stdout.String())
		errOutput := strings.TrimSpace(stderr.String())
		if output != "" {
			result.HelpText = output
		} else if errOutput != "" {
			result.HelpText = errOutput
		} else {
			// 尝试 -h
			var stdout2, stderr2 bytes.Buffer
			cmd2 := exec.Command(command, "-h")
			cmd2.Stdout = &stdout2
			cmd2.Stderr = &stderr2
			cmd2.WaitDelay = 5 * time.Second
			_ = cmd2.Run()
			output2 := strings.TrimSpace(stdout2.String())
			errOutput2 := strings.TrimSpace(stderr2.String())
			if output2 != "" {
				result.HelpText = output2
			} else if errOutput2 != "" {
				result.HelpText = errOutput2
			} else {
				result.HelpText = "无法获取该命令的帮助信息"
			}
		}
	} else {
		output := strings.TrimSpace(stdout.String())
		errOutput := strings.TrimSpace(stderr.String())
		if output != "" {
			result.HelpText = output
		} else {
			result.HelpText = errOutput
		}
	}

	// 限制输出长度
	if len(result.HelpText) > 10000 {
		result.HelpText = result.HelpText[:10000] + "\n... (输出已截断)"
	}

	return result
}
