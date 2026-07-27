package onnx

import "os/exec"

// runShell 执行 shell 命令（用于调用 curl 下载模型）
func runShell(cmd string) error {
	return exec.Command("sh", "-c", cmd).Run()
}