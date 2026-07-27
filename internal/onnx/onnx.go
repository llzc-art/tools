// Package onnx 提供 ONNX Runtime 的 Go 封装。
//
// 当前仅用于证件照后端的 BiRefNet-RMBG2 模型推理。
// 浏览器前端因 wasm memory 限制无法运行 ~350MB 的大模型，
// 故改用 Go + ONNX Runtime 1.20 (CGO) 在服务端做推理。
//
// 使用流程：
//  1. server 启动时调用 onnx.InitOnce() 初始化环境（全局只一次）
//  2. 调用 BiRefNetSession() 懒加载模型会话（首次调用时下载模型）
//  3. 调用 RunBiRefNet() 执行单张图推理
//  4. server 关闭时无需手动 DestroyEnvironment（进程退出时由 C runtime 清理）
package onnx

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	ort "github.com/yalue/onnxruntime_go"
)

// 相对路径，相对于项目根目录
// data/onnxruntime/lib/libonnxruntime.dylib 由 Makefile / 文档引导用户放置
var (
	defaultLibraryRelPath = filepath.Join("data", "onnxruntime", "lib")
	pythonONNXPath        = "/Library/Frameworks/Python.framework/Versions/3.10/lib/python3.10/site-packages/onnxruntime/capi/libonnxruntime.1.20.0.dylib"
)

var (
	initOnce      sync.Once
	initErr       error
	initializedMu sync.Mutex
	initialized   bool
)

// InitOnce 初始化 ONNX Runtime 全局环境（进程内仅一次）。
// 必须在调用任何 session/run 函数前调用。
//
// 库路径查找顺序：
//  1. ORT_SHARED_LIB_PATH 环境变量
//  2. ./data/onnxruntime/lib/libonnxruntime{,.so,.dylib}（项目内置）
//  3. macOS Python onnxruntime 包内 dylib（开发环境常见）
//  4. Linux 标准路径（/usr/local/lib, /usr/lib）
//  5. Windows 标准路径（C:\Program Files\...）
func InitOnce() error {
	initOnce.Do(func() {
		initializedMu.Lock()
		defer initializedMu.Unlock()

		libPath, err := findSharedLibrary()
		if err != nil {
			initErr = fmt.Errorf("找不到 onnxruntime 共享库: %w", err)
			return
		}

		ort.SetSharedLibraryPath(libPath)
		if err := ort.InitializeEnvironment(); err != nil {
			initErr = fmt.Errorf("InitializeEnvironment 失败: %w", err)
			return
		}
		initialized = true
	})
	return initErr
}

// IsInitialized 返回环境是否已初始化（便于调试）。
func IsInitialized() bool {
	initializedMu.Lock()
	defer initializedMu.Unlock()
	return initialized
}

func findSharedLibrary() (string, error) {
	// 1. 环境变量
	if p := os.Getenv("ORT_SHARED_LIB_PATH"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	// 2. 项目内置 data/onnxruntime/lib
	cwd, _ := os.Getwd()
	for i := 0; i < 4; i++ {
		candidate := filepath.Join(cwd, defaultLibraryRelPath)
		if found, _ := filepath.Glob(filepath.Join(candidate, "libonnxruntime*")); len(found) > 0 {
			return found[0], nil
		}
		cwd = filepath.Dir(cwd)
	}

	// 3. macOS Python onnxruntime（开发环境兜底）
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat(pythonONNXPath); err == nil {
			return pythonONNXPath, nil
		}
	}

	// 4. Linux 标准路径
	if runtime.GOOS == "linux" {
		for _, p := range []string{
			"/usr/local/lib/libonnxruntime.so",
			"/usr/local/lib/libonnxruntime.so.1",
			"/usr/lib/libonnxruntime.so",
			"/usr/lib/x86_64-linux-gnu/libonnxruntime.so",
		} {
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}

	return "", fmt.Errorf("未在项目 data/onnxruntime/lib/、%s 或系统路径中找到 libonnxruntime 库", pythonONNXPath)
}