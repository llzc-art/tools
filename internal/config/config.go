package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Log      LogConfig      `yaml:"log"`
	LLM      LLMConfig      `yaml:"llm"`
}

type ServerConfig struct {
	Port         int `yaml:"port"`
	ReadTimeout  int `yaml:"read_timeout"`
	WriteTimeout int `yaml:"write_timeout"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type LogConfig struct {
	Level      string `yaml:"level"`       // 日志级别: debug, info, warn, error
	Filename   string `yaml:"filename"`    // 日志文件路径
	MaxSize    int    `yaml:"max_size"`    // 单个日志文件最大 MB
	MaxBackups int    `yaml:"max_backups"` // 保留旧文件最大个数
	MaxAge     int    `yaml:"max_age"`     // 保留旧文件最大天数
	Compress   bool   `yaml:"compress"`    // 是否压缩旧文件
	Format     string `yaml:"format"`      // 输出格式: json, text
}

// LLMConfig LLM 对话配置
type LLMConfig struct {
	ChatTimeout   int `yaml:"chat_timeout"`   // 非流式对话超时（秒）
	StreamTimeout int `yaml:"stream_timeout"` // 流式对话超时（秒）
}

var C Config

func Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, &C)
}

func Default() {
	C = Config{
		Server: ServerConfig{
			Port:         8080,
			ReadTimeout:  10,
			WriteTimeout: 10,
		},
		Database: DatabaseConfig{
			Path: "./data/tools.db",
		},
		Log: LogConfig{
			Level:      "info",
			Filename:   "./logs/tools.log",
			MaxSize:    100,
			MaxBackups: 10,
			MaxAge:     30,
			Compress:   true,
			Format:     "json",
		},
		LLM: LLMConfig{
			ChatTimeout:   120,
			StreamTimeout: 300,
		},
	}
}
