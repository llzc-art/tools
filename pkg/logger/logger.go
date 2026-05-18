package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Level 日志级别
type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
	FATAL
)

var levelNames = map[Level]string{
	DEBUG: "DEBUG",
	INFO:  "INFO",
	WARN:  "WARN",
	ERROR: "ERROR",
	FATAL: "FATAL",
}

// Config 日志配置
type Config struct {
	Level      string `yaml:"level"`       // 日志级别: debug, info, warn, error
	Filename   string `yaml:"filename"`    // 日志文件路径
	MaxSize    int    `yaml:"max_size"`    // 单个日志文件最大 MB
	MaxBackups int    `yaml:"max_backups"` // 保留旧文件最大个数
	MaxAge     int    `yaml:"max_age"`     // 保留旧文件最大天数
	Compress   bool   `yaml:"compress"`    // 是否压缩旧文件
	Format     string `yaml:"format"`      // 输出格式: json, text
}

// Logger 日志实例
type Logger struct {
	mu       sync.Mutex
	level    Level
	format   string
	writers  []io.Writer
	fileOnly bool // 是否只写文件
}

var defaultLogger *Logger

func init() {
	defaultLogger = &Logger{
		level:   INFO,
		format:  "text",
		writers: []io.Writer{os.Stdout},
	}
}

// Init 初始化日志模块
func Init(cfg Config) error {
	level, err := parseLevel(cfg.Level)
	if err != nil {
		level = INFO
	}

	writers := []io.Writer{os.Stdout}

	if cfg.Filename != "" {
		dir := filepath.Dir(cfg.Filename)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建日志目录失败: %w", err)
		}

		maxSize := cfg.MaxSize
		if maxSize <= 0 {
			maxSize = 100
		}
		maxBackups := cfg.MaxBackups
		if maxBackups <= 0 {
			maxBackups = 10
		}
		maxAge := cfg.MaxAge
		if maxAge <= 0 {
			maxAge = 30
		}

		fileWriter := &lumberjack.Logger{
			Filename:   cfg.Filename,
			MaxSize:    maxSize,
			MaxBackups: maxBackups,
			MaxAge:     maxAge,
			Compress:   cfg.Compress,
		}
		writers = append(writers, fileWriter)
	}

	format := cfg.Format
	if format == "" {
		format = "text"
	}

	defaultLogger = &Logger{
		level:   level,
		format:  format,
		writers: writers,
	}
	return nil
}

// NewFileOnlyLogger 创建只写文件的日志实例（用于中间件等不需要同时输出控制台的场景）
func NewFileOnlyLogger(cfg Config) (*Logger, error) {
	level, err := parseLevel(cfg.Level)
	if err != nil {
		level = INFO
	}

	writers := []io.Writer{}
	if cfg.Filename != "" {
		dir := filepath.Dir(cfg.Filename)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("创建日志目录失败: %w", err)
		}

		maxSize := cfg.MaxSize
		if maxSize <= 0 {
			maxSize = 100
		}
		maxBackups := cfg.MaxBackups
		if maxBackups <= 0 {
			maxBackups = 10
		}
		maxAge := cfg.MaxAge
		if maxAge <= 0 {
			maxAge = 30
		}

		fileWriter := &lumberjack.Logger{
			Filename:   cfg.Filename,
			MaxSize:    maxSize,
			MaxBackups: maxBackups,
			MaxAge:     maxAge,
			Compress:   cfg.Compress,
		}
		writers = append(writers, fileWriter)
	} else {
		writers = append(writers, os.Stdout)
	}

	format := cfg.Format
	if format == "" {
		format = "text"
	}

	return &Logger{
		level:     level,
		format:    format,
		writers:   writers,
		fileOnly:  true,
	}, nil
}

func parseLevel(s string) (Level, error) {
	switch s {
	case "debug", "DEBUG":
		return DEBUG, nil
	case "info", "INFO":
		return INFO, nil
	case "warn", "WARN":
		return WARN, nil
	case "error", "ERROR":
		return ERROR, nil
	case "fatal", "FATAL":
		return FATAL, nil
	default:
		return INFO, fmt.Errorf("未知日志级别: %s", s)
	}
}

// logEntry 日志条目
type logEntry struct {
	Level   string `json:"level"`
	Time    string `json:"time"`
	Message string `json:"message"`
	Caller  string `json:"caller,omitempty"`
	Fields  any    `json:"fields,omitempty"`
}

func (l *Logger) output(level Level, caller string, msg string, fields map[string]interface{}) {
	if level < l.level {
		return
	}

	now := time.Now().Format("2006-01-02 15:04:05.000")
	levelName := levelNames[level]

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, w := range l.writers {
		if l.format == "json" {
			entry := logEntry{
				Level:   levelName,
				Time:    now,
				Message: msg,
				Caller:  caller,
				Fields:  fields,
			}
			data, _ := json.Marshal(entry)
			fmt.Fprintln(w, string(data))
		} else {
			if fields != nil {
				fmt.Fprintf(w, "[%s] [%s] [%s] %s fields=%v\n", now, levelName, caller, msg, fields)
			} else {
				fmt.Fprintf(w, "[%s] [%s] [%s] %s\n", now, levelName, caller, msg)
			}
		}
	}

	if level == FATAL {
		os.Exit(1)
	}
}

// 便捷方法

func Debug(msg string)                          { defaultLogger.output(DEBUG, "", msg, nil) }
func Info(msg string)                           { defaultLogger.output(INFO, "", msg, nil) }
func Warn(msg string)                           { defaultLogger.output(WARN, "", msg, nil) }
func Error(msg string)                          { defaultLogger.output(ERROR, "", msg, nil) }
func Fatal(msg string)                          { defaultLogger.output(FATAL, "", msg, nil) }

func Debugf(format string, args ...interface{}) { defaultLogger.output(DEBUG, "", fmt.Sprintf(format, args...), nil) }
func Infof(format string, args ...interface{})  { defaultLogger.output(INFO, "", fmt.Sprintf(format, args...), nil) }
func Warnf(format string, args ...interface{})  { defaultLogger.output(WARN, "", fmt.Sprintf(format, args...), nil) }
func Errorf(format string, args ...interface{}){ defaultLogger.output(ERROR, "", fmt.Sprintf(format, args...), nil) }
func Fatalf(format string, args ...interface{}) { defaultLogger.output(FATAL, "", fmt.Sprintf(format, args...), nil) }

// 带调用者
func Debugc(caller, msg string)                  { defaultLogger.output(DEBUG, caller, msg, nil) }
func Infoc(caller, msg string)                   { defaultLogger.output(INFO, caller, msg, nil) }
func Warnc(caller, msg string)                   { defaultLogger.output(WARN, caller, msg, nil) }
func Errorc(caller, msg string)                  { defaultLogger.output(ERROR, caller, msg, nil) }

// 带字段
func WithFields(level Level, caller string, msg string, fields map[string]interface{}) {
	defaultLogger.output(level, caller, msg, fields)
}

// GetLevel 获取当前日志级别
func GetLevel() Level {
	return defaultLogger.level
}

// Sync 刷新日志缓冲
func Sync() {
	defaultLogger.mu.Lock()
	defer defaultLogger.mu.Unlock()
	for _, w := range defaultLogger.writers {
		if s, ok := w.(interface{ Sync() error }); ok {
			_ = s.Sync()
		}
		if w, ok := w.(interface{ Close() error }); ok {
			_ = w.Close()
		}
	}
}
