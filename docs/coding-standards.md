# 开发规范文档

## 1. 代码规范

### 1.1 Go 代码规范

遵循 [Effective Go](https://go.dev/doc/effective_go) 和 [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments) 规范。

#### 命名规范

| 类型     | 规范                     | 示例                          |
|---------|-------------------------|------------------------------|
| 包名     | 小写，简短，无下划线        | `handler`, `service`          |
| 文件名   | 小写，下划线分隔            | `time_format.go`              |
| 结构体   | 大驼峰                    | `ToolInfo`, `TimeStampReq`    |
| 接口     | 大驼峰，通常以 -er 结尾     | `Reader`, `Formatter`         |
| 函数/方法 | 大驼峰（导出）/ 小驼峰（私有）| `GetTimestamp`, `parseTime`   |
| 常量     | 大驼峰                    | `DefaultPort`, `MaxRetry`     |
| 变量     | 小驼峰                    | `toolName`, `requestID`       |

#### 错误处理

```go
// 正确：处理错误
result, err := service.GetTimestamp()
if err != nil {
    return response.Error(err)
}

// 错误：忽略错误
result, _ := service.GetTimestamp()
```

#### 注释规范

```go
// ToolService 提供工具相关的业务逻辑处理。
type ToolService struct {
    // db 数据库访问对象
    db *sql.DB
}

// GetTimestamp 获取当前 Unix 时间戳。
// unit 参数指定时间戳单位，支持 "s"（秒）和 "ms"（毫秒）。
func (s *ToolService) GetTimestamp(unit string) (int64, error) {
    // ...
}
```

### 1.2 项目结构规范

```
internal/
├── handler/        # HTTP 请求处理器，负责参数解析与响应返回
├── middleware/     # 中间件，处理通用逻辑（CORS、日志、恢复等）
├── model/          # 数据模型，定义结构体
├── service/        # 业务逻辑层，核心处理逻辑
└── repository/     # 数据访问层，数据库操作

pkg/
├── response/       # 统一响应格式
└── validator/      # 参数校验工具
```

### 1.3 分层职责

| 层级         | 职责                                   | 依赖方向         |
|-------------|---------------------------------------|-----------------|
| handler     | 参数解析、调用 service、构造响应          | → service       |
| middleware  | 请求拦截、通用处理                       | → handler       |
| service     | 业务逻辑处理                           | → repository    |
| repository  | 数据库 CRUD 操作                        | → model         |
| model       | 数据结构定义，无逻辑                     | 无依赖           |

## 2. Git 规范

### 2.1 分支管理

| 分支          | 说明                          |
|--------------|------------------------------|
| main         | 主分支，稳定版本               |
| develop      | 开发分支，日常开发合并          |
| feature/*    | 功能分支，新功能开发            |
| fix/*        | 修复分支，Bug 修复             |
| release/*    | 发布分支，版本发布准备          |

### 2.2 Commit 规范

使用 [Conventional Commits](https://www.conventionalcommits.org/) 格式：

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Type 类型**：

| 类型       | 说明                  |
|-----------|----------------------|
| feat      | 新功能                |
| fix       | Bug 修复              |
| docs      | 文档更新              |
| style     | 代码格式（不影响逻辑）   |
| refactor  | 重构（非新功能、非修复）  |
| perf      | 性能优化              |
| test      | 测试相关              |
| chore     | 构建/工具变动          |

**示例**：

```
feat(timestamp): 新增时间戳转换接口

- 支持秒级和毫秒级时间戳转换
- 支持自定义时间格式
```

### 2.3 版本号规范

遵循 [语义化版本](https://semver.org/lang/zh-CN/)：

```
MAJOR.MINOR.PATCH
```

- **MAJOR**：不兼容的 API 变更
- **MINOR**：向后兼容的功能新增
- **PATCH**：向后兼容的 Bug 修复

## 3. API 设计规范

### 3.1 URL 设计

- 使用名词复数形式：`/api/timestamps`
- 使用小写字母和连字符：`/api/base64/encode`
- 嵌套层级不超过 3 层

### 3.2 HTTP 方法

| 方法     | 用途        | 示例                    |
|---------|------------|------------------------|
| GET     | 查询资源    | `GET /api/timestamp/now` |
| POST    | 创建/操作   | `POST /api/base64/encode` |

### 3.3 请求参数

- GET 请求：使用 Query 参数
- POST 请求：使用 JSON Body
- 参数名使用小驼峰命名：`fromFormat`

### 3.4 响应格式

统一使用以下 JSON 格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {}
}
```

## 4. 测试规范

### 4.1 测试文件

- 测试文件与源文件同目录，以 `_test.go` 结尾
- 文件命名：`<filename>_test.go`

### 4.2 测试命名

```go
func TestFunctionName_Scenario_ExpectedResult(t *testing.T) {
    // 测试逻辑
}

// 示例
func TestGetTimestamp_SecondUnit_ReturnsUnixTimestamp(t *testing.T) {
    // ...
}
```

### 4.3 测试覆盖

- 核心业务逻辑测试覆盖率 ≥ 80%
- 使用 table-driven 测试模式：

```go
func TestBase64Encode(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
    }{
        {"simple string", "hello", "aGVsbG8="},
        {"empty string", "", ""},
        {"chinese", "你好", "5L2g5aW9"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := Base64Encode(tt.input)
            if result != tt.expected {
                t.Errorf("expected %s, got %s", tt.expected, result)
            }
        })
    }
}
```

### 4.4 运行测试

```bash
# 运行所有测试
go test ./...

# 运行指定包测试
go test ./internal/service/...

# 查看覆盖率
go test -cover ./...

# 生成覆盖率报告
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## 5. 日志规范

### 5.1 日志级别

| 级别    | 使用场景                              |
|--------|--------------------------------------|
| DEBUG  | 调试信息，开发环境使用                   |
| INFO   | 常规运行信息（启动、关闭、请求日志等）    |
| WARN   | 警告信息（可恢复的异常情况）             |
| ERROR  | 错误信息（影响功能但不影响服务运行）      |
| FATAL  | 致命错误（导致服务停止）                 |

### 5.2 日志格式

使用结构化 JSON 日志：

```json
{
  "level": "info",
  "time": "2024-05-18T10:40:00+08:00",
  "method": "GET",
  "path": "/api/ping",
  "status": 200,
  "duration": "1.23ms",
  "ip": "127.0.0.1"
}
```

## 6. 安全规范

1. 所有用户输入必须校验，防止注入攻击
2. 敏感配置（数据库密码等）不硬编码，使用配置文件或环境变量
3. 错误信息不暴露系统内部细节（如堆栈信息、文件路径）
4. API 接口支持限流，防止滥用
5. 使用 HTTPS 传输敏感数据
