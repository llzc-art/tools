# 系统设计文档

## 1. 系统架构

### 1.1 整体架构

本项目采用前后端分离的 B/S 架构，整体分为三层：

```
┌─────────────────────────────────────────────┐
│                  客户端层                     │
│        Vue 3.0 + Vite (浏览器)              │
└──────────────────┬──────────────────────────┘
                   │ HTTP / HTTPS
┌──────────────────▼──────────────────────────┐
│                 服务层                        │
│         fasthttp (Golang 后端)               │
│  ┌───────────┐ ┌──────────┐ ┌────────────┐  │
│  │ 路由与中间件 │ │ 业务逻辑  │ │ 工具处理器  │  │
│  └───────────┘ └──────────┘ └────────────┘  │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│                 数据层                        │
│            SQLite (内嵌数据库)                │
└─────────────────────────────────────────────┘
```

### 1.2 技术栈

| 层级     | 技术选型      | 说明                                    |
|---------|-------------|----------------------------------------|
| 前端     | Vue 3.0 + Vite | 渐进式 JavaScript 框架，SFC 组件化     |
| 后端     | fasthttp    | 高性能 HTTP 框架，零内存分配优化          |
| 数据库   | SQLite      | 内嵌关系型数据库，无需独立部署             |
| 开发语言 | Golang      | 后端开发语言，编译型、高并发              |

## 2. 目录结构设计

```
tools/
├── main.go                 # 程序入口
├── go.mod                  # Go 模块定义
├── build.sh                # 编译打包脚本
├── docs/                   # 项目文档
├── internal/               # 内部包
│   ├── config/             # 配置管理
│   ├── database/            # 数据库初始化
│   ├── handler/            # HTTP 请求处理器
│   │   ├── ping.go         # 健康检查
│   │   ├── timestamp.go    # 时间戳工具
│   │   ├── timeformat.go   # 时间格式化工具
│   │   ├── base64.go       # Base64 编解码
│   │   ├── url.go          # URL 编解码
│   │   ├── hash.go         # Hash 哈希
│   │   ├── uuid.go         # UUID/随机数生成
│   │   ├── json.go         # JSON 格式化
│   │   ├── urlcode.go      # URL 解析/构建/Unicode
│   │   ├── ip.go           # IP 查询
│   │   ├── regex.go        # 正则表达式
│   │   ├── string.go       # 字符串工具
│   │   ├── jwt.go          # JWT 解码
│   │   ├── llm.go          # LLM 对话
│   │   ├── document.go     # 文档解析工具
│   │   ├── note.go          # 笔记工具
│   │   ├── linux_command.go  # Linux 命令查询工具
│   │   ├── network.go       # 网络工具
│   │   ├── api_proxy.go    # API 代理转发
│   │   ├── api_tester.go   # API 调试器状态持久化
│   │   ├── openapi_import.go # OpenAPI/Swagger 导入
│   │   └── static.go       # 静态文件服务
│   ├── middleware/          # 中间件
│   │   ├── cors.go         # 跨域中间件
│   │   ├── logger.go       # 日志中间件
│   │   └── recovery.go     # 异常恢复中间件
│   └── service/            # 业务逻辑层
├── pkg/                    # 可复用公共包
│   ├── logger/             # 日志包
│   └── response/           # 统一响应格式
├── config/                 # 配置文件
│   ├── config.yaml         # 应用配置
│   └── integration/        # 应用对接 API 定义
│       ├── cloud.yaml      # 云平台 API（腾讯云/阿里云/AWS/华为云）
│       ├── wechat.yaml     # 微信 API
│       ├── wecom.yaml      # 企业微信 API
│       └── feishu.yaml     # 飞书 API
└── web/                    # 前端项目
    ├── src/
    │   ├── App.vue         # 根组件
    │   ├── api.js          # API 请求工具
    │   └── components/     # 工具组件
    │       ├── APITesterTool.vue
    │       ├── LLMChatTool.vue
    │       ├── TimestampTool.vue
    │       ├── TimeFormatTool.vue
    │       ├── Base64EncodeTool.vue
    │       ├── URLTool.vue
    │       ├── HashTool.vue
    │       ├── UUIDTool.vue
    │       ├── JSONTool.vue
    │       ├── URLCodeTool.vue
    │       ├── IPTool.vue
    │       ├── RegexTool.vue
    │       ├── StringTool.vue
    │       ├── JWTTool.vue
    │       ├── DocxToMdTool.vue
    │       ├── ExcelToMdTool.vue
    │       ├── PdfToMdTool.vue
    │       ├── NoteTool.vue
    │       ├── LinuxCommandTool.vue
    │       ├── PingTool.vue
    │       ├── PortProbeTool.vue
    │       └── SSHProbeTool.vue
    ├── index.html
    ├── vite.config.js
    └── package.json
```

## 3. 核心模块设计

### 3.1 HTTP 服务模块

基于 fasthttp 构建 HTTP 服务，核心职责：

1. **路由注册**：将 URL 路径映射到对应的 handler 函数
2. **中间件链**：请求经过 CORS → Logger → Recovery → Handler 处理
3. **请求分发**：根据路由规则将请求分发到对应的处理器

```
请求 → fasthttp.Server → Router → Middleware Chain → Handler → Response
```

### 3.2 工具处理器模块

每个工具对应一个独立的 handler，遵循统一接口规范：

- 接收请求参数
- 调用对应的 service 层处理业务逻辑
- 返回统一格式的 JSON 响应

### 3.3 业务逻辑模块

Service 层负责具体的业务逻辑处理，与 HTTP 层解耦：

| 服务 | 说明 |
|------|------|
| TimestampService | 时间戳获取与转换 |
| TimeFormatService | 时间格式化与转换 |
| Base64Service | Base64 编码与解码 |
| URLService | URL 查询参数编解码 |
| HashService | MD5/SHA1/SHA256/SHA512 哈希计算 |
| UUIDService | UUID v4 批量生成 |
| RandomService | 随机字符串生成、雪花算法 ID 生成 |
| JSONService | JSON 格式化与压缩 |
| URLCodeService | URL 组件编解码、URL 解析/构建、Unicode 编解码 |
| IPService | IP 地址查询、CIDR 子网计算 |
| RegexService | 正则表达式匹配与替换 |
| StringService | 字符串统计、大小写转换、命名转换、Hex 转换 |
| JWTService | JWT Token 解码 |
| LLMService | LLM 对话（流式/非流式） |
| DocumentService | 文档解析（DOCX/Excel/PDF 转 Markdown） |
| APIProxyService | HTTP 请求代理转发 |
| APITesterService | 调试器状态持久化 |
| OpenAPIImportService | Swagger 2.0 / OpenAPI 3.0 解析导入 |
| LinuxCommandService | Linux 命令帮助信息获取（执行系统命令 --help） |
| NetworkService | 网络探测（Ping/端口/SSH 连通性检测） |
| IntegrationService | 应用对接（云平台签名调用、微信/企业微信/飞书代理） |

### 3.4 API 代理模块

`api_proxy.go` 负责将前端发起的 HTTP 请求通过后端代理转发，解决浏览器跨域限制：

- 支持 7 种 HTTP 方法
- 支持自定义请求头和请求体
- 支持 multipart/form-data 文件上传（base64 编码传输）
- 可配置超时时间（默认 30s，最大 300s）
- 禁止自动重定向

### 3.5 OpenAPI 导入模块

`openapi_import.go` 负责解析 Swagger 2.0 和 OpenAPI 3.0 JSON 格式的 API 文档：

- 按 tag 自动创建分组
- 自动解析 securityDefinitions/components.securitySchemes
- 从 JSON Schema 自动生成示例请求体

## 4. 统一响应格式

所有 API 接口返回统一的 JSON 格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {}
}
```

| 字段      | 类型     | 说明                          |
|----------|---------|------------------------------|
| code     | int     | 状态码，0 表示成功，非 0 表示失败  |
| message  | string  | 状态描述信息                    |
| data     | object  | 响应数据，失败时为 null          |

### 错误码定义

| 错误码 | 说明                |
|-------|--------------------|
| 0     | 成功                |
| 1001  | 参数错误             |
| 1002  | 数据格式错误          |
| 2001  | Base64 解码失败      |
| 2002  | 时间格式解析失败       |
| 2003  | URL 编解码失败        |
| 2004  | JSON 处理失败         |
| 2005  | Unicode 编解码失败    |
| 2006  | IP 地址处理失败       |
| 2007  | 正则表达式错误        |
| 2008  | 十六进制解码失败       |
| 2009  | LLM 对话请求失败      |
| 2010  | 文档转换失败          |
| 5000  | 服务器内部错误        |

## 5. 中间件设计

### 5.1 CORS 跨域中间件

- 允许前端跨域访问 API
- 可配置允许的 Origin、Methods、Headers

### 5.2 Logger 日志中间件

- 记录每个请求的方法、路径、响应状态码、耗时
- 使用结构化日志输出

### 5.3 Recovery 异常恢复中间件

- 捕获 handler 中的 panic 异常
- 返回 500 错误响应，防止服务崩溃

## 6. 配置管理

使用 YAML 格式配置文件，支持以下配置项：

```yaml
server:
  port: 8080           # 服务监听端口
  read_timeout: 10     # 读超时（秒）
  write_timeout: 10    # 写超时（秒）

database:
  path: "./data/tools.db"  # SQLite 数据库文件路径

log:
  level: "info"        # 日志级别
  format: "json"       # 日志格式

llm:
  stream_timeout: 300  # 流式对话超时（秒）
  chat_timeout: 120    # 非流式对话超时（秒）
```

### 应用对接 API 定义配置

`config/integration/` 目录存放各平台 API 定义，服务启动时自动加载，无需修改代码即可新增/修改接口：

```
config/integration/
├── cloud.yaml      # 云平台 API + 服务映射（腾讯云/阿里云/AWS/华为云）
├── wechat.yaml     # 微信开放平台
├── wecom.yaml      # 企业微信
└── feishu.yaml     # 飞书开放平台
```

**cloud.yaml 结构示例：**

```yaml
platforms:
  - id: tencent
    name: 腾讯云
    base_url: "https://cvm.tencentcloudapi.com"
    sign_method: tc3-hmac-sha256
    region: ap-guangzhou          # 默认区域
    regions:                      # 支持的区域列表（前端下拉选择）
      - value: ap-guangzhou
        label: 华南地区(广州)
      - value: ap-shanghai
        label: 华东地区(上海)
    auth_fields:
      - key: secret_id
        label: SecretId
        type: text
        required: true
    apis:
      - id: tc-cvm-list
        name: 查询实例列表
        method: POST
        path: "/"
        body_template: '{"Action":"DescribeInstances",...}'
    tencent_service_mappings:      # Action -> 服务/主机
      - action: DescribeInstances
        service: cvm
        host: cvm.tencentcloudapi.com
      - action: DescribeDisks
        service: cbs
        host: cbs.tencentcloudapi.com

  - id: aliyun
    name: 阿里云
    aliyun_host_mappings:           # Action -> 主机
      - action: DescribeInstances
        host: ecs.aliyuncs.com
      - action: DescribeDBInstances
        host: rds.aliyuncs.com

  - id: aws
    name: AWS
    aws_service_mappings:          # Category -> 服务/主机模板
      - category: S3
        service: s3
        host_template: "s3.%s.amazonaws.com"
      - category: RDS
        service: rds
        host_template: "rds.%s.amazonaws.com"
```

**wechat.yaml / wecom.yaml / feishu.yaml 结构示例：**

```yaml
base_url: "https://api.weixin.qq.com"
auth_fields:
  - key: app_id
    label: AppID
    type: text
    required: true
apis:
  - id: wx-token
    name: 获取Access Token
    method: GET
    path: /cgi-bin/token
    query_params: "grant_type=client_credential&appid={{app_id}}&secret={{app_secret}}"
```

## 7. 前端设计

### 7.1 技术方案

- **框架**：Vue 3.0 Composition API
- **构建**：Vite
- **组件**：SFC 单文件组件
- **状态**：provide/inject 轻量共享
- **API**：fetch 原生请求
- **Markdown**：marked + highlight.js

### 7.2 工具分类

| 分类 ID | 分类名称 | 包含工具 |
|---------|---------|---------|
| dev | 开发调试 | API 调试 |
| ai | 人工智能 | AI 对话 |
| codec | 字符编码 | Base64 编解码、URL 编解码、URL 解析构建、JWT 解码、字符处理 |
| crypto | 加密生成 | 哈希摘要、ID 生成器 |
| data | 数据处理 | JSON 美化、正则匹配 |
| time | 时间日期 | 时间戳转换、日期格式化 |
| network | 网络工具 | IP 查询、Ping 测试、端口探测、SSH 探测 |
| document | 文档解析 | DOCX 转 Markdown、Excel 转 Markdown、PDF 转 Markdown |
| notes | 笔记 | 我的笔记 |
| linux | Linux | 命令查询 |

### 7.3 全局功能

| 功能 | 说明 |
|------|------|
| 工具搜索 | 顶部搜索栏，按工具名称或 ID 实时过滤 |
| 侧边栏折叠 | 可收起/展开侧栏，移动端默认收起 |
| 记忆上次工具 | 切换工具后自动记住，下次打开恢复 |
| 全局 Toast 提示 | 统一的轻量提示消息 |
| 全局确认/提示弹窗 | 自定义对话框组件 |
| 剪贴板复制 | 所有工具结果均支持点击复制 |
| 响应式布局 | 适配桌面和移动端（768px 断点） |

### 7.4 部署集成

前端通过 `npm run build` 构建到 `web/dist/`，Go 通过 `//go:embed web/dist` 嵌入二进制，实现单文件部署。
