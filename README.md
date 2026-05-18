# 攻城师天梯

基于 Web 的在线工具集合平台，提供日常开发与工作中常用的各类小工具，涵盖开发调试、AI 对话、时间处理、编解码、加密生成、数据处理、网络工具等 **7 大分类 14 个工具**。单文件部署，开箱即用。

## 项目技术选型

| 层级 | 技术 | 说明 |
|------|------|------|
| 后端 | Golang + [fasthttp](https://github.com/valyala/fasthttp) | 高性能 HTTP 框架，零内存分配 |
| 前端 | Vue 3.0 + Vite | Composition API，SFC 组件化 |
| 数据库 | SQLite（内嵌） | 无需独立部署数据库服务 |
| 部署 | Go `embed` 嵌入前端 | **单二进制文件部署**，无需 Nginx |

## 快速开始

### 环境要求

- Go 1.24+
- Node.js 18+（仅前端构建时需要）

### 安装依赖

```bash
go mod tidy
```

### 启动服务

```bash
go run main.go
```

### 构建二进制

```bash
# 编译当前平台并打包
./build.sh -v 1.0.0

# 全平台编译打包
./build.sh -a -v 1.0.0

# 跳过前端构建（dist 已存在）
./build.sh -s -v 1.0.0
```

部署只需将安装包解压即可运行，无需安装任何其他依赖。

```bash
./tools-server                    # 使用默认配置
./tools-server -c config.yaml     # 指定配置文件
```

## 项目架构

```
tools/
├── main.go                     # 程序入口，启动 fasthttp 服务，嵌入前端资源
├── go.mod                      # Go 模块依赖管理
├── build.sh                    # 编译打包脚本
├── config/                     # 配置文件
│   └── config.yaml             # 应用配置
├── docs/                       # 项目文档
├── internal/                   # 内部包
│   ├── config/                 # 配置管理
│   ├── database/                # 数据库初始化
│   ├── handler/                # HTTP 请求处理器
│   │   ├── ping.go             # 健康检查
│   │   ├── timestamp.go        # 时间戳工具
│   │   ├── timeformat.go       # 时间格式化工具
│   │   ├── base64.go           # Base64 编解码工具
│   │   ├── url.go              # URL 编解码工具
│   │   ├── hash.go             # Hash 哈希工具
│   │   ├── uuid.go             # UUID/随机数生成工具
│   │   ├── json.go             # JSON 格式化工具
│   │   ├── urlcode.go          # URL 解析/构建/Unicode 工具
│   │   ├── ip.go               # IP 查询工具
│   │   ├── regex.go            # 正则表达式工具
│   │   ├── string.go           # 字符串工具
│   │   ├── jwt.go              # JWT 解码工具
│   │   ├── llm.go              # LLM 对话工具
│   │   ├── api_proxy.go        # API 代理转发
│   │   ├── api_tester.go       # API 调试器状态持久化
│   │   ├── openapi_import.go   # OpenAPI/Swagger 导入
│   │   └── static.go           # 静态文件服务（嵌入前端）
│   ├── middleware/              # 中间件
│   │   ├── cors.go             # 跨域中间件
│   │   ├── logger.go           # 日志中间件
│   │   └── recovery.go         # 异常恢复中间件
│   └── service/                # 业务逻辑层
├── pkg/                        # 可复用公共包
│   ├── logger/                 # 日志包（级别、轮转、压缩、JSON/Text）
│   └── response/               # 统一响应格式
└── web/                        # 前端资源（嵌入二进制）
    ├── src/
    │   ├── App.vue             # 根组件
    │   ├── api.js              # HTTP 工具函数
    │   └── components/         # 工具组件
    ├── index.html
    ├── vite.config.js
    └── package.json
```

## 工具列表

### 🔌 开发调试

| 工具名称 | 说明 |
|---------|------|
| API 调试 | 类 Postman 的 HTTP 接口调试工具，支持多种请求方法、环境管理、分组接口管理、cURL 导入、OpenAPI 导入、代理模式、变量替换、响应自动美化（JSON/XML/HTML 语法高亮、图片预览、音视频播放） |

### 💬 人工智能

| 工具名称 | 说明 |
|---------|------|
| AI 对话 | 支持 OpenAI 兼容 API，流式/非流式对话，Markdown 渲染 + 代码高亮，多配置管理，对话历史持久化 |

### 🔤 字符编码

| 工具名称 | 说明 |
|---------|------|
| Base64 编解码 | 4 种编码模式（Standard/Base64URL/无填充），左右双面板 |
| URL 编解码 | URL 查询参数编码/解码 |
| URL 解析构建 | URL 组件编解码、URL 解析（6 个组成部分）、Unicode 编解码 |
| JWT 解码 | JWT Token 解码，时间字段智能解析（iat/exp/nbf 转可读时间+相对时间） |
| 字符处理 | 字符统计（字节/字符/行/词/中文）、大小写转换、驼峰/下划线命名、Hex 转换 |

### 🔐 加密生成

| 工具名称 | 说明 |
|---------|------|
| 哈希摘要 | MD5/SHA-1/SHA-256/SHA-512 哈希计算 |
| ID 生成器 | UUID v4（标准/无横线）、雪花算法（自定义 Epoch + 节点 ID）、随机字符串（11 种字符集）、自定义字符集，批量生成 |

### 📋 数据处理

| 工具名称 | 说明 |
|---------|------|
| JSON 美化 | JSON 格式化/压缩，统计压缩率 |
| 正则匹配 | 正则表达式匹配测试、替换 |

### ⏱ 时间日期

| 工具名称 | 说明 |
|---------|------|
| 时间戳转换 | 获取当前时间戳（秒/毫秒）、时间戳 ↔ 时间互转，支持自定义格式和时区 |
| 日期格式化 | 时间格式转换、时区转换，内置 Go 格式参考表 |

### 🌍 网络工具

| 工具名称 | 说明 |
|---------|------|
| IP 查询 | IP 地址版本查询（IPv4/IPv6）、CIDR 子网计算（网络地址/掩码/可用主机数） |

## API 接口

服务启动后，默认监听端口 `:8080`，提供 RESTful API 接口。

### 接口列表

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/ping | 健康检查 |
| **时间戳** | | |
| GET | /api/timestamp/now | 获取当前时间戳 |
| POST | /api/timestamp/to-time | 时间戳转时间 |
| POST | /api/timestamp/from-time | 时间转时间戳 |
| **时间格式化** | | |
| POST | /api/timeformat/convert | 时间格式转换 |
| **Base64** | | |
| POST | /api/base64/encode | Base64 编码 |
| POST | /api/base64/decode | Base64 解码 |
| **URL 编解码** | | |
| POST | /api/url/encode | URL 编码 |
| POST | /api/url/decode | URL 解码 |
| **URL 解析构建** | | |
| POST | /api/urlcode/encode | URL 组件编码 |
| POST | /api/urlcode/decode | URL 组件解码 |
| POST | /api/urlcode/parse | URL 解析 |
| POST | /api/urlcode/build | URL 构建 |
| **Unicode** | | |
| POST | /api/unicode/encode | Unicode 编码 |
| POST | /api/unicode/decode | Unicode 解码 |
| **哈希** | | |
| POST | /api/hash/compute | Hash 哈希计算 |
| **ID 生成** | | |
| POST | /api/uuid/generate | UUID 生成 |
| POST | /api/random/generate | 随机字符串/雪花算法 ID 生成 |
| **JSON** | | |
| POST | /api/json/format | JSON 格式化 |
| POST | /api/json/compress | JSON 压缩 |
| **IP** | | |
| POST | /api/ip/lookup | IP 地址查询 |
| POST | /api/ip/cidr | CIDR 计算 |
| **正则** | | |
| POST | /api/regex/match | 正则表达式匹配 |
| POST | /api/regex/replace | 正则表达式替换 |
| **字符串** | | |
| POST | /api/string/count | 字符串统计 |
| POST | /api/string/to-upper | 字符串转大写 |
| POST | /api/string/to-lower | 字符串转小写 |
| POST | /api/string/to-camel | 转驼峰命名 |
| POST | /api/string/to-snake | 转下划线命名 |
| POST | /api/string/to-hex | 字符串转十六进制 |
| POST | /api/hex/to-string | 十六进制转字符串 |
| **JWT** | | |
| POST | /api/jwt/decode | JWT 解码 |
| **LLM** | | |
| POST | /api/llm/chat | LLM 对话（支持流式 SSE） |
| GET | /api/llm/config/list | LLM 配置列表 |
| POST | /api/llm/config/save | 保存 LLM 配置 |
| POST | /api/llm/config/delete | 删除 LLM 配置 |
| POST | /api/llm/config/default | 设置默认配置 |
| POST | /api/llm/messages/clear | 清空对话历史 |
| POST | /api/llm/messages/save | 保存对话消息 |
| POST | /api/llm/messages/load | 加载对话消息 |
| **API 调试** | | |
| POST | /api/proxy/send | API 代理转发请求 |
| POST | /api/proxy/openapi-import | OpenAPI/Swagger 导入 |
| POST | /api/api-tester/state/get | 获取调试器状态 |
| POST | /api/api-tester/state/save | 保存调试器状态 |

详细接口文档请参考 [API 接口文档](docs/api.md)。
