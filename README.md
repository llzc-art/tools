# 攻城师天梯

基于 Web 的在线工具集合平台，提供日常开发与工作中常用的各类小工具，涵盖开发调试、AI 对话、时间处理、编解码、加密生成、数据处理、网络工具、文档解析、笔记、Linux 命令、应用对接等 **11 大分类 27 个工具**。单文件部署，开箱即用。

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

## 工具列表

### 🔌 开发调试
- **API 调试** — 类 Postman 的 HTTP 接口调试，支持环境管理、分组接口管理、cURL/OpenAPI 导入、代理模式、变量替换、响应自动美化

### 💬 人工智能
- **AI 对话** — 支持 OpenAI 兼容 API，流式/非流式对话，Markdown 渲染 + 代码高亮，多配置管理，对话历史持久化

### 🔤 字符编码
- **Base64 编解码** — 4 种编码模式（Standard/Base64URL/无填充），左右双面板
- **URL 编解码** — URL 查询参数编码/解码
- **URL 解析构建** — URL 组件编解码、URL 解析（6 个组成部分）、Unicode 编解码
- **JWT 解码** — JWT Token 解码，时间字段智能解析
- **字符处理** — 字符统计、大小写转换、驼峰/下划线命名、Hex 转换

### 🔐 加密生成
- **哈希摘要** — MD5/SHA-1/SHA-256/SHA-512 哈希计算
- **ID 生成器** — UUID v4、雪花算法、随机字符串，批量生成

### 📋 数据处理
- **JSON 美化** — JSON 格式化/压缩，统计压缩率
- **格式转换** — JSON/YAML/XML 自动识别与相互转换
- **正则匹配** — 正则表达式匹配测试、替换

### ⏱ 时间日期
- **时间戳转换** — 当前时间戳获取、时间戳 ↔ 时间互转，支持自定义格式和时区
- **日期格式化** — 时间格式转换、时区转换，内置 Go 格式参考表

### 🌍 网络工具
- **IP 查询** — IP 地址版本查询、CIDR 子网计算
- **Ping 测试** — 批量测试网络连通性，显示延迟信息
- **端口探测** — 批量探测端口连通性，显示开放状态和响应延迟
- **SSH 探测** — 探测 SSH 连通性，支持密码/密钥认证

### 📄 文档解析
- **DOCX 转 Markdown** — .docx 文件转换为 Markdown
- **Excel 转 Markdown** — .xlsx 文件转换为 Markdown 表格，支持多工作表
- **PDF 转 Markdown** — .pdf 文件转换为 Markdown，支持文本提取和表格识别

### 📝 笔记
- **我的笔记** — 目录管理、笔记文档创建/编辑/删除，内容持久化存储

### 🐧 Linux
- **命令查询** — Linux 命令快速搜索查询、自定义维护、系统 --help 自动获取

### ☁️ 应用对接
- **云平台API** — 腾讯云/阿里云/AWS/华为云 API 调试，预定义常用接口，凭证管理
- **微信API** — 微信公众号/小程序 API 调试，预定义 12 个常用接口，一键获取 Token
- **企业微信API** — 企业微信 API 调试，预定义 12 个常用接口，一键获取 Token
- **飞书API** — 飞书开放 API 调试，预定义 13 个常用接口，支持路径参数替换

## 项目结构

```
tools/
├── main.go                 # 程序入口，路由注册，嵌入前端资源
├── config/                 # 配置文件
│   ├── config.yaml          # 服务配置（端口/数据库/日志）
│   └── integration/         # 应用对接 API 定义
│       ├── cloud.yaml       # 云平台 API + 服务映射配置（腾讯云/阿里云/AWS/华为云）
│       ├── wechat.yaml      # 微信 API
│       ├── wecom.yaml       # 企业微信 API
│       └── feishu.yaml      # 飞书 API
├── internal/               # 内部包
│   ├── config/             # 配置管理
│   ├── database/           # 数据库初始化
│   ├── handler/            # HTTP 请求处理器
│   ├── middleware/         # 中间件（CORS/日志/恢复）
│   └── service/            # 业务逻辑层
├── pkg/                    # 可复用公共包
│   ├── logger/             # 日志包
│   └── response/           # 统一响应格式
└── web/                    # 前端资源（嵌入二进制）
    └── src/
        ├── App.vue         # 根组件
        ├── api.js          # HTTP 工具函数
        └── components/     # 工具组件
```
