# 部署文档

## 1. 部署概述

本项目采用单机部署方式。前端资源通过 Go `embed` 嵌入二进制文件，数据库为内嵌 SQLite，**无需额外部署 Nginx 或外部数据库**，一个二进制文件即可运行。

## 2. 环境要求

### 2.1 开发环境

| 软件       | 版本要求      | 说明               |
|-----------|-------------|-------------------|
| Go        | 1.24+       | 后端开发与编译       |
| Node.js   | 18+         | 前端构建            |
| Git       | 2.x         | 版本管理            |

### 2.2 生产环境

| 软件    | 版本要求 | 说明                          |
|--------|---------|------------------------------|
| Linux  | -       | 推荐 CentOS 7+ / Ubuntu 20+  |
| 内存   | ≥ 512MB | 最低要求                      |
| 磁盘   | ≥ 1GB   | 包含数据库存储空间              |

## 3. 编译构建

### 3.1 一键构建（推荐）

使用项目根目录的 `build.sh` 脚本：

```bash
# 编译当前平台并打包
./build.sh -v 1.0.0

# 全平台编译打包（Linux/macOS/Windows，amd64/arm64）
./build.sh -a -v 1.0.0

# 跳过前端构建（dist 已存在）
./build.sh -s -v 1.0.0
```

### 3.2 手动编译

```bash
# 进入项目目录
cd /path/to/tools

# 安装依赖
go mod tidy

# 编译
go build -o tools-server main.go

# 指定版本号编译
go build -ldflags="-s -w -X main.Version=1.0.0 -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o tools-server main.go
```

编译参数说明：

| 参数                     | 说明                          |
|------------------------|------------------------------|
| -s                     | 去除符号表，减小二进制体积        |
| -w                     | 去除 DWARF 调试信息            |
| -X main.Version=xxx    | 注入版本号                     |
| -X main.BuildTime=xxx  | 注入构建时间                   |

### 3.3 前端构建（已嵌入二进制，通常无需单独构建）

```bash
cd /path/to/tools/web
npm install
npm run build
```

构建产物输出到 `web/dist/` 目录，Go 编译时通过 `//go:embed web/dist` 自动嵌入。

### 3.4 交叉编译

```bash
# Linux amd64
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o tools-server-linux-amd64 main.go

# Linux arm64
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o tools-server-linux-arm64 main.go

# macOS amd64
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o tools-server-darwin-amd64 main.go

# macOS arm64 (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o tools-server-darwin-arm64 main.go

# Windows amd64
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o tools-server-windows-amd64.exe main.go
```

## 4. 部署步骤

### 4.1 单文件部署（推荐）

前端资源已嵌入二进制，只需部署一个可执行文件 + 配置文件即可：

```bash
# 创建部署目录
mkdir -p /opt/tools/{data,logs,config}

# 复制可执行文件
cp tools-server /opt/tools/
chmod +x /opt/tools/tools-server

# 复制配置文件
cp config/config.yaml /opt/tools/config/

# 启动服务
cd /opt/tools
./tools-server -c ./config/config.yaml
```

### 4.2 配置文件

编辑 `/opt/tools/config/config.yaml`：

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
  filename: "./logs/app.log"  # 日志文件路径

llm:
  chat_timeout: 120    # 非流式对话超时（秒）
  stream_timeout: 300  # 流式对话超时（秒）
```

### 4.3 后台启动

```bash
nohup /opt/tools/tools-server -c /opt/tools/config/config.yaml > /opt/tools/logs/startup.log 2>&1 &
```

## 5. Systemd 服务配置

创建服务文件 `/etc/systemd/system/tools.service`：

```ini
[Unit]
Description=Tools Server
After=network.target

[Service]
Type=simple
User=tools
Group=tools
WorkingDirectory=/opt/tools
ExecStart=/opt/tools/tools-server -c /opt/tools/config/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

管理命令：

```bash
# 重载服务配置
sudo systemctl daemon-reload

# 启动服务
sudo systemctl start tools

# 停止服务
sudo systemctl stop tools

# 重启服务
sudo systemctl restart tools

# 查看服务状态
sudo systemctl status tools

# 设置开机自启
sudo systemctl enable tools

# 取消开机自启
sudo systemctl disable tools

# 查看服务日志
sudo journalctl -u tools -f
```

## 6. Nginx 反向代理（可选）

如果需要通过域名访问或添加 HTTPS，可在前面加一层 Nginx：

### 6.1 HTTP 配置

```nginx
server {
    listen       80;
    server_name  tools.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE 流式响应支持
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 300s;
    }
}
```

### 6.2 HTTPS 配置

```nginx
server {
    listen       443 ssl http2;
    server_name  tools.example.com;

    ssl_certificate      /etc/nginx/ssl/tools.crt;
    ssl_certificate_key  /etc/nginx/ssl/tools.key;
    ssl_protocols        TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 300s;
    }
}

# HTTP 重定向到 HTTPS
server {
    listen 80;
    server_name tools.example.com;
    return 301 https://$host$request_uri;
}
```

> **注意**：Nginx 代理 LLM 流式对话时需关闭 `proxy_buffering` 和 `proxy_cache`，并增大 `proxy_read_timeout`。

## 7. Docker 部署

### 7.1 Dockerfile

```dockerfile
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o tools-server main.go

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata
WORKDIR /opt/tools

COPY --from=builder /app/tools-server ./
COPY --from=builder /app/config/config.yaml ./config/

RUN mkdir -p data logs

EXPOSE 8080

ENTRYPOINT ["./tools-server"]
CMD ["-c", "./config/config.yaml"]
```

### 7.2 构建与运行

```bash
# 构建镜像
docker build -t tools-server:1.0.0 .

# 运行容器
docker run -d \
  --name tools \
  -p 8080:8080 \
  -v /opt/tools/data:/opt/tools/data \
  -v /opt/tools/logs:/opt/tools/logs \
  tools-server:1.0.0
```

## 8. 运维操作

### 8.1 健康检查

```bash
curl http://localhost:8080/api/ping
```

### 8.2 查看版本

```bash
./tools-server -v
```

### 8.3 日志查看

```bash
# 实时查看日志
tail -f /opt/tools/logs/app.log

# 查看最近 100 行日志
tail -n 100 /opt/tools/logs/app.log
```

### 8.4 数据备份

```bash
# 备份数据库
cp /opt/tools/data/tools.db /opt/tools/data/tools.db.$(date +%Y%m%d%H%M%S).bak
```

### 8.5 版本更新

```bash
# 停止服务
sudo systemctl stop tools

# 备份旧版本
cp /opt/tools/tools-server /opt/tools/tools-server.bak

# 替换新版本
cp tools-server /opt/tools/tools-server

# 启动服务
sudo systemctl start tools

# 验证
curl http://localhost:8080/api/ping
```
