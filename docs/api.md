# API 接口文档

## 1. 概述

- **Base URL**：`http://localhost:8080`
- **协议**：HTTP
- **数据格式**：JSON
- **字符编码**：UTF-8

## 2. 统一响应格式

### 成功响应

```json
{
  "code": 0,
  "message": "success",
  "data": {}
}
```

### 失败响应

```json
{
  "code": 1001,
  "message": "参数错误",
  "data": null
}
```

### 错误码列表

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
| 5000  | 服务器内部错误        |

---

## 3. 健康检查

### 3.1 Ping

**GET** `/api/ping`

检查服务是否正常运行。

#### 响应示例

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "status": "ok",
    "timestamp": 1716000000
  }
}
```

---

## 4. 时间戳工具

### 4.1 获取当前时间戳

**GET** `/api/timestamp/now`

获取当前 Unix 时间戳。

#### 请求参数

| 参数    | 类型   | 必填 | 说明                                        |
|--------|-------|------|--------------------------------------------|
| unit   | string | 否   | 时间戳单位，可选值：`s`（秒，默认）、`ms`（毫秒） |

#### 响应示例

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "timestamp": 1716000000,
    "unit": "s"
  }
}
```

### 4.2 时间戳转时间

**POST** `/api/timestamp/to-time`

将 Unix 时间戳转换为可读时间格式。

#### 请求参数

| 参数       | 类型   | 必填 | 说明                                              |
|-----------|-------|------|--------------------------------------------------|
| timestamp | int64  | 是   | Unix 时间戳                                        |
| unit      | string | 否   | 时间戳单位，可选值：`s`（秒，默认）、`ms`（毫秒）     |
| format    | string | 否   | 输出格式，默认 `2006-01-02 15:04:05`                |
| timezone  | string | 否   | 时区，默认 `Asia/Shanghai`                          |

### 4.3 时间转时间戳

**POST** `/api/timestamp/from-time`

将可读时间格式转换为 Unix 时间戳。

#### 请求参数

| 参数      | 类型   | 必填 | 说明                                            |
|----------|-------|------|------------------------------------------------|
| time     | string | 是   | 时间字符串                                        |
| format   | string | 否   | 输入格式，默认 `2006-01-02 15:04:05`               |
| timezone | string | 否   | 时区，默认 `Asia/Shanghai`                         |

---

## 5. 时间格式化工具

### 5.1 时间格式转换

**POST** `/api/timeformat/convert`

将时间从一种格式转换为另一种格式。

#### 请求参数

| 参数         | 类型   | 必填 | 说明                  |
|-------------|-------|------|----------------------|
| time        | string | 是   | 时间字符串             |
| from_format | string | 是   | 源时间格式             |
| to_format   | string | 是   | 目标时间格式           |
| from_tz     | string | 否   | 源时区，默认 `Asia/Shanghai` |
| to_tz       | string | 否   | 目标时区，默认 `Asia/Shanghai` |

---

## 6. Base64 工具

### 6.1 Base64 编码

**POST** `/api/base64/encode`

对字符串进行 Base64 编码。

#### 请求参数

| 参数    | 类型   | 必填 | 说明          |
|--------|-------|------|--------------|
| input  | string | 是   | 待编码的字符串  |

#### 响应示例

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "input": "Hello, World!",
    "output": "SGVsbG8sIFdvcmxkIQ=="
  }
}
```

### 6.2 Base64 解码

**POST** `/api/base64/decode`

对 Base64 编码的字符串进行解码。

#### 请求参数

| 参数    | 类型   | 必填 | 说明               |
|--------|-------|------|-------------------|
| input  | string | 是   | Base64 编码的字符串  |

---

## 7. URL 编解码工具

### 7.1 URL 编码

**POST** `/api/url/encode`

对字符串进行 URL 查询参数编码。

#### 请求参数

| 参数    | 类型   | 必填 | 说明          |
|--------|-------|------|--------------|
| input  | string | 是   | 待编码的字符串  |

### 7.2 URL 解码

**POST** `/api/url/decode`

对 URL 编码的字符串进行解码。

#### 请求参数

| 参数    | 类型   | 必填 | 说明               |
|--------|-------|------|-------------------|
| input  | string | 是   | URL 编码的字符串    |

---

## 8. Hash 哈希工具

### 8.1 哈希计算

**POST** `/api/hash/compute`

对字符串计算哈希值。

#### 请求参数

| 参数    | 类型   | 必填 | 说明                                    |
|--------|-------|------|----------------------------------------|
| input  | string | 是   | 待计算的字符串                           |
| algo   | string | 否   | 算法，可选值：`md5`（默认）、`sha1`、`sha256`、`sha512` |

---

## 9. UUID / 随机数生成工具

### 9.1 生成 UUID（兼容旧接口）

**POST** `/api/uuid/generate`

批量生成 UUID v4。

#### 请求参数

| 参数    | 类型 | 必填 | 说明                       |
|--------|------|------|---------------------------|
| count  | int  | 否   | 生成数量，默认 1，最大 100   |

#### 响应示例

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "uuids": [
      "550e8400-e29b-41d4-a716-446655440000",
      "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
    ],
    "count": 2
  }
}
```

### 9.2 通用 ID / 随机字符串生成

**POST** `/api/random/generate`

支持多种模式的 ID 和随机字符串生成。

#### 请求参数

| 参数         | 类型   | 必填 | 说明                                                        |
|-------------|-------|------|------------------------------------------------------------|
| mode        | string | 否   | 生成模式，可选值：`uuid`（默认）、`uuid_no_dash`、`snowflake`、`random`、`custom` |
| count       | int    | 否   | 生成数量，默认 1，最大 100                                     |
| length      | int    | 否   | 字符串长度（random/custom 模式），默认 32，最大 1024           |
| charset     | string | 否   | 预定义字符集名称（random 模式），如 `alphanumeric`、`hex`、`numeric` 等 |
| custom_chars | string | 否   | 自定义字符集（custom 模式）                                    |
| epoch       | int64  | 否   | 雪花算法起始时间（Unix 秒），默认 1704067200（2024-01-01）     |
| node_id     | int    | 否   | 雪花算法节点 ID（0-1023），默认 0                              |

#### 响应示例

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "items": [
      "550e8400-e29b-41d4-a716-446655440000"
    ],
    "count": 1,
    "mode": "uuid"
  }
}
```

---

## 10. JSON 工具

### 10.1 JSON 格式化

**POST** `/api/json/format`

将 JSON 字符串格式化（美化）。

#### 请求参数

| 参数     | 类型   | 必填 | 说明                     |
|---------|-------|------|-------------------------|
| input   | string | 是   | JSON 字符串               |
| indent  | int    | 否   | 缩进空格数，默认 2         |

### 10.2 JSON 压缩

**POST** `/api/json/compress`

将 JSON 字符串压缩为单行。

#### 请求参数

| 参数    | 类型   | 必填 | 说明          |
|--------|-------|------|--------------|
| input  | string | 是   | JSON 字符串    |

#### 响应示例

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "input": "{\n  \"key\": \"value\"\n}",
    "output": "{\"key\":\"value\"}",
    "before": 22,
    "after": 15,
    "saved": 7
  }
}
```

---

## 11. URL 编码/解码/解析/构建

### 11.1 URL 组件编码

**POST** `/api/urlcode/encode`

对 URL 路径组件进行编码（编码所有特殊字符）。

#### 请求参数

| 参数    | 类型   | 必填 | 说明          |
|--------|-------|------|--------------|
| input  | string | 是   | 待编码的字符串  |

### 11.2 URL 组件解码

**POST** `/api/urlcode/decode`

对 URL 编码的路径组件进行解码。

#### 请求参数

| 参数    | 类型   | 必填 | 说明               |
|--------|-------|------|-------------------|
| input  | string | 是   | URL 编码的字符串    |

### 11.3 URL 解析

**POST** `/api/urlcode/parse`

解析 URL 为各组成部分。

#### 请求参数

| 参数 | 类型   | 必填 | 说明     |
|-----|-------|------|---------|
| url | string | 是   | URL 字符串 |

#### 响应示例

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "url": "https://example.com:8080/path?q=1#section",
    "scheme": "https",
    "host": "example.com",
    "port": "8080",
    "path": "/path",
    "query": "q=1",
    "fragment": "section"
  }
}
```

### 11.4 URL 构建

**POST** `/api/urlcode/build`

从各组成部分构建 URL。

#### 请求参数

| 参数       | 类型   | 必填 | 说明       |
|-----------|-------|------|-----------|
| scheme    | string | 否   | 协议       |
| host      | string | 否   | 主机名     |
| port      | string | 否   | 端口       |
| path      | string | 否   | 路径       |
| query     | string | 否   | 查询参数   |
| fragment  | string | 否   | 锚点片段   |

---

## 12. Unicode 编解码

### 12.1 Unicode 编码

**POST** `/api/unicode/encode`

将字符串中的非 ASCII 字符转换为 Unicode 转义序列。

#### 请求参数

| 参数    | 类型   | 必填 | 说明          |
|--------|-------|------|--------------|
| input  | string | 是   | 待编码的字符串  |

### 12.2 Unicode 解码

**POST** `/api/unicode/decode`

将 Unicode 转义序列还原为字符串。

#### 请求参数

| 参数    | 类型   | 必填 | 说明              |
|--------|-------|------|------------------|
| input  | string | 是   | 含 Unicode 转义的字符串 |

---

## 13. IP 查询工具

### 13.1 IP 地址查询

**POST** `/api/ip/lookup`

查询 IP 地址信息（版本、类型）。

#### 请求参数

| 参数 | 类型   | 必填 | 说明       |
|-----|-------|------|-----------|
| ip  | string | 是   | IP 地址    |

#### 响应示例

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "ip": "192.168.1.1",
    "version": "IPv4",
    "is_ipv4": true,
    "is_ipv6": false
  }
}
```

### 13.2 CIDR 计算

**POST** `/api/ip/cidr`

计算 CIDR 子网信息。

#### 请求参数

| 参数  | 类型   | 必填 | 说明            |
|------|-------|------|----------------|
| cidr | string | 是   | CIDR 地址（如 192.168.1.0/24） |

---

## 14. 正则表达式工具

### 14.1 正则匹配测试

**POST** `/api/regex/match`

测试正则表达式是否匹配，返回所有匹配项。

#### 请求参数

| 参数     | 类型   | 必填 | 说明          |
|---------|-------|------|--------------|
| pattern | string | 是   | 正则表达式     |
| input   | string | 是   | 测试字符串     |

### 14.2 正则替换

**POST** `/api/regex/replace`

使用正则表达式替换匹配的字符串。

#### 请求参数

| 参数     | 类型   | 必填 | 说明          |
|---------|-------|------|--------------|
| pattern | string | 是   | 正则表达式     |
| input   | string | 是   | 源字符串       |
| replace | string | 是   | 替换字符串     |

---

## 15. 字符串工具

### 15.1 字符串统计

**POST** `/api/string/count`

统计字符串的字符数、字节数、行数、词数、中文数。

#### 请求参数

| 参数    | 类型   | 必填 | 说明          |
|--------|-------|------|--------------|
| input  | string | 否   | 待统计的字符串  |

### 15.2 字符串转大写

**POST** `/api/string/to-upper`

### 15.3 字符串转小写

**POST** `/api/string/to-lower`

### 15.4 转驼峰命名

**POST** `/api/string/to-camel`

### 15.5 转下划线命名

**POST** `/api/string/to-snake`

### 15.6 字符串转十六进制

**POST** `/api/string/to-hex`

### 15.7 十六进制转字符串

**POST** `/api/hex/to-string`

---

## 16. JWT 解码工具

### 16.1 JWT 解码

**POST** `/api/jwt/decode`

解码 JWT Token，展示 Header 和 Payload 内容。

#### 请求参数

| 参数   | 类型   | 必填 | 说明              |
|-------|-------|------|------------------|
| token | string | 是   | JWT Token 字符串   |

#### 响应示例

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "header": {
      "alg": "HS256",
      "typ": "JWT"
    },
    "payload": {
      "sub": "1234567890",
      "name": "John Doe",
      "iat": 1516239022
    },
    "valid": true
  }
}
```

---

## 17. LLM 对话工具

### 17.1 LLM 对话

**POST** `/api/llm/chat`

向 LLM 模型发起对话，支持 OpenAI 兼容 API 格式，支持流式和非流式响应。

#### 请求参数

| 参数         | 类型     | 必填 | 说明                                          |
|-------------|---------|------|----------------------------------------------|
| base_url    | string  | 是   | API 基础地址（如 `https://api.openai.com/v1`）  |
| api_key     | string  | 否   | API Key（Bearer Token）                        |
| model       | string  | 是   | 模型 ID（如 `gpt-3.5-turbo`、`deepseek-chat`）  |
| messages    | array   | 是   | 对话消息列表                                    |
| stream      | boolean | 否   | 是否流式响应，默认 `false`                       |
| max_tokens  | integer | 否   | 最大生成 token 数                                |
| temperature | number  | 否   | 温度参数（0-2），默认 `0.7`                       |

#### messages 消息格式

| 参数     | 类型   | 必填 | 说明                                    |
|---------|-------|------|----------------------------------------|
| role    | string | 是   | 角色：`system`、`user`、`assistant`       |
| content | string | 是   | 消息内容                                 |

#### 流式响应格式（SSE）

当 `stream: true` 时，响应格式为 `text/event-stream`，逐块推送：

```
data: {"id":"chatcmpl-xxx","model":"gpt-3.5-turbo","content":"你","finish":false}

data: {"id":"chatcmpl-xxx","model":"gpt-3.5-turbo","content":"好","finish":false}

data: {"id":"chatcmpl-xxx","model":"gpt-3.5-turbo","content":"","finish":true}

data: [DONE]
```

### 17.2 LLM 配置管理

#### 获取所有配置

**GET** `/api/llm/config/list`

#### 获取单个配置

**POST** `/api/llm/config/get`

| 参数 | 类型  | 必填 | 说明    |
|-----|------|------|--------|
| id  | int64 | 是   | 配置 ID |

#### 获取默认配置

**POST** `/api/llm/config/get-default`

#### 创建配置

**POST** `/api/llm/config/create`

| 参数         | 类型    | 必填 | 说明                  |
|-------------|--------|------|----------------------|
| name        | string | 否   | 配置名称               |
| base_url    | string | 否   | API 基础地址           |
| api_key     | string | 否   | API Key               |
| model       | string | 否   | 模型 ID               |
| temperature | float  | 否   | 温度，默认 0.7          |
| max_tokens  | int    | 否   | 最大 token 数，默认 4096 |
| stream      | bool   | 否   | 是否流式，默认 true      |
| is_default  | bool   | 否   | 是否为默认配置           |

#### 更新配置

**POST** `/api/llm/config/update`

| 参数 | 类型  | 必填 | 说明    |
|-----|------|------|--------|
| id  | int64 | 是   | 配置 ID |
| （其他字段同创建） | | | |

#### 删除配置

**POST** `/api/llm/config/delete`

| 参数 | 类型  | 必填 | 说明    |
|-----|------|------|--------|
| id  | int64 | 是   | 配置 ID |

#### 设置默认配置

**POST** `/api/llm/config/set-default`

| 参数 | 类型  | 必填 | 说明    |
|-----|------|------|--------|
| id  | int64 | 是   | 配置 ID |

### 17.3 LLM 消息管理

#### 获取消息列表

**POST** `/api/llm/messages/get`

| 参数      | 类型  | 必填 | 说明    |
|----------|------|------|--------|
| config_id | int64 | 是   | 配置 ID |

#### 保存消息列表

**POST** `/api/llm/messages/save`

| 参数      | 类型   | 必填 | 说明        |
|----------|--------|------|------------|
| config_id | int64  | 是   | 配置 ID     |
| messages | array  | 是   | 消息列表     |

#### 清空消息

**POST** `/api/llm/messages/clear`

| 参数      | 类型  | 必填 | 说明    |
|----------|------|------|--------|
| config_id | int64 | 是   | 配置 ID |

---

## 18. API 代理工具

### 18.1 代理转发请求

**POST** `/api/proxy/send`

通过后端代理发送 HTTP 请求，绕过浏览器跨域限制。

#### 请求参数

| 参数            | 类型     | 必填 | 说明                                              |
|----------------|---------|------|--------------------------------------------------|
| method         | string  | 是   | HTTP 方法（GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS） |
| url            | string  | 是   | 请求 URL                                          |
| headers        | object  | 否   | 请求头键值对                                       |
| body           | string  | 否   | 请求体内容                                         |
| body_type      | string  | 否   | 请求体类型：none/json/form/multipart/raw           |
| form_data      | array   | 否   | 表单字段列表（form/multipart 时使用）               |
| multipart_files | array  | 否   | 文件上传列表（multipart 时使用）                    |
| timeout        | int     | 否   | 超时时间（秒），默认 30，最大 300                    |

#### form_data 字段格式

| 参数     | 类型    | 必填 | 说明                    |
|---------|--------|------|------------------------|
| key     | string | 是   | 字段名                  |
| value   | string | 是   | 字段值                  |
| enabled | bool   | 否   | 是否启用                 |
| type    | string | 否   | 类型：text（默认）/file  |

#### multipart_files 字段格式

| 参数          | 类型   | 必填 | 说明                    |
|--------------|--------|------|------------------------|
| fieldname    | string | 是   | 表单字段名              |
| filename     | string | 是   | 文件名                  |
| content      | string | 是   | Base64 编码的文件内容    |
| content_type | string | 否   | MIME 类型               |

#### 响应示例

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "status_code": 200,
    "headers": {
      "Content-Type": "application/json"
    },
    "body": "{\"message\":\"ok\"}",
    "size": 16,
    "duration": 45
  }
}
```

### 18.2 OpenAPI 导入

**POST** `/api/proxy/openapi-import`

导入 Swagger 2.0 / OpenAPI 3.0 格式的 API 文档。

#### 请求参数

| 参数     | 类型   | 必填 | 说明                              |
|---------|-------|------|----------------------------------|
| url     | string | 否   | OpenAPI 文档 URL（与 content 二选一） |
| content | string | 否   | OpenAPI JSON 内容（与 url 二选一）    |

#### 响应示例

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "title": "Petstore API",
    "version": "1.0.0",
    "groups": [
      {
        "name": "pets",
        "base_url": "",
        "headers": [],
        "apis": [
          {
            "name": "listPets",
            "method": "GET",
            "path": "/pets",
            "summary": "List all pets"
          }
        ]
      }
    ]
  }
}
```

---

## 19. API 测试器状态

### 19.1 获取调试器状态

**POST** `/api/api-tester/state/get`

获取 API 调试工具的完整持久化状态。

### 19.2 保存调试器状态

**POST** `/api/api-tester/state/save`

保存 API 调试工具的完整状态（500ms 防抖自动保存）。

#### 请求参数

整个请求体为 JSON 对象，包含以下字段：

| 参数          | 类型   | 说明               |
|--------------|--------|-------------------|
| method       | string | 当前 HTTP 方法      |
| url          | string | 当前请求 URL       |
| bodyType     | string | 请求体类型          |
| body         | string | 请求体内容          |
| authType     | string | 认证类型            |
| authToken    | string | Bearer Token       |
| headers      | array  | 请求头列表          |
| queryParams  | array  | 查询参数列表        |
| formData     | array  | 表单数据列表        |
| localVars    | array  | 局部变量列表        |
| groups       | array  | API 分组数据        |
| environments | array  | 环境配置列表        |
| useProxy     | bool   | 是否使用代理模式     |
