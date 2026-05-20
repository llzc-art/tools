# 数据库设计文档

## 1. 概述

本项目使用 SQLite 内嵌数据库，无需独立部署数据库服务。数据库文件默认存储在 `./data/tools.db`。

## 2. 技术选型

| 项目       | 说明                                        |
|-----------|--------------------------------------------|
| 数据库     | SQLite 3                                   |
| 驱动       | github.com/mattn/go-sqlite3                |
| 连接方式   | 内嵌，通过文件路径连接                        |
| 默认路径   | `./data/tools.db`                          |

## 3. 数据表设计

### 3.1 LLM 配置表 (llm_config)

存储 LLM 对话的配置信息，支持多套配置。

| 字段         | 类型      | 约束           | 说明                                      |
|-------------|----------|---------------|------------------------------------------|
| id          | INTEGER  | PRIMARY KEY AUTOINCREMENT | 配置 ID                      |
| name        | TEXT     | NOT NULL DEFAULT '' | 配置名称                             |
| base_url    | TEXT     | NOT NULL DEFAULT '' | API 基础地址                          |
| api_key     | TEXT     | NOT NULL DEFAULT '' | API Key（Bearer Token）               |
| model       | TEXT     | NOT NULL DEFAULT '' | 模型 ID                               |
| temperature | REAL     | NOT NULL DEFAULT 0.7 | 温度参数（0-2）                      |
| max_tokens  | INTEGER  | NOT NULL DEFAULT 4096 | 最大 token 数                         |
| stream      | INTEGER  | NOT NULL DEFAULT 1 | 是否流式输出（1=是，0=否）                 |
| is_default  | INTEGER  | NOT NULL DEFAULT 0 | 是否为默认配置（1=是，0=否）               |
| created_at  | DATETIME | NOT NULL DEFAULT (datetime('now','localtime')) | 创建时间 |
| updated_at  | DATETIME | NOT NULL DEFAULT (datetime('now','localtime')) | 更新时间 |

#### 建表语句

```sql
CREATE TABLE IF NOT EXISTS llm_config (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL DEFAULT '',
    base_url    TEXT    NOT NULL DEFAULT '',
    api_key     TEXT    NOT NULL DEFAULT '',
    model       TEXT    NOT NULL DEFAULT '',
    temperature REAL    NOT NULL DEFAULT 0.7,
    max_tokens  INTEGER NOT NULL DEFAULT 4096,
    stream      INTEGER NOT NULL DEFAULT 1,
    is_default  INTEGER NOT NULL DEFAULT 0,
    created_at  DATETIME NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at  DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
);
```

### 3.2 LLM 消息表 (llm_message)

存储 LLM 对话的消息记录，按配置 ID 关联。

| 字段        | 类型      | 约束           | 说明              |
|------------|----------|---------------|------------------|
| id         | INTEGER  | PRIMARY KEY AUTOINCREMENT | 消息 ID |
| config_id  | INTEGER  | NOT NULL DEFAULT 0 | 关联的配置 ID      |
| role       | TEXT     | NOT NULL       | 角色：system/user/assistant |
| content    | TEXT     | NOT NULL DEFAULT '' | 消息内容       |
| created_at | DATETIME | NOT NULL DEFAULT (datetime('now','localtime')) | 创建时间 |

#### 建表语句

```sql
CREATE TABLE IF NOT EXISTS llm_message (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    config_id  INTEGER NOT NULL DEFAULT 0,
    role       TEXT    NOT NULL,
    content    TEXT    NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
);
```

### 3.3 API 测试器状态表 (api_tester_state)

存储 API 调试工具的完整状态，采用单行存储设计（id 固定为 1）。

| 字段        | 类型      | 约束                              | 说明                |
|------------|----------|-----------------------------------|--------------------|
| id         | INTEGER  | PRIMARY KEY CHECK(id = 1)         | 固定为 1（单行存储）    |
| data       | TEXT     | NOT NULL DEFAULT '{}'             | 完整状态 JSON 数据     |
| updated_at | DATETIME | NOT NULL DEFAULT (datetime('now','localtime')) | 更新时间 |

#### 建表语句

```sql
CREATE TABLE IF NOT EXISTS api_tester_state (
    id         INTEGER PRIMARY KEY CHECK(id = 1),
    data       TEXT    NOT NULL DEFAULT '{}',
    updated_at DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
);

INSERT OR IGNORE INTO api_tester_state (id, data) VALUES (1, '{}');
```

#### data 字段结构

`data` 字段存储完整的 API 调试器状态 JSON，包含：

```json
{
  "method": "GET",
  "url": "https://api.example.com/users",
  "bodyType": "none",
  "body": "",
  "authType": "none",
  "authToken": "",
  "authUser": "",
  "authPass": "",
  "headers": [{"key": "Content-Type", "value": "application/json", "enabled": true}],
  "queryParams": [{"key": "", "value": "", "enabled": true}],
  "formData": [{"key": "", "value": "", "enabled": true, "type": "text", "filename": "", "fileContent": ""}],
  "localVars": [],
  "groups": [{
    "id": "1", "name": "用户模块", "expanded": true,
    "baseUrl": "", "headers": [],
    "apis": [{"id": "2", "name": "获取用户列表", "method": "GET", "path": "/users"}]
  }],
  "environments": [{
    "id": "3", "name": "开发环境", "baseUrl": "https://dev.api.example.com",
    "variables": [{"key": "token", "value": "xxx"}],
    "headers": []
  }],
  "activeEnvId": "3",
  "activeGroupId": "1",
  "activeApiId": "2",
  "useProxy": false,
  "idCounter": 1700000000000
}
```

### 3.4 笔记目录表 (note_folder)

存储笔记的目录结构，支持多级目录。

| 字段        | 类型      | 约束           | 说明              |
|------------|----------|---------------|------------------|
| id         | INTEGER  | PRIMARY KEY AUTOINCREMENT | 目录 ID |
| name       | TEXT     | NOT NULL       | 目录名称           |
| parent_id  | INTEGER  | NOT NULL DEFAULT 0 | 父目录 ID（0 表示顶级） |
| sort_order | INTEGER  | NOT NULL DEFAULT 0 | 排序序号           |
| created_at | DATETIME | NOT NULL DEFAULT (datetime('now','localtime')) | 创建时间 |
| updated_at | DATETIME | NOT NULL DEFAULT (datetime('now','localtime')) | 更新时间 |

#### 建表语句

```sql
CREATE TABLE IF NOT EXISTS note_folder (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    parent_id  INTEGER NOT NULL DEFAULT 0,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
);
```

### 3.5 笔记文档表 (note_document)

存储笔记文档内容，按目录 ID 关联。

| 字段        | 类型      | 约束           | 说明              |
|------------|----------|---------------|------------------|
| id         | INTEGER  | PRIMARY KEY AUTOINCREMENT | 文档 ID |
| folder_id  | INTEGER  | NOT NULL DEFAULT 0 | 所属目录 ID        |
| title      | TEXT     | NOT NULL DEFAULT '' | 文档标题          |
| content    | TEXT     | NOT NULL DEFAULT '' | 文档内容          |
| sort_order | INTEGER  | NOT NULL DEFAULT 0 | 排序序号           |
| created_at | DATETIME | NOT NULL DEFAULT (datetime('now','localtime')) | 创建时间 |
| updated_at | DATETIME | NOT NULL DEFAULT (datetime('now','localtime')) | 更新时间 |

#### 建表语句

```sql
CREATE TABLE IF NOT EXISTS note_document (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    folder_id  INTEGER NOT NULL DEFAULT 0,
    title      TEXT    NOT NULL DEFAULT '',
    content    TEXT    NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
);
```

### 3.6 Linux 命令表 (linux_command)

存储用户维护的 Linux 命令及其使用说明。

| 字段        | 类型      | 约束           | 说明              |
|------------|----------|---------------|------------------|
| id         | INTEGER  | PRIMARY KEY AUTOINCREMENT | 命令 ID |
| name       | TEXT     | NOT NULL UNIQUE | 命令名称（唯一）    |
| description | TEXT    | NOT NULL DEFAULT '' | 简短描述          |
| usage      | TEXT     | NOT NULL DEFAULT '' | 使用方法说明       |
| created_at | DATETIME | NOT NULL DEFAULT (datetime('now','localtime')) | 创建时间 |
| updated_at | DATETIME | NOT NULL DEFAULT (datetime('now','localtime')) | 更新时间 |

#### 建表语句

```sql
CREATE TABLE IF NOT EXISTS linux_command (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    NOT NULL DEFAULT '',
    usage       TEXT    NOT NULL DEFAULT '',
    created_at  DATETIME NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at  DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
);
```

## 4. 数据库迁移

项目启动时自动执行数据库迁移，确保表结构为最新版本。迁移逻辑在应用初始化阶段完成：

1. 检查数据库文件是否存在，不存在则创建
2. 依次执行建表语句（使用 `IF NOT EXISTS`）
3. 插入初始数据（使用 `INSERT OR IGNORE` 避免重复插入）

## 5. 数据备份

- SQLite 数据库为单文件，备份方式为直接复制数据库文件
- 建议在低峰期进行备份操作
- 备份命令：`cp ./data/tools.db ./data/tools.db.bak`
