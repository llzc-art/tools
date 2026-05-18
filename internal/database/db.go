package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

// Init 初始化数据库连接并建表
func Init(dbPath string) error {
	// 确保目录存在
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建数据库目录失败: %w", err)
	}

	var err error
	DB, err = sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return fmt.Errorf("打开数据库失败: %w", err)
	}

	// 连接池配置
	DB.SetMaxOpenConns(1) // SQLite 单写
	DB.SetMaxIdleConns(1)

	if err := createTables(); err != nil {
		return fmt.Errorf("建表失败: %w", err)
	}

	return nil
}

func createTables() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS llm_config (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL DEFAULT '',
			base_url TEXT NOT NULL DEFAULT '',
			api_key TEXT NOT NULL DEFAULT '',
			model TEXT NOT NULL DEFAULT '',
			temperature REAL NOT NULL DEFAULT 0.7,
			max_tokens INTEGER NOT NULL DEFAULT 4096,
			stream INTEGER NOT NULL DEFAULT 1,
			is_default INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL DEFAULT (datetime('now','localtime')),
			updated_at DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
		)`,
		`CREATE TABLE IF NOT EXISTS llm_message (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			config_id INTEGER NOT NULL DEFAULT 0,
			role TEXT NOT NULL,
			content TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
		)`,
		`CREATE TABLE IF NOT EXISTS api_tester_state (
			id INTEGER PRIMARY KEY CHECK(id = 1),
			data TEXT NOT NULL DEFAULT '{}',
			updated_at DATETIME NOT NULL DEFAULT (datetime('now','localtime'))
		)`,
		// 初始化 api_tester_state 单行记录
		`INSERT OR IGNORE INTO api_tester_state (id, data) VALUES (1, '{}')`,
	}

	for _, s := range stmts {
		if _, err := DB.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

// Close 关闭数据库
func Close() {
	if DB != nil {
		DB.Close()
	}
}
