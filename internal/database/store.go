package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// LLMConfig LLM 配置模型
type LLMConfig struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`
	BaseURL     string  `json:"base_url"`
	APIKey      string  `json:"api_key"`
	Model       string  `json:"model"`
	Temperature float64 `json:"temperature"`
	MaxTokens   int     `json:"max_tokens"`
	Stream      bool    `json:"stream"`
	IsDefault   bool    `json:"is_default"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

// LLMMessage LLM 对话消息
type LLMMessage struct {
	ID       int64  `json:"id"`
	ConfigID int64  `json:"config_id"`
	Role     string `json:"role"`
	Content  string `json:"content"`
}

// ListLLMConfigs 获取所有 LLM 配置
func ListLLMConfigs() ([]LLMConfig, error) {
	rows, err := DB.Query("SELECT id, name, base_url, api_key, model, temperature, max_tokens, stream, is_default, created_at, updated_at FROM llm_config ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []LLMConfig
	for rows.Next() {
		var c LLMConfig
		var stream, isDefault int
		if err := rows.Scan(&c.ID, &c.Name, &c.BaseURL, &c.APIKey, &c.Model, &c.Temperature, &c.MaxTokens, &stream, &isDefault, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.Stream = stream == 1
		c.IsDefault = isDefault == 1
		configs = append(configs, c)
	}
	return configs, nil
}

// GetLLMConfig 获取单个 LLM 配置
func GetLLMConfig(id int64) (*LLMConfig, error) {
	var c LLMConfig
	var stream, isDefault int
	err := DB.QueryRow("SELECT id, name, base_url, api_key, model, temperature, max_tokens, stream, is_default, created_at, updated_at FROM llm_config WHERE id = ?", id).
		Scan(&c.ID, &c.Name, &c.BaseURL, &c.APIKey, &c.Model, &c.Temperature, &c.MaxTokens, &stream, &isDefault, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.Stream = stream == 1
	c.IsDefault = isDefault == 1
	return &c, nil
}

// GetDefaultLLMConfig 获取默认 LLM 配置
func GetDefaultLLMConfig() (*LLMConfig, error) {
	var c LLMConfig
	var stream, isDefault int
	err := DB.QueryRow("SELECT id, name, base_url, api_key, model, temperature, max_tokens, stream, is_default, created_at, updated_at FROM llm_config WHERE is_default = 1 LIMIT 1").
		Scan(&c.ID, &c.Name, &c.BaseURL, &c.APIKey, &c.Model, &c.Temperature, &c.MaxTokens, &stream, &isDefault, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.Stream = stream == 1
	c.IsDefault = isDefault == 1
	return &c, nil
}

// CreateLLMConfig 创建 LLM 配置
func CreateLLMConfig(c *LLMConfig) error {
	stream := 0
	if c.Stream {
		stream = 1
	}
	isDefault := 0
	if c.IsDefault {
		isDefault = 1
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	result, err := DB.Exec(
		"INSERT INTO llm_config (name, base_url, api_key, model, temperature, max_tokens, stream, is_default, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		c.Name, c.BaseURL, c.APIKey, c.Model, c.Temperature, c.MaxTokens, stream, isDefault, now, now,
	)
	if err != nil {
		return err
	}
	c.ID, _ = result.LastInsertId()
	c.CreatedAt = now
	c.UpdatedAt = now
	return nil
}

// UpdateLLMConfig 更新 LLM 配置
func UpdateLLMConfig(c *LLMConfig) error {
	stream := 0
	if c.Stream {
		stream = 1
	}
	isDefault := 0
	if c.IsDefault {
		isDefault = 1
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err := DB.Exec(
		"UPDATE llm_config SET name=?, base_url=?, api_key=?, model=?, temperature=?, max_tokens=?, stream=?, is_default=?, updated_at=? WHERE id=?",
		c.Name, c.BaseURL, c.APIKey, c.Model, c.Temperature, c.MaxTokens, stream, isDefault, now, c.ID,
	)
	return err
}

// DeleteLLMConfig 删除 LLM 配置
func DeleteLLMConfig(id int64) error {
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	tx.Exec("DELETE FROM llm_message WHERE config_id = ?", id)
	_, err = tx.Exec("DELETE FROM llm_config WHERE id = ?", id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// SetDefaultLLMConfig 设置默认配置
func SetDefaultLLMConfig(id int64) error {
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	tx.Exec("UPDATE llm_config SET is_default = 0")
	tx.Exec("UPDATE llm_config SET is_default = 1 WHERE id = ?", id)
	return tx.Commit()
}

// --- LLM Messages ---

// ListLLMMessages 获取某个配置的消息列表
func ListLLMMessages(configID int64) ([]LLMMessage, error) {
	rows, err := DB.Query("SELECT id, config_id, role, content FROM llm_message WHERE config_id = ? ORDER BY id", configID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var msgs []LLMMessage
	for rows.Next() {
		var m LLMMessage
		if err := rows.Scan(&m.ID, &m.ConfigID, &m.Role, &m.Content); err != nil {
			return nil, err
		}
		msgs = append(msgs, m)
	}
	return msgs, nil
}

// SaveLLMMessages 替换保存某个配置的所有消息
func SaveLLMMessages(configID int64, messages []LLMMessage) error {
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	tx.Exec("DELETE FROM llm_message WHERE config_id = ?", configID)

	for _, m := range messages {
		tx.Exec("INSERT INTO llm_message (config_id, role, content) VALUES (?, ?, ?)", configID, m.Role, m.Content)
	}
	return tx.Commit()
}

// ClearLLMMessages 清空某个配置的消息
func ClearLLMMessages(configID int64) error {
	_, err := DB.Exec("DELETE FROM llm_message WHERE config_id = ?", configID)
	return err
}

// --- API Tester State ---

// GetAPITesterState 获取 API 测试器完整状态
func GetAPITesterState() (map[string]interface{}, error) {
	var data string
	err := DB.QueryRow("SELECT data FROM api_tester_state WHERE id = 1").Scan(&data)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return nil, fmt.Errorf("解析数据失败: %w", err)
	}
	return result, nil
}

// SaveAPITesterState 保存 API 测试器完整状态
func SaveAPITesterState(state map[string]interface{}) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("序列化数据失败: %w", err)
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err = DB.Exec("UPDATE api_tester_state SET data = ?, updated_at = ? WHERE id = 1", string(data), now)
	return err
}
