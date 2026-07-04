package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// LLMConfig LLM 配置模型
type LLMConfig struct {
	ID               int64   `json:"id"`
	Name             string  `json:"name"`
	BaseURL          string  `json:"base_url"`
	APIKey           string  `json:"api_key"`
	Model            string  `json:"model"`
	Temperature      float64 `json:"temperature"`
	TopP             float64 `json:"top_p"`
	MaxTokens        int     `json:"max_tokens"`
	Stream           bool    `json:"stream"`
	PresencePenalty  float64 `json:"presence_penalty"`
	FrequencyPenalty float64 `json:"frequency_penalty"`
	ResponseFormat   string  `json:"response_format"`
	Stop             string  `json:"stop"` // JSON 数组字符串
	IsDefault        bool    `json:"is_default"`
	CreatedAt        string  `json:"created_at"`
	UpdatedAt        string  `json:"updated_at"`
}

// LLMMessage LLM 对话消息
type LLMMessage struct {
	ID       int64  `json:"id"`
	ConfigID int64  `json:"config_id"`
	Role     string `json:"role"`
	Content  string `json:"content"`
	Meta     string `json:"meta,omitempty"` // JSON: {finishReason, model, usage}
}

const llmConfigColumns = "id, name, base_url, api_key, model, temperature, top_p, max_tokens, stream, presence_penalty, frequency_penalty, response_format, stop, is_default, created_at, updated_at"

func scanLLMConfig(row interface{ Scan(...interface{}) error }) (*LLMConfig, error) {
	var c LLMConfig
	var stream, isDefault int
	err := row.Scan(&c.ID, &c.Name, &c.BaseURL, &c.APIKey, &c.Model, &c.Temperature, &c.TopP, &c.MaxTokens, &stream, &c.PresencePenalty, &c.FrequencyPenalty, &c.ResponseFormat, &c.Stop, &isDefault, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	c.Stream = stream == 1
	c.IsDefault = isDefault == 1
	return &c, nil
}

// ListLLMConfigs 获取所有 LLM 配置
func ListLLMConfigs() ([]LLMConfig, error) {
	rows, err := DB.Query("SELECT " + llmConfigColumns + " FROM llm_config ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []LLMConfig
	for rows.Next() {
		c, err := scanLLMConfig(rows)
		if err != nil {
			return nil, err
		}
		configs = append(configs, *c)
	}
	return configs, nil
}

// GetLLMConfig 获取单个 LLM 配置
func GetLLMConfig(id int64) (*LLMConfig, error) {
	c, err := scanLLMConfig(DB.QueryRow("SELECT "+llmConfigColumns+" FROM llm_config WHERE id = ?", id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// GetDefaultLLMConfig 获取默认 LLM 配置
func GetDefaultLLMConfig() (*LLMConfig, error) {
	c, err := scanLLMConfig(DB.QueryRow("SELECT "+llmConfigColumns+" FROM llm_config WHERE is_default = 1 LIMIT 1"))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c, nil
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
		"INSERT INTO llm_config (name, base_url, api_key, model, temperature, top_p, max_tokens, stream, presence_penalty, frequency_penalty, response_format, stop, is_default, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		c.Name, c.BaseURL, c.APIKey, c.Model, c.Temperature, c.TopP, c.MaxTokens, stream, c.PresencePenalty, c.FrequencyPenalty, c.ResponseFormat, c.Stop, isDefault, now, now,
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
		"UPDATE llm_config SET name=?, base_url=?, api_key=?, model=?, temperature=?, top_p=?, max_tokens=?, stream=?, presence_penalty=?, frequency_penalty=?, response_format=?, stop=?, is_default=?, updated_at=? WHERE id=?",
		c.Name, c.BaseURL, c.APIKey, c.Model, c.Temperature, c.TopP, c.MaxTokens, stream, c.PresencePenalty, c.FrequencyPenalty, c.ResponseFormat, c.Stop, isDefault, now, c.ID,
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
	rows, err := DB.Query("SELECT id, config_id, role, content, meta FROM llm_message WHERE config_id = ? ORDER BY id", configID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var msgs []LLMMessage
	for rows.Next() {
		var m LLMMessage
		if err := rows.Scan(&m.ID, &m.ConfigID, &m.Role, &m.Content, &m.Meta); err != nil {
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
		meta := m.Meta
		if meta == "" {
			// 将 meta 对象序列化为 JSON
			if m.Meta != "" {
				meta = m.Meta
			}
		}
		tx.Exec("INSERT INTO llm_message (config_id, role, content, meta) VALUES (?, ?, ?, ?)", configID, m.Role, m.Content, meta)
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

// --- Note Folder ---

// NoteFolder 笔记目录
type NoteFolder struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	ParentID  int64  `json:"parent_id"`
	SortOrder int    `json:"sort_order"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// ListNoteFolders 获取所有笔记目录
func ListNoteFolders() ([]NoteFolder, error) {
	rows, err := DB.Query("SELECT id, name, parent_id, sort_order, created_at, updated_at FROM note_folder ORDER BY sort_order, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var folders []NoteFolder
	for rows.Next() {
		var f NoteFolder
		if err := rows.Scan(&f.ID, &f.Name, &f.ParentID, &f.SortOrder, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		folders = append(folders, f)
	}
	return folders, nil
}

// CreateNoteFolder 创建笔记目录
func CreateNoteFolder(f *NoteFolder) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	result, err := DB.Exec("INSERT INTO note_folder (name, parent_id, sort_order, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
		f.Name, f.ParentID, f.SortOrder, now, now)
	if err != nil {
		return err
	}
	f.ID, _ = result.LastInsertId()
	f.CreatedAt = now
	f.UpdatedAt = now
	return nil
}

// UpdateNoteFolder 更新笔记目录
func UpdateNoteFolder(f *NoteFolder) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err := DB.Exec("UPDATE note_folder SET name=?, parent_id=?, sort_order=?, updated_at=? WHERE id=?",
		f.Name, f.ParentID, f.SortOrder, now, f.ID)
	return err
}

// DeleteNoteFolder 删除笔记目录（同时删除其下所有文档）
func DeleteNoteFolder(id int64) error {
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	tx.Exec("DELETE FROM note_document WHERE folder_id = ?", id)
	_, err = tx.Exec("DELETE FROM note_folder WHERE id = ?", id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// --- Note Document ---

// NoteDocument 笔记文档
type NoteDocument struct {
	ID        int64  `json:"id"`
	FolderID  int64  `json:"folder_id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	SortOrder int    `json:"sort_order"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// ListNoteDocuments 获取某个目录下的所有文档
func ListNoteDocuments(folderID int64) ([]NoteDocument, error) {
	rows, err := DB.Query("SELECT id, folder_id, title, content, sort_order, created_at, updated_at FROM note_document WHERE folder_id = ? ORDER BY sort_order, id", folderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var docs []NoteDocument
	for rows.Next() {
		var d NoteDocument
		if err := rows.Scan(&d.ID, &d.FolderID, &d.Title, &d.Content, &d.SortOrder, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, err
		}
		docs = append(docs, d)
	}
	return docs, nil
}

// GetNoteDocument 获取单个文档
func GetNoteDocument(id int64) (*NoteDocument, error) {
	var d NoteDocument
	err := DB.QueryRow("SELECT id, folder_id, title, content, sort_order, created_at, updated_at FROM note_document WHERE id = ?", id).
		Scan(&d.ID, &d.FolderID, &d.Title, &d.Content, &d.SortOrder, &d.CreatedAt, &d.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// CreateNoteDocument 创建笔记文档
func CreateNoteDocument(d *NoteDocument) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	result, err := DB.Exec("INSERT INTO note_document (folder_id, title, content, sort_order, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		d.FolderID, d.Title, d.Content, d.SortOrder, now, now)
	if err != nil {
		return err
	}
	d.ID, _ = result.LastInsertId()
	d.CreatedAt = now
	d.UpdatedAt = now
	return nil
}

// UpdateNoteDocument 更新笔记文档
func UpdateNoteDocument(d *NoteDocument) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err := DB.Exec("UPDATE note_document SET folder_id=?, title=?, content=?, sort_order=?, updated_at=? WHERE id=?",
		d.FolderID, d.Title, d.Content, d.SortOrder, now, d.ID)
	return err
}

// DeleteNoteDocument 删除笔记文档
func DeleteNoteDocument(id int64) error {
	_, err := DB.Exec("DELETE FROM note_document WHERE id = ?", id)
	return err
}

// --- Linux Command ---

// LinuxCommand Linux 命令
type LinuxCommand struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Usage       string `json:"usage"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// ListLinuxCommands 获取所有 Linux 命令
func ListLinuxCommands() ([]LinuxCommand, error) {
	rows, err := DB.Query("SELECT id, name, description, usage, created_at, updated_at FROM linux_command ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cmds []LinuxCommand
	for rows.Next() {
		var c LinuxCommand
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.Usage, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		cmds = append(cmds, c)
	}
	return cmds, nil
}

// SearchLinuxCommands 搜索 Linux 命令（按名称或描述模糊匹配）
func SearchLinuxCommands(keyword string) ([]LinuxCommand, error) {
	pattern := "%" + keyword + "%"
	rows, err := DB.Query("SELECT id, name, description, usage, created_at, updated_at FROM linux_command WHERE name LIKE ? OR description LIKE ? ORDER BY name", pattern, pattern)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cmds []LinuxCommand
	for rows.Next() {
		var c LinuxCommand
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.Usage, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		cmds = append(cmds, c)
	}
	return cmds, nil
}

// GetLinuxCommand 获取单个命令
func GetLinuxCommand(id int64) (*LinuxCommand, error) {
	var c LinuxCommand
	err := DB.QueryRow("SELECT id, name, description, usage, created_at, updated_at FROM linux_command WHERE id = ?", id).
		Scan(&c.ID, &c.Name, &c.Description, &c.Usage, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// GetLinuxCommandByName 按名称获取命令
func GetLinuxCommandByName(name string) (*LinuxCommand, error) {
	var c LinuxCommand
	err := DB.QueryRow("SELECT id, name, description, usage, created_at, updated_at FROM linux_command WHERE name = ?", name).
		Scan(&c.ID, &c.Name, &c.Description, &c.Usage, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// CreateLinuxCommand 创建 Linux 命令
func CreateLinuxCommand(c *LinuxCommand) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	result, err := DB.Exec("INSERT INTO linux_command (name, description, usage, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
		c.Name, c.Description, c.Usage, now, now)
	if err != nil {
		return err
	}
	c.ID, _ = result.LastInsertId()
	c.CreatedAt = now
	c.UpdatedAt = now
	return nil
}

// UpdateLinuxCommand 更新 Linux 命令
func UpdateLinuxCommand(c *LinuxCommand) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err := DB.Exec("UPDATE linux_command SET name=?, description=?, usage=?, updated_at=? WHERE id=?",
		c.Name, c.Description, c.Usage, now, c.ID)
	return err
}

// DeleteLinuxCommand 删除 Linux 命令
func DeleteLinuxCommand(id int64) error {
	_, err := DB.Exec("DELETE FROM linux_command WHERE id = ?", id)
	return err
}

// --- Article ---

// Article 文章
type Article struct {
	ID        int64  `json:"id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	Status    string `json:"status"` // draft, published
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// ListArticles 获取所有文章
func ListArticles() ([]Article, error) {
	rows, err := DB.Query("SELECT id, title, content, status, created_at, updated_at FROM article ORDER BY updated_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var articles []Article
	for rows.Next() {
		var a Article
		if err := rows.Scan(&a.ID, &a.Title, &a.Content, &a.Status, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		articles = append(articles, a)
	}
	return articles, nil
}

// GetArticle 获取单篇文章
func GetArticle(id int64) (*Article, error) {
	var a Article
	err := DB.QueryRow("SELECT id, title, content, status, created_at, updated_at FROM article WHERE id = ?", id).
		Scan(&a.ID, &a.Title, &a.Content, &a.Status, &a.CreatedAt, &a.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// CreateArticle 创建文章
func CreateArticle(a *Article) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	result, err := DB.Exec("INSERT INTO article (title, content, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
		a.Title, a.Content, a.Status, now, now)
	if err != nil {
		return err
	}
	a.ID, _ = result.LastInsertId()
	a.CreatedAt = now
	a.UpdatedAt = now
	return nil
}

// UpdateArticle 更新文章
func UpdateArticle(a *Article) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err := DB.Exec("UPDATE article SET title=?, content=?, status=?, updated_at=? WHERE id=?",
		a.Title, a.Content, a.Status, now, a.ID)
	return err
}

// DeleteArticle 删除文章（同时删除发布日志）
func DeleteArticle(id int64) error {
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	tx.Exec("DELETE FROM article_publish_log WHERE article_id = ?", id)
	_, err = tx.Exec("DELETE FROM article WHERE id = ?", id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// --- Article Channel ---

// ArticleChannel 发布渠道配置
type ArticleChannel struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	ChannelType string `json:"channel_type"` // wechat, csdn, tencent_cloud, juejin, custom
	Config      string `json:"config"`       // JSON 格式的配置（API密钥等）
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// ListArticleChannels 获取所有渠道
func ListArticleChannels() ([]ArticleChannel, error) {
	rows, err := DB.Query("SELECT id, name, channel_type, config, enabled, created_at, updated_at FROM article_channel ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var channels []ArticleChannel
	for rows.Next() {
		var c ArticleChannel
		var enabled int
		if err := rows.Scan(&c.ID, &c.Name, &c.ChannelType, &c.Config, &enabled, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.Enabled = enabled == 1
		channels = append(channels, c)
	}
	return channels, nil
}

// GetArticleChannel 获取单个渠道
func GetArticleChannel(id int64) (*ArticleChannel, error) {
	var c ArticleChannel
	var enabled int
	err := DB.QueryRow("SELECT id, name, channel_type, config, enabled, created_at, updated_at FROM article_channel WHERE id = ?", id).
		Scan(&c.ID, &c.Name, &c.ChannelType, &c.Config, &enabled, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.Enabled = enabled == 1
	return &c, nil
}

// CreateArticleChannel 创建渠道
func CreateArticleChannel(c *ArticleChannel) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	enabled := 0
	if c.Enabled {
		enabled = 1
	}
	result, err := DB.Exec("INSERT INTO article_channel (name, channel_type, config, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		c.Name, c.ChannelType, c.Config, enabled, now, now)
	if err != nil {
		return err
	}
	c.ID, _ = result.LastInsertId()
	c.CreatedAt = now
	c.UpdatedAt = now
	return nil
}

// UpdateArticleChannel 更新渠道
func UpdateArticleChannel(c *ArticleChannel) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	enabled := 0
	if c.Enabled {
		enabled = 1
	}
	_, err := DB.Exec("UPDATE article_channel SET name=?, channel_type=?, config=?, enabled=?, updated_at=? WHERE id=?",
		c.Name, c.ChannelType, c.Config, enabled, now, c.ID)
	return err
}

// DeleteArticleChannel 删除渠道
func DeleteArticleChannel(id int64) error {
	_, err := DB.Exec("DELETE FROM article_channel WHERE id = ?", id)
	return err
}

// --- Article Publish Log ---

// ArticlePublishLog 发布日志
type ArticlePublishLog struct {
	ID          int64  `json:"id"`
	ArticleID   int64  `json:"article_id"`
	ChannelID   int64  `json:"channel_id"`
	ChannelName string `json:"channel_name"`
	Status      string `json:"status"` // success, failed
	Message     string `json:"message"`
	PublishedAt string `json:"published_at"`
}

// ListArticlePublishLogs 获取文章的发布日志
func ListArticlePublishLogs(articleID int64) ([]ArticlePublishLog, error) {
	rows, err := DB.Query(`
		SELECT l.id, l.article_id, l.channel_id, c.name, l.status, l.message, l.published_at
		FROM article_publish_log l
		LEFT JOIN article_channel c ON l.channel_id = c.id
		WHERE l.article_id = ?
		ORDER BY l.published_at DESC
	`, articleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []ArticlePublishLog
	for rows.Next() {
		var l ArticlePublishLog
		var channelName sql.NullString
		if err := rows.Scan(&l.ID, &l.ArticleID, &l.ChannelID, &channelName, &l.Status, &l.Message, &l.PublishedAt); err != nil {
			return nil, err
		}
		if channelName.Valid {
			l.ChannelName = channelName.String
		}
		logs = append(logs, l)
	}
	return logs, nil
}

// CreateArticlePublishLog 创建发布日志
func CreateArticlePublishLog(log *ArticlePublishLog) error {
	result, err := DB.Exec("INSERT INTO article_publish_log (article_id, channel_id, status, message, published_at) VALUES (?, ?, ?, ?, datetime('now','localtime'))",
		log.ArticleID, log.ChannelID, log.Status, log.Message)
	if err != nil {
		return err
	}
	log.ID, _ = result.LastInsertId()
	return nil
}
