package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"regexp"
	"strings"
	"time"

	"lelezc.com/tools/internal/database"
)

// httpClient 带超时的 HTTP 客户端，用于调用各平台 API
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

// ArticleService 文章服务
type ArticleService struct{}

// NewArticleService 创建文章服务
func NewArticleService() *ArticleService {
	return &ArticleService{}
}

// ArticleListResult 文章列表
type ArticleListResult struct {
	Articles []database.Article `json:"articles"`
}

// List 获取文章列表（不含正文内容，减少传输量）
func (s *ArticleService) List() (*ArticleListResult, error) {
	articles, err := database.ListArticles()
	if err != nil {
		return nil, fmt.Errorf("获取文章列表失败: %w", err)
	}
	if articles == nil {
		articles = []database.Article{}
	}
	return &ArticleListResult{Articles: articles}, nil
}

// Get 获取文章详情
func (s *ArticleService) Get(id int64) (*database.Article, error) {
	article, err := database.GetArticle(id)
	if err != nil {
		return nil, fmt.Errorf("获取文章失败: %w", err)
	}
	if article == nil {
		return nil, nil
	}
	return article, nil
}

// Create 创建文章
func (s *ArticleService) Create(title, content string) (*database.Article, error) {
	article := &database.Article{
		Title:   title,
		Content: content,
		Status:  "draft",
	}
	if err := database.CreateArticle(article); err != nil {
		return nil, fmt.Errorf("创建文章失败: %w", err)
	}
	return article, nil
}

// Update 更新文章
func (s *ArticleService) Update(id int64, title, content, status string) (*database.Article, error) {
	article, err := database.GetArticle(id)
	if err != nil {
		return nil, fmt.Errorf("获取文章失败: %w", err)
	}
	if article == nil {
		return nil, fmt.Errorf("文章不存在")
	}

	if title != "" {
		article.Title = title
	}
	if content != "" {
		article.Content = content
	}
	if status != "" {
		article.Status = status
	}

	if err := database.UpdateArticle(article); err != nil {
		return nil, fmt.Errorf("更新文章失败: %w", err)
	}
	return article, nil
}

// Delete 删除文章
func (s *ArticleService) Delete(id int64) error {
	return database.DeleteArticle(id)
}

// --- 渠道管理 ---

// ChannelListResult 渠道列表
type ChannelListResult struct {
	Channels []database.ArticleChannel `json:"channels"`
}

// ListChannels 获取所有渠道
func (s *ArticleService) ListChannels() (*ChannelListResult, error) {
	channels, err := database.ListArticleChannels()
	if err != nil {
		return nil, fmt.Errorf("获取渠道列表失败: %w", err)
	}
	if channels == nil {
		channels = []database.ArticleChannel{}
	}
	return &ChannelListResult{Channels: channels}, nil
}

// CreateChannel 创建渠道
func (s *ArticleService) CreateChannel(name, channelType, configJSON string, enabled bool) (*database.ArticleChannel, error) {
	channel := &database.ArticleChannel{
		Name:        name,
		ChannelType: channelType,
		Config:      configJSON,
		Enabled:     enabled,
	}
	if err := database.CreateArticleChannel(channel); err != nil {
		return nil, fmt.Errorf("创建渠道失败: %w", err)
	}
	return channel, nil
}

// UpdateChannel 更新渠道
func (s *ArticleService) UpdateChannel(id int64, name, channelType, configJSON string, enabled bool) (*database.ArticleChannel, error) {
	channel, err := database.GetArticleChannel(id)
	if err != nil {
		return nil, fmt.Errorf("获取渠道失败: %w", err)
	}
	if channel == nil {
		return nil, fmt.Errorf("渠道不存在")
	}

	if name != "" {
		channel.Name = name
	}
	if channelType != "" {
		channel.ChannelType = channelType
	}
	if configJSON != "" {
		channel.Config = configJSON
	}
	channel.Enabled = enabled

	if err := database.UpdateArticleChannel(channel); err != nil {
		return nil, fmt.Errorf("更新渠道失败: %w", err)
	}
	return channel, nil
}

// DeleteChannel 删除渠道
func (s *ArticleService) DeleteChannel(id int64) error {
	return database.DeleteArticleChannel(id)
}

// --- 发布 ---

// PublishRequest 发布请求
type PublishRequest struct {
	ArticleID  int64   `json:"article_id"`
	ChannelIDs []int64 `json:"channel_ids"`
}

// PublishResult 发布结果
type PublishResult struct {
	Total   int              `json:"total"`
	Success int              `json:"success"`
	Failed  int              `json:"failed"`
	Logs    []PublishLogItem `json:"logs"`
}

// PublishLogItem 单条发布日志
type PublishLogItem struct {
	ChannelID   int64  `json:"channel_id"`
	ChannelName string `json:"channel_name"`
	Status      string `json:"status"` // success, failed
	Message     string `json:"message"`
}

// PublishLogsResult 发布日志列表
type PublishLogsResult struct {
	Logs []database.ArticlePublishLog `json:"logs"`
}

// Publish 发布文章到指定渠道
func (s *ArticleService) Publish(req *PublishRequest) (*PublishResult, error) {
	article, err := database.GetArticle(req.ArticleID)
	if err != nil {
		return nil, fmt.Errorf("获取文章失败: %w", err)
	}
	if article == nil {
		return nil, fmt.Errorf("文章不存在")
	}

	result := &PublishResult{
		Total: len(req.ChannelIDs),
		Logs:  make([]PublishLogItem, 0, len(req.ChannelIDs)),
	}

	for _, chID := range req.ChannelIDs {
		channel, err := database.GetArticleChannel(chID)
		if err != nil || channel == nil {
			result.Logs = append(result.Logs, PublishLogItem{
				ChannelID: chID,
				Status:    "failed",
				Message:   "渠道不存在",
			})
			result.Failed++
			continue
		}

		logItem := s.publishToChannel(article, channel)
		result.Logs = append(result.Logs, logItem)

		if logItem.Status == "success" {
			result.Success++
		} else {
			result.Failed++
		}

		// 记录发布日志
		_ = database.CreateArticlePublishLog(&database.ArticlePublishLog{
			ArticleID:   req.ArticleID,
			ChannelID:   chID,
			Status:      logItem.Status,
			Message:     logItem.Message,
			PublishedAt: time.Now().Format("2006-01-02 15:04:05"),
		})
	}

	// 如果有成功发布的，更新文章状态
	if result.Success > 0 {
		article.Status = "published"
		_ = database.UpdateArticle(article)
	}

	return result, nil
}

// publishToChannel 发布到指定渠道
func (s *ArticleService) publishToChannel(article *database.Article, channel *database.ArticleChannel) PublishLogItem {
	switch channel.ChannelType {
	case "wechat":
		return s.publishToWeChat(article, channel)
	case "csdn":
		return s.publishToCSDN(article, channel)
	case "tencent_cloud":
		return s.publishToTencentCloud(article, channel)
	case "juejin":
		return s.publishToJuejin(article, channel)
	default:
		return s.publishToCustom(article, channel)
	}
}

// =============================================================================
// 微信公众号 - 官方 API
// 流程：获取 access_token → 创建草稿 → 发布草稿
// 参考文档：https://developers.weixin.qq.com/doc/offiaccount/Draft_Box/Add_draft.html
// =============================================================================

// wechatTokenResp 微信 access_token 响应
type wechatTokenResp struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	ErrCode     int    `json:"errcode"`
	ErrMsg      string `json:"errmsg"`
}

// wechatDraftResp 微信创建草稿响应
type wechatDraftResp struct {
	MediaID string `json:"media_id"`
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

// wechatPublishResp 微信发布草稿响应
type wechatPublishResp struct {
	PublishID string `json:"publish_id"`
	ErrCode   int    `json:"errcode"`
	ErrMsg    string `json:"errmsg"`
}

func (s *ArticleService) publishToWeChat(article *database.Article, channel *database.ArticleChannel) PublishLogItem {
	var cfg map[string]string
	if err := json.Unmarshal([]byte(channel.Config), &cfg); err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "配置JSON解析失败: " + err.Error()}
	}

	appID := strings.TrimSpace(cfg["app_id"])
	appSecret := strings.TrimSpace(cfg["app_secret"])

	if appID == "" || appSecret == "" {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "微信公众号 AppID 或 AppSecret 未配置"}
	}

	// 步骤1：获取 access_token
	tokenURL := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=%s&secret=%s", appID, appSecret)
	resp, err := httpClient.Get(tokenURL)
	if err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "获取 access_token 失败: " + err.Error()}
	}
	defer resp.Body.Close()

	var tokenResp wechatTokenResp
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "解析 access_token 响应失败"}
	}
	if tokenResp.ErrCode != 0 {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed",
			Message: fmt.Sprintf("获取 access_token 失败 (errcode=%d): %s", tokenResp.ErrCode, tokenResp.ErrMsg)}
	}
	if tokenResp.AccessToken == "" {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "access_token 为空"}
	}

	accessToken := tokenResp.AccessToken

	// 步骤2：创建草稿（微信公众号需要 HTML 格式内容）
	htmlContent := markdownToHTML(article.Content)
	draftBody := map[string]interface{}{
		"articles": []map[string]interface{}{
			{
				"title":              article.Title,
				"content":            htmlContent,
				"author":             cfg["author"],
				"digest":             truncateString(stripHTML(article.Content), 100),
				"content_source_url": "",
				"need_open_comment":  0,
				"only_fans_can_comment": 0,
			},
		},
	}

	draftJSON, _ := json.Marshal(draftBody)
	draftURL := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/draft/add?access_token=%s", accessToken)
	draftResp, err := httpClient.Post(draftURL, "application/json", bytes.NewReader(draftJSON))
	if err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "创建草稿失败: " + err.Error()}
	}
	defer draftResp.Body.Close()

	var draftResult wechatDraftResp
	if err := json.NewDecoder(draftResp.Body).Decode(&draftResult); err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "解析草稿响应失败"}
	}
	if draftResult.ErrCode != 0 {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed",
			Message: fmt.Sprintf("创建草稿失败 (errcode=%d): %s", draftResult.ErrCode, draftResult.ErrMsg)}
	}

	// 步骤3：发布草稿
	publishBody := map[string]string{"media_id": draftResult.MediaID}
	publishJSON, _ := json.Marshal(publishBody)
	publishURL := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/freepublish/submit?access_token=%s", accessToken)
	pubResp, err := httpClient.Post(publishURL, "application/json", bytes.NewReader(publishJSON))
	if err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "发布草稿失败: " + err.Error()}
	}
	defer pubResp.Body.Close()

	var pubResult wechatPublishResp
	if err := json.NewDecoder(pubResp.Body).Decode(&pubResult); err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "解析发布响应失败"}
	}
	if pubResult.ErrCode != 0 {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed",
			Message: fmt.Sprintf("发布失败 (errcode=%d): %s", pubResult.ErrCode, pubResult.ErrMsg)}
	}

	return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "success",
		Message: fmt.Sprintf("发布成功！publish_id: %s", pubResult.PublishID)}
}

// =============================================================================
// CSDN - 内部 API（Cookie 认证）
// 接口：POST https://mp.csdn.net/mdeditor/saveArticle (multipart/form-data)
// =============================================================================

// csdnSaveResp CSDN 保存响应
type csdnSaveResp struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

func (s *ArticleService) publishToCSDN(article *database.Article, channel *database.ArticleChannel) PublishLogItem {
	var cfg map[string]string
	if err := json.Unmarshal([]byte(channel.Config), &cfg); err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "配置JSON解析失败: " + err.Error()}
	}

	cookie := strings.TrimSpace(cfg["cookie"])
	if cookie == "" {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "CSDN Cookie 未配置，请在浏览器登录 CSDN 后复制 Cookie"}
	}

	tags := strings.TrimSpace(cfg["tags"])
	if tags == "" {
		tags = "技术"
	}
	categories := strings.TrimSpace(cfg["categories"])
	articleType := strings.TrimSpace(cfg["type"])
	if articleType == "" {
		articleType = "original"
	}

	// 构建 multipart/form-data 请求体
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// CSDN mdeditor 需要同时传 markdowncontent 和 HTML content
	htmlContent := markdownToHTML(article.Content)

	_ = writer.WriteField("title", article.Title)
	_ = writer.WriteField("markdowncontent", article.Content)
	_ = writer.WriteField("content", htmlContent)
	_ = writer.WriteField("tags", tags)
	_ = writer.WriteField("categories", categories)
	_ = writer.WriteField("channel", "31")
	_ = writer.WriteField("type", articleType)
	_ = writer.WriteField("articleedittype", "1")  // 1 = Markdown 编辑器
	_ = writer.WriteField("id", "")                  // 留空 = 新建
	_ = writer.WriteField("private", "")
	_ = writer.WriteField("status", "1")             // 1 = 发布
	_ = writer.WriteField("Description", "")

	writer.Close()

	req, err := http.NewRequest("POST", "https://mp.csdn.net/mdeditor/saveArticle", &buf)
	if err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "构建请求失败: " + err.Error()}
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Cookie", cookie)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	req.Header.Set("Referer", "https://mp.csdn.net/")
	req.Header.Set("Origin", "https://mp.csdn.net")

	resp, err := httpClient.Do(req)
	if err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "请求 CSDN 失败: " + err.Error()}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	// CSDN 返回格式可能是 JSON 或简单字符串
	var csdnResp csdnSaveResp
	if err := json.Unmarshal(bodyBytes, &csdnResp); err != nil {
		// 非 JSON 响应，判断是否包含成功标识
		if resp.StatusCode == 200 && (strings.Contains(bodyStr, "success") || strings.Contains(bodyStr, "article_id")) {
			return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "success",
				Message: fmt.Sprintf("发布成功！响应: %s", truncateString(bodyStr, 100))}
		}
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed",
			Message: fmt.Sprintf("发布失败，HTTP %d: %s", resp.StatusCode, truncateString(bodyStr, 200))}
	}

	if csdnResp.Code == 200 || csdnResp.Code == 0 {
		extraInfo := ""
		if csdnResp.Data != nil {
			if dataMap, ok := csdnResp.Data.(map[string]interface{}); ok {
				if aid, ok := dataMap["article_id"]; ok {
					extraInfo = fmt.Sprintf("，文章ID: %v", aid)
				} else if id, ok := dataMap["id"]; ok {
					extraInfo = fmt.Sprintf("，ID: %v", id)
				} else if url, ok := dataMap["url"]; ok {
					extraInfo = fmt.Sprintf("，地址: %v", url)
				}
			}
		}
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "success",
			Message: fmt.Sprintf("发布成功%s", extraInfo)}
	}

	return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed",
		Message: fmt.Sprintf("发布失败: %s", csdnResp.Message)}
}

// =============================================================================
// 腾讯云开发者社区 - 内部 API（Cookie 认证）
// 通过抓包获取的接口，Cookie 需从浏览器登录后获取
// =============================================================================

// tencentCloudResp 腾讯云社区响应
type tencentCloudResp struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

func (s *ArticleService) publishToTencentCloud(article *database.Article, channel *database.ArticleChannel) PublishLogItem {
	var cfg map[string]string
	if err := json.Unmarshal([]byte(channel.Config), &cfg); err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "配置JSON解析失败: " + err.Error()}
	}

	cookie := strings.TrimSpace(cfg["cookie"])
	if cookie == "" {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "腾讯云社区 Cookie 未配置，请在浏览器登录 cloud.tencent.com 后复制 Cookie"}
	}

	tags := strings.TrimSpace(cfg["tags"])

	// 腾讯云社区使用 HTML 格式内容
	htmlContent := markdownToHTML(article.Content)

	reqBody := map[string]interface{}{
		"title":   article.Title,
		"content": htmlContent,
		"md_content": article.Content,
	}
	if tags != "" {
		reqBody["tags"] = tags
	}

	bodyJSON, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", "https://cloud.tencent.com/developer/services/article/save", bytes.NewReader(bodyJSON))
	if err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "构建请求失败: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Cookie", cookie)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	req.Header.Set("Referer", "https://cloud.tencent.com/developer")
	req.Header.Set("Origin", "https://cloud.tencent.com")

	resp, err := httpClient.Do(req)
	if err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "请求腾讯云社区失败: " + err.Error()}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	var tcResp tencentCloudResp
	if err := json.Unmarshal(bodyBytes, &tcResp); err != nil {
		if resp.StatusCode == 200 {
			return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "success",
				Message: fmt.Sprintf("发布成功（HTTP %d），响应: %s", resp.StatusCode, truncateString(bodyStr, 100))}
		}
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed",
			Message: fmt.Sprintf("发布失败，HTTP %d: %s", resp.StatusCode, truncateString(bodyStr, 200))}
	}

	if tcResp.Code == 0 || tcResp.Code == 200 {
		articleURL := ""
		if tcResp.Data != nil {
			if dataMap, ok := tcResp.Data.(map[string]interface{}); ok {
				if url, ok := dataMap["url"]; ok {
					articleURL = fmt.Sprintf("，地址: %v", url)
				}
			}
		}
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "success",
			Message: fmt.Sprintf("发布成功%s", articleURL)}
	}

	return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed",
		Message: fmt.Sprintf("发布失败: %s", tcResp.Message)}
}

// =============================================================================
// 掘金 - 内部 API（Cookie 认证）
// 流程：创建草稿 → 发布草稿
// 接口来源：抓包分析 https://api.juejin.cn
// 参考：juejin.cn/post/7504943335842512915
// =============================================================================

// juejinCommonResp 掘金通用响应
type juejinCommonResp struct {
	ErrNo  int         `json:"err_no"`
	ErrMsg string      `json:"err_msg"`
	Data   interface{} `json:"data"`
}

func (s *ArticleService) publishToJuejin(article *database.Article, channel *database.ArticleChannel) PublishLogItem {
	var cfg map[string]string
	if err := json.Unmarshal([]byte(channel.Config), &cfg); err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "配置JSON解析失败: " + err.Error()}
	}

	cookie := strings.TrimSpace(cfg["cookie"])
	if cookie == "" {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "掘金 Cookie 未配置，请在浏览器登录 juejin.cn 后复制 Cookie"}
	}

	categoryID := strings.TrimSpace(cfg["category_id"])
	if categoryID == "" {
		categoryID = "6809637769959178254" // 默认：后端
	}

	// tag_ids 逗号分隔
	var tagIDs []string
	if tagsStr := strings.TrimSpace(cfg["tag_ids"]); tagsStr != "" {
		tagIDs = splitAndTrim(tagsStr, ",")
	}

	// brief_content 需要在 50-100 字符之间
	briefContent := truncateString(stripHTML(article.Content), 100)
	if len([]rune(briefContent)) < 50 {
		briefContent = briefContent + "..." + strings.Repeat(" ", 50-len([]rune(briefContent)))
	}

	// authorization 请求头（部分账号需要）
	authorization := strings.TrimSpace(cfg["authorization"])

	// --- 步骤1：创建草稿 ---
	draftBody := map[string]interface{}{
		"category_id":   categoryID,
		"tag_ids":       tagIDs,
		"title":         article.Title,
		"brief_content": briefContent,
		"edit_type":     10, // 10 = Markdown 模式
		"mark_content":  article.Content,
		"html_content":  "deprecated", // 掘金已废弃此字段
		"cover_image":   "",
		"link_url":      "",
		"theme_ids":     []string{},
	}

	draftJSON, _ := json.Marshal(draftBody)
	req, err := http.NewRequest("POST", "https://api.juejin.cn/content_api/v1/article_draft/create", bytes.NewReader(draftJSON))
	if err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "构建草稿请求失败: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Cookie", cookie)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	req.Header.Set("Referer", "https://juejin.cn/")
	req.Header.Set("Origin", "https://juejin.cn")
	if authorization != "" {
		req.Header.Set("authorization", authorization)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "请求掘金创建草稿失败: " + err.Error()}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	var draftResp juejinCommonResp
	if err := json.Unmarshal(bodyBytes, &draftResp); err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed",
			Message: fmt.Sprintf("解析掘金草稿响应失败: %s", truncateString(string(bodyBytes), 200))}
	}
	if draftResp.ErrNo != 0 {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed",
			Message: fmt.Sprintf("掘金创建草稿失败 (err_no=%d): %s", draftResp.ErrNo, draftResp.ErrMsg)}
	}

	// 提取 draft_id
	draftID := ""
	if draftResp.Data != nil {
		if dataMap, ok := draftResp.Data.(map[string]interface{}); ok {
			if id, ok := dataMap["id"]; ok {
				draftID = fmt.Sprintf("%v", id)
			}
		}
	}
	if draftID == "" || draftID == "0" {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "创建草稿成功但未获取到 draft_id"}
	}

	// --- 步骤2：发布草稿 ---
	pubBody := map[string]interface{}{
		"draft_id":    draftID,
		"sync_to_org": false,
		"column_ids":  []string{},
		"theme_ids":   []string{},
	}

	pubJSON, _ := json.Marshal(pubBody)
	req2, err := http.NewRequest("POST", "https://api.juejin.cn/content_api/v1/article/publish", bytes.NewReader(pubJSON))
	if err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "构建发布请求失败: " + err.Error()}
	}
	req2.Header.Set("Content-Type", "application/json; charset=utf-8")
	req2.Header.Set("Cookie", cookie)
	req2.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	req2.Header.Set("Referer", "https://juejin.cn/")
	req2.Header.Set("Origin", "https://juejin.cn")
	if authorization != "" {
		req2.Header.Set("authorization", authorization)
	}

	resp2, err := httpClient.Do(req2)
	if err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "请求掘金发布失败: " + err.Error()}
	}
	defer resp2.Body.Close()

	bodyBytes2, _ := io.ReadAll(resp2.Body)

	var pubResp juejinCommonResp
	if err := json.Unmarshal(bodyBytes2, &pubResp); err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed",
			Message: fmt.Sprintf("解析掘金发布响应失败: %s", truncateString(string(bodyBytes2), 200))}
	}
	if pubResp.ErrNo != 0 {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed",
			Message: fmt.Sprintf("掘金发布失败 (err_no=%d): %s", pubResp.ErrNo, pubResp.ErrMsg)}
	}

	articleID := ""
	if pubResp.Data != nil {
		if dataMap, ok := pubResp.Data.(map[string]interface{}); ok {
			if aid, ok := dataMap["article_id"]; ok {
				articleID = fmt.Sprintf("%v", aid)
			}
		}
	}

	articleURL := ""
	if articleID != "" {
		articleURL = fmt.Sprintf("，地址: https://juejin.cn/post/%s", articleID)
	}

	return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "success",
		Message: fmt.Sprintf("发布成功%s", articleURL)}
}

// =============================================================================
// 自定义渠道 - 向指定 URL 发送 POST 请求
// =============================================================================

func (s *ArticleService) publishToCustom(article *database.Article, channel *database.ArticleChannel) PublishLogItem {
	var cfg map[string]string
	if err := json.Unmarshal([]byte(channel.Config), &cfg); err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "配置JSON解析失败"}
	}

	url := strings.TrimSpace(cfg["url"])
	if url == "" {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "自定义渠道 URL 未配置"}
	}

	reqBody := map[string]interface{}{
		"title":   article.Title,
		"content": article.Content,
	}
	bodyJSON, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyJSON))
	if err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "构建请求失败: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	// 自定义请求头
	if headersStr := strings.TrimSpace(cfg["headers"]); headersStr != "" {
		var headers map[string]string
		if json.Unmarshal([]byte(headersStr), &headers) == nil {
			for k, v := range headers {
				req.Header.Set(k, v)
			}
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed", Message: "请求自定义渠道失败: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "success",
			Message: fmt.Sprintf("发布成功，HTTP %d", resp.StatusCode)}
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	return PublishLogItem{ChannelID: channel.ID, ChannelName: channel.Name, Status: "failed",
		Message: fmt.Sprintf("发布失败，HTTP %d: %s", resp.StatusCode, truncateString(string(bodyBytes), 200))}
}

// =============================================================================
// 发布日志
// =============================================================================

// GetPublishLogs 获取发布日志
func (s *ArticleService) GetPublishLogs(articleID int64) (*PublishLogsResult, error) {
	logs, err := database.ListArticlePublishLogs(articleID)
	if err != nil {
		return nil, fmt.Errorf("获取发布日志失败: %w", err)
	}
	if logs == nil {
		logs = []database.ArticlePublishLog{}
	}
	return &PublishLogsResult{Logs: logs}, nil
}

// =============================================================================
// 工具函数：Markdown → HTML 转换
// =============================================================================

// markdownToHTML 将 Markdown 文本转换为 HTML
func markdownToHTML(md string) string {
	if md == "" {
		return ""
	}

	html := md

	// 转义 HTML 保留字符
	html = strings.ReplaceAll(html, "&", "&amp;")
	html = strings.ReplaceAll(html, "<", "&lt;")
	html = strings.ReplaceAll(html, ">", "&gt;")

	// 代码块 ``` (先处理，避免被后续规则干扰)
	codeBlockRegex := regexp.MustCompile("(?s)```(\\w*)\\n?(.*?)```")
	html = codeBlockRegex.ReplaceAllStringFunc(html, func(match string) string {
		parts := codeBlockRegex.FindStringSubmatch(match)
		if len(parts) < 3 {
			return match
		}
		lang := parts[1]
		code := strings.TrimSpace(parts[2])
		// 还原代码块内的 HTML 实体
		code = strings.ReplaceAll(code, "&amp;", "&")
		code = strings.ReplaceAll(code, "&lt;", "<")
		code = strings.ReplaceAll(code, "&gt;", ">")
		langAttr := ""
		if lang != "" {
			langAttr = fmt.Sprintf(` class="language-%s"`, lang)
		}
		return fmt.Sprintf(`<pre><code%s>%s</code></pre>`, langAttr, code)
	})

	// 行内代码
	html = regexp.MustCompile("`([^`]+)`").ReplaceAllString(html, "<code>$1</code>")

	// 水平线
	html = regexp.MustCompile(`(?m)^[-*_]{3,}\s*$`).ReplaceAllString(html, "<hr/>")

	// 图片
	html = regexp.MustCompile(`!\[([^\]]*)\]\(([^)]+)\)`).ReplaceAllString(html, `<img src="$2" alt="$1"/>`)

	// 链接
	html = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`).ReplaceAllString(html, `<a href="$2" target="_blank">$1</a>`)

	// 标题
	html = regexp.MustCompile(`(?m)^###### (.+)$`).ReplaceAllString(html, "<h6>$1</h6>")
	html = regexp.MustCompile(`(?m)^##### (.+)$`).ReplaceAllString(html, "<h5>$1</h5>")
	html = regexp.MustCompile(`(?m)^#### (.+)$`).ReplaceAllString(html, "<h4>$1</h4>")
	html = regexp.MustCompile(`(?m)^### (.+)$`).ReplaceAllString(html, "<h3>$1</h3>")
	html = regexp.MustCompile(`(?m)^## (.+)$`).ReplaceAllString(html, "<h2>$1</h2>")
	html = regexp.MustCompile(`(?m)^# (.+)$`).ReplaceAllString(html, "<h1>$1</h1>")

	// 粗体 + 斜体
	html = regexp.MustCompile(`\*\*\*(.+?)\*\*\*`).ReplaceAllString(html, "<strong><em>$1</em></strong>")
	html = regexp.MustCompile(`\*\*(.+?)\*\*`).ReplaceAllString(html, "<strong>$1</strong>")
	html = regexp.MustCompile(`\*(.+?)\*`).ReplaceAllString(html, "<em>$1</em>")

	// 删除线
	html = regexp.MustCompile(`~~(.+?)~~`).ReplaceAllString(html, "<del>$1</del>")

	// 引用
	html = regexp.MustCompile(`(?m)^&gt; (.+)$`).ReplaceAllString(html, "<blockquote>$1</blockquote>")

	// 有序列表
	html = regexp.MustCompile(`(?m)^(\d+)\. (.+)$`).ReplaceAllString(html, "<!--ol-->$2<!--/ol-->")

	// 无序列表
	html = regexp.MustCompile(`(?m)^[\-\*\+] (.+)$`).ReplaceAllString(html, "<!--li-->$1<!--/li-->")

	// 包裹列表项
	html = wrapLists(html)

	// 段落
	html = regexp.MustCompile(`(?m)^(?!<[a-z/]|<!--).+(?<![a-z]>)$`).ReplaceAllString(html, "<p>$0</p>")

	// 清理空段落
	html = strings.ReplaceAll(html, "<p></p>", "")

	return html
}

// wrapLists 将列表标记包裹在 <ul> 或 <ol> 中
func wrapLists(html string) string {
	// 处理有序列表 <!--ol-->...<!--/ol-->
	olRegex := regexp.MustCompile(`(?s)((?:<!--ol-->.*?<!--/ol-->\n?)+)`)
	html = olRegex.ReplaceAllStringFunc(html, func(match string) string {
		inner := strings.ReplaceAll(match, "<!--ol-->", "<li>")
		inner = strings.ReplaceAll(inner, "<!--/ol-->", "</li>")
		return "<ol>\n" + inner + "</ol>\n"
	})

	// 处理无序列表 <!--li-->...<!--/li-->
	liRegex := regexp.MustCompile(`(?s)((?:<!--li-->.*?<!--/li-->\n?)+)`)
	html = liRegex.ReplaceAllStringFunc(html, func(match string) string {
		inner := strings.ReplaceAll(match, "<!--li-->", "<li>")
		inner = strings.ReplaceAll(inner, "<!--/li-->", "</li>")
		return "<ul>\n" + inner + "</ul>\n"
	})

	return html
}

// =============================================================================
// 通用工具函数
// =============================================================================

// truncateString 截断字符串到指定长度
func truncateString(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

// stripHTML 移除 HTML 标签，返回纯文本
func stripHTML(html string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	text := re.ReplaceAllString(html, "")
	text = strings.TrimSpace(text)
	// 压缩多余空白
	spaceRe := regexp.MustCompile(`\s+`)
	text = spaceRe.ReplaceAllString(text, " ")
	return text
}

// splitAndTrim 拆分字符串并去除每个元素两端的空白
func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
