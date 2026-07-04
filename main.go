package main

import (
	"embed"
	"flag"
	"fmt"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/config"
	"lelezc.com/tools/internal/database"
	"lelezc.com/tools/internal/handler"
	"lelezc.com/tools/internal/middleware"
	"lelezc.com/tools/pkg/logger"
)

//go:embed web/dist
var webFS embed.FS

var (
	Version   = "dev"
	BuildTime = "unknown"
)

// registerRoutes 注册所有 API 路由，返回 path -> handler 的映射
func registerRoutes() map[string]fasthttp.RequestHandler {
	routes := make(map[string]fasthttp.RequestHandler)

	// 基础
	routes["/api/ping"] = handler.Ping

	// 时间戳工具
	routes["/api/timestamp/now"] = handler.TimestampNow
	routes["/api/timestamp/to-time"] = handler.TimestampToTime
	routes["/api/timestamp/from-time"] = handler.TimestampFromTime

	// 时间格式化工具
	routes["/api/timeformat/convert"] = handler.TimeFormatConvert

	// Base64 编解码工具
	routes["/api/base64/encode"] = handler.Base64Encode
	routes["/api/base64/decode"] = handler.Base64Decode

	// URL 编解码工具
	routes["/api/url/encode"] = handler.URLEncode
	routes["/api/url/decode"] = handler.URLDecode

	// Hash 哈希工具
	routes["/api/hash/compute"] = handler.HashCompute

	// 对称加密工具
	routes["/api/symmetric/compute"] = handler.SymmetricCompute
	routes["/api/symmetric/key-sizes"] = handler.SymmetricKeySizes

	// 非对称加密工具
	routes["/api/asymmetric/encrypt"] = handler.AsymmetricEncrypt
	routes["/api/asymmetric/decrypt"] = handler.AsymmetricDecrypt
	routes["/api/asymmetric/sign"] = handler.AsymmetricSign
	routes["/api/asymmetric/verify"] = handler.AsymmetricVerify

	// 密钥生成工具
	routes["/api/keygen/generate"] = handler.KeyGenGenerate
	routes["/api/keygen/types"] = handler.KeyGenTypes

	// UUID / 随机字符串生成工具
	routes["/api/uuid/generate"] = handler.UUIDGenerate
	routes["/api/random/generate"] = handler.RandomGenerate

	// JSON 工具
	routes["/api/json/format"] = handler.JSONFormat
	routes["/api/json/compress"] = handler.JSONCompress

	// 数据格式转换工具
	routes["/api/data-convert/detect"] = handler.DataConvertDetect
	routes["/api/data-convert/convert"] = handler.DataConvert

	// URL 编码/解码/解析/构建
	routes["/api/urlcode/encode"] = handler.URLEncodeComponent
	routes["/api/urlcode/decode"] = handler.URLDecodeComponent
	routes["/api/urlcode/parse"] = handler.URLParse
	routes["/api/urlcode/build"] = handler.URLBuild

	// Unicode 编解码
	routes["/api/unicode/encode"] = handler.UnicodeEncode
	routes["/api/unicode/decode"] = handler.UnicodeDecode

	// IP 查询工具
	routes["/api/ip/lookup"] = handler.IPLookup
	routes["/api/ip/cidr"] = handler.IPCIDR

	// 正则表达式工具
	routes["/api/regex/match"] = handler.RegexMatch
	routes["/api/regex/replace"] = handler.RegexReplace

	// 字符串工具
	routes["/api/string/count"] = handler.StringCount
	routes["/api/string/to-upper"] = handler.StringToUpper
	routes["/api/string/to-lower"] = handler.StringToLower
	routes["/api/string/to-camel"] = handler.StringToCamel
	routes["/api/string/to-snake"] = handler.StringToSnake
	routes["/api/string/to-hex"] = handler.StringToHex
	routes["/api/hex/to-string"] = handler.HexToString

	// JWT 解码工具
	routes["/api/jwt/decode"] = handler.JWTDecode

	// LLM 对话工具
	routes["/api/llm/chat"] = handler.LLMChat

	// LLM 配置管理
	routes["/api/llm/config/list"] = handler.LLMConfigList
	routes["/api/llm/config/get"] = handler.LLMConfigGet
	routes["/api/llm/config/get-default"] = handler.LLMConfigGetDefault
	routes["/api/llm/config/create"] = handler.LLMConfigCreate
	routes["/api/llm/config/update"] = handler.LLMConfigUpdate
	routes["/api/llm/config/delete"] = handler.LLMConfigDelete
	routes["/api/llm/config/set-default"] = handler.LLMConfigSetDefault
	routes["/api/llm/messages/get"] = handler.LLMMessagesGet
	routes["/api/llm/messages/save"] = handler.LLMMessagesSave
	routes["/api/llm/messages/clear"] = handler.LLMMessagesClear

	// API 测试器状态持久化
	routes["/api/api-tester/state/get"] = handler.APITesterStateGet
	routes["/api/api-tester/state/save"] = handler.APITesterStateSave

	// 文档解析工具
	routes["/api/document/docx-to-md"] = handler.DocxToMd
	routes["/api/document/excel-to-md"] = handler.ExcelToMd
	routes["/api/document/pdf-to-md"] = handler.PdfToMd

	// 笔记工具
	routes["/api/note/folder/list"] = handler.NoteFolderList
	routes["/api/note/folder/create"] = handler.NoteFolderCreate
	routes["/api/note/folder/update"] = handler.NoteFolderUpdate
	routes["/api/note/folder/delete"] = handler.NoteFolderDelete
	routes["/api/note/document/list"] = handler.NoteDocumentList
	routes["/api/note/document/get"] = handler.NoteDocumentGet
	routes["/api/note/document/create"] = handler.NoteDocumentCreate
	routes["/api/note/document/update"] = handler.NoteDocumentUpdate
	routes["/api/note/document/delete"] = handler.NoteDocumentDelete

	// 网络工具
	routes["/api/network/ping"] = handler.NetworkPing
	routes["/api/network/port-probe"] = handler.NetworkPortProbe
	routes["/api/network/ssh-probe"] = handler.NetworkSSHProbe

	// Linux 命令查询工具
	routes["/api/linux-command/list"] = handler.LinuxCommandList
	routes["/api/linux-command/search"] = handler.LinuxCommandSearch
	routes["/api/linux-command/get"] = handler.LinuxCommandGet
	routes["/api/linux-command/create"] = handler.LinuxCommandCreate
	routes["/api/linux-command/update"] = handler.LinuxCommandUpdate
	routes["/api/linux-command/delete"] = handler.LinuxCommandDelete
	routes["/api/linux-command/help"] = handler.LinuxCommandHelp

	// 应用对接工具
	routes["/api/integration/cloud/platforms"] = handler.IntegrationCloudPlatforms
	routes["/api/integration/cloud/call"] = handler.IntegrationCloudCall
	routes["/api/integration/wechat/apis"] = handler.IntegrationWeChatAPIs
	routes["/api/integration/wechat/token"] = handler.IntegrationWeChatToken
	routes["/api/integration/wechat/call"] = handler.IntegrationWeChatCall
	routes["/api/integration/wecom/apis"] = handler.IntegrationWeComAPIs
	routes["/api/integration/wecom/token"] = handler.IntegrationWeComToken
	routes["/api/integration/wecom/call"] = handler.IntegrationWeComCall
	routes["/api/integration/feishu/apis"] = handler.IntegrationFeishuAPIs
	routes["/api/integration/feishu/token"] = handler.IntegrationFeishuToken
	routes["/api/integration/feishu/call"] = handler.IntegrationFeishuCall

	// API 代理工具
	routes["/api/proxy/send"] = handler.APIProxy
	routes["/api/proxy/openapi-import"] = handler.OpenAPIImport

	// 证件照工具
	routes["/api/idphoto/process"] = handler.IDPhotoProcess
	routes["/api/idphoto/presets"] = handler.IDPhotoPresets
	routes["/api/idphoto/print-layout"] = handler.IDPhotoPrintLayout

	// DDL 解析工具
	routes["/api/ddl/parse"] = handler.DDLParse

	// 文章写作和发布工具
	routes["/api/article/list"] = handler.ArticleList
	routes["/api/article/get"] = handler.ArticleGet
	routes["/api/article/create"] = handler.ArticleCreate
	routes["/api/article/update"] = handler.ArticleUpdate
	routes["/api/article/delete"] = handler.ArticleDelete
	routes["/api/article/channel/list"] = handler.ArticleChannelList
	routes["/api/article/channel/create"] = handler.ArticleChannelCreate
	routes["/api/article/channel/update"] = handler.ArticleChannelUpdate
	routes["/api/article/channel/delete"] = handler.ArticleChannelDelete
	routes["/api/article/publish"] = handler.ArticlePublish
	routes["/api/article/publish/logs"] = handler.ArticlePublishLogs

	return routes
}

func main() {
	configFile := flag.String("c", "config/config.yaml", "配置文件路径")
	showVersion := flag.Bool("v", false, "显示版本信息")
	flag.Parse()

	if *showVersion {
		fmt.Printf("攻城师天梯 %s (built at %s)\n", Version, BuildTime)
		return
	}

	// 加载配置
	if err := config.Load(*configFile); err != nil {
		fmt.Printf("[WARN] 加载配置文件失败，使用默认配置: %v\n", err)
		config.Default()
	}

	// 初始化日志
	logCfg := logger.Config{
		Level:      config.C.Log.Level,
		Filename:   config.C.Log.Filename,
		MaxSize:    config.C.Log.MaxSize,
		MaxBackups: config.C.Log.MaxBackups,
		MaxAge:     config.C.Log.MaxAge,
		Compress:   config.C.Log.Compress,
		Format:     config.C.Log.Format,
	}
	if err := logger.Init(logCfg); err != nil {
		fmt.Printf("[WARN] 初始化日志文件失败，仅输出到控制台: %v\n", err)
	}
	defer logger.Sync()

	// 初始化数据库
	if err := database.Init(config.C.Database.Path); err != nil {
		logger.Warnf("初始化数据库失败: %v", err)
	} else {
		defer database.Close()
		logger.Infof("数据库: %s", config.C.Database.Path)
	}

	// 注册路由
	routes := registerRoutes()
	staticHandler := handler.NewStaticHandler(webFS)

	requestHandler := func(ctx *fasthttp.RequestCtx) {
		path := string(ctx.Path())

		// 查找 API 路由
		if h, ok := routes[path]; ok {
			h(ctx)
			return
		}

		// 静态文件服务
		staticHandler.Serve(ctx)
	}

	// 应用中间件
	handlerChain := middleware.CORS(middleware.Logger(middleware.Recovery(requestHandler)))

	// 创建服务器
	addr := fmt.Sprintf(":%d", config.C.Server.Port)
	server := &fasthttp.Server{
		Handler:            handlerChain,
		Name:               "tools-server",
		MaxConnsPerIP:      500,
		MaxRequestsPerConn: 1000,
		MaxRequestBodySize: 32 * 1024 * 1024, // 最大请求体 32MB，支持图片上传
	}

	logger.Infof("攻城师天梯 v%s 启动中...", Version)
	logger.Infof("服务监听: http://localhost%s", addr)
	logger.Infof("日志文件: %s", config.C.Log.Filename)
	logger.Infof("LLM 超时: 非流式 %ds / 流式 %ds", config.C.LLM.ChatTimeout, config.C.LLM.StreamTimeout)
	logger.Infof("已注册 %d 个 API 路由", len(routes))
	logger.Info("按 Ctrl+C 停止服务")

	if err := server.ListenAndServe(addr); err != nil {
		logger.Fatalf("服务启动失败: %v", err)
	}
}
