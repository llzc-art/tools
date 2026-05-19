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

	// 创建静态文件处理器
	staticHandler := handler.NewStaticHandler(webFS)

	// 注册路由
	requestHandler := func(ctx *fasthttp.RequestCtx) {
		path := string(ctx.Path())

		switch {
		case path == "/api/ping":
			handler.Ping(ctx)

		// 时间戳工具
		case path == "/api/timestamp/now":
			handler.TimestampNow(ctx)
		case path == "/api/timestamp/to-time":
			handler.TimestampToTime(ctx)
		case path == "/api/timestamp/from-time":
			handler.TimestampFromTime(ctx)

		// 时间格式化工具
		case path == "/api/timeformat/convert":
			handler.TimeFormatConvert(ctx)

		// Base64 编解码工具
		case path == "/api/base64/encode":
			handler.Base64Encode(ctx)
		case path == "/api/base64/decode":
			handler.Base64Decode(ctx)

		// URL 编解码工具
		case path == "/api/url/encode":
			handler.URLEncode(ctx)
		case path == "/api/url/decode":
			handler.URLDecode(ctx)

		// Hash 哈希工具
		case path == "/api/hash/compute":
			handler.HashCompute(ctx)

		// 对称加密工具
		case path == "/api/symmetric/compute":
			handler.SymmetricCompute(ctx)
		case path == "/api/symmetric/key-sizes":
			handler.SymmetricKeySizes(ctx)

		// 非对称加密工具
		case path == "/api/asymmetric/encrypt":
			handler.AsymmetricEncrypt(ctx)
		case path == "/api/asymmetric/decrypt":
			handler.AsymmetricDecrypt(ctx)
		case path == "/api/asymmetric/sign":
			handler.AsymmetricSign(ctx)
		case path == "/api/asymmetric/verify":
			handler.AsymmetricVerify(ctx)

		// 密钥生成工具
		case path == "/api/keygen/generate":
			handler.KeyGenGenerate(ctx)
		case path == "/api/keygen/types":
			handler.KeyGenTypes(ctx)

		// UUID / 随机字符串生成工具
		case path == "/api/uuid/generate":
			handler.UUIDGenerate(ctx)
		case path == "/api/random/generate":
			handler.RandomGenerate(ctx)

		// JSON 工具
		case path == "/api/json/format":
			handler.JSONFormat(ctx)
		case path == "/api/json/compress":
			handler.JSONCompress(ctx)

		// URL 编码/解码/解析/构建
		case path == "/api/urlcode/encode":
			handler.URLEncodeComponent(ctx)
		case path == "/api/urlcode/decode":
			handler.URLDecodeComponent(ctx)
		case path == "/api/urlcode/parse":
			handler.URLParse(ctx)
		case path == "/api/urlcode/build":
			handler.URLBuild(ctx)

		// Unicode 编解码
		case path == "/api/unicode/encode":
			handler.UnicodeEncode(ctx)
		case path == "/api/unicode/decode":
			handler.UnicodeDecode(ctx)

		// IP 查询工具
		case path == "/api/ip/lookup":
			handler.IPLookup(ctx)
		case path == "/api/ip/cidr":
			handler.IPCIDR(ctx)

		// 正则表达式工具
		case path == "/api/regex/match":
			handler.RegexMatch(ctx)
		case path == "/api/regex/replace":
			handler.RegexReplace(ctx)

		// 字符串工具
		case path == "/api/string/count":
			handler.StringCount(ctx)
		case path == "/api/string/to-upper":
			handler.StringToUpper(ctx)
		case path == "/api/string/to-lower":
			handler.StringToLower(ctx)
		case path == "/api/string/to-camel":
			handler.StringToCamel(ctx)
		case path == "/api/string/to-snake":
			handler.StringToSnake(ctx)
		case path == "/api/string/to-hex":
			handler.StringToHex(ctx)
		case path == "/api/hex/to-string":
			handler.HexToString(ctx)

		// JWT 解码工具
		case path == "/api/jwt/decode":
			handler.JWTDecode(ctx)

		// LLM 对话工具
		case path == "/api/llm/chat":
			handler.LLMChat(ctx)

		// LLM 配置管理
		case path == "/api/llm/config/list":
			handler.LLMConfigList(ctx)
		case path == "/api/llm/config/get":
			handler.LLMConfigGet(ctx)
		case path == "/api/llm/config/get-default":
			handler.LLMConfigGetDefault(ctx)
		case path == "/api/llm/config/create":
			handler.LLMConfigCreate(ctx)
		case path == "/api/llm/config/update":
			handler.LLMConfigUpdate(ctx)
		case path == "/api/llm/config/delete":
			handler.LLMConfigDelete(ctx)
		case path == "/api/llm/config/set-default":
			handler.LLMConfigSetDefault(ctx)
		case path == "/api/llm/messages/get":
			handler.LLMMessagesGet(ctx)
		case path == "/api/llm/messages/save":
			handler.LLMMessagesSave(ctx)
		case path == "/api/llm/messages/clear":
			handler.LLMMessagesClear(ctx)

		// API 测试器状态持久化
		case path == "/api/api-tester/state/get":
			handler.APITesterStateGet(ctx)
		case path == "/api/api-tester/state/save":
			handler.APITesterStateSave(ctx)

		// API 代理工具
		case path == "/api/proxy/send":
			handler.APIProxy(ctx)
		case path == "/api/proxy/openapi-import":
			handler.OpenAPIImport(ctx)

		default:
			// 静态文件服务
			staticHandler.Serve(ctx)
		}
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
	}

	logger.Infof("攻城师天梯 v%s 启动中...", Version)
	logger.Infof("服务监听: http://localhost%s", addr)
	logger.Infof("日志文件: %s", config.C.Log.Filename)
	logger.Infof("LLM 超时: 非流式 %ds / 流式 %ds", config.C.LLM.ChatTimeout, config.C.LLM.StreamTimeout)
	logger.Info("按 Ctrl+C 停止服务")

	if err := server.ListenAndServe(addr); err != nil {
		logger.Fatalf("服务启动失败: %v", err)
	}
}
