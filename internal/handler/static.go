package handler

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/valyala/fasthttp"
)

type StaticHandler struct {
	fileServer http.Handler
	embedFS    fs.FS
}

func NewStaticHandler(embedFS fs.FS) *StaticHandler {
	// 去掉 embed FS 的 "web/dist" 前缀
	subFS, _ := fs.Sub(embedFS, "web/dist")
	return &StaticHandler{
		fileServer: http.FileServer(http.FS(subFS)),
		embedFS:    subFS,
	}
}

func (h *StaticHandler) Serve(ctx *fasthttp.RequestCtx) {
	path := string(ctx.Path())

	// API 路径不处理
	if strings.HasPrefix(path, "/api/") {
		return
	}

	// 去除前导斜杠
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}

	// 空路径或根路径指向 index.html
	if path == "" || path == "/" {
		path = "index.html"
	}

	// 检查文件是否存在
	file, err := h.embedFS.Open(path)
	if err != nil {
		// SPA 回退：文件不存在时返回 index.html
		path = "index.html"
	} else {
		file.Close()
	}

	// 设置正确的 Content-Type
	if strings.HasSuffix(path, ".html") {
		ctx.SetContentType("text/html; charset=utf-8")
	} else if strings.HasSuffix(path, ".css") {
		ctx.SetContentType("text/css; charset=utf-8")
	} else if strings.HasSuffix(path, ".js") {
		ctx.SetContentType("application/javascript; charset=utf-8")
	} else if strings.HasSuffix(path, ".json") {
		ctx.SetContentType("application/json; charset=utf-8")
	} else if strings.HasSuffix(path, ".svg") {
		ctx.SetContentType("image/svg+xml")
	} else if strings.HasSuffix(path, ".png") {
		ctx.SetContentType("image/png")
	} else if strings.HasSuffix(path, ".ico") {
		ctx.SetContentType("image/x-icon")
	}

	// 读取文件内容
	data, err := fs.ReadFile(h.embedFS, path)
	if err != nil {
		ctx.SetStatusCode(404)
		return
	}
	ctx.SetBody(data)
}
