package handler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/service"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

var documentSvc = service.NewDocumentService()

// DocxToMd docx 转 markdown 接口
// 支持两种方式：
// 1. multipart/form-data 上传文件（字段: file, output_path 可选）
// 2. application/json 指定服务器文件路径（字段: input_path, output_path 可选）
func DocxToMd(ctx *fasthttp.RequestCtx) {
	contentType := string(ctx.Request.Header.ContentType())

	if strings.HasPrefix(contentType, "multipart/form-data") {
		handleDocConvertUpload(ctx, ".docx", documentSvc.DocxToMd)
		return
	}

	handleDocConvertPath(ctx, documentSvc.DocxToMd)
}

// ExcelToMd excel 转 markdown 接口
func ExcelToMd(ctx *fasthttp.RequestCtx) {
	contentType := string(ctx.Request.Header.ContentType())

	if strings.HasPrefix(contentType, "multipart/form-data") {
		handleDocConvertUpload(ctx, ".xlsx", documentSvc.ExcelToMd)
		return
	}

	handleDocConvertPath(ctx, documentSvc.ExcelToMd)
}

// PdfToMd pdf 转 markdown 接口
func PdfToMd(ctx *fasthttp.RequestCtx) {
	contentType := string(ctx.Request.Header.ContentType())

	if strings.HasPrefix(contentType, "multipart/form-data") {
		handleDocConvertUpload(ctx, ".pdf", documentSvc.PdfToMd)
		return
	}

	handleDocConvertPath(ctx, documentSvc.PdfToMd)
}

// docConvertFunc 文档转换函数类型
type docConvertFunc func(inputPath string, outputPath string) (*service.DocConvertResult, error)

// handleDocConvertUpload 处理文件上传方式的文档转换
func handleDocConvertUpload(ctx *fasthttp.RequestCtx, allowedExt string, convertFn docConvertFunc) {
	// 解析 multipart 表单
	form, err := ctx.MultipartForm()
	if err != nil {
		logger.Errorc("DocConvert", "解析 multipart 表单失败: "+err.Error())
		response.Error(ctx, 1001, "解析上传表单失败")
		return
	}

	// 获取上传文件
	files, ok := form.File["file"]
	if !ok || len(files) == 0 {
		response.Error(ctx, 1001, "请上传文件")
		return
	}

	fileHeader := files[0]
	fileName := fileHeader.Filename

	// 支持多种扩展名检查（如 .xlsx 和 .xls）
	extValid := false
	for _, ext := range strings.Split(allowedExt, "/") {
		if strings.HasSuffix(strings.ToLower(fileName), ext) {
			extValid = true
			break
		}
	}
	if !extValid {
		response.Error(ctx, 1001, "仅支持 "+allowedExt+" 格式文件")
		return
	}

	// 保存上传文件到临时目录
	tmpDir, err := os.MkdirTemp("", "doc-convert-*")
	if err != nil {
		logger.Errorc("DocConvert", "创建临时目录失败: "+err.Error())
		response.Error(ctx, 2001, "创建临时目录失败")
		return
	}
	defer os.RemoveAll(tmpDir)

	tmpInputPath := filepath.Join(tmpDir, fileName)
	if err := fasthttp.SaveMultipartFile(fileHeader, tmpInputPath); err != nil {
		logger.Errorc("DocConvert", "保存上传文件失败: "+err.Error())
		response.Error(ctx, 2001, "保存上传文件失败")
		return
	}

	// 获取可选的输出路径
	outputPath := ""
	if vals, ok := form.Value["output_path"]; ok && len(vals) > 0 {
		outputPath = vals[0]
	}

	result, err := convertFn(tmpInputPath, outputPath)
	if err != nil {
		logger.Errorc("DocConvert", "文档转换失败: "+err.Error())
		response.Error(ctx, 2010, err.Error())
		return
	}

	response.Success(ctx, result)
}

// handleDocConvertPath 处理指定文件路径方式的文档转换
func handleDocConvertPath(ctx *fasthttp.RequestCtx, convertFn docConvertFunc) {
	var req struct {
		InputPath  string `json:"input_path"`
		OutputPath string `json:"output_path,omitempty"`
	}

	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}

	if req.InputPath == "" {
		response.Error(ctx, 1001, "input_path 参数不能为空")
		return
	}

	result, err := convertFn(req.InputPath, req.OutputPath)
	if err != nil {
		logger.Errorc("DocConvert", "文档转换失败: "+err.Error())
		response.Error(ctx, 2010, err.Error())
		return
	}

	response.Success(ctx, result)
}
