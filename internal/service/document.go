package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tsawler/tabula"
	"github.com/xuri/excelize/v2"
	"github.com/zakahan/docx2md"
	"lelezc.com/tools/pkg/logger"
)

// DocumentService 文档解析服务
type DocumentService struct{}

// NewDocumentService 创建文档解析服务实例
func NewDocumentService() *DocumentService {
	return &DocumentService{}
}

// DocConvertResult 文档转换结果
type DocConvertResult struct {
	Markdown   string   `json:"markdown"`
	OutputPath string   `json:"output_path,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// DocxToMd 将 docx 文件转换为 markdown
// inputPath: 输入的 docx 文件路径
// outputPath: 可选，输出的 markdown 文件路径。为空则只返回内容不保存文件
func (s *DocumentService) DocxToMd(inputPath string, outputPath string) (*DocConvertResult, error) {
	// 校验输入文件
	absInput, err := filepath.Abs(inputPath)
	if err != nil {
		return nil, fmt.Errorf("输入文件路径无效: %v", err)
	}
	if _, err := os.Stat(absInput); os.IsNotExist(err) {
		return nil, fmt.Errorf("输入文件不存在: %s", absInput)
	}
	if !strings.HasSuffix(strings.ToLower(absInput), ".docx") {
		return nil, fmt.Errorf("仅支持 .docx 格式文件")
	}

	// 使用 docx2md 进行转换
	// docx2md.DocxConvert 需要一个输出目录来存放 md 文件和图片
	tmpDir, err := os.MkdirTemp("", "docx-convert-*")
	if err != nil {
		return nil, fmt.Errorf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_, markdownStr, err := docx2md.DocxConvert(absInput, tmpDir)
	if err != nil {
		return nil, fmt.Errorf("docx 转 markdown 失败: %v", err)
	}

	result := &DocConvertResult{
		Markdown: markdownStr,
	}

	// 如果指定了输出路径，保存到文件
	if outputPath != "" {
		absOutput, err := filepath.Abs(outputPath)
		if err != nil {
			return nil, fmt.Errorf("输出文件路径无效: %v", err)
		}
		outDir := filepath.Dir(absOutput)
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return nil, fmt.Errorf("创建输出目录失败: %v", err)
		}
		if err := os.WriteFile(absOutput, []byte(markdownStr), 0644); err != nil {
			return nil, fmt.Errorf("写入输出文件失败: %v", err)
		}
		result.OutputPath = absOutput
	}

	return result, nil
}

// ExcelToMd 将 excel 文件转换为 markdown
// inputPath: 输入的 xlsx 文件路径
// outputPath: 可选，输出的 markdown 文件路径
func (s *DocumentService) ExcelToMd(inputPath string, outputPath string) (*DocConvertResult, error) {
	// 校验输入文件
	absInput, err := filepath.Abs(inputPath)
	if err != nil {
		return nil, fmt.Errorf("输入文件路径无效: %v", err)
	}
	if _, err := os.Stat(absInput); os.IsNotExist(err) {
		return nil, fmt.Errorf("输入文件不存在: %s", absInput)
	}
	ext := strings.ToLower(filepath.Ext(absInput))
	if ext != ".xlsx" && ext != ".xls" {
		return nil, fmt.Errorf("仅支持 .xlsx/.xls 格式文件")
	}

	// 首先尝试使用 tabula 进行转换（支持更丰富的格式）
	markdownStr, warnings, err := s.excelToMdViaTabula(absInput)
	if err == nil && markdownStr != "" {
		result := &DocConvertResult{
			Markdown: markdownStr,
		}
		if len(warnings) > 0 {
			result.Warnings = warnings
		}
		if outputPath != "" {
			absOutput, err := filepath.Abs(outputPath)
			if err != nil {
				return nil, fmt.Errorf("输出文件路径无效: %v", err)
			}
			outDir := filepath.Dir(absOutput)
			if err := os.MkdirAll(outDir, 0755); err != nil {
				return nil, fmt.Errorf("创建输出目录失败: %v", err)
			}
			if err := os.WriteFile(absOutput, []byte(markdownStr), 0644); err != nil {
				return nil, fmt.Errorf("写入输出文件失败: %v", err)
			}
			result.OutputPath = absOutput
		}
		return result, nil
	}

	// tabula 失败时回退到 excelize
	logger.Infof("tabula 转换失败，回退到 excelize: %v", err)
	markdownStr, err = s.excelToMdViaExcelize(absInput)
	if err != nil {
		return nil, fmt.Errorf("excel 转 markdown 失败: %v", err)
	}

	result := &DocConvertResult{
		Markdown: markdownStr,
	}

	if outputPath != "" {
		absOutput, err := filepath.Abs(outputPath)
		if err != nil {
			return nil, fmt.Errorf("输出文件路径无效: %v", err)
		}
		outDir := filepath.Dir(absOutput)
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return nil, fmt.Errorf("创建输出目录失败: %v", err)
		}
		if err := os.WriteFile(absOutput, []byte(markdownStr), 0644); err != nil {
			return nil, fmt.Errorf("写入输出文件失败: %v", err)
		}
		result.OutputPath = absOutput
	}

	return result, nil
}

// excelToMdViaTabula 使用 tabula 库将 excel 转换为 markdown
func (s *DocumentService) excelToMdViaTabula(inputPath string) (string, []string, error) {
	md, tabulaWarnings, err := tabula.Open(inputPath).ToMarkdown()
	if err != nil {
		return "", nil, fmt.Errorf("tabula 转换失败: %v", err)
	}
	var warnings []string
	for _, w := range tabulaWarnings {
		warnings = append(warnings, w.Message)
	}
	return md, warnings, nil
}

// excelToMdViaExcelize 使用 excelize 库将 excel 转换为 markdown 表格
func (s *DocumentService) excelToMdViaExcelize(inputPath string) (string, error) {
	f, err := excelize.OpenFile(inputPath)
	if err != nil {
		return "", fmt.Errorf("打开 excel 文件失败: %v", err)
	}
	defer f.Close()

	var sb strings.Builder

	sheets := f.GetSheetList()
	for i, sheet := range sheets {
		if i > 0 {
			sb.WriteString("\n\n")
		}
		if len(sheets) > 1 {
			sb.WriteString(fmt.Sprintf("## %s\n\n", sheet))
		}

		rows, err := f.GetRows(sheet)
		if err != nil {
			return "", fmt.Errorf("读取工作表 %s 失败: %v", sheet, err)
		}

		if len(rows) == 0 {
			continue
		}

		// 找出最大列数
		maxCols := 0
		for _, row := range rows {
			if len(row) > maxCols {
				maxCols = len(row)
			}
		}

		if maxCols == 0 {
			continue
		}

		// 生成 Markdown 表格
		for ri, row := range rows {
			sb.WriteString("| ")
			for ci := 0; ci < maxCols; ci++ {
				if ci > 0 {
					sb.WriteString(" | ")
				}
				if ci < len(row) {
					sb.WriteString(strings.ReplaceAll(row[ci], "\n", "<br/>"))
				}
			}
			sb.WriteString(" |\n")

			// 第一行后添加分隔行
			if ri == 0 {
				sb.WriteString("|")
				for ci := 0; ci < maxCols; ci++ {
					sb.WriteString(" --- |")
				}
				sb.WriteString("\n")
			}
		}
	}

	return sb.String(), nil
}

// PdfToMd 将 PDF 文件转换为 markdown
// inputPath: 输入的 pdf 文件路径
// outputPath: 可选，输出的 markdown 文件路径
func (s *DocumentService) PdfToMd(inputPath string, outputPath string) (*DocConvertResult, error) {
	// 校验输入文件
	absInput, err := filepath.Abs(inputPath)
	if err != nil {
		return nil, fmt.Errorf("输入文件路径无效: %v", err)
	}
	if _, err := os.Stat(absInput); os.IsNotExist(err) {
		return nil, fmt.Errorf("输入文件不存在: %s", absInput)
	}
	if !strings.HasSuffix(strings.ToLower(absInput), ".pdf") {
		return nil, fmt.Errorf("仅支持 .pdf 格式文件")
	}

	// 使用 tabula 进行转换
	md, tabulaWarnings, err := tabula.Open(absInput).ToMarkdown()
	if err != nil {
		return nil, fmt.Errorf("pdf 转 markdown 失败: %v", err)
	}

	result := &DocConvertResult{
		Markdown: md,
	}

	if len(tabulaWarnings) > 0 {
		var warnings []string
		for _, w := range tabulaWarnings {
			warnings = append(warnings, w.Message)
		}
		result.Warnings = warnings
	}

	// 如果指定了输出路径，保存到文件
	if outputPath != "" {
		absOutput, err := filepath.Abs(outputPath)
		if err != nil {
			return nil, fmt.Errorf("输出文件路径无效: %v", err)
		}
		outDir := filepath.Dir(absOutput)
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return nil, fmt.Errorf("创建输出目录失败: %v", err)
		}
		if err := os.WriteFile(absOutput, []byte(md), 0644); err != nil {
			return nil, fmt.Errorf("写入输出文件失败: %v", err)
		}
		result.OutputPath = absOutput
	}

	return result, nil
}
