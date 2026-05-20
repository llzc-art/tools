package service

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// DataConvertService 数据格式转换服务
type DataConvertService struct{}

// NewDataConvertService 创建数据格式转换服务
func NewDataConvertService() *DataConvertService {
	return &DataConvertService{}
}

// DataConvertResult 转换结果
type DataConvertResult struct {
	SourceFormat string `json:"source_format"`
	TargetFormat string `json:"target_format"`
	Output       string `json:"output"`
	Error        string `json:"error,omitempty"`
}

// DetectFormat 自动检测数据格式
func (s *DataConvertService) DetectFormat(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}

	// JSON 检测：以 { 或 [ 开头
	if (strings.HasPrefix(input, "{") || strings.HasPrefix(input, "[")) && json.Valid([]byte(input)) {
		return "json"
	}

	// XML 检测：以 < 开头
	if strings.HasPrefix(input, "<") {
		decoder := xml.NewDecoder(strings.NewReader(input))
		for {
			token, err := decoder.Token()
			if err != nil {
				break
			}
			if _, ok := token.(xml.StartElement); ok {
				return "xml"
			}
		}
	}

	// YAML 检测：尝试解析，YAML 是 JSON 的超集所以要排除 JSON
	if !strings.HasPrefix(input, "{") && !strings.HasPrefix(input, "[") && !strings.HasPrefix(input, "<") {
		var v interface{}
		if err := yaml.Unmarshal([]byte(input), &v); err == nil && v != nil {
			return "yaml"
		}
	}

	// 如果前面都没匹配，尝试 YAML（YAML 可以解析简单值）
	var v interface{}
	if err := yaml.Unmarshal([]byte(input), &v); err == nil && v != nil {
		return "yaml"
	}

	return ""
}

// Convert 数据格式转换
func (s *DataConvertService) Convert(input string, sourceFormat string, targetFormat string) *DataConvertResult {
	result := &DataConvertResult{
		SourceFormat: sourceFormat,
		TargetFormat: targetFormat,
	}

	// 自动检测源格式
	if sourceFormat == "" || sourceFormat == "auto" {
		detected := s.DetectFormat(input)
		if detected == "" {
			result.Error = "无法识别输入数据的格式，请手动指定源格式"
			return result
		}
		sourceFormat = detected
		result.SourceFormat = sourceFormat
	}

	// 源格式与目标格式相同
	if sourceFormat == targetFormat {
		result.Output = input
		return result
	}

	// 第一步：解析输入为通用数据结构
	var data interface{}
	var parseErr error

	switch sourceFormat {
	case "json":
		parseErr = json.Unmarshal([]byte(input), &data)
	case "yaml":
		parseErr = yaml.Unmarshal([]byte(input), &data)
	case "xml":
		data, parseErr = xmlToMap(input)
	default:
		result.Error = fmt.Sprintf("不支持的源格式: %s", sourceFormat)
		return result
	}

	if parseErr != nil {
		result.Error = fmt.Sprintf("解析%s失败: %v", sourceFormat, parseErr)
		return result
	}

	// 第二步：转换为目标格式
	var output string
	var convertErr error

	switch targetFormat {
	case "json":
		output, convertErr = toJSON(data)
	case "yaml":
		output, convertErr = toYAML(data)
	case "xml":
		output, convertErr = toXML(data)
	default:
		result.Error = fmt.Sprintf("不支持的目标格式: %s", targetFormat)
		return result
	}

	if convertErr != nil {
		result.Error = fmt.Sprintf("转换为%s失败: %v", targetFormat, convertErr)
		return result
	}

	result.Output = output
	return result
}

// ============================================================
// JSON 转换
// ============================================================

func toJSON(data interface{}) (string, error) {
	// 先清理 YAML 特殊类型
	cleaned := normalizeData(data)
	bytes, err := json.MarshalIndent(cleaned, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// ============================================================
// YAML 转换
// ============================================================

func toYAML(data interface{}) (string, error) {
	cleaned := normalizeData(data)
	var buf strings.Builder
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(cleaned); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ============================================================
// XML 转换
// ============================================================

// xmlRoot XML 根节点
type xmlRoot struct {
	XMLName xml.Name `xml:"root"`
	Content interface{} `xml:",any"`
}

// xmlEntry 用于表示 XML 中的键值对
type xmlEntry struct {
	XMLName xml.Name
	Content string `xml:",chardata"`
	Children []xmlEntry `xml:",any"`
}

func toXML(data interface{}) (string, error) {
	cleaned := normalizeData(data)

	var root xmlEntry
	root.XMLName = xml.Name{Local: "root"}
	root.Children = mapToXMLEntries(cleaned)

	output, err := xml.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", err
	}

	return xml.Header + string(output), nil
}

func mapToXMLEntries(data interface{}) []xmlEntry {
	switch v := data.(type) {
	case map[string]interface{}:
		var entries []xmlEntry
		for key, val := range v {
			entry := xmlEntry{XMLName: xml.Name{Local: sanitizeXMLName(key)}}
			switch child := val.(type) {
			case map[string]interface{}:
				entry.Children = mapToXMLEntries(child)
			case []interface{}:
				for _, item := range child {
					itemEntry := xmlEntry{XMLName: xml.Name{Local: sanitizeXMLName(key) + "Item"}}
					switch it := item.(type) {
					case map[string]interface{}:
						itemEntry.Children = mapToXMLEntries(it)
					default:
						itemEntry.Content = fmt.Sprintf("%v", it)
					}
					entry.Children = append(entry.Children, itemEntry)
				}
			default:
				entry.Content = fmt.Sprintf("%v", child)
			}
			entries = append(entries, entry)
		}
		return entries
	default:
		return []xmlEntry{{Content: fmt.Sprintf("%v", v)}}
	}
}

func xmlToMap(input string) (interface{}, error) {
	decoder := xml.NewDecoder(strings.NewReader(input))
	var result interface{}
	var err error

	result, err = decodeXML(decoder)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func decodeXML(decoder *xml.Decoder) (interface{}, error) {
	result := make(map[string]interface{})

	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}

		switch t := token.(type) {
		case xml.StartElement:
			children, err := decodeXML(decoder)
			if err != nil {
				return nil, err
			}

			// 同名元素合并为数组
			if existing, ok := result[t.Name.Local]; ok {
				switch v := existing.(type) {
				case []interface{}:
					result[t.Name.Local] = append(v, children)
				default:
					result[t.Name.Local] = []interface{}{v, children}
				}
			} else {
				result[t.Name.Local] = children
			}

		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text != "" && len(result) == 0 {
				return text, nil
			}

		case xml.EndElement:
			if len(result) == 0 {
				return "", nil
			}
			if len(result) == 1 {
				for _, v := range result {
					return v, nil
				}
			}
			return result, nil
		}
	}
}

// ============================================================
// 辅助函数
// ============================================================

// normalizeData 规范化数据，将 YAML 的特殊类型转为 JSON 兼容类型
func normalizeData(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		m := make(map[string]interface{}, len(v))
		for key, val := range v {
			m[key] = normalizeData(val)
		}
		return m
	case []interface{}:
		s := make([]interface{}, len(v))
		for i, val := range v {
			s[i] = normalizeData(val)
		}
		return s
	default:
		return v
	}
}

// sanitizeXMLName 清理 XML 标签名（只允许字母数字下划线横线）
func sanitizeXMLName(name string) string {
	var b strings.Builder
	for i, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			b.WriteRune(c)
		} else if c == ' ' {
			b.WriteRune('_')
		} else if i == 0 {
			// 首字符不能是数字，加前缀
			b.WriteString("x_")
			b.WriteRune(c)
		}
	}
	result := b.String()
	if result == "" {
		return "item"
	}
	// 首字符必须是字母或下划线
	if result[0] >= '0' && result[0] <= '9' {
		result = "x_" + result
	}
	return result
}
