package service

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type StringService struct{}

func NewStringService() *StringService {
	return &StringService{}
}

type StringCountResult struct {
	Input       string `json:"input"`
	Length      int    `json:"length"`
	ByteCount   int    `json:"byte_count"`
	RuneCount   int    `json:"rune_count"`
	LineCount   int    `json:"line_count"`
	WordCount   int    `json:"word_count"`
	ChineseCount int   `json:"chinese_count"`
}

func (s *StringService) Count(input string) *StringCountResult {
	lineCount := strings.Count(input, "\n") + 1
	if input == "" {
		lineCount = 0
	}

	wordCount := 0
	chineseCount := 0
	for _, r := range input {
		if unicode.Is(unicode.Han, r) {
			chineseCount++
			wordCount++
		} else if unicode.IsSpace(r) {
			// skip
		} else if unicode.IsLetter(r) || unicode.IsDigit(r) {
			wordCount++
		}
	}

	return &StringCountResult{
		Input:        input,
		Length:       len(input),
		ByteCount:    len(input),
		RuneCount:    utf8.RuneCountInString(input),
		LineCount:    lineCount,
		WordCount:    wordCount,
		ChineseCount: chineseCount,
	}
}

type StringCaseResult struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

func (s *StringService) ToUpper(input string) *StringCaseResult {
	return &StringCaseResult{Input: input, Output: strings.ToUpper(input)}
}

func (s *StringService) ToLower(input string) *StringCaseResult {
	return &StringCaseResult{Input: input, Output: strings.ToLower(input)}
}

func (s *StringService) ToCamel(input string) *StringCaseResult {
	parts := strings.Fields(input)
	for i := range parts {
		if i == 0 {
			parts[i] = strings.ToLower(parts[i])
		} else {
			parts[i] = strings.Title(parts[i])
		}
	}
	return &StringCaseResult{Input: input, Output: strings.Join(parts, "")}
}

func (s *StringService) ToSnake(input string) *StringCaseResult {
	var buf strings.Builder
	for i, r := range input {
		if unicode.IsUpper(r) {
			if i > 0 {
				buf.WriteByte('_')
			}
			buf.WriteRune(unicode.ToLower(r))
		} else if r == ' ' || r == '-' {
			buf.WriteByte('_')
		} else {
			buf.WriteRune(r)
		}
	}
	return &StringCaseResult{Input: input, Output: buf.String()}
}

type HexConvertResult struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

func (s *StringService) StringToHex(input string) *HexConvertResult {
	return &HexConvertResult{
		Input:  input,
		Output: fmt.Sprintf("%x", input),
	}
}

func (s *StringService) HexToString(input string) (*HexConvertResult, error) {
	clean := strings.ReplaceAll(input, " ", "")
	clean = strings.ReplaceAll(clean, "0x", "")
	clean = strings.ReplaceAll(clean, "0X", "")
	var buf strings.Builder
	for i := 0; i+2 <= len(clean); i += 2 {
		b, err := strconv.ParseUint(clean[i:i+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("十六进制解码失败: %v", err)
		}
		buf.WriteByte(byte(b))
	}
	return &HexConvertResult{Input: input, Output: buf.String()}, nil
}
