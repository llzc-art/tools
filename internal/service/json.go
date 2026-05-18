package service

import (
	"bytes"
	"encoding/json"
	"strings"
)

type JSONService struct{}

func NewJSONService() *JSONService {
	return &JSONService{}
}

type JSONFormatResult struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

func (s *JSONService) Format(input string, indent int) (*JSONFormatResult, error) {
	if indent <= 0 {
		indent = 2
	}

	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(input), "", strings.Repeat(" ", indent)); err != nil {
		return nil, err
	}

	return &JSONFormatResult{
		Input:  input,
		Output: buf.String(),
	}, nil
}

type JSONCompressResult struct {
	Input   string `json:"input"`
	Output  string `json:"output"`
	Before  int    `json:"before"`
	After   int    `json:"after"`
	Saved   int    `json:"saved"`
}

func (s *JSONService) Compress(input string) (*JSONCompressResult, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(input)); err != nil {
		return nil, err
	}

	output := buf.String()
	before := len(input)
	after := len(output)

	return &JSONCompressResult{
		Input:  input,
		Output: output,
		Before: before,
		After:  after,
		Saved:  before - after,
	}, nil
}
