package service

import (
	"encoding/base64"
)

type Base64Service struct{}

func NewBase64Service() *Base64Service {
	return &Base64Service{}
}

type Base64EncodeResult struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

type Base64DecodeResult struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

// encoding 返回对应的 base64 编码器
func getEncoding(encoding string) *base64.Encoding {
	switch encoding {
	case "url":
		return base64.URLEncoding
	case "url_raw":
		return base64.RawURLEncoding
	case "raw":
		return base64.RawStdEncoding
	default:
		return base64.StdEncoding
	}
}

func (s *Base64Service) Encode(input string, encoding string) *Base64EncodeResult {
	enc := getEncoding(encoding)
	return &Base64EncodeResult{
		Input:  input,
		Output: enc.EncodeToString([]byte(input)),
	}
}

func (s *Base64Service) Decode(input string, encoding string) (*Base64DecodeResult, error) {
	enc := getEncoding(encoding)
	decoded, err := enc.DecodeString(input)
	if err != nil {
		return nil, err
	}
	return &Base64DecodeResult{
		Input:  input,
		Output: string(decoded),
	}, nil
}
