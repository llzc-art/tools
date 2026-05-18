package service

import (
	"net/url"
)

type URLService struct{}

func NewURLService() *URLService {
	return &URLService{}
}

type URLEncodeResult struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

func (s *URLService) Encode(input string) *URLEncodeResult {
	return &URLEncodeResult{
		Input:  input,
		Output: url.QueryEscape(input),
	}
}

type URLDecodeResult struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

func (s *URLService) Decode(input string) (*URLDecodeResult, error) {
	decoded, err := url.QueryUnescape(input)
	if err != nil {
		return nil, err
	}
	return &URLDecodeResult{
		Input:  input,
		Output: decoded,
	}, nil
}
