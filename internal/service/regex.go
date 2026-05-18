package service

import (
	"regexp"
)

type RegexService struct{}

func NewRegexService() *RegexService {
	return &RegexService{}
}

type RegexMatchResult struct {
	Pattern string   `json:"pattern"`
	Input   string   `json:"input"`
	Matches []string `json:"matches"`
	Matched bool     `json:"matched"`
}

func (s *RegexService) Match(pattern, input string) (*RegexMatchResult, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	matches := re.FindAllString(input, -1)
	return &RegexMatchResult{
		Pattern: pattern,
		Input:   input,
		Matches: matches,
		Matched: len(matches) > 0,
	}, nil
}

type RegexReplaceResult struct {
	Pattern string `json:"pattern"`
	Input   string `json:"input"`
	Replace string `json:"replace"`
	Output  string `json:"output"`
}

func (s *RegexService) Replace(pattern, input, replace string) (*RegexReplaceResult, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	output := re.ReplaceAllString(input, replace)
	return &RegexReplaceResult{
		Pattern: pattern,
		Input:   input,
		Replace: replace,
		Output:  output,
	}, nil
}
