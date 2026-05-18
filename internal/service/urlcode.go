package service

import (
	"net/url"
	"strconv"
	"strings"
)

type URLCodeService struct{}

func NewURLCodeService() *URLCodeService {
	return &URLCodeService{}
}

type URLEncodeComponentResult struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

// EncodeComponent 对 URL 组件进行编码（编码所有特殊字符）
func (s *URLCodeService) EncodeComponent(input string) *URLEncodeComponentResult {
	return &URLEncodeComponentResult{
		Input:  input,
		Output: url.PathEscape(input),
	}
}

type URLDecodeComponentResult struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

func (s *URLCodeService) DecodeComponent(input string) (*URLDecodeComponentResult, error) {
	decoded, err := url.PathUnescape(input)
	if err != nil {
		return nil, err
	}
	return &URLDecodeComponentResult{
		Input:  input,
		Output: decoded,
	}, nil
}

type URLParseResult struct {
	URL      string `json:"url"`
	Scheme   string `json:"scheme"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	Path     string `json:"path"`
	Query    string `json:"query"`
	Fragment string `json:"fragment"`
}

func (s *URLCodeService) Parse(rawURL string) (*URLParseResult, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else if u.Scheme == "http" {
			port = "80"
		}
	}

	return &URLParseResult{
		URL:      rawURL,
		Scheme:   u.Scheme,
		Host:     u.Hostname(),
		Port:     port,
		Path:     u.Path,
		Query:    u.RawQuery,
		Fragment: u.Fragment,
	}, nil
}

type URLBuildResult struct {
	URL string `json:"url"`
}

func (s *URLCodeService) Build(scheme, host, port, path, query, fragment string) *URLBuildResult {
	var buf strings.Builder
	if scheme != "" {
		buf.WriteString(scheme)
		buf.WriteString("://")
	}
	buf.WriteString(host)
	if port != "" && !((scheme == "http" && port == "80") || (scheme == "https" && port == "443")) {
		buf.WriteString(":")
		buf.WriteString(port)
	}
	if path != "" {
		if !strings.HasPrefix(path, "/") {
			buf.WriteString("/")
		}
		buf.WriteString(path)
	}
	if query != "" {
		buf.WriteString("?")
		buf.WriteString(query)
	}
	if fragment != "" {
		buf.WriteString("#")
		buf.WriteString(fragment)
	}
	return &URLBuildResult{URL: buf.String()}
}

type UnicodeEncodeResult struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

func (s *URLCodeService) UnicodeEncode(input string) *UnicodeEncodeResult {
	var buf strings.Builder
	for _, r := range input {
		if r > 127 {
			buf.WriteString(`\u`)
			buf.WriteString(strconv.FormatInt(int64(r), 16))
		} else {
			buf.WriteRune(r)
		}
	}
	return &UnicodeEncodeResult{
		Input:  input,
		Output: buf.String(),
	}
}

type UnicodeDecodeResult struct {
	Input  string `json:"input"`
	Output string `json:"output"`
}

func (s *URLCodeService) UnicodeDecode(input string) (*UnicodeDecodeResult, error) {
	var buf strings.Builder
	i := 0
	for i < len(input) {
		if i+5 < len(input) && input[i:i+2] == `\u` {
			hexStr := input[i+2 : i+6]
			val, err := strconv.ParseInt(hexStr, 16, 32)
			if err != nil {
				buf.WriteByte(input[i])
				i++
				continue
			}
			buf.WriteRune(rune(val))
			i += 6
		} else {
			buf.WriteByte(input[i])
			i++
		}
	}
	return &UnicodeDecodeResult{
		Input:  input,
		Output: buf.String(),
	}, nil
}
