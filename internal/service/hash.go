package service

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"

	"github.com/tjfoc/gmsm/sm3"
)

type HashService struct{}

func NewHashService() *HashService {
	return &HashService{}
}

type HashResult struct {
	Input  string `json:"input"`
	Output string `json:"output"`
	Algo   string `json:"algo"`
}

func (s *HashService) MD5(input string) *HashResult {
	h := md5.Sum([]byte(input))
	return &HashResult{
		Input:  input,
		Output: hex.EncodeToString(h[:]),
		Algo:   "md5",
	}
}

func (s *HashService) SHA1(input string) *HashResult {
	h := sha1.Sum([]byte(input))
	return &HashResult{
		Input:  input,
		Output: hex.EncodeToString(h[:]),
		Algo:   "sha1",
	}
}

func (s *HashService) SHA256(input string) *HashResult {
	h := sha256.Sum256([]byte(input))
	return &HashResult{
		Input:  input,
		Output: hex.EncodeToString(h[:]),
		Algo:   "sha256",
	}
}

func (s *HashService) SHA512(input string) *HashResult {
	h := sha512.Sum512([]byte(input))
	return &HashResult{
		Input:  input,
		Output: hex.EncodeToString(h[:]),
		Algo:   "sha512",
	}
}

func (s *HashService) SM3(input string) *HashResult {
	h := sm3.Sm3Sum([]byte(input))
	return &HashResult{
		Input:  input,
		Output: hex.EncodeToString(h[:]),
		Algo:   "sm3",
	}
}
