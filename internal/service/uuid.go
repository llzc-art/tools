package service

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

type RandomGenService struct{}

func NewRandomGenService() *RandomGenService {
	return &RandomGenService{}
}

// 预定义字符集
var charsets = map[string]string{
	"alphanumeric": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	"alpha":        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"upper":        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"lower":        "abcdefghijklmnopqrstuvwxyz",
	"numeric":      "0123456789",
	"hex":          "0123456789abcdef",
	"hex_upper":    "0123456789ABCDEF",
	"base62":       "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	"base64":       "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
	"symbol":       "!@#$%^&*()_+-=[]{}|;:',.<>?/`~",
	"alphanum_sym": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=",
}

type RandomGenResult struct {
	Items      []string `json:"items"`
	Count      int      `json:"count"`
	Length     int      `json:"length"`
	Mode       string   `json:"mode"`
	Charset    string   `json:"charset,omitempty"`
	CustomCS   string   `json:"customCharset,omitempty"`
	SnowEpoch  int64    `json:"snowEpoch,omitempty"`
	SnowNodeID int64    `json:"snowNodeId,omitempty"`
}

type RandomGenParams struct {
	Count         int    `json:"count"`
	Length        int    `json:"length"`
	Mode          string `json:"mode"`           // uuid, uuid_nodash, random, custom, snowflake
	Charset       string `json:"charset"`        // 预定义字符集名称
	CustomCharset string `json:"customCharset"`  // 自定义字符集
	NoDash        bool   `json:"noDash"`         // UUID 是否去掉横线（兼容旧参数）
	SnowEpoch     int64  `json:"snowEpoch"`      // 雪花算法起始时间（毫秒），默认 2024-01-01 00:00:00 UTC
	SnowNodeID    int64  `json:"snowNodeId"`     // 雪花算法节点ID (0-1023)
}

func (s *RandomGenService) Generate(params RandomGenParams) *RandomGenResult {
	if params.Count <= 0 {
		params.Count = 1
	}
	if params.Count > 100 {
		params.Count = 100
	}

	items := make([]string, params.Count)
	result := &RandomGenResult{
		Count: params.Count,
		Mode:  params.Mode,
	}

	switch params.Mode {
	case "uuid":
		for i := 0; i < params.Count; i++ {
			items[i] = generateV4()
		}
		result.Length = 36
	case "uuid_nodash":
		for i := 0; i < params.Count; i++ {
			items[i] = strings.ReplaceAll(generateV4(), "-", "")
		}
		result.Length = 32
	case "snowflake":
		if params.SnowEpoch <= 0 {
			// 默认 2024-01-01 00:00:00 UTC
			params.SnowEpoch = 1704067200000
		}
		if params.SnowNodeID < 0 || params.SnowNodeID > 1023 {
			params.SnowNodeID = 1
		}
		sf := newSnowflake(params.SnowEpoch, params.SnowNodeID)
		for i := 0; i < params.Count; i++ {
			items[i] = fmt.Sprintf("%d", sf.Next())
		}
		result.Length = 19
		result.SnowEpoch = params.SnowEpoch
		result.SnowNodeID = params.SnowNodeID
	default:
		// random 或 custom
		if params.Length <= 0 {
			params.Length = 32
		}
		if params.Length > 1024 {
			params.Length = 1024
		}
		result.Length = params.Length

		cs := ""
		if params.Mode == "custom" && params.CustomCharset != "" {
			cs = params.CustomCharset
			result.CustomCS = cs
		} else {
			if params.Charset == "" {
				params.Charset = "alphanumeric"
			}
			cs = charsets[params.Charset]
			if cs == "" {
				cs = params.Charset // 可能直接传了字符集
			}
			result.Charset = params.Charset
		}

		for i := 0; i < params.Count; i++ {
			items[i] = generateRandomString(params.Length, cs)
		}
	}

	result.Items = items
	return result
}

func generateV4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func generateRandomString(length int, charset string) string {
	if len(charset) == 0 {
		charset = charsets["alphanumeric"]
	}
	csLen := big.NewInt(int64(len(charset)))
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		n, _ := rand.Int(rand.Reader, csLen)
		result[i] = charset[n.Int64()]
	}
	return string(result)
}

// ========== 雪花算法 (Snowflake) ==========

const (
	snowflakeNodeBits  = 10
	snowflakeSeqBits   = 12
	snowflakeMaxNode   = -1 ^ (-1 << snowflakeNodeBits)   // 1023
	snowflakeMaxSeq    = -1 ^ (-1 << snowflakeSeqBits)    // 4095
	snowflakeNodeShift = snowflakeSeqBits
	snowflakeTimeShift = snowflakeSeqBits + snowflakeNodeBits
)

type snowflake struct {
	mu      sync.Mutex
	epoch   int64 // 起始时间（毫秒）
	nodeID  int64 // 节点ID (0-1023)
	lastTs  int64 // 上次时间戳
	sequence int64 // 序列号
}

func newSnowflake(epoch, nodeID int64) *snowflake {
	return &snowflake{
		epoch:  epoch,
		nodeID: nodeID & snowflakeMaxNode,
	}
}

func (s *snowflake) Next() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UnixMilli()
	ts := now - s.epoch

	if ts <= s.lastTs {
		// 时钟回拨或同一毫秒
		if ts == s.lastTs {
			s.sequence = (s.sequence + 1) & snowflakeMaxSeq
			if s.sequence == 0 {
				// 序列号溢出，等待下一毫秒
				for now <= s.lastTs+s.epoch {
					time.Sleep(100 * time.Microsecond)
					now = time.Now().UnixMilli()
				}
				ts = now - s.epoch
			}
		} else {
			// 时钟回拨，序列号归零
			s.sequence = 0
		}
	} else {
		s.sequence = 0
	}

	s.lastTs = ts
	return (ts << snowflakeTimeShift) | (s.nodeID << snowflakeNodeShift) | s.sequence
}
