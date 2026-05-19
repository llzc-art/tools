package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/tjfoc/gmsm/sm4"
)

type SymmetricService struct{}

func NewSymmetricService() *SymmetricService {
	return &SymmetricService{}
}

type SymmetricResult struct {
	Algo      string `json:"algo"`
	Mode      string `json:"mode"`
	Operation string `json:"operation"`
	Input     string `json:"input"`
	Output    string `json:"output"`
	Key       string `json:"key"`
}

// ========== 填充方法 ==========

// pkcs7Pad PKCS7 填充
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

// pkcs7Unpad PKCS7 去填充
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("数据为空")
	}
	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, fmt.Errorf("填充数据无效")
	}
	return data[:len(data)-padding], nil
}

// zeroPad 零填充：补 0 到块大小的整数倍
func zeroPad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	if padding == 0 {
		padding = blockSize
	}
	padText := make([]byte, padding)
	return append(data, padText...)
}

// zeroUnpad 去零填充：去掉末尾的零字节
func zeroUnpad(data []byte) []byte {
	end := len(data)
	for end > 0 && data[end-1] == 0 {
		end--
	}
	return data[:end]
}

// applyPad 根据填充类型执行填充
func applyPad(data []byte, blockSize int, padding string) ([]byte, error) {
	switch padding {
	case "pkcs7", "":
		return pkcs7Pad(data, blockSize), nil
	case "zero":
		return zeroPad(data, blockSize), nil
	case "none":
		if len(data)%blockSize != 0 {
			return nil, fmt.Errorf("NoPadding 模式下数据长度必须是块大小(%d)的整数倍", blockSize)
		}
		return data, nil
	default:
		return nil, fmt.Errorf("不支持的填充类型: %s，可选: pkcs7, zero, none", padding)
	}
}

// applyUnpad 根据填充类型去填充
func applyUnpad(data []byte, padding string) ([]byte, error) {
	switch padding {
	case "pkcs7", "":
		return pkcs7Unpad(data)
	case "zero":
		return zeroUnpad(data), nil
	case "none":
		return data, nil
	default:
		return nil, fmt.Errorf("不支持的填充类型: %s", padding)
	}
}

func (s *SymmetricService) Encrypt(algo, mode, input, keyStr, keyFormat, padding, ivHex string) (*SymmetricResult, error) {
	key, err := decodeKey(keyStr, keyFormat)
	if err != nil {
		return nil, err
	}
	iv, err := decodeIV(ivHex)
	if err != nil {
		return nil, err
	}
	data := []byte(input)

	var ciphertext []byte
	switch algo {
	case "aes":
		ciphertext, err = s.encryptAES(data, key, mode, padding, iv)
	case "des":
		ciphertext, err = s.encryptDES(data, key, mode, padding, iv)
	case "3des":
		ciphertext, err = s.encrypt3DES(data, key, mode, padding, iv)
	case "sm4":
		ciphertext, err = s.encryptSM4(data, key, mode, padding, iv)
	default:
		return nil, fmt.Errorf("不支持的算法: %s", algo)
	}
	if err != nil {
		return nil, err
	}

	return &SymmetricResult{
		Algo:      algo,
		Mode:      mode,
		Operation: "encrypt",
		Input:     input,
		Output:    hex.EncodeToString(ciphertext),
		Key:       keyStr,
	}, nil
}

func (s *SymmetricService) Decrypt(algo, mode, inputHex, keyStr, keyFormat, padding, ivHex string) (*SymmetricResult, error) {
	key, err := decodeKey(keyStr, keyFormat)
	if err != nil {
		return nil, err
	}
	iv, err := decodeIV(ivHex)
	if err != nil {
		return nil, err
	}
	data, err := hex.DecodeString(inputHex)
	if err != nil {
		return nil, fmt.Errorf("密文格式错误(需要hex): %v", err)
	}

	var plaintext []byte
	switch algo {
	case "aes":
		plaintext, err = s.decryptAES(data, key, mode, padding, iv)
	case "des":
		plaintext, err = s.decryptDES(data, key, mode, padding, iv)
	case "3des":
		plaintext, err = s.decrypt3DES(data, key, mode, padding, iv)
	case "sm4":
		plaintext, err = s.decryptSM4(data, key, mode, padding, iv)
	default:
		return nil, fmt.Errorf("不支持的算法: %s", algo)
	}
	if err != nil {
		return nil, err
	}

	return &SymmetricResult{
		Algo:      algo,
		Mode:      mode,
		Operation: "decrypt",
		Input:     inputHex,
		Output:    string(plaintext),
		Key:       keyStr,
	}, nil
}

// decodeKey 根据格式解析密钥：text 直接取字节，hex 从十六进制解码
func decodeKey(keyStr, keyFormat string) ([]byte, error) {
	switch keyFormat {
	case "hex":
		key, err := hex.DecodeString(keyStr)
		if err != nil {
			return nil, fmt.Errorf("密钥Hex格式错误: %v", err)
		}
		return key, nil
	case "text", "":
		return []byte(keyStr), nil
	default:
		return nil, fmt.Errorf("不支持的密钥格式: %s，可选: text, hex", keyFormat)
	}
}

// decodeIV 解析 IV，空则返回 nil（使用默认 IV），hex 格式
func decodeIV(ivHex string) ([]byte, error) {
	if ivHex == "" {
		return nil, nil
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return nil, fmt.Errorf("IV格式错误(需要hex): %v", err)
	}
	return iv, nil
}

// ========== AES ==========

func (s *SymmetricService) encryptAES(data, key []byte, mode, padding string, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return s.encryptBlock(data, key, block, mode, padding, iv)
}

func (s *SymmetricService) decryptAES(data, key []byte, mode, padding string, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return s.decryptBlock(data, key, block, mode, padding, iv)
}

// ========== DES ==========

func (s *SymmetricService) encryptDES(data, key []byte, mode, padding string, iv []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return s.encryptBlock(data, key, block, mode, padding, iv)
}

func (s *SymmetricService) decryptDES(data, key []byte, mode, padding string, iv []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return s.decryptBlock(data, key, block, mode, padding, iv)
}

// ========== 3DES ==========

func (s *SymmetricService) encrypt3DES(data, key []byte, mode, padding string, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	return s.encryptBlock(data, key, block, mode, padding, iv)
}

func (s *SymmetricService) decrypt3DES(data, key []byte, mode, padding string, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	return s.decryptBlock(data, key, block, mode, padding, iv)
}

// ========== SM4 ==========

func (s *SymmetricService) encryptSM4(data, key []byte, mode, padding string, iv []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return s.encryptBlock(data, key, block, mode, padding, iv)
}

func (s *SymmetricService) decryptSM4(data, key []byte, mode, padding string, iv []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return s.decryptBlock(data, key, block, mode, padding, iv)
}

// ========== 通用分组模式加密/解密 ==========

func (s *SymmetricService) encryptBlock(data, key []byte, block cipher.Block, mode, padding string, iv []byte) ([]byte, error) {
	// GCM 模式走专用路径（不需要填充）
	if mode == "gcm" {
		return s.encryptGCM(data, block)
	}

	// ECB/CBC 需要填充；流模式(CFB/OFB/CTR)不需要
	var processed []byte
	if mode == "ecb" || mode == "cbc" {
		padded, err := applyPad(data, block.BlockSize(), padding)
		if err != nil {
			return nil, err
		}
		processed = padded
	} else {
		processed = data
	}

	// 获取 IV：优先使用自定义 IV，否则从密钥派生
	getIV := func() []byte {
		if len(iv) > 0 {
			return iv
		}
		defaultIV := make([]byte, block.BlockSize())
		copy(defaultIV, key[:block.BlockSize()])
		return defaultIV
	}

	switch mode {
	case "ecb":
		ciphertext := make([]byte, len(processed))
		bs := block.BlockSize()
		for i := 0; i < len(processed); i += bs {
			block.Encrypt(ciphertext[i:i+bs], processed[i:i+bs])
		}
		return ciphertext, nil
	case "cbc":
		cbc := cipher.NewCBCEncrypter(block, getIV())
		ciphertext := make([]byte, len(processed))
		cbc.CryptBlocks(ciphertext, processed)
		return ciphertext, nil
	case "cfb":
		stream := cipher.NewCFBEncrypter(block, getIV())
		ciphertext := make([]byte, len(data))
		stream.XORKeyStream(ciphertext, data)
		return ciphertext, nil
	case "ofb":
		stream := cipher.NewOFB(block, getIV())
		ciphertext := make([]byte, len(data))
		stream.XORKeyStream(ciphertext, data)
		return ciphertext, nil
	case "ctr":
		stream := cipher.NewCTR(block, getIV())
		ciphertext := make([]byte, len(data))
		stream.XORKeyStream(ciphertext, data)
		return ciphertext, nil
	default:
		return nil, fmt.Errorf("不支持的模式: %s", mode)
	}
}

func (s *SymmetricService) decryptBlock(data, key []byte, block cipher.Block, mode, padding string, iv []byte) ([]byte, error) {
	// GCM 模式走专用路径（不需要去填充）
	if mode == "gcm" {
		return s.decryptGCM(data, block)
	}

	var plaintext []byte
	var err error

	// 获取 IV：优先使用自定义 IV，否则从密钥派生
	getIV := func() []byte {
		if len(iv) > 0 {
			return iv
		}
		defaultIV := make([]byte, block.BlockSize())
		copy(defaultIV, key[:block.BlockSize()])
		return defaultIV
	}

	switch mode {
	case "ecb":
		plaintext = make([]byte, len(data))
		bs := block.BlockSize()
		if len(data)%bs != 0 {
			return nil, fmt.Errorf("密文长度不是块大小的整数倍")
		}
		for i := 0; i < len(data); i += bs {
			block.Decrypt(plaintext[i:i+bs], data[i:i+bs])
		}
	case "cbc":
		cbc := cipher.NewCBCDecrypter(block, getIV())
		plaintext = make([]byte, len(data))
		cbc.CryptBlocks(plaintext, data)
	case "cfb":
		stream := cipher.NewCFBDecrypter(block, getIV())
		plaintext = make([]byte, len(data))
		stream.XORKeyStream(plaintext, data)
	case "ofb":
		stream := cipher.NewOFB(block, getIV())
		plaintext = make([]byte, len(data))
		stream.XORKeyStream(plaintext, data)
	case "ctr":
		stream := cipher.NewCTR(block, getIV())
		plaintext = make([]byte, len(data))
		stream.XORKeyStream(plaintext, data)
	default:
		return nil, fmt.Errorf("不支持的模式: %s", mode)
	}

	if err != nil {
		return nil, err
	}

	// ECB/CBC 需要去填充；流模式(CFB/OFB/CTR)不需要
	if mode == "ecb" || mode == "cbc" {
		plaintext, err = applyUnpad(plaintext, padding)
		if err != nil {
			return nil, err
		}
	}

	return plaintext, nil
}

// ========== GCM 模式 ==========
// 输出格式: nonce(12字节) || ciphertext || tag(16字节)

const gcmNonceSize = 12
const gcmTagSize = 16

func (s *SymmetricService) encryptGCM(data []byte, block cipher.Block) ([]byte, error) {
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM初始化失败: %v", err)
	}

	nonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("生成nonce失败: %v", err)
	}

	// Seal 返回 nonce || ciphertext，其中 ciphertext 末尾包含 tag
	ciphertext := aead.Seal(nil, nonce, data, nil)

	// 拼接: nonce || ciphertext(含tag)
	result := make([]byte, 0, gcmNonceSize+len(ciphertext))
	result = append(result, nonce...)
	result = append(result, ciphertext...)
	return result, nil
}

func (s *SymmetricService) decryptGCM(data []byte, block cipher.Block) ([]byte, error) {
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM初始化失败: %v", err)
	}

	if len(data) < gcmNonceSize+aead.NonceSize() {
		// 至少需要 nonce + tag 长度
		return nil, fmt.Errorf("密文数据过短，无法提取nonce和tag")
	}

	nonce := data[:gcmNonceSize]
	ciphertextWithTag := data[gcmNonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertextWithTag, nil)
	if err != nil {
		return nil, fmt.Errorf("GCM解密失败(数据可能被篡改或密钥错误): %v", err)
	}
	return plaintext, nil
}

// KeySizeInfo 返回算法的密钥长度说明
type KeySizeInfo struct {
	Algo    string `json:"algo"`
	KeyBits []int  `json:"keyBits"`
}

func (s *SymmetricService) KeySizes() []KeySizeInfo {
	return []KeySizeInfo{
		{Algo: "aes", KeyBits: []int{128, 192, 256}},
		{Algo: "des", KeyBits: []int{64}},
		{Algo: "3des", KeyBits: []int{192}},
		{Algo: "sm4", KeyBits: []int{128}},
	}
}
