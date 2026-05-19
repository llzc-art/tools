package service

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/tjfoc/gmsm/sm2"
	gmx509 "github.com/tjfoc/gmsm/x509"
)

type AsymmetricService struct{}

func NewAsymmetricService() *AsymmetricService {
	return &AsymmetricService{}
}

type AsymmetricResult struct {
	Algo      string `json:"algo"`
	Operation string `json:"operation"`
	Input     string `json:"input"`
	Output    string `json:"output"`
}

type SignResult struct {
	Algo      string `json:"algo"`
	Input     string `json:"input"`
	Signature string `json:"signature"`
}

type VerifyResult struct {
	Algo    string `json:"algo"`
	Input   string `json:"input"`
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

// ========== 加密/解密 ==========

func (s *AsymmetricService) Encrypt(algo, input, pubKeyPEM, padding string) (*AsymmetricResult, error) {
	switch algo {
	case "rsa":
		return s.encryptRSA(input, pubKeyPEM, padding)
	case "sm2":
		return s.encryptSM2(input, pubKeyPEM)
	default:
		return nil, fmt.Errorf("不支持的算法: %s", algo)
	}
}

func (s *AsymmetricService) Decrypt(algo, inputHex, privKeyPEM, padding string) (*AsymmetricResult, error) {
	switch algo {
	case "rsa":
		return s.decryptRSA(inputHex, privKeyPEM, padding)
	case "sm2":
		return s.decryptSM2(inputHex, privKeyPEM)
	default:
		return nil, fmt.Errorf("不支持的算法: %s", algo)
	}
}

func (s *AsymmetricService) encryptRSA(input, pubKeyPEM, padding string) (*AsymmetricResult, error) {
	pub, err := parseRSAPublicKey(pubKeyPEM)
	if err != nil {
		return nil, err
	}

	var ciphertext []byte
	switch padding {
	case "oaep":
		ciphertext, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, []byte(input), nil)
	default: // pkcs1v15
		ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(input))
	}
	if err != nil {
		return nil, err
	}
	return &AsymmetricResult{
		Algo:      "rsa",
		Operation: "encrypt",
		Input:     input,
		Output:    hex.EncodeToString(ciphertext),
	}, nil
}

func (s *AsymmetricService) decryptRSA(inputHex, privKeyPEM, padding string) (*AsymmetricResult, error) {
	priv, err := parseRSAPrivateKey(privKeyPEM)
	if err != nil {
		return nil, err
	}
	ciphertext, err := hex.DecodeString(inputHex)
	if err != nil {
		return nil, fmt.Errorf("密文格式错误(需要hex): %v", err)
	}

	var plaintext []byte
	switch padding {
	case "oaep":
		plaintext, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, nil)
	default: // pkcs1v15
		plaintext, err = rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
	}
	if err != nil {
		return nil, err
	}
	return &AsymmetricResult{
		Algo:      "rsa",
		Operation: "decrypt",
		Input:     inputHex,
		Output:    string(plaintext),
	}, nil
}

func (s *AsymmetricService) encryptSM2(input, pubKeyPEM string) (*AsymmetricResult, error) {
	pub, err := parseSM2PublicKey(pubKeyPEM)
	if err != nil {
		return nil, err
	}
	ciphertext, err := pub.EncryptAsn1([]byte(input), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &AsymmetricResult{
		Algo:      "sm2",
		Operation: "encrypt",
		Input:     input,
		Output:    hex.EncodeToString(ciphertext),
	}, nil
}

func (s *AsymmetricService) decryptSM2(inputHex, privKeyPEM string) (*AsymmetricResult, error) {
	priv, err := parseSM2PrivateKey(privKeyPEM)
	if err != nil {
		return nil, err
	}
	ciphertext, err := hex.DecodeString(inputHex)
	if err != nil {
		return nil, fmt.Errorf("密文格式错误(需要hex): %v", err)
	}
	plaintext, err := priv.DecryptAsn1(ciphertext)
	if err != nil {
		return nil, err
	}
	return &AsymmetricResult{
		Algo:      "sm2",
		Operation: "decrypt",
		Input:     inputHex,
		Output:    string(plaintext),
	}, nil
}

// ========== 签名/验签 ==========

func (s *AsymmetricService) Sign(algo, input, privKeyPEM, padding string) (*SignResult, error) {
	switch algo {
	case "rsa":
		return s.signRSA(input, privKeyPEM, padding)
	case "sm2":
		return s.signSM2(input, privKeyPEM)
	default:
		return nil, fmt.Errorf("不支持的算法: %s", algo)
	}
}

func (s *AsymmetricService) Verify(algo, input, signatureHex, pubKeyPEM, padding string) (*VerifyResult, error) {
	switch algo {
	case "rsa":
		return s.verifyRSA(input, signatureHex, pubKeyPEM, padding)
	case "sm2":
		return s.verifySM2(input, signatureHex, pubKeyPEM)
	default:
		return nil, fmt.Errorf("不支持的算法: %s", algo)
	}
}

func (s *AsymmetricService) signRSA(input, privKeyPEM, padding string) (*SignResult, error) {
	priv, err := parseRSAPrivateKey(privKeyPEM)
	if err != nil {
		return nil, err
	}
	hashed := sha256.Sum256([]byte(input))

	var sig []byte
	switch padding {
	case "pss":
		sig, err = rsa.SignPSS(rand.Reader, priv, crypto.SHA256, hashed[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	default: // pkcs1v15
		sig, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	}
	if err != nil {
		return nil, err
	}
	return &SignResult{
		Algo:      "rsa",
		Input:     input,
		Signature: hex.EncodeToString(sig),
	}, nil
}

func (s *AsymmetricService) verifyRSA(input, signatureHex, pubKeyPEM, padding string) (*VerifyResult, error) {
	pub, err := parseRSAPublicKey(pubKeyPEM)
	if err != nil {
		return nil, err
	}
	sig, err := hex.DecodeString(signatureHex)
	if err != nil {
		return nil, fmt.Errorf("签名格式错误(需要hex): %v", err)
	}
	hashed := sha256.Sum256([]byte(input))

	var verifyErr error
	switch padding {
	case "pss":
		verifyErr = rsa.VerifyPSS(pub, crypto.SHA256, hashed[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	default: // pkcs1v15
		verifyErr = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], sig)
	}

	valid := verifyErr == nil
	msg := "验签通过"
	if verifyErr != nil {
		msg = "验签失败: " + verifyErr.Error()
	}
	return &VerifyResult{
		Algo:    "rsa",
		Input:   input,
		Valid:   valid,
		Message: msg,
	}, nil
}

func (s *AsymmetricService) signSM2(input, privKeyPEM string) (*SignResult, error) {
	priv, err := parseSM2PrivateKey(privKeyPEM)
	if err != nil {
		return nil, err
	}
	sig, err := priv.Sign(rand.Reader, []byte(input), nil)
	if err != nil {
		return nil, err
	}
	return &SignResult{
		Algo:      "sm2",
		Input:     input,
		Signature: hex.EncodeToString(sig),
	}, nil
}

func (s *AsymmetricService) verifySM2(input, signatureHex, pubKeyPEM string) (*VerifyResult, error) {
	pub, err := parseSM2PublicKey(pubKeyPEM)
	if err != nil {
		return nil, err
	}
	sig, err := hex.DecodeString(signatureHex)
	if err != nil {
		return nil, fmt.Errorf("签名格式错误(需要hex): %v", err)
	}
	valid := pub.Verify([]byte(input), sig)
	msg := "验签通过"
	if !valid {
		msg = "验签失败"
	}
	return &VerifyResult{
		Algo:    "sm2",
		Input:   input,
		Valid:   valid,
		Message: msg,
	}, nil
}

// ========== 密钥解析辅助函数 ==========

func parseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("无法解析公钥 PEM")
	}
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		pub2, err2 := x509.ParsePKIXPublicKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("无法解析 RSA 公钥")
		}
		rsaPub, ok := pub2.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("不是 RSA 公钥")
		}
		return rsaPub, nil
	}
	return pub, nil
}

func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("无法解析私钥 PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		key2, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("无法解析 RSA 私钥")
		}
		rsaKey, ok := key2.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("不是 RSA 私钥")
		}
		return rsaKey, nil
	}
	return key, nil
}

func parseSM2PublicKey(pemStr string) (*sm2.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("无法解析公钥 PEM")
	}
	// 尝试 gmsm x509 解析
	pub, err := gmx509.ParseSm2PublicKey(block.Bytes)
	if err == nil {
		return pub, nil
	}
	// 尝试标准 PKIX 解析
	pub2, err2 := gmx509.ParsePKIXPublicKey(block.Bytes)
	if err2 == nil {
		if sm2Pub, ok := pub2.(*sm2.PublicKey); ok {
			return sm2Pub, nil
		}
	}
	return nil, fmt.Errorf("无法解析 SM2 公钥")
}

func parseSM2PrivateKey(pemStr string) (*sm2.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("无法解析私钥 PEM")
	}
	// 尝试 gmsm 私钥解析
	priv, err := gmx509.ParseSm2PrivateKey(block.Bytes)
	if err == nil {
		return priv, nil
	}
	// 尝试 PKCS8 无加密解析
	priv2, err2 := gmx509.ParsePKCS8UnecryptedPrivateKey(block.Bytes)
	if err2 == nil {
		return priv2, nil
	}
	return nil, fmt.Errorf("无法解析 SM2 私钥")
}
