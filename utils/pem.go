package utils

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

func LoadPrivateKeyFromPEMFile(filename string) (*rsa.PrivateKey, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, errors.New("读取PEM文件内容失败")
	}
	return LoadPrivateKeyFromPEM(content)
}

// 以下为加载PEM格式私钥的示例函数
func LoadPrivateKeyFromPEM(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("无法解码PEM数据")
	}

	// 处理PKCS#1格式私钥
	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	// 处理PKCS#8格式私钥
	if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key.(*rsa.PrivateKey), nil
	}

	return nil, errors.New("不支持的私钥格式")
}

func LoadPublicKeyFromPEMFile(filename string) (*rsa.PublicKey, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, errors.New("读取PEM文件内容失败")
	}
	return LoadPublicKeyFromPEM(content)
}

// 以下为加载PEM格式私钥的示例函数
func LoadPublicKeyFromPEM(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("无法解码PEM数据")
	}

	// 处理不同格式的公钥
	switch block.Type {
	case "PUBLIC KEY": // PKCS#8格式
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析PKCS#8公钥失败: %v", err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("不是有效的RSA公钥")
		}
		return rsaPub, nil

	case "RSA PUBLIC KEY": // PKCS#1格式
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析PKCS#1公钥失败: %v", err)
		}
		return pub, nil

	default:
		return nil, fmt.Errorf("不支持的PEM类型: %s", block.Type)
	}
}

func LoadECPrivateKeyFromPEMFile(filename string) (*ecdsa.PrivateKey, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, errors.New("读取PEM文件内容失败")
	}
	return LoadECPrivateKeyFromPEM(content)
}

// 以下为加载PEM格式私钥的示例函数
func LoadECPrivateKeyFromPEM(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("无法解码PEM数据")
	}

	return x509.ParseECPrivateKey(block.Bytes)
}

func LoadECPublicKeyFromPEMFile(filename string) (*ecdsa.PublicKey, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, errors.New("读取PEM文件内容失败")
	}
	return LoadECPublicKeyFromPEM(content)
}

// 以下为加载PEM格式私钥的示例函数
func LoadECPublicKeyFromPEM(pemData []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("无法解码PEM数据")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("不是有效的ECDSA公钥")
	}

	return ecPub, nil
}
