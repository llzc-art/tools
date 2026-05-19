package service

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/tjfoc/gmsm/sm2"
	gmx509 "github.com/tjfoc/gmsm/x509"
	"golang.org/x/crypto/ssh"
)

type KeyGenService struct{}

func NewKeyGenService() *KeyGenService {
	return &KeyGenService{}
}

type KeyGenResult struct {
	Type       string `json:"type"`
	Algo       string `json:"algo"`
	Bits       int    `json:"bits"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
	Comment    string `json:"comment,omitempty"`
}

func (s *KeyGenService) Generate(keyType string, bits int) (*KeyGenResult, error) {
	switch keyType {
	case "rsa":
		return s.generateRSA(bits)
	case "ecdsa":
		return s.generateECDSA(bits)
	case "ed25519":
		return s.generateEd25519()
	case "sm2":
		return s.generateSM2()
	case "ssh-rsa":
		return s.generateSSHRSA(bits)
	case "ssh-ed25519":
		return s.generateSSHEd25519()
	case "ssh-ecdsa":
		return s.generateSSHECDSA(bits)
	default:
		return nil, fmt.Errorf("不支持的密钥类型: %s", keyType)
	}
}

func (s *KeyGenService) generateRSA(bits int) (*KeyGenResult, error) {
	if bits == 0 {
		bits = 2048
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	privBytes := x509.MarshalPKCS1PrivateKey(key)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	pubBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes})

	return &KeyGenResult{
		Type:       "rsa",
		Algo:       "RSA",
		Bits:       bits,
		PublicKey:  string(pubPEM),
		PrivateKey: string(privPEM),
	}, nil
}

func (s *KeyGenService) generateECDSA(bits int) (*KeyGenResult, error) {
	var curve elliptic.Curve
	switch bits {
	case 224, 0:
		curve = elliptic.P224()
		bits = 224
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		curve = elliptic.P256()
		bits = 256
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	privBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	return &KeyGenResult{
		Type:       "ecdsa",
		Algo:       "ECDSA",
		Bits:       bits,
		PublicKey:  string(pubPEM),
		PrivateKey: string(privPEM),
	}, nil
}

func (s *KeyGenService) generateEd25519() (*KeyGenResult, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	return &KeyGenResult{
		Type:       "ed25519",
		Algo:       "Ed25519",
		Bits:       256,
		PublicKey:  string(pubPEM),
		PrivateKey: string(privPEM),
	}, nil
}

func (s *KeyGenService) generateSM2() (*KeyGenResult, error) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	privBytes, err := gmx509.MarshalSm2UnecryptedPrivateKey(key)
	if err != nil {
		return nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "SM2 PRIVATE KEY", Bytes: privBytes})

	pubBytes, err := gmx509.MarshalSm2PublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "SM2 PUBLIC KEY", Bytes: pubBytes})

	return &KeyGenResult{
		Type:       "sm2",
		Algo:       "SM2",
		Bits:       256,
		PublicKey:  string(pubPEM),
		PrivateKey: string(privPEM),
	}, nil
}

func (s *KeyGenService) generateSSHRSA(bits int) (*KeyGenResult, error) {
	if bits == 0 {
		bits = 2048
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	pubKey, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("生成SSH公钥失败: %v", err)
	}

	sshPub := string(ssh.MarshalAuthorizedKey(pubKey))
	sshPriv := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))

	return &KeyGenResult{
		Type:       "ssh-rsa",
		Algo:       "SSH RSA",
		Bits:       bits,
		PublicKey:  sshPub,
		PrivateKey: sshPriv,
		Comment:    "user@host",
	}, nil
}

func (s *KeyGenService) generateSSHEd25519() (*KeyGenResult, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	pubKey, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil, fmt.Errorf("生成SSH公钥失败: %v", err)
	}

	sshPub := string(ssh.MarshalAuthorizedKey(pubKey))

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	sshPriv := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}))

	return &KeyGenResult{
		Type:       "ssh-ed25519",
		Algo:       "SSH Ed25519",
		Bits:       256,
		PublicKey:  sshPub,
		PrivateKey: sshPriv,
		Comment:    "user@host",
	}, nil
}

func (s *KeyGenService) generateSSHECDSA(bits int) (*KeyGenResult, error) {
	var curve elliptic.Curve
	switch bits {
	case 256, 0:
		curve = elliptic.P256()
		bits = 256
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		curve = elliptic.P256()
		bits = 256
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	pubKey, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("生成SSH公钥失败: %v", err)
	}

	sshPub := string(ssh.MarshalAuthorizedKey(pubKey))

	privBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	sshPriv := string(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	}))

	return &KeyGenResult{
		Type:       "ssh-ecdsa",
		Algo:       "SSH ECDSA",
		Bits:       bits,
		PublicKey:  sshPub,
		PrivateKey: sshPriv,
		Comment:    "user@host",
	}, nil
}

// SupportedTypes 返回支持的密钥类型
type KeyTypeInfo struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Category   string `json:"category"`
	KeyBits    []int  `json:"keyBits,omitempty"`
	DefaultBit int    `json:"defaultBit,omitempty"`
}

func (s *KeyGenService) SupportedTypes() []KeyTypeInfo {
	return []KeyTypeInfo{
		{Type: "rsa", Name: "RSA", Category: "pem", KeyBits: []int{1024, 2048, 3072, 4096}, DefaultBit: 2048},
		{Type: "ecdsa", Name: "ECDSA", Category: "pem", KeyBits: []int{224, 256, 384, 521}, DefaultBit: 256},
		{Type: "ed25519", Name: "Ed25519", Category: "pem"},
		{Type: "sm2", Name: "SM2 (国密)", Category: "pem"},
		{Type: "ssh-rsa", Name: "SSH RSA", Category: "ssh", KeyBits: []int{2048, 3072, 4096}, DefaultBit: 2048},
		{Type: "ssh-ed25519", Name: "SSH Ed25519", Category: "ssh"},
		{Type: "ssh-ecdsa", Name: "SSH ECDSA", Category: "ssh", KeyBits: []int{256, 384, 521}, DefaultBit: 256},
	}
}
