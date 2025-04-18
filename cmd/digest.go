/**数字签名工具，包括MD5、SHA1、SHA256、SHA512、SHA1WITHRSA等*/
package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"lelezc.com/tools/utils"
)

var digestCmd = &cobra.Command{
	Use:   "digist [operation]",
	Short: "digist tools",
	Long:  `数字签名处理工具, 用于编码或解码数字签名`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		operation := args[0]
		data, err := cmd.Flags().GetString("soureData")
		if err != nil {
			fmt.Println("处理失败", err)
			return
		}

		signData, err := cmd.Flags().GetString("signData")
		if err != nil {
			fmt.Println("处理失败", err)
			return
		}

		switch operation {
		case "fmd5":
			handleFileDigist(data)
		case "md5":
			md5Hash := md5.Sum([]byte(data))
			fmt.Println("MD5:", hex.EncodeToString(md5Hash[:]))
		case "sha1":
			sha1Hash := sha1.Sum([]byte(data))
			fmt.Println("SHA1:", hex.EncodeToString(sha1Hash[:]))
		case "sha256":
			sha256Hash := sha256.Sum256([]byte(data))
			fmt.Println("SHA1:", hex.EncodeToString(sha256Hash[:]))
		case "sha512":
			sha256Hash := sha512.Sum512([]byte(data))
			fmt.Println("SHA1:", hex.EncodeToString(sha256Hash[:]))
		case "sha1ecdsa", "sha256ecdsa", "sha512ecdsa", "noneecdsa":
			pemFile, _ := cmd.Flags().GetString("pemFile")
			handleDigistWithEcdsa(operation, data, pemFile)
		case "sha1rsa", "sha256rsa", "sha512rsa", "nonersa":
			pemFile, _ := cmd.Flags().GetString("pemFile")
			handleDigistWithRsa(operation, data, pemFile)
		case "sha1ecdsav", "sha256ecdsav", "sha512ecdsav", "noneecdsav":
			pemFile, _ := cmd.Flags().GetString("pemFile")
			handleDigistWithEcdsaV(operation, data, signData, pemFile)
		case "sha1rsav", "sha256rsav", "sha512rsav", "nonersav":
			pemFile, _ := cmd.Flags().GetString("pemFile")
			handleDigistWithRsaV(operation, data, signData, pemFile)
		default:
			fmt.Println("不支持的操作类型")
		}
	},
}

func handleDigistWithRsa(operation, data, pemFile string) {
	var err error
	var signature []byte

	rsaPk, err := utils.LoadPrivateKeyFromPEMFile(pemFile)
	if err != nil {
		fmt.Println("处理失败", err)
		return
	}

	switch operation {
	case "sha1rsa":
		hashed := sha1.Sum([]byte(data))
		signature, err = rsa.SignPKCS1v15(rand.Reader, rsaPk, crypto.SHA1, hashed[:])
	case "sha256rsa":
		hashed := sha256.Sum256([]byte(data))
		signature, err = rsa.SignPKCS1v15(rand.Reader, rsaPk, crypto.SHA256, hashed[:])
	case "sha512rsa":
		hashed := sha512.Sum512([]byte(data))
		signature, err = rsa.SignPKCS1v15(rand.Reader, rsaPk, crypto.SHA512, hashed[:])
	case "nonersa":
		hashed := []byte(data)
		signature, err = rsa.SignPKCS1v15(rand.Reader, rsaPk, crypto.Hash(0), hashed[:])
	default:
		err = errors.New("不支持的操作")
	}

	if err != nil {
		fmt.Println("处理失败", err)
	} else {
		fmt.Println(hex.EncodeToString(signature))
	}
}

func handleDigistWithEcdsa(operation, data, pemFile string) {
	var err error
	var signature []byte

	ecsdaPk, err := utils.LoadECPrivateKeyFromPEMFile(pemFile)
	if err != nil {
		fmt.Println("处理失败", err)
		return
	}

	switch operation {
	case "sha1ecdsa":
		hashed := sha1.Sum([]byte(data))
		signature, err = ecdsa.SignASN1(rand.Reader, ecsdaPk, hashed[:])
	case "sha256ecdsa":
		hashed := sha256.Sum256([]byte(data))
		signature, err = ecdsa.SignASN1(rand.Reader, ecsdaPk, hashed[:])
	case "sha512ecdsa":
		hashed := sha512.Sum512([]byte(data))
		signature, err = ecdsa.SignASN1(rand.Reader, ecsdaPk, hashed[:])
	case "noneecdsa":
		hashed := []byte(data)
		signature, err = ecdsa.SignASN1(rand.Reader, ecsdaPk, hashed[:])
	}

	if err != nil {
		fmt.Println("处理失败", err)
	} else {
		fmt.Println(hex.EncodeToString(signature))
	}
}

func handleDigistWithEcdsaV(operation, data, signData, pemFile string) {
	var err error

	ecsdaPk, err := utils.LoadECPublicKeyFromPEMFile(pemFile)
	if err != nil {
		fmt.Println("处理失败", err)
		return
	}

	var isOk bool
	signed, _ := hex.DecodeString(signData)
	switch operation {
	case "sha1ecdsav":
		hashed := sha1.Sum([]byte(data))
		isOk = ecdsa.VerifyASN1(ecsdaPk, hashed[:], signed[:])
	case "sha256ecdsav":
		hashed := sha256.Sum256([]byte(data))
		isOk = ecdsa.VerifyASN1(ecsdaPk, hashed[:], signed[:])
	case "sha512ecdsav":
		hashed := sha512.Sum512([]byte(data))
		isOk = ecdsa.VerifyASN1(ecsdaPk, hashed[:], signed[:])
	case "noneecdsav":
		hashed := []byte(data)
		isOk = ecdsa.VerifyASN1(ecsdaPk, hashed[:], signed[:])
	}

	if err != nil {
		fmt.Println("处理失败", err)
	} else {
		fmt.Println(isOk)
	}
}

func handleDigistWithRsaV(operation, data, signData, pemFile string) {
	var err error

	rsaPk, err := utils.LoadPublicKeyFromPEMFile(pemFile)
	if err != nil {
		fmt.Println("处理失败", err)
		return
	}

	signed, _ := hex.DecodeString(signData)
	switch operation {
	case "sha1rsav":
		hashed := sha1.Sum([]byte(data))
		err = rsa.VerifyPKCS1v15(rsaPk, crypto.SHA1, hashed[:], signed[:])
	case "sha256rsav":
		hashed := sha256.Sum256([]byte(data))
		err = rsa.VerifyPKCS1v15(rsaPk, crypto.SHA256, hashed[:], signed[:])
	case "sha512rsav":
		hashed := sha512.Sum512([]byte(data))
		err = rsa.VerifyPKCS1v15(rsaPk, crypto.SHA512, hashed[:], signed[:])
	case "nonersav":
		hashed := []byte(data)
		err = rsa.VerifyPKCS1v15(rsaPk, crypto.Hash(0), hashed[:], signed[:])
	default:
		err = errors.New("不支持的操作")
	}

	if err != nil {
		fmt.Println("false, error:", err)
	} else {
		fmt.Println("true")
	}
}

func handleFileDigist(filePath string) {
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// 创建 MD5 哈希器
	hasher := md5.New()

	// 将文件内容写入哈希器
	if _, err := io.Copy(hasher, file); err != nil {
		panic(err)
	}

	// 计算哈希值
	hashBytes := hasher.Sum(nil)
	fmt.Println("File MD5:", hex.EncodeToString(hashBytes))
}

func initDigestCmd() {
	digestCmd.Flags().StringP("soureData", "d", "", "源字符串")
	digestCmd.Flags().StringP("signData", "s", "", "签名值Hex")
	digestCmd.Flags().StringP("publicKey", "u", "", "公钥文件或字符串")
	digestCmd.Flags().StringP("privateKey", "r", "", "私钥文件或字符串")
	rootCmd.AddCommand(digestCmd)
}
