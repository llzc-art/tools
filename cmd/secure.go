package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var secureCmd = &cobra.Command{
	Use:   "secure [operation]",
	Short: "secure tools",
	Long:  `数字加密处理工具, 用于加解密文本`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		operation := args[0]
		switch operation {
		case "encrypt":
			encrypt(cmd)
		case "descrypt":
			descrypt(cmd)
		default:
			fmt.Println("不支持的操作类型")
		}
	},
}

func encrypt(cmd *cobra.Command) {

}

func descrypt(cmd *cobra.Command) {

}

func initSecureCmd() {
	digestCmd.Flags().StringP("soureData", "d", "", "源字符串")
	digestCmd.Flags().StringP("publicKey", "u", "", "公钥文件或字符串")
	digestCmd.Flags().StringP("privateKey", "r", "", "私钥文件或字符串")
	rootCmd.AddCommand(secureCmd)
}
