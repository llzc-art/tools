/**数字签名工具，包括MD5、SHA1、SHA256、SHA512、SHA1WITHRSA等*/
package cmd

import (
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"
)

var base64Cmd = &cobra.Command{
	Use:   "base64 [operation]",
	Short: "base64 tools",
	Long:  `Base64处理工具, 用于编码或解码base64字符串`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		operation := args[0]
		data, err := cmd.Flags().GetString("data")
		if err != nil {
			fmt.Println("处理失败", err)
			return
		}
		if operation == "encoede" {
			fmt.Println(base64.StdEncoding.EncodeToString([]byte(data)))
		} else if operation == "decode" {
			decodeByte, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				fmt.Println("处理失败", err)
				return
			}
			fmt.Println(string(decodeByte))
		} else {
			fmt.Println("不支持的操作")
		}
	},
}

func initBase64Cmd() {
	base64Cmd.Flags().StringP("data", "d", "", "需要处理的字符串")
	rootCmd.AddCommand(base64Cmd)
}
