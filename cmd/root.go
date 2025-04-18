package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "lelezct",
	Short: "lelezct万能工具",
	Long:  `lelezct万能工具`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Use lelezct -h or --help for help.")
	},
}

func initAll() {
	initTime()
	initVersion()
	initDigestCmd()
	initSecureCmd()
	initBase64Cmd()
}

func Execute() {
	initAll()
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
