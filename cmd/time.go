package cmd

import (
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

var timeCmd = &cobra.Command{
	Use:   "time [operation]",
	Short: "time tools",
	Long:  `时间处理工具, 用于获取当前时间或者时间格式转换`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		operation := args[0]
		if operation == "now" {
			handleNow(cmd)
		} else if operation == "parse" {
			handleParse(cmd)
		} else {
			fmt.Println("不支持的操作")
		}
	},
	ValidArgs: []string{"now", "parse"},
}

func handleNow(cmd *cobra.Command) {
	kind, _ := cmd.Flags().GetString("tkind")
	if kind == "" {
		kind = "d"
	}
	outputTime(kind, time.Now())
}

func handleParse(cmd *cobra.Command) {
	kind, _ := cmd.Flags().GetString("fkind")
	if kind == "" {
		kind = "d"
	}
	tkind, _ := cmd.Flags().GetString("tkind")
	if tkind == "" {
		tkind = "d"
	}
	var err error
	var realtime time.Time
	var datetimeNumber int64
	datetime, _ := cmd.Flags().GetString("datetime")
	datetimeNumber, _ = strconv.ParseInt(datetime, 10, 64)
	switch kind {
	case "d":
		realtime, err = time.Parse(time.DateTime, datetime)
	case "s":
		realtime = time.Unix(datetimeNumber, 0)
	case "m":
		realtime = time.UnixMilli(datetimeNumber)
	case "n":
		realtime = time.UnixMicro(datetimeNumber)
	default:
		realtime, err = time.Parse(time.DateTime, datetime)
	}
	if err != nil {
		fmt.Println("格式化失败", err)
	}
	outputTime(tkind, realtime)
}

func outputTime(kind string, t time.Time) {
	switch kind {
	case "d":
		fmt.Println(t.Format(time.DateTime))
	case "s":
		fmt.Println(t.Unix())
	case "m":
		fmt.Println(t.UnixMilli())
	case "n":
		fmt.Println(t.UnixNano())
	default:
		fmt.Println(t.Format(time.DateTime))
	}
}

func initTime() {
	timeCmd.Flags().StringP("datetime", "d", "", "当前时间字符串")
	timeCmd.Flags().StringP("fkind", "f", "", "源时间戳类型(d、s、m、n)")
	timeCmd.Flags().StringP("tkind", "t", "", "目标时间戳类型(d、s、m、n)")
	rootCmd.AddCommand(timeCmd)
}
