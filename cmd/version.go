package cmd
 
import (
    "fmt"
    "github.com/spf13/cobra"
)
 
var versionCmd = &cobra.Command{
    Use:   "version",
    Short: "show version of lelezc",
    Long: `All tools have a version, this is lelezc's"`,
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println("lelezc-1.0")
    },
}
 
func initVersion()  {
    rootCmd.AddCommand(versionCmd)
}