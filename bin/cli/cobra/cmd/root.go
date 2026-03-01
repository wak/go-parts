package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

/*
 * ルートコマンドの定義
 */
var rootCmd = &cobra.Command{
	Use:   "cobra-cli",
	Short: "Cobra sample command (short)",
	Long:  `Cobra sample command (long)`,

	// サブコマンドなしで動作する処理がある場合は、以下を定義する。
	// Run: func(cmd *cobra.Command, args []string) {
	// 	fmt.Print("default command")
	// },
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
}
