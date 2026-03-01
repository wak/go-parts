package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

/*
 * helloサブコマンドの定義
 */
var helloCmd = &cobra.Command{
	Use:   "hello",
	Short: "挨拶します。",
	Long:  `cobra-cliのサブコマンドです。--nameオプションで、挨拶する名前を指定できます。`,
	Run: func(cmd *cobra.Command, args []string) {
		name, _ := cmd.Flags().GetString("name")
		fmt.Printf("hello %s.", name)
	},
}

func init() {
	// helloサブコマンドをCobraに登録する
	rootCmd.AddCommand(helloCmd)

	helloCmd.PersistentFlags().String("name", "<unknown>", "Greeting name")
	// helloCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
