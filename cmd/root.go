package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "jwt",
	Short: "A helper tool for working with JWTs",
	Long:  "A helper tool for working with JWTs",
}

func init() {
	rootCmd.AddCommand((&DebugTokenCmd{}).CMD())
	rootCmd.AddCommand((&GenerateTokenCmd{}).CMD())
	rootCmd.AddCommand((&GenerateKeyCmd{}).CMD())
}

func Execute() error {
	return rootCmd.Execute()
}
