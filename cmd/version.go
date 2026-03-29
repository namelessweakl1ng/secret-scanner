package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("secret-scanner v1.0.0")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
