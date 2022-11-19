package cmd

import (
	"os"

	"github.com/mxssl/doh/query"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "doh",
	Short: "Simple DNS over HTTPS cli client for cloudflare",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		query.Do(args[0], args[1])
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.SetUsageTemplate("Usage:\n  doh [query type] [domain name]\n")
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
