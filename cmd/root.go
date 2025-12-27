package cmd

import (
	"os"

	"github.com/mxssl/doh/query"
	"github.com/spf13/cobra"
)

var (
	whoisFlag  bool
	jsonFlag   bool
	appVersion string
	appCommit  string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "doh",
	Short: "Simple DNS over HTTPS cli client for cloudflare",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		err := query.Do(args[0], args[1], whoisFlag, jsonFlag)
		if err != nil && jsonFlag {
			query.OutputJSONError(err)
			return nil // Prevent Cobra from printing error again
		}
		return err
	},
}

func init() {
	rootCmd.Flags().BoolVar(&whoisFlag, "whois", false, "perform WHOIS lookup for IP addresses")
	rootCmd.Flags().BoolVar(&jsonFlag, "json", false, "output results in JSON format")
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(version, commit string) {
	appVersion = version
	appCommit = commit
	rootCmd.SetUsageTemplate("Usage:\n  doh [flags] [query type] [domain name]\n\nFlags:\n{{.LocalFlags.FlagUsages}}")
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
