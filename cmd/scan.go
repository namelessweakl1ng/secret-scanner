package cmd

import (
	"fmt"
	"os"

	"github.com/namelessweakl1ng/secret-scanner/internal/config"
	"github.com/namelessweakl1ng/secret-scanner/internal/git"
	"github.com/namelessweakl1ng/secret-scanner/internal/output"
	"github.com/namelessweakl1ng/secret-scanner/internal/scanner"

	"github.com/spf13/cobra"
)

var configPath string
var jsonOutput bool
var verbose bool
var tableOutput bool
var useGit bool
var useDiff bool
var stagedOnly bool
var githubOutput bool

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a directory for secrets",
	Args:  cobra.MinimumNArgs(1),

	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]

		cfg, err := config.LoadConfig(configPath)
		if err != nil {
			fmt.Println("Error loading config:", err)
			os.Exit(2)
		}

		scanner.LoadRules(cfg)
		scanner.SetVerbose(verbose)
		scanner.LoadGitignore(path)
		scanner.SetIgnoredDirs(cfg.Ignore)

		var results []scanner.GroupedResult

		if stagedOnly {
			files, err := git.GetStagedFiles()
			if err != nil {
				fmt.Println("Git error:", err)
				os.Exit(2)
			}

			if len(files) == 0 {
				fmt.Println("No staged files")
				os.Exit(0)
			}

			results = scanner.ScanFiles(files)

		} else if useGit {
			content, err := git.GetGitHistory(path)
			if err != nil {
				fmt.Println("Git error:", err)
				os.Exit(2)
			}

			raw := scanner.ScanGitContent(content)
			results = scanner.GroupResults(raw)

		} else if useDiff {
			content, err := git.GetGitDiff(path)
			if err != nil {
				fmt.Println("Git error:", err)
				os.Exit(2)
			}

			raw := scanner.ScanGitContent(content)
			results = scanner.GroupResults(raw)

		} else {
			results = scanner.ScanDirectory(path)
		}
		if githubOutput {
			output.PrintGitHubAnnotations(results)

			if len(results) > 0 {
				os.Exit(1)
			}
			os.Exit(0)
		}

		if jsonOutput {
			output.PrintJSON(results)

			if len(results) > 0 {
				os.Exit(1)
			}
			os.Exit(0)
		}
		if verbose {
			fmt.Printf("Scanned path: %s\n", path)
			fmt.Printf("Total findings: %d\n", len(results))
		}

		if tableOutput {
			output.PrintTable(results)
		} else {
			output.Print(results)
		}

		if len(results) > 0 {
			os.Exit(1)
		}
		os.Exit(0)
	},
}

func init() {
	scanCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	scanCmd.Flags().StringVar(&configPath, "config", "rules/rules.yaml", "Path to config file")
	scanCmd.Flags().BoolVar(&verbose, "verbose", false, "Enable verbose output")
	scanCmd.Flags().BoolVar(&tableOutput, "table", false, "Output in table format")
	scanCmd.Flags().BoolVar(&useGit, "git", false, "Scan git history")
	scanCmd.Flags().BoolVar(&useDiff, "diff", false, "Scan recent git changes")
	scanCmd.Flags().BoolVar(&stagedOnly, "staged", false, "Scan only staged files")
	scanCmd.Flags().BoolVar(&githubOutput, "github", false, "Output GitHub annotations")
	rootCmd.AddCommand(scanCmd)
}
