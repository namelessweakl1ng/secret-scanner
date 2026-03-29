package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/namelessweakl1ng/secret-scanner/internal/scanner"

	"github.com/olekukonko/tablewriter"
)

type Location struct {
	File string
	Line int
}

func PrintTable(results []scanner.GroupedResult) {
	table := tablewriter.NewWriter(os.Stdout)

	table.Header([]string{"LEVEL", "MATCH", "OCCURRENCES", "LOCATIONS"})

	for _, r := range results {
		var locations []string
		for _, loc := range r.Locations {
			locations = append(locations, fmt.Sprintf("%s:%d", loc.File, loc.Line))
		}

		table.Append([]string{
			r.Severity,
			r.Match,
			fmt.Sprintf("%d", len(r.Locations)),
			strings.Join(locations, ", "),
		})
	}

	table.Render()
}

func colorSeverity(sev string) string {
	switch sev {
	case "HIGH":
		return "\033[31mHIGH\033[0m"
	case "MEDIUM":
		return "\033[33mMEDIUM\033[0m"
	default:
		return sev
	}
}

func Print(results []scanner.GroupedResult) {
	severityRank := map[string]int{
		"HIGH":   3,
		"MEDIUM": 2,
		"LOW":    1,
	}

	sort.Slice(results, func(i, j int) bool {
		return severityRank[results[i].Severity] > severityRank[results[j].Severity]
	})

	for _, r := range results {
		fmt.Printf("[%s] %s (%d occurrences)\n",
			colorSeverity(r.Severity),
			r.Match,
			len(r.Locations),
		)

		for _, loc := range r.Locations {
			fmt.Printf("  → %s:%d\n", loc.File, loc.Line)
		}

		fmt.Println()
	}

	fmt.Printf("Scan complete: %d issue(s) found\n", len(results))
}

func PrintJSON(results []scanner.GroupedResult) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Println("Error generating JSON:", err)
		os.Exit(2)
	}
	fmt.Println(string(data))
}

func PrintGitHubAnnotations(results []scanner.GroupedResult) {
	for _, r := range results {
		for _, loc := range r.Locations {
			level := "warning"

			if r.Severity == "HIGH" {
				level = "error"
			}

			fmt.Printf("::%s file=%s,line=%d::Secret detected (%s)\n",
				level,
				loc.File,
				loc.Line,
				r.Match,
			)
		}
	}
}
