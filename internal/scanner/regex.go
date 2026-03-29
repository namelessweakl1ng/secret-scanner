package scanner

import (
	"regexp"

	"github.com/namelessweakl1ng/secret-scanner/internal/config"
)

type CompiledRule struct {
	Name     string
	Regex    *regexp.Regexp
	Severity string
}

var compiledRules []CompiledRule

func LoadRules(cfg *config.Config) {
	compiledRules = []CompiledRule{} // ✅ CRITICAL

	for _, r := range cfg.Rules {
		re := regexp.MustCompile(r.Pattern)

		compiledRules = append(compiledRules, CompiledRule{
			Name:     r.Name,
			Regex:    re,
			Severity: r.Severity,
		})
	}
}
func MatchRegex(line string) []struct {
	Rule  CompiledRule
	Value string
} {
	var matches []struct {
		Rule  CompiledRule
		Value string
	}

	for _, rule := range compiledRules {
		re := rule.Regex
		found := re.FindAllString(line, -1)

		for _, f := range found {
			matches = append(matches, struct {
				Rule  CompiledRule
				Value string
			}{
				Rule:  rule,
				Value: f,
			})
		}
	}

	return matches
}
