package scanner

import (
	"bufio"
	"os"
	"strings"
)

var gitignorePatterns []string

func LoadGitignore(root string) {
	file, err := os.Open(root + "/.gitignore")
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		gitignorePatterns = append(gitignorePatterns, line)
	}
}

func ShouldIgnore(path string) bool {
	// 🔥 ADD THIS
	if strings.Contains(path, "testdata") {
		return true
	}

	// existing logic (KEEP)
	for _, pattern := range gitignorePatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}
	for _, ignore := range ignoredDirs {
		if strings.Contains(path, ignore) {
			return true
		}
	}

	for _, f := range ignoredFiles {
		if strings.Contains(path, f) {
			return true
		}
	}

	return false
}
