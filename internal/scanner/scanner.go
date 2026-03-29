package scanner

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var ignoredFiles = []string{
	"go.sum",
	".secret-scanner-cache.json",
}

var keywords = []string{
	"password",
	"secret",
	"token",
	"api_key",
	"apikey",
	"access_key",
	"auth",
}
var allowlist = []string{
	"namelessweakl1ng",
}

var seen = make(map[string]bool)
var seenMutex sync.Mutex
var verbose bool
var ignoredDirs []string

type Result struct {
	File     string
	Line     int
	Match    string
	Severity string
}

type GroupedResult struct {
	Match     string
	Severity  string
	Locations []Location
}

type Location struct {
	File string
	Line int
}

func isAllowlisted(s string) bool {
	s = strings.ToLower(s)

	for _, a := range allowlist {
		if strings.Contains(s, strings.ToLower(a)) {
			return true
		}
	}

	return false
}

func SetVerbose(v bool) {
	verbose = v
}

func SetIgnoredDirs(dirs []string) {
	ignoredDirs = dirs
}

func isLikelyVariable(s string) bool {
	hasLetter := false
	hasNumber := false

	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasLetter = true
		}
		if c >= '0' && c <= '9' {
			hasNumber = true
		}
	}

	// variable names usually have letters but no numbers
	return hasLetter && !hasNumber
}

func calculateScore(isRegex bool, entropy float64, contextScore int, isValidated bool) int {
	score := 0

	if isRegex {
		score += 4
	}

	if entropy > 4.0 {
		score += 4
	} else if entropy > 3.0 {
		score += 2
	}

	score += contextScore

	if isValidated {
		score += 5 // 🔥 BIG BOOST
	}

	return score
}
func ScanFiles(paths []string) []GroupedResult {
	seen = make(map[string]bool)

	resultMap := make(map[string]*GroupedResult)

	for _, path := range paths {

		// ✅ skip ignored
		if ShouldIgnore(path) || strings.Contains(path, "testdata") {
			continue
		}

		// ✅ skip binary
		if isBinary(path) {
			continue
		}

		// ✅ skip large files
		info, err := os.Stat(path)
		if err != nil || info.Size() > 5*1024*1024 {
			continue
		}

		fileResults := scanFile(path)

		for _, r := range fileResults {
			existing, ok := resultMap[r.Match]

			if !ok {
				resultMap[r.Match] = &GroupedResult{
					Match:    r.Match,
					Severity: r.Severity,
					Locations: []Location{
						{File: r.File, Line: r.Line},
					},
				}
			} else {
				existing.Locations = append(existing.Locations, Location{
					File: r.File,
					Line: r.Line,
				})

				if r.Severity == "HIGH" {
					existing.Severity = "HIGH"
				}
			}
		}
	}

	var results []GroupedResult
	for _, v := range resultMap {
		results = append(results, *v)
	}

	return results
}

func getSeverity(score int) string {
	if score >= 10 {
		return "HIGH"
	}
	if score >= 6 {
		return "MEDIUM"
	}
	return "LOW"
}
func makeFingerprint(file string, line int, match string) string {
	data := fmt.Sprintf("%s:%d:%s", file, line, match)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

func hasContext(line string) int {
	line = strings.ToLower(line)
	score := 0

	for _, k := range keywords {
		if strings.Contains(line, k) {

			// stronger keywords
			if k == "password" || k == "secret" {
				score += 7
			} else {
				score += 3
			}
		}
	}

	return score
}

func isBase64Like(s string) bool {
	if len(s) < 20 {
		return false
	}

	for _, c := range s {
		if !(c >= 'a' && c <= 'z' ||
			c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' ||
			c == '+' || c == '/' || c == '=') {
			return false
		}
	}

	return true
}

func extractStrings(line string) []string {
	var results []string
	current := ""

	for _, ch := range line {
		if ch == '"' || ch == '\'' {
			continue
		}

		if (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || (ch == '_') {
			current += string(ch)
		} else {
			if len(current) > 0 {
				results = append(results, current)
				current = ""
			}
		}
	}

	if len(current) > 0 {
		results = append(results, current)
	}

	return results
}

func isLikelyFalsePositive(s string) bool {

	// UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
	if len(s) == 36 && strings.Count(s, "-") == 4 {
		return true
	}

	// detect real hex hash (only lowercase a-f + digits)
	isHex := true
	for _, c := range s {
		if !((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) {
			isHex = false
			break
		}
	}

	// only ignore if it's clearly a hash (long + pure hex)
	if isHex && len(s) >= 32 {
		return true
	}

	// base64-like (common noise)
	if strings.Contains(s, "==") && len(s) > 20 {
		return true
	}

	return false
}

func isBinary(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil {
		return false
	}

	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return true
		}
	}

	return false
}

func ScanGitContent(content string) []Result {
	var results []Result

	lines := strings.Split(content, "\n")

	for i, line := range lines {

		// Only scan added lines
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}

		// Remove "+" prefix
		line = strings.TrimPrefix(line, "+")

		// 🔁 Reuse your existing logic
		tokens := extractStrings(line)

		for _, token := range tokens {
			matches := MatchRegex(token)

			for _, m := range matches {
				isValidated := false
				if isLikelyVariable(m.Value) || isBase64Like(m.Value) {
					continue
				}

				// JWT
				if strings.HasPrefix(m.Value, "eyJ") {
					if !IsValidJWT(m.Value) {
						continue
					}
					isValidated = true
				}

				// AWS
				if strings.HasPrefix(m.Value, "AKIA") {
					if !IsValidAWSKey(m.Value) {
						continue
					}
					isValidated = true
				}

				fingerprint := makeFingerprint(fmt.Sprintf("git-%d-%s", i, line), i, m.Value)

				seenMutex.Lock()
				if seen[fingerprint] {
					seenMutex.Unlock()
					continue
				}
				seen[fingerprint] = true
				seenMutex.Unlock()

				severity := m.Rule.Severity

				if severity == "" {
					contextScore := hasContext(line)
					entropy := CalculateEntropy(m.Value)
					score := calculateScore(true, entropy, contextScore, isValidated)
					severity = getSeverity(score)
				}

				results = append(results, Result{
					File:     "git-history",
					Line:     i + 1,
					Match:    m.Value,
					Severity: severity,
				})
			}
		}
	}

	return results
}

func ScanDirectory(root string) []GroupedResult {
	seen = make(map[string]bool)
	cache := LoadCache()
	newCache := make(FileCache)
	resultMap := make(map[string]*GroupedResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	type FileJob struct {
		Path string
		Hash string
	}

	fileChan := make(chan FileJob, 100)

	// worker pool
	numWorkers := 5

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range fileChan {
				path := job.Path
				hash := job.Hash

				fileResults := scanFile(path)

				mu.Lock()

				newCache[path] = CachedFile{
					Hash:    hash,
					Results: fileResults,
				}

				for _, r := range fileResults {

					existing, ok := resultMap[r.Match]

					if !ok {
						resultMap[r.Match] = &GroupedResult{
							Match:    r.Match,
							Severity: r.Severity,
							Locations: []Location{
								{File: r.File, Line: r.Line},
							},
						}
					} else {
						existing.Locations = append(existing.Locations, Location{
							File: r.File,
							Line: r.Line,
						})

						if r.Severity == "HIGH" {
							existing.Severity = "HIGH"
						}
					}
				}
				mu.Unlock()
			}
		}()
	}

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {

		// ✅ FIRST: handle error BEFORE using info
		if err != nil {
			if verbose {
				fmt.Println("[WARN] Skipping:", path, "error:", err)
			}
			return nil
		}

		// ✅ EXTRA SAFETY (important)
		if info == nil {
			return nil
		}
		if ShouldIgnore(path) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if info.Size() > 5*1024*1024 {
			return nil
		}
		if isBinary(path) {
			return nil
		}
		// ✅ ADD THIS HERE
		if ShouldIgnore(path) {
			return nil
		}

		// 🔥 NEW CODE STARTS HERE
		hash, err := HashFile(path)
		if err != nil {
			return nil
		}

		if cached, ok := cache[path]; ok && cached.Hash == hash {
			if verbose {
				fmt.Println("Reusing cached results:", path)
			}

			// 🔥 reuse previous results
			mu.Lock()
			for _, r := range cached.Results {
				existing, ok := resultMap[r.Match]

				if !ok {
					resultMap[r.Match] = &GroupedResult{
						Match:    r.Match,
						Severity: r.Severity,
						Locations: []Location{
							{File: r.File, Line: r.Line},
						},
					}
				} else {
					existing.Locations = append(existing.Locations, Location{
						File: r.File,
						Line: r.Line,
					})
				}
			}
			mu.Unlock()

			newCache[path] = cached
			return nil
		}
		// 🔥 NEW CODE ENDS HERE

		fileChan <- FileJob{
			Path: path,
			Hash: hash,
		}
		return nil
	})

	close(fileChan)
	wg.Wait()

	var results []GroupedResult
	for _, v := range resultMap {
		results = append(results, *v)
	}
	SaveCache(newCache)
	return results
}

func scanFile(path string) []Result {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var results []Result
	scanner := bufio.NewScanner(file)

	lineNum := 1
	for scanner.Scan() {
		line := scanner.Text()
		if verbose {
			if lineNum == 1 && verbose {
				fmt.Printf("Scanning file: %s\n", path)
			}
		}
		// 🔥 Strong keyword-based detection
		lower := strings.ToLower(line)
		tokens := extractStrings(line)

		for _, k := range keywords {
			if strings.Contains(lower, k) && len(line) > 10 && len(tokens) > 0 {

				for _, t := range tokens {
					if len(t) >= 16 &&
						!isAllowlisted(t) &&
						!isLikelyFalsePositive(t) &&
						!isLikelyVariable(t) &&
						!isBase64Like(t) {
						fingerprint := makeFingerprint(path, lineNum, t)

						seenMutex.Lock()
						if seen[fingerprint] {
							seenMutex.Unlock()
							continue
						}
						seen[fingerprint] = true
						seenMutex.Unlock()
						if verbose {
							fmt.Printf("[DEBUG] Keyword match: %s (%s:%d)\n", t, path, lineNum)
						}
						results = append(results, Result{
							File:     path,
							Line:     lineNum,
							Match:    t,
							Severity: "MEDIUM",
						})
					}
				}
			}
		}
		// 🔍 Regex-based detection
		tokens = extractStrings(line)

		for _, token := range tokens {
			matches := MatchRegex(token)
			isValidated := false

			for _, m := range matches {
				if isAllowlisted(m.Value) {
					continue
				}
				if isLikelyVariable(m.Value) || isBase64Like(m.Value) {
					continue
				}
				// JWT
				if strings.HasPrefix(m.Value, "eyJ") {
					if !IsValidJWT(m.Value) {
						continue
					}
					isValidated = true
				}

				// AWS
				if strings.HasPrefix(m.Value, "AKIA") {
					if !IsValidAWSKey(m.Value) {
						continue
					}
					isValidated = true
				}

				fingerprint := makeFingerprint(path, lineNum, m.Value)

				seenMutex.Lock()
				if seen[fingerprint] {
					seenMutex.Unlock()
					continue
				}
				seen[fingerprint] = true
				seenMutex.Unlock()

				severity := m.Rule.Severity

				// fallback if not defined
				if severity == "" {
					contextScore := hasContext(line)
					entropy := CalculateEntropy(m.Value)

					score := calculateScore(true, entropy, contextScore, isValidated)
					severity = getSeverity(score)
				}

				if verbose {
					fmt.Printf("[DEBUG] Regex match: %s (%s:%d)\n", m.Value, path, lineNum)
				}

				results = append(results, Result{
					File:     path,
					Line:     lineNum,
					Match:    m.Value,
					Severity: severity,
				})
			}
		}

		// 🧠 Entropy-based detection
		tokens = extractStrings(line)

		for _, s := range tokens {
			if isAllowlisted(s) {
				continue
			}
			if strings.Contains(strings.ToLower(s), "namelessweakl1ng") {
				continue
			}

			if isLikelyVariable(s) {
				continue
			}

			if len(s) < 12 {
				continue
			}

			if isLikelyFalsePositive(s) || isBase64Like(s) {
				continue
			}

			entropy := CalculateEntropy(s)
			contextScore := hasContext(line)

			score := calculateScore(false, entropy, contextScore, false)

			if entropy < 4.5 || len(s) < 20 {
				continue
			}

			severity := getSeverity(score)

			fingerprint := makeFingerprint(path, lineNum, s)

			seenMutex.Lock()
			if seen[fingerprint] {
				seenMutex.Unlock()
				continue
			}
			seen[fingerprint] = true
			seenMutex.Unlock()
			if verbose {
				fmt.Printf("[DEBUG] Entropy match: %s (%s:%d)\n", s, path, lineNum)
			}
			results = append(results, Result{
				File:     path,
				Line:     lineNum,
				Match:    s,
				Severity: severity,
			})
		}

		lineNum++
	}

	return results
}

func GroupResults(results []Result) []GroupedResult {
	resultMap := make(map[string]*GroupedResult)

	for _, r := range results {
		existing, ok := resultMap[r.Match]

		if !ok {
			resultMap[r.Match] = &GroupedResult{
				Match:    r.Match,
				Severity: r.Severity,
				Locations: []Location{
					{File: r.File, Line: r.Line},
				},
			}
		} else {
			existing.Locations = append(existing.Locations, Location{
				File: r.File,
				Line: r.Line,
			})

			if r.Severity == "HIGH" {
				existing.Severity = "HIGH"
			}
		}
	}

	var grouped []GroupedResult
	for _, v := range resultMap {
		grouped = append(grouped, *v)
	}

	return grouped
}
