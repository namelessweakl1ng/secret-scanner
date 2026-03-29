package git

import (
	"bytes"
	"os/exec"
)

// Full history
func GetGitHistory(repoPath string) (string, error) {
	cmd := exec.Command("git", "-C", repoPath, "log", "-p")

	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return "", err
	}

	return out.String(), nil
}

// Only recent changes
func GetGitDiff(repoPath string) (string, error) {
	cmd := exec.Command("git", "-C", repoPath, "diff", "HEAD~1")

	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return "", err
	}

	return out.String(), nil
}
