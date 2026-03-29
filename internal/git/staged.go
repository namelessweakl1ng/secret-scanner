package git

import (
	"bytes"
	"os/exec"
	"strings"
)

func GetStagedFiles() ([]string, error) {
	cmd := exec.Command("git", "diff", "--cached", "--name-only")

	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(out.String(), "\n")

	var files []string
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			files = append(files, l)
		}
	}

	return files, nil
}
