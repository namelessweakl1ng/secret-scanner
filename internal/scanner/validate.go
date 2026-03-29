package scanner

import (
	"encoding/base64"
	"regexp"
	"strings"
)

var awsKeyRegex = regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`)

func IsValidAWSKey(key string) bool {
	return awsKeyRegex.MatchString(key)
}

// Validate JWT structure
func IsValidJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	for _, p := range parts {
		_, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil {
			return false
		}
	}

	return true
}
