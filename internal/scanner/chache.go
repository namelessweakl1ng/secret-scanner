package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
)

type CachedFile struct {
	Hash    string
	Results []Result
}

type FileCache map[string]CachedFile

const cacheFile = ".secret-scanner-cache.json"

// Load cache from disk
func LoadCache() FileCache {
	cache := make(FileCache)

	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return cache
	}

	json.Unmarshal(data, &cache)
	return cache
}

// Save cache to disk
func SaveCache(cache FileCache) {
	data, _ := json.MarshalIndent(cache, "", "  ")
	os.WriteFile(cacheFile, data, 0644)
}

// Hash file content
func HashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}
