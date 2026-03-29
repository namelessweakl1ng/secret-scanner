package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	Severity string `yaml:"severity"`
}

type Config struct {
	Rules  []Rule   `yaml:"rules"`
	Ignore []string `yaml:"ignore"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)

	return &config, err
}
