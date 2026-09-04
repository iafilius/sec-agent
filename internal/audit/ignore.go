package audit

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// LoadSecIgnoreRules reads and parses ignore patterns from .secignore if present.
func LoadSecIgnoreRules(ignoreFilePath string) []string {
	if ignoreFilePath == "" {
		ignoreFilePath = ".secignore"
	}
	var rules []string
	// #nosec G304 G703
	if data, err := os.ReadFile(ignoreFilePath); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				rules = append(rules, line)
			}
		}
	}
	return rules
}

// ShouldIgnoreFile checks if a given file path matches any .secignore rules.
func ShouldIgnoreFile(file string, rules []string) bool {
	for _, rule := range rules {
		if matched, _ := filepath.Match(rule, file); matched {
			return true
		}
		if strings.Contains(file, rule) {
			return true
		}
	}
	return false
}

// ShouldIgnoreLine checks if a specific line of code matches any .secignore line suppression rules.
func ShouldIgnoreLine(line string, rules []string) bool {
	for _, rule := range rules {
		if strings.Contains(line, rule) {
			return true
		}
	}
	return false
}
