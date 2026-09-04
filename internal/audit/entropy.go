package audit

import (
	"math"
	"strings"
)

var defaultWeakDictionary = []string{
	"admin123", "password", "p@ssword1", "123456", "secret", "test", "demo",
}

// CalculateEntropy computes Shannon entropy in bits per character for a given string.
func CalculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range counts {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// IsHighEntropyString detects high-entropy string tokens commonly indicative of secrets or hashes.
func IsHighEntropyString(s string) bool {
	words := strings.Fields(s)
	for _, word := range words {
		cleaned := strings.Trim(word, `"',:;()[]{}<>=`)
		if len(cleaned) >= 32 && CalculateEntropy(cleaned) > 4.6 {
			return true
		}
	}
	return false
}

// IsWeakPassword checks if a password string has low entropy or matches known weak dictionary passwords.
func IsWeakPassword(val string) bool {
	val = strings.TrimSpace(val)
	if len(val) == 0 {
		return true
	}

	if len(val) < 16 && CalculateEntropy(val) < 3.0 {
		return true
	}

	lowerVal := strings.ToLower(val)
	for _, w := range defaultWeakDictionary {
		if lowerVal == w || strings.Contains(lowerVal, w) {
			return true
		}
	}

	return false
}
