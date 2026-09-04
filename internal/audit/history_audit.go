package audit

import (
	"bufio"
	"os"
	"strings"

	"secure_secrets/internal/store"
)

// LeakMatch records a detected plaintext credential or matching pattern in a workstation shell history file.
type LeakMatch struct {
	MatchType   string `json:"match_type"`
	Path        string `json:"path"`
	LineNumber  int    `json:"line_number"`
	SecretPath  string `json:"secret_path,omitempty"`
	PatternName string `json:"pattern_name,omitempty"`
	LineSnippet string `json:"line_snippet"`
	RedactedVal string `json:"redacted_val,omitempty"`
}

// AuditShellHistory scans discovered shell history files for occurrences of active secrets or known regex credential signatures.
func AuditShellHistory(historyFiles []store.HistoryFile, secrets map[string]store.SecretEntry) []LeakMatch {
	secretValues := make(map[string]string)
	for keyPath, entry := range secrets {
		val := strings.TrimSpace(entry.Value)
		if len(val) > 4 && val != "<migrated_to_sec>" {
			secretValues[val] = keyPath
		}
	}

	var matches []LeakMatch

	for _, hf := range historyFiles {
		// #nosec G304 G703
		f, err := os.Open(hf.Path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			cleanLine := line
			if hf.ShellName == "zsh" && strings.HasPrefix(line, ": ") {
				if idx := strings.Index(line, ";"); idx != -1 {
					cleanLine = line[idx+1:]
				}
			}

			// Engine 1: Exact Vault Secret Matching
			for secVal, secPath := range secretValues {
				if strings.Contains(cleanLine, secVal) {
					redactSnippet := strings.ReplaceAll(cleanLine, secVal, "[REDACTED_BY_SEC]")
					matches = append(matches, LeakMatch{
						MatchType:   "Vault Exact Match",
						Path:        hf.Path,
						LineNumber:  lineNum,
						SecretPath:  secPath,
						LineSnippet: redactSnippet,
						RedactedVal: secVal,
					})
				}
			}

			// Engine 2: Regex Matching
			for _, pat := range DefaultSecretPatterns {
				if found := pat.Regex.FindString(cleanLine); found != "" {
					alreadyMatched := false
					for _, m := range matches {
						if m.Path == hf.Path && m.LineNumber == lineNum {
							alreadyMatched = true
							break
						}
					}
					if !alreadyMatched {
						redactSnippet := strings.ReplaceAll(cleanLine, found, "[REDACTED_BY_SEC]")
						matches = append(matches, LeakMatch{
							MatchType:   "Regex Match",
							Path:        hf.Path,
							LineNumber:  lineNum,
							PatternName: pat.Name,
							LineSnippet: redactSnippet,
							RedactedVal: found,
						})
					}
				}
			}
		}
		_ = f.Close()
	}

	return matches
}
