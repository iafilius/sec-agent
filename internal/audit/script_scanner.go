package audit

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ScriptFinding represents an insecure command-line flag or credential pattern detected in a script file.
type ScriptFinding struct {
	FilePath    string `json:"file_path"`
	LineNumber  int    `json:"line_number"`
	LineSnippet string `json:"line_snippet"`
	Match       string `json:"match"`
	Reason      string `json:"reason"`
	Suggestion  string `json:"suggestion"`
}

var (
	shortPassFlagRegex = regexp.MustCompile(`(?i)(?:^|[\s;&|])(?:(?:sudo\s+)?([a-zA-Z0-9_\-\.\/]+)\s+)?-p(?:=|\s+)(['"]?)([^\s;&|\$\-\'\"\#` + "`" + `]+)`)
	longPassFlagRegex  = regexp.MustCompile(`(?i)(?:--password|--pass|--token|--auth-token|--api-key)(?:=|\s+)(['"]?)([^\s;&|\$\-\'\"\#` + "`" + `]+)`)

	safeShortFlagCommands = map[string]bool{
		"mkdir": true, "ssh": true, "scp": true, "sftp": true, "pacman": true,
		"tar": true, "sed": true, "grep": true, "psql": true, "ping": true,
		"git": true, "docker": true, "podman": true, "nc": true, "netcat": true,
		"socat": true, "iptables": true, "rsync": true, "make": true,
	}
)

func isNumericOrPort(s string) bool {
	if _, err := strconv.Atoi(s); err == nil {
		return true
	}
	return false
}

// ScanScriptFile parses a single file and flags potential plaintext credentials or insecure CLI password flags.
func ScanScriptFile(filePath string) ([]ScriptFinding, error) {
	// #nosec G304 G703
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []ScriptFinding
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Check long flags (--password=secret, --token secret)
		if matches := longPassFlagRegex.FindStringSubmatch(rawLine); len(matches) >= 3 {
			val := matches[2]
			if val != "" && !strings.HasPrefix(val, "$") && !strings.HasPrefix(val, "{") && !isNumericOrPort(val) {
				findings = append(findings, ScriptFinding{
					FilePath:    filePath,
					LineNumber:  lineNum,
					LineSnippet: strings.TrimSpace(rawLine),
					Match:       matches[0],
					Reason:      "Plaintext credential passed via CLI argument flag (exposed in ps aux and history)",
					Suggestion:  "Extract to environment variable (e.g. export TOKEN=...) or wrap with 'sec run -- <cmd>'",
				})
				continue
			}
		}

		// Check short flag (-p secret)
		if matches := shortPassFlagRegex.FindStringSubmatch(rawLine); len(matches) >= 4 {
			cmd := strings.ToLower(filepath.Base(matches[1]))
			val := matches[3]

			if !safeShortFlagCommands[cmd] && val != "" && !strings.HasPrefix(val, "$") && !strings.HasPrefix(val, "{") && !isNumericOrPort(val) {
				findings = append(findings, ScriptFinding{
					FilePath:    filePath,
					LineNumber:  lineNum,
					LineSnippet: strings.TrimSpace(rawLine),
					Match:       matches[0],
					Reason:      fmt.Sprintf("Insecure '-p <password>' argument used with %s (exposed in ps aux and history)", matches[1]),
					Suggestion:  "Support environment variable method (e.g. PASSWORD=\"${PASSWORD:-$1}\") or execute via 'sec run'",
				})
			}
		}
	}

	return findings, scanner.Err()
}

// IsScriptCandidate determines whether a file extension or name should be analyzed during directory scans.
func IsScriptCandidate(path string, isDir bool) bool {
	if isDir {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".sh", ".bash", ".zsh", ".py", ".rb", ".js", ".ts", ".env":
		return true
	}
	base := filepath.Base(path)
	if base == "Makefile" || base == "Dockerfile" || strings.HasPrefix(base, ".env.") {
		return true
	}
	return false
}

// ScanScriptsDirectory recursively scans a target file or folder for script security issues.
func ScanScriptsDirectory(targetPath string) ([]ScriptFinding, []string, error) {
	cleanTarget := filepath.Clean(targetPath)
	info, err := os.Stat(cleanTarget)
	if err != nil {
		return nil, nil, err
	}

	var scannedFiles []string
	var allFindings []ScriptFinding

	if !info.IsDir() {
		scannedFiles = append(scannedFiles, cleanTarget)
		findings, err := ScanScriptFile(cleanTarget)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}
		return allFindings, scannedFiles, nil
	}

	err = filepath.WalkDir(cleanTarget, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".") && name != "." && name != ".." {
				return filepath.SkipDir
			}
			switch name {
			case "node_modules", "vendor", "publish", "dist", ".bin", "build":
				return filepath.SkipDir
			}
			return nil
		}
		if IsScriptCandidate(path, d.IsDir()) {
			scannedFiles = append(scannedFiles, path)
			findings, scanErr := ScanScriptFile(path)
			if scanErr == nil {
				allFindings = append(allFindings, findings...)
			}
		}
		return nil
	})

	return allFindings, scannedFiles, err
}
