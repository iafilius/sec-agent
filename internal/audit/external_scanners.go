package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ToolLookupFunc allows unit tests to override binary discovery.
var ToolLookupFunc = defaultDiscoverTool

// BrewInstallFunc allows unit tests to intercept Homebrew installation calls.
var BrewInstallFunc = defaultInstallViaHomebrew

func defaultDiscoverTool(toolName string) (string, string, bool) {
	candidates := []string{
		toolName,
		filepath.Join("/opt/homebrew/bin", toolName),
		filepath.Join("/usr/local/bin", toolName),
	}
	var binPath string
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil && p != "" {
			binPath = p
			break
		}
	}
	if binPath == "" {
		return "", "", false
	}

	version := "installed"
	var verCmd *exec.Cmd
	if toolName == "gitleaks" {
		// #nosec G204
		verCmd = exec.Command(binPath, "version")
	} else {
		// #nosec G204
		verCmd = exec.Command(binPath, "--version")
	}
	if out, err := verCmd.CombinedOutput(); err == nil {
		v := strings.TrimSpace(string(out))
		if lines := strings.Split(v, "\n"); len(lines) > 0 {
			version = strings.TrimSpace(lines[0])
		}
	}
	return binPath, version, true
}

func defaultInstallViaHomebrew(toolName string) error {
	switch toolName {
	case "gitleaks", "trufflehog":
	default:
		return fmt.Errorf("unsupported scanner tool for Homebrew auto-install: %q", toolName)
	}

	brewPath, err := exec.LookPath("brew")
	if err != nil {
		for _, candidate := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
			if _, statErr := os.Stat(candidate); statErr == nil {
				brewPath = candidate
				break
			}
		}
	}
	if brewPath == "" {
		return fmt.Errorf("Homebrew ('brew') not found on PATH; install Homebrew from https://brew.sh first")
	}

	// #nosec G204
	cmd := exec.Command(brewPath, "install", toolName)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

type gitleaksFinding struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	File        string `json:"File"`
	Match       string `json:"Match"`
	Secret      string `json:"Secret"`
	RuleID      string `json:"RuleID"`
	Commit      string `json:"Commit"`
}

type trufflehogFinding struct {
	DetectorName string `json:"DetectorName"`
	Verified     bool   `json:"Verified"`
	Raw          string `json:"Raw"`
	Redacted     string `json:"Redacted"`
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"Filesystem"`
			Git struct {
				File   string `json:"file"`
				Line   int    `json:"line"`
				Commit string `json:"commit"`
			} `json:"Git"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

// RunExternalScanners discovers and optionally invokes Homebrew-managed gitleaks and trufflehog scanners.
func RunExternalScanners(
	cleanTarget string,
	isDir bool,
	opts ScanOptions,
	profile string,
	vaultValToKey map[string]string,
	ignoreRules []string,
) ([]ScanActionItem, map[string]EngineStatus, []string) {
	statuses := make(map[string]EngineStatus)
	var hints []string
	var items []ScanActionItem

	// Avoid running unconstrained external full-home walks when target is literally $HOME
	isHomeRoot := false
	if home, err := os.UserHomeDir(); err == nil && filepath.Clean(cleanTarget) == filepath.Clean(home) {
		isHomeRoot = true
	}

	// 1. Gitleaks discovery & optional auto-install
	glPath, glVer, glInstalled := ToolLookupFunc("gitleaks")
	if !glInstalled && opts.InstallTools {
		if err := BrewInstallFunc("gitleaks"); err == nil {
			glPath, glVer, glInstalled = ToolLookupFunc("gitleaks")
		} else {
			hints = append(hints, fmt.Sprintf("Failed to auto-install gitleaks via Homebrew: %v", err))
		}
	}

	if !glInstalled {
		hint := "Install 'gitleaks' via Homebrew for 160+ deep token signatures and base64 decoding: brew install gitleaks (or pass --install-tools)"
		statuses["gitleaks"] = EngineStatus{
			Name:        "gitleaks",
			Active:      false,
			Installed:   false,
			InstallHint: "brew install gitleaks",
			Notes:       hint,
		}
		hints = append(hints, hint)
	} else if isHomeRoot {
		statuses["gitleaks"] = EngineStatus{
			Name:       "gitleaks",
			Active:     false,
			Installed:  true,
			Version:    glVer,
			BinaryPath: glPath,
			Notes:      "Skipped full $HOME tree walk in gitleaks to prevent macOS TCC Library stalls; sec-native dotfile scanner active. Run 'sec scan ~/workspace' to run gitleaks on project folders.",
		}
	} else {
		statuses["gitleaks"] = EngineStatus{
			Name:       "gitleaks",
			Active:     true,
			Installed:  true,
			Version:    glVer,
			BinaryPath: glPath,
		}
		glDirItems := executeGitleaks(glPath, "dir", cleanTarget, profile, vaultValToKey, ignoreRules)
		items = append(items, glDirItems...)

		if opts.GitHistory && isDir {
			glGitItems := executeGitleaks(glPath, "git", cleanTarget, profile, vaultValToKey, ignoreRules)
			items = append(items, glGitItems...)
		}
	}

	// 2. TruffleHog discovery & optional execution (--deep or --verify-live)
	thPath, thVer, thInstalled := ToolLookupFunc("trufflehog")
	needTrufflehog := opts.Deep || opts.VerifyLive
	if !thInstalled && needTrufflehog && opts.InstallTools {
		if err := BrewInstallFunc("trufflehog"); err == nil {
			thPath, thVer, thInstalled = ToolLookupFunc("trufflehog")
		} else {
			hints = append(hints, fmt.Sprintf("Failed to auto-install trufflehog via Homebrew: %v", err))
		}
	}

	if !thInstalled {
		hint := "Install 'trufflehog' via Homebrew for 700+ credential detectors and live API verification: brew install trufflehog (or pass --install-tools)"
		statuses["trufflehog"] = EngineStatus{
			Name:        "trufflehog",
			Active:      false,
			Installed:   false,
			InstallHint: "brew install trufflehog",
			Notes:       hint,
		}
		if needTrufflehog {
			hints = append(hints, hint)
		}
	} else if !needTrufflehog {
		statuses["trufflehog"] = EngineStatus{
			Name:       "trufflehog",
			Active:     false,
			Installed:  true,
			Version:    thVer,
			BinaryPath: thPath,
			Notes:      "Installed (standby; pass --deep or --verify-live to enable TruffleHog engine)",
		}
	} else if isHomeRoot {
		statuses["trufflehog"] = EngineStatus{
			Name:       "trufflehog",
			Active:     false,
			Installed:  true,
			Version:    thVer,
			BinaryPath: thPath,
			Notes:      "Skipped on root $HOME directory; target a specific workspace subfolder.",
		}
	} else {
		statuses["trufflehog"] = EngineStatus{
			Name:       "trufflehog",
			Active:     true,
			Installed:  true,
			Version:    thVer,
			BinaryPath: thPath,
		}
		thItems := executeTrufflehog(thPath, cleanTarget, opts, profile, vaultValToKey, ignoreRules)
		items = append(items, thItems...)
	}

	return items, statuses, hints
}

func shouldSkipExternalFindingPath(relPath string, ignoreRules []string) bool {
	if ShouldIgnoreFile(relPath, ignoreRules) {
		return true
	}
	base := filepath.Base(relPath)
	if strings.HasSuffix(base, "_test.go") || strings.HasSuffix(base, ".tmpl") || strings.HasSuffix(base, ".example") || strings.HasSuffix(base, ".sample") {
		return true
	}
	parts := strings.Split(filepath.ToSlash(relPath), "/")
	for _, p := range parts {
		if SafeSkipDirs[p] || p == "publish" {
			return true
		}
	}
	return false
}

func executeGitleaks(binPath, mode, cleanTarget, profile string, vaultValToKey map[string]string, ignoreRules []string) []ScanActionItem {
	args := []string{
		mode,
		"--report-format", "json",
		"--report-path", "-",
		"--redact=100",
		"--no-banner",
		"--exit-code", "0",
		cleanTarget,
	}
	// #nosec G204
	cmd := exec.Command(binPath, args...)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil
	}
	return ParseGitleaksJSONOutput(out, mode, cleanTarget, profile, vaultValToKey, ignoreRules)
}

// ParseGitleaksJSONOutput parses gitleaks JSON output into redacted ScanActionItem entries.
func ParseGitleaksJSONOutput(rawJSON []byte, mode, cleanTarget, profile string, vaultValToKey map[string]string, ignoreRules []string) []ScanActionItem {
	trimmed := bytes.TrimSpace(rawJSON)
	if len(trimmed) == 0 || string(trimmed) == "null" || string(trimmed) == "[]" {
		return nil
	}
	var findings []gitleaksFinding
	if err := json.Unmarshal(trimmed, &findings); err != nil {
		return nil
	}

	var items []ScanActionItem
	for _, f := range findings {
		relPath := relativeDisplayPath(cleanTarget, f.File)
		if shouldSkipExternalFindingPath(relPath, ignoreRules) {
			continue
		}
		if strings.Contains(f.Match, "<migrated_to_sec>") || strings.Contains(f.Match, "[REDACTED_BY_SEC]") {
			continue
		}
		lineNum := f.StartLine
		if lineNum <= 0 {
			lineNum = 1
		}

		cat := "KNOWN_TOKEN_SIGNATURE"
		engineLabel := "gitleaks"
		desc := fmt.Sprintf("Gitleaks detected %s (%s)", f.Description, f.RuleID)
		if mode == "git" && f.Commit != "" {
			cat = "GIT_HISTORY_LEAK"
			engineLabel = "gitleaks-git"
			shortCommit := f.Commit
			if len(shortCommit) > 8 {
				shortCommit = shortCommit[:8]
			}
			desc = fmt.Sprintf("Leaked secret in Git commit %s: %s (%s)", shortCommit, f.Description, f.RuleID)
		}

		matchedVaultKey := ""
		if f.Secret != "" {
			if vk, ok := vaultValToKey[f.Secret]; ok {
				matchedVaultKey = vk
			}
		}

		strat := BuildIntegrationStrategy(profile, relPath, cat, f.RuleID)
		if cat == "GIT_HISTORY_LEAK" {
			strat = IntegrationStrategy{
				Feasibility:      FeasibilityNeedsAdaptation,
				CurrentBlocker:   "Plaintext secret is permanently recorded in Git commit history.",
				SuggestedCommand: fmt.Sprintf("git filter-repo --path %s --invert-paths --force", relPath),
				WorkspaceAdvice: &WorkspaceAdaptationAdvice{
					Summary: "Rotate compromised credential immediately and purge file from Git history",
					Steps: []string{
						fmt.Sprintf("Rotate the leaked credential in the upstream provider and store the new value via: sec set %s", strings.ToLower(strings.ReplaceAll(f.RuleID, "-", "/"))),
						fmt.Sprintf("Rewrite repository history using git-filter-repo: git filter-repo --path %s --invert-paths --force", relPath),
						"Install the sec-agent pre-commit guard to block future leaks: sec githook install",
					},
				},
			}
		}

		snippet := f.Match
		if snippet == "" {
			snippet = fmt.Sprintf("[%s REDACTED]", f.RuleID)
		}
		snippet = ScrubSecretLine(snippet, f.Secret)
		snippet = strings.ReplaceAll(snippet, "REDACTED", "[REDACTED_BY_SEC]")

		items = append(items, ScanActionItem{
			Severity:            SeverityHigh,
			Category:            cat,
			Engines:             []string{engineLabel},
			FilePath:            relPath,
			LineNumber:          lineNum,
			RuleID:              f.RuleID,
			Description:         desc,
			MatchedVaultKey:     matchedVaultKey,
			RedactedSnippet:     snippet,
			Fingerprint:         ComputeFindingFingerprint(relPath, lineNum, cat, f.RuleID),
			IntegrationStrategy: strat,
		})
	}
	return items
}

func executeTrufflehog(binPath, cleanTarget string, opts ScanOptions, profile string, vaultValToKey map[string]string, ignoreRules []string) []ScanActionItem {
	args := []string{"filesystem", "--json", "--no-update"}
	if opts.VerifyLive {
		args = append(args, "--only-verified")
	}
	args = append(args, cleanTarget)
	// #nosec G204
	cmd := exec.Command(binPath, args...)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil
	}
	return ParseTrufflehogJSONLines(out, cleanTarget, profile, vaultValToKey, ignoreRules)
}

// ParseTrufflehogJSONLines parses newline-delimited JSON findings from trufflehog into redacted ScanActionItem entries.
func ParseTrufflehogJSONLines(rawOutput []byte, cleanTarget, profile string, vaultValToKey map[string]string, ignoreRules []string) []ScanActionItem {
	var items []ScanActionItem
	scanner := bufio.NewScanner(bytes.NewReader(rawOutput))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var tf trufflehogFinding
		if err := json.Unmarshal(line, &tf); err != nil || tf.DetectorName == "" {
			continue
		}
		file := tf.SourceMetadata.Data.Filesystem.File
		lineNum := tf.SourceMetadata.Data.Filesystem.Line
		if file == "" {
			file = tf.SourceMetadata.Data.Git.File
			lineNum = tf.SourceMetadata.Data.Git.Line
		}
		if file == "" {
			continue
		}
		relPath := relativeDisplayPath(cleanTarget, file)
		if shouldSkipExternalFindingPath(relPath, ignoreRules) {
			continue
		}
		if lineNum <= 0 {
			lineNum = 1
		}

		matchedVaultKey := ""
		if tf.Raw != "" {
			if vk, ok := vaultValToKey[tf.Raw]; ok {
				matchedVaultKey = vk
			}
		}

		sev := SeverityHigh
		if tf.Verified {
			sev = SeverityCritical
		}
		ruleID := "trufflehog-" + strings.ToLower(tf.DetectorName)
		cat := "KNOWN_TOKEN_SIGNATURE"
		strat := BuildIntegrationStrategy(profile, relPath, cat, tf.DetectorName)

		desc := fmt.Sprintf("TruffleHog detected %s credential", tf.DetectorName)
		if tf.Verified {
			desc = fmt.Sprintf("TruffleHog VERIFIED LIVE %s credential!", tf.DetectorName)
		}

		items = append(items, ScanActionItem{
			Severity:            sev,
			Category:            cat,
			Engines:             []string{"trufflehog"},
			FilePath:            relPath,
			LineNumber:          lineNum,
			RuleID:              ruleID,
			Description:         desc,
			MatchedVaultKey:     matchedVaultKey,
			RedactedSnippet:     fmt.Sprintf("%s: [REDACTED_BY_SEC]", tf.DetectorName),
			VerifiedLive:        tf.Verified,
			Fingerprint:         ComputeFindingFingerprint(relPath, lineNum, cat, ruleID),
			IntegrationStrategy: strat,
		})
	}
	return items
}

