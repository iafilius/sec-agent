package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"secure_secrets/internal/store"
)

func TestCalculateEntropyAndWeakness(t *testing.T) {
	if CalculateEntropy("") != 0.0 {
		t.Errorf("expected 0 entropy for empty string")
	}

	lowEntropy := "aaaaaaa"
	if CalculateEntropy(lowEntropy) > 1.0 {
		t.Errorf("expected low entropy for repetitive string, got %f", CalculateEntropy(lowEntropy))
	}

	highEntropy := "8fA!9xL#2kQ@7vP$1mZ%4wY^6tB&3nC*"
	if !IsHighEntropyString(highEntropy) {
		t.Errorf("expected high entropy detection for random key string")
	}

	if !IsWeakPassword("password") {
		t.Errorf("expected 'password' to be flagged as weak")
	}

	if !IsWeakPassword("admin123") {
		t.Errorf("expected 'admin123' to be flagged as weak")
	}

	if IsWeakPassword("Kx9#mP2$vL8!zQ4@wR7") {
		t.Errorf("expected strong password not to be flagged as weak")
	}
}

func TestScriptScanner(t *testing.T) {
	tmpDir := t.TempDir()
	scriptFile := filepath.Join(tmpDir, "deploy.sh")

	content := `#!/bin/bash
# Safe mkdir
mkdir -p /tmp/myfolder

# Insecure command with -p flag
ansible-vault view vault.yml -p secret123

# Insecure command with --password flag
curl -X POST https://api.example.com --password my-plain-password
`
	if err := os.WriteFile(scriptFile, []byte(content), 0700); err != nil {
		t.Fatalf("failed to write test script: %v", err)
	}

	findings, err := ScanScriptFile(scriptFile)
	if err != nil {
		t.Fatalf("ScanScriptFile failed: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 insecure flag findings, got %d", len(findings))
	}

	dirFindings, scanned, err := ScanScriptsDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ScanScriptsDirectory failed: %v", err)
	}
	if len(scanned) != 1 || len(dirFindings) != 2 {
		t.Errorf("expected 1 scanned file with 2 findings, got %d files and %d findings", len(scanned), len(dirFindings))
	}
}

func TestHistoryAudit(t *testing.T) {
	tmpDir := t.TempDir()
	histFile := filepath.Join(tmpDir, ".zsh_history")

	histContent := `: 1700000000:0;echo "Running tests"
: 1700000001:0;export AWS_KEY=AKIAIOSFODNN7EXAMPLE
: 1700000002:0;curl https://api.com -H "Authorization: Bearer super-secret-vault-token-xyz"
`
	if err := os.WriteFile(histFile, []byte(histContent), 0600); err != nil {
		t.Fatalf("failed to write mock history: %v", err)
	}

	historyFiles := []store.HistoryFile{
		{ShellName: "zsh", Path: histFile},
	}

	secrets := map[string]store.SecretEntry{
		"api/token": {
			Value:   "super-secret-vault-token-xyz",
			Comment: "test secret",
			Created: time.Now(),
		},
	}

	matches := AuditShellHistory(historyFiles, secrets)
	if len(matches) < 2 {
		t.Fatalf("expected at least 2 leak matches (AWS key regex + exact vault token), got %d", len(matches))
	}

	foundVaultMatch := false
	foundRegexMatch := false
	for _, m := range matches {
		if m.MatchType == "Vault Exact Match" && m.SecretPath == "api/token" {
			foundVaultMatch = true
		}
		if m.MatchType == "Regex Match" && m.PatternName == "AWS Access Key ID" {
			foundRegexMatch = true
		}
	}

	if !foundVaultMatch {
		t.Errorf("failed to detect exact vault token in history")
	}
	if !foundRegexMatch {
		t.Errorf("failed to detect AWS key pattern in history")
	}
}

func TestIgnoreRules(t *testing.T) {
	tmpDir := t.TempDir()
	ignoreFile := filepath.Join(tmpDir, ".secignore")
	ignoreContent := `# Ignore node modules and specific keys
node_modules/*
AKIAIOSFODNN7EXAMPLE
`
	if err := os.WriteFile(ignoreFile, []byte(ignoreContent), 0600); err != nil {
		t.Fatalf("failed to write .secignore: %v", err)
	}

	rules := LoadSecIgnoreRules(ignoreFile)
	if len(rules) != 2 {
		t.Fatalf("expected 2 ignore rules, got %d", len(rules))
	}

	if !ShouldIgnoreFile("node_modules/package.json", rules) {
		t.Errorf("expected node_modules/package.json to be ignored")
	}

	if !ShouldIgnoreLine("export AWS=AKIAIOSFODNN7EXAMPLE", rules) {
		t.Errorf("expected line containing AKIAIOSFODNN7EXAMPLE to be ignored")
	}
}
