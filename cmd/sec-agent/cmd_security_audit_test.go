package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secure_secrets/internal/audit"
	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"
)

func TestDaemonSessionHijackingSSHCheck(t *testing.T) {
	profile := "hijack-test-profile"

	// 1. Setup paths
	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	_ = os.Remove(sockPath)
	_ = os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	// 2. Build the 'sec' binary
	buildCmd := exec.Command("go", "build", "-o", "sec_hijack_bin", ".")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("failed to build test binary: %v", err)
	}
	defer os.Remove("sec_hijack_bin")

	// 3. Initialize store
	masterKey := []byte("01234567890123456789012345678902")
	st := &store.EncryptedStore{
		Secrets: map[store.SecretKey]store.SecretEntry{
			"test/key": {Value: "safe-val"},
		},
	}
	_ = store.SaveStore(profile, st, masterKey)

	// 4. Start daemon
	d, err := daemon.NewDaemon(profile, 30*time.Second, Version)
	if err != nil {
		t.Fatalf("failed to create test daemon: %v", err)
	}
	d.SetMasterKeyForTest(masterKey)
	d.SetSecretsForTest(map[string]store.SecretEntry{
		"test/key": {Value: "safe-val"},
	})
	token := "hijack-token-123"
	d.SetSessionTokenForTest(token)

	go func() {
		if err := d.Start(); err != nil {
			t.Logf("daemon stopped: %v", err)
		}
	}()
	defer d.Stop()

	// Wait for socket
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 5. Query the daemon with SSH environment variable set on the query command
	queryCmd := exec.Command("./sec_hijack_bin", "get", "test/key", "--profile", profile)
	queryCmd.Env = append(os.Environ(), "SSH_CLIENT=127.0.0.1 12345 22", "SEC_SESSION_TOKEN="+token)
	out, err := queryCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected query from SSH environment to fail, but it succeeded: %s", string(out))
	}

	if !strings.Contains(string(out), "ACCESS DENIED") {
		t.Errorf("expected access denied error, got: %s", string(out))
	}

	// 6. Verify that the daemon has wiped its keys and locked itself automatically
	safeQueryCmd := exec.Command("./sec_hijack_bin", "get", "test/key", "--profile", profile)
	safeQueryCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	safeOut, err := safeQueryCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected safe query on hijacked-locked session to fail, but it succeeded: %s", string(safeOut))
	}
}

func TestCleanupCommandDryRun(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SEC_CONFIG_DIR", tmpDir)

	testBakFile := filepath.Join(tmpDir, "test_legacy_vault.enc.bak.20260101")
	if err := os.WriteFile(testBakFile, []byte("fake legacy backup"), 0600); err != nil {
		t.Fatalf("failed to write test bak file: %v", err)
	}

	// Dry run cleanup
	handleCleanup("default", true)

	// Verify file still exists after dry run
	if _, err := os.Stat(testBakFile); os.IsNotExist(err) {
		t.Errorf("expected test bak file to remain after --dry-run, but it was deleted")
	}

	// Real cleanup
	handleCleanup("default", false)

	// Verify file was deleted
	if _, err := os.Stat(testBakFile); !os.IsNotExist(err) {
		t.Errorf("expected test bak file to be deleted after cleanup")
	}
}

func TestSecurityAttackVectorDefenses(t *testing.T) {
	t.Run("Path Traversal Attacks Rejection", func(t *testing.T) {
		attackVectors := []string{
			"../../tmp/malicious",
			"/etc/shadow",
			"..\\windows\\system32",
			"prod/../../secret",
			"default\x00path",
			"my profile with spaces",
			"prod\nnewline",
		}

		for _, attack := range attackVectors {
			// Test store path traversal rejection
			if _, err := store.GetStorePath(attack); err == nil {
				t.Errorf("GetStorePath(%q) expected path traversal error, got nil", attack)
			}

			// Test socket path traversal rejection
			if _, err := config.GetSocketPath(attack); err == nil {
				t.Errorf("GetSocketPath(%q) expected path traversal error, got nil", attack)
			}

			// Test PID path traversal rejection
			if _, err := config.GetPIDFilePath(attack); err == nil {
				t.Errorf("GetPIDFilePath(%q) expected path traversal error, got nil", attack)
			}
		}
	})

	t.Run("Subshell Environment Variable Key Injection Filtering", func(t *testing.T) {
		illegalKeys := []string{
			"",
			"   ",
			"123DIGIT_START",
			"BAD=KEY",
			"NULL\x00BYTE",
			"NEWLINE\nKEY",
			"CTRL\x07CHAR",
		}

		for _, k := range illegalKeys {
			if err := config.EnvVarKey(k).Validate(); err == nil {
				t.Errorf("EnvVarKey(%q).Validate() expected error for illegal key, got nil", k)
			}
		}

		validKeys := []string{
			"DATABASE_URL",
			"_PRIVATE_TOKEN",
			"API_KEY_V2",
			"AWS_SECRET_ACCESS_KEY",
		}

		for _, k := range validKeys {
			if err := config.EnvVarKey(k).Validate(); err != nil {
				t.Errorf("EnvVarKey(%q).Validate() unexpected error for valid key: %v", k, err)
			}
		}
	})
}

func TestGitHookScannerAndIDEProxy(t *testing.T) {
	// Test Entropy Calculation
	if !audit.IsHighEntropyString("9aB3xZ7qL1mK4wP8vN2jR5tY6uI0oS9dF") {
		t.Errorf("expected high entropy detection for high entropy base64-like string")
	}
	if audit.IsHighEntropyString("hello world this is a normal string") {
		t.Errorf("did not expect high entropy detection for normal string")
	}

	// Test Rule Exclusion
	rules := []string{"test_file.go", "ignore_me"}
	if !audit.ShouldIgnoreFile("test_file.go", rules) {
		t.Errorf("expected file to be ignored by rules")
	}

	// Test splitEnvPair helper
	pair := splitEnvPair("FOO=BAR")
	if pair.Key != "FOO" || pair.Value != "BAR" {
		t.Errorf("expected Key=FOO Value=BAR, got %v", pair)
	}
}

func TestClipboardConcealmentAndRedactor(t *testing.T) {
	// Test Concealed Clipboard copy on macOS
	if err := copyConcealedToClipboard("test_secret_value_123"); err != nil {
		t.Logf("copyConcealedToClipboard note: %v", err)
	}

	// Test Command Registry Parity for new commands
	spec, found := findCommandSpec("redact")
	if !found || spec.Name != "redact" {
		t.Errorf("expected command 'redact' in registry")
	}

	envSpec, foundEnv := findCommandSpec("env-file")
	if !foundEnv || envSpec.Name != "env-file" {
		t.Errorf("expected command 'env-file' in registry")
	}
}

func TestScriptInsecureFlagScanner(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Insecure script with -p and --password
	insecureScript := filepath.Join(tempDir, "deploy_insecure.sh")
	insecureContent := `#!/bin/bash
echo "Starting deployment"
mysql -u root -p mySecretPass123 -h localhost
./custom-tool --password=SuperSecretPassword --token authKey9876
`
	if err := os.WriteFile(insecureScript, []byte(insecureContent), 0600); err != nil {
		t.Fatalf("failed to write insecure script: %v", err)
	}

	findings, err := audit.ScanScriptFile(insecureScript)
	if err != nil {
		t.Fatalf("scanScriptFile returned error: %v", err)
	}
	if len(findings) < 2 {
		t.Errorf("expected at least 2 insecure findings, got %d", len(findings))
	}

	// 2. Safe script with safe commands, port numbers, env variables
	safeScript := filepath.Join(tempDir, "deploy_safe.sh")
	safeContent := `#!/bin/bash
# Safe mkdir with -p
mkdir -p /var/log/myapp
# Safe SSH with port -p 2222
ssh -p 2222 user@remote-host "ls"
# Safe env var usage
mysql -u root -p"$MYSQL_PWD" -h localhost
sec-agent run -- ./custom-tool
`
	if err := os.WriteFile(safeScript, []byte(safeContent), 0600); err != nil {
		t.Fatalf("failed to write safe script: %v", err)
	}

	safeFindings, err := audit.ScanScriptFile(safeScript)
	if err != nil {
		t.Fatalf("scanScriptFile returned error: %v", err)
	}
	if len(safeFindings) != 0 {
		t.Errorf("expected 0 findings for safe script, got %d: %v", len(safeFindings), safeFindings)
	}
}
