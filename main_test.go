package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secure_secrets/config"
	"secure_secrets/crypto"
	"secure_secrets/daemon"
	"secure_secrets/store"
)

func TestMainIntegration(t *testing.T) {
	profile := "main-integration-test"

	// 1. Clean up stale files
	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	os.Remove(sockPath)
	os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	// 2. Build the 'sec' binary
	buildCmd := exec.Command("go", "build", "-o", "sec_test_bin", "main.go")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("failed to build sec test binary: %v", err)
	}
	defer os.Remove("sec_test_bin")

	// 3. Programmatically spin up the daemon under the test profile
	d, err := daemon.NewDaemon(profile, 30*time.Second, "v1.0.0")
	if err != nil {
		t.Fatalf("failed to create test daemon: %v", err)
	}

	// Preset the masterKey and dummy secrets to unlock it programmatically
	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901")) // 32-byte key
	d.SetSecretsForTest(map[string]store.SecretEntry{
		"velocloud-provider/vco-url": {
			Value:   "https://vco.example.com",
			Comment: "mock url",
		},
		"velocloud-provider/vco-token": {
			Value:   "mock-token-12345",
			Comment: "mock token",
		},
		"other-category/test-key": {
			Value: "some-value",
		},
	})
	d.SetSessionTokenForTest("integration-token-123")

	go func() {
		if err := d.Start(); err != nil {
			t.Logf("daemon stopped: %v", err)
		}
	}()
	defer d.Stop()

	// Wait for socket to appear
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	testEnv := append(os.Environ(), "SEC_SESSION_TOKEN=integration-token-123")

	// 4. Test 1: Verify 'sec env' output and prefix filtering
	envCmd := exec.Command("./sec_test_bin", "env", "velocloud-provider", "--profile", profile)
	envCmd.Env = testEnv
	envOut, err := envCmd.Output()
	if err != nil {
		t.Fatalf("sec env failed: %v", err)
	}
	envLines := strings.Split(strings.TrimSpace(string(envOut)), "\n")
	if len(envLines) != 2 {
		t.Errorf("expected 2 exported secrets, got %d. Output:\n%s", len(envLines), string(envOut))
	}
	// Check if keys are converted properly
	hasURL := false
	hasToken := false
	for _, line := range envLines {
		if strings.Contains(line, "VELOCLOUD_PROVIDER_VCO_URL") {
			hasURL = true
		}
		if strings.Contains(line, "VELOCLOUD_PROVIDER_VCO_TOKEN") {
			hasToken = true
		}
	}
	if !hasURL || !hasToken {
		t.Errorf("missing expected environment exports in env output: %s", string(envOut))
	}

	// 5. Test 2: Verify 'sec export --format json' output
	expCmd := exec.Command("./sec_test_bin", "export", "--format", "json", "--profile", profile)
	expCmd.Env = testEnv
	expOut, err := expCmd.Output()
	if err != nil {
		t.Fatalf("sec export json failed: %v", err)
	}
	var secrets map[string]store.SecretEntry
	if err := json.Unmarshal(expOut, &secrets); err != nil {
		t.Fatalf("failed to parse exported JSON: %v", err)
	}
	if len(secrets) != 3 {
		t.Errorf("expected 3 exported secrets in JSON, got %d", len(secrets))
	}
	if secrets["velocloud-provider/vco-token"].Value != "mock-token-12345" {
		t.Errorf("JSON export value mismatch")
	}

	// 6. Test 3: Verify 'sec run' subprocess environment injection
	runCmd := exec.Command("./sec_test_bin", "run", "--profile", profile, "--", "env")
	runCmd.Env = testEnv
	runOut, err := runCmd.Output()
	if err != nil {
		t.Fatalf("sec run env failed: %v", err)
	}
	runStr := string(runOut)
	if !strings.Contains(runStr, "VELOCLOUD_PROVIDER_VCO_URL=https://vco.example.com") {
		t.Errorf("subprocess did not receive injected environment variable. Output:\n%s", runStr)
	}

	// 7. Test 4: Verify exit code propagation
	exitCmd := exec.Command("./sec_test_bin", "run", "--profile", profile, "--", "sh", "-c", "exit 42")
	exitCmd.Env = testEnv
	err = exitCmd.Run()
	if err == nil {
		t.Errorf("expected exit status 42, got nil error")
	} else {
		if exitError, ok := err.(*exec.ExitError); ok {
			if exitError.ExitCode() != 42 {
				t.Errorf("expected exit code 42, got %d", exitError.ExitCode())
			}
		} else {
			t.Errorf("unexpected error type for exit: %v", err)
		}
	}

	// 8. Test 5: Verify 'sec lock' command locks the session and subsequent queries fail
	lockCmd := exec.Command("./sec_test_bin", "lock", "--profile", profile)
	lockCmd.Env = testEnv
	if err := lockCmd.Run(); err != nil {
		t.Fatalf("sec lock failed: %v", err)
	}

	queryBlockedCmd := exec.Command("./sec_test_bin", "get", "other-category/test-key", "--profile", profile)
	queryBlockedCmd.Env = testEnv
	_, err = queryBlockedCmd.Output()
	if err == nil {
		t.Errorf("expected query on locked session to fail, but it succeeded")
	}
}

func TestPathToEnvKey(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"database/prod/password", "DATABASE_PROD_PASSWORD"},
		{"api-key/stripe-key", "API_KEY_STRIPE_KEY"},
		{"nested/some-value_123", "NESTED_SOME_VALUE_123"},
		{"special/!@#$characters", "SPECIAL_CHARACTERS"},
	}

	for _, tt := range tests {
		got := pathToEnvKey(tt.path)
		if got != tt.want {
			t.Errorf("pathToEnvKey(%q) = %q; want %q", tt.path, got, tt.want)
		}
	}
}

func TestDatabaseAtomicWritesAndBackups(t *testing.T) {
	profile := "atomic-backup-test-profile"
	dbPath, _ := store.GetStorePath(profile)
	dir := filepath.Dir(dbPath)
	backupDir := filepath.Join(dir, "backups", profile)

	// Clean up any stale files of our test profile only
	_ = os.Remove(dbPath)
	_ = os.RemoveAll(backupDir)
	defer func() {
		_ = os.Remove(dbPath)
		_ = os.RemoveAll(backupDir)
	}()

	// Ensure config directory and backups directory exist
	// #nosec G301
	_ = os.MkdirAll(backupDir, 0700)

	masterKey := []byte("01234567890123456789012345678901")
	st := &store.EncryptedStore{
		Secrets: map[string]store.SecretEntry{
			"test/key": {Value: "initial-val"},
		},
	}

	// Save multiple times to trigger backup creations and rotations
	for i := 0; i < 15; i++ {
		st.Secrets["test/key"] = store.SecretEntry{Value: fmt.Sprintf("val-%d", i)}
		err := store.SaveStore(profile, st, masterKey)
		if err != nil {
			t.Fatalf("failed to save store at iteration %d: %v", i, err)
		}
	}

	// Verify backups directory contains exactly 10 backups (the max limit)
	files, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("failed to read backups directory: %v", err)
	}

	var backupCount int
	for _, f := range files {
		if !f.IsDir() && strings.HasPrefix(f.Name(), "secrets.enc.") {
			backupCount++

			// Verify backup copy can be decrypted successfully
			backupPath := filepath.Join(backupDir, f.Name())
			// #nosec G304 G703
			data, err := os.ReadFile(backupPath)
			if err != nil {
				t.Fatalf("failed to read backup file %s: %v", backupPath, err)
			}
			plaintext, err := crypto.Decrypt(masterKey, data)
			if err != nil {
				t.Fatalf("failed to decrypt backup file %s: %v", backupPath, err)
			}
			var tempStore store.EncryptedStore
			if err := json.Unmarshal(plaintext, &tempStore); err != nil {
				t.Fatalf("failed to unmarshal decrypted backup JSON %s: %v", backupPath, err)
			}
		}
	}

	if backupCount != 10 {
		t.Errorf("expected exactly 10 backup files under %s, got %d", backupDir, backupCount)
	}
}

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
	buildCmd := exec.Command("go", "build", "-o", "sec_hijack_bin", "main.go")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("failed to build test binary: %v", err)
	}
	defer os.Remove("sec_hijack_bin")

	// 3. Initialize store
	masterKey := []byte("01234567890123456789012345678902")
	st := &store.EncryptedStore{
		Secrets: map[string]store.SecretEntry{
			"test/key": {Value: "safe-val"},
		},
	}
	_ = store.SaveStore(profile, st, masterKey)

	// 4. Start daemon
	d, err := daemon.NewDaemon(profile, 30*time.Second, "v1.0.0")
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
