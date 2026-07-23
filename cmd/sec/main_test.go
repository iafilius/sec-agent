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

	"secure_secrets/internal/config"
	"secure_secrets/internal/crypto"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"
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

	// 6b. Test 'sec load' batch environment output with prefix trimming
	loadCmd := exec.Command("./sec_test_bin", "load", "velocloud-provider", "--profile", profile)
	loadCmd.Env = testEnv
	loadOut, err := loadCmd.Output()
	if err != nil {
		t.Fatalf("sec load failed: %v", err)
	}
	loadStr := string(loadOut)
	if !strings.Contains(loadStr, "export VCO_URL=\"https://vco.example.com\"") || !strings.Contains(loadStr, "export VCO_TOKEN=\"mock-token-12345\"") {
		t.Errorf("sec load output mismatch. Got:\n%s", loadStr)
	}

	// 6c. Test 'sec run --group' scoped environment variable injection
	runGroupCmd := exec.Command("./sec_test_bin", "run", "--group", "velocloud-provider", "--profile", profile, "--", "env")
	runGroupCmd.Env = testEnv
	runGroupOut, err := runGroupCmd.Output()
	if err != nil {
		t.Fatalf("sec run --group failed: %v", err)
	}
	runGroupStr := string(runGroupOut)
	if !strings.Contains(runGroupStr, "VCO_URL=https://vco.example.com") || strings.Contains(runGroupStr, "OTHER_CATEGORY") {
		t.Errorf("sec run --group output mismatch. Got:\n%s", runGroupStr)
	}

	// 6d. Test 'sec get --prefix' batch group retrieval
	getGroupCmd := exec.Command("./sec_test_bin", "get", "velocloud-provider", "--prefix", "--profile", profile)
	getGroupCmd.Env = testEnv
	getGroupOut, err := getGroupCmd.Output()
	if err != nil {
		t.Fatalf("sec get --prefix failed: %v", err)
	}
	getGroupStr := string(getGroupOut)
	if !strings.Contains(getGroupStr, "velocloud-provider/vco-url=https://vco.example.com") {
		t.Errorf("sec get --prefix output mismatch. Got:\n%s", getGroupStr)
	}

	// 6e. Test single secret rename ('sec mv')
	mvSingleCmd := exec.Command("./sec_test_bin", "mv", "other-category/test-key", "new-category/renamed-key", "--profile", profile)
	mvSingleCmd.Env = testEnv
	if err := mvSingleCmd.Run(); err != nil {
		t.Fatalf("sec mv single key failed: %v", err)
	}
	getRenamedCmd := exec.Command("./sec_test_bin", "get", "new-category/renamed-key", "--profile", profile)
	getRenamedCmd.Env = testEnv
	renamedOut, err := getRenamedCmd.Output()
	if err != nil || strings.TrimSpace(string(renamedOut)) != "some-value" {
		t.Fatalf("sec get renamed key failed: %v, got %q", err, string(renamedOut))
	}

	// 6f. Test prefix namespace refactoring ('sec mv --prefix')
	mvPrefixCmd := exec.Command("./sec_test_bin", "mv", "velocloud-provider", "provider-v2", "--prefix", "--profile", profile)
	mvPrefixCmd.Env = testEnv
	if err := mvPrefixCmd.Run(); err != nil {
		t.Fatalf("sec mv --prefix failed: %v", err)
	}
	getV2Cmd := exec.Command("./sec_test_bin", "get", "provider-v2/vco-url", "--profile", profile)
	getV2Cmd.Env = testEnv
	v2Out, err := getV2Cmd.Output()
	if err != nil || strings.TrimSpace(string(v2Out)) != "https://vco.example.com" {
		t.Fatalf("sec get provider-v2 key failed: %v, got %q", err, string(v2Out))
	}

	// 6g. Test 'sec ls' path listing
	lsCmd := exec.Command("./sec_test_bin", "ls", "provider-v2", "--profile", profile)
	lsCmd.Env = testEnv
	lsOut, err := lsCmd.Output()
	if err != nil || !strings.Contains(string(lsOut), "provider-v2/vco-url") {
		t.Fatalf("sec ls failed: %v, output: %s", err, string(lsOut))
	}

	// 6h. Test 'sec status' diagnostic output
	statusCmd := exec.Command("./sec_test_bin", "status", "--profile", profile)
	statusCmd.Env = testEnv
	statusOut, err := statusCmd.Output()
	if err != nil || !strings.Contains(string(statusOut), "UNLOCKED") {
		t.Fatalf("sec status failed: %v, output: %s", err, string(statusOut))
	}

	// 6i. Test 'sec audit' log retrieval
	auditCmd := exec.Command("./sec_test_bin", "audit", "--profile", profile)
	auditCmd.Env = testEnv
	auditOut, err := auditCmd.Output()
	if err != nil {
		t.Fatalf("sec audit failed: %v", err)
	}
	t.Logf("Audit log output length: %d bytes", len(auditOut))

	// 6j. Test 'sec gen' secret generation
	genCmd := exec.Command("./sec_test_bin", "gen", "generated/password", "--length", "24", "--profile", profile)
	genCmd.Env = testEnv
	if err := genCmd.Run(); err != nil {
		t.Fatalf("sec gen failed: %v", err)
	}
	getGenCmd := exec.Command("./sec_test_bin", "get", "generated/password", "--profile", profile)
	getGenCmd.Env = testEnv
	genOut, err := getGenCmd.Output()
	if err != nil || len(strings.TrimSpace(string(genOut))) != 24 {
		t.Fatalf("sec get generated password failed: %v, got %q", err, string(genOut))
	}

	// 6k. Test 'sec cp' secret duplication
	cpCmd := exec.Command("./sec_test_bin", "cp", "generated/password", "copied/password", "--profile", profile)
	cpCmd.Env = testEnv
	if err := cpCmd.Run(); err != nil {
		t.Fatalf("sec cp failed: %v", err)
	}
	getCpCmd := exec.Command("./sec_test_bin", "get", "copied/password", "--profile", profile)
	getCpCmd.Env = testEnv
	cpOut, err := getCpCmd.Output()
	if err != nil || strings.TrimSpace(string(cpOut)) != strings.TrimSpace(string(genOut)) {
		t.Fatalf("sec get copied password failed: %v, got %q", err, string(cpOut))
	}

	// 6l. Test 'sec doctor' diagnostics
	docCmd := exec.Command("./sec_test_bin", "doctor", "--profile", profile)
	docCmd.Env = testEnv
	docOut, err := docCmd.Output()
	if err != nil || !strings.Contains(string(docOut), "All system diagnostic checks complete") {
		t.Fatalf("sec doctor failed: %v, output: %s", err, string(docOut))
	}

	// 6m. Test 'sec import' JSON import
	importFile := filepath.Join(t.TempDir(), "import_test.json")
	os.WriteFile(importFile, []byte(`{"IMPORTED_KEY_1":"val1","IMPORTED_KEY_2":"val2"}`), 0600)
	importCmd := exec.Command("./sec_test_bin", "import", importFile, "--prefix", "imported-app", "--profile", profile)
	importCmd.Env = testEnv
	if err := importCmd.Run(); err != nil {
		t.Fatalf("sec import failed: %v", err)
	}
	getImportCmd := exec.Command("./sec_test_bin", "get", "imported-app/IMPORTED_KEY_1", "--profile", profile)
	getImportCmd.Env = testEnv
	impOut, err := getImportCmd.Output()
	if err != nil || strings.TrimSpace(string(impOut)) != "val1" {
		t.Fatalf("sec get imported key failed: %v, got %q", err, string(impOut))
	}

	// 6n. Test 'sec rm' secret deletion
	rmSingleCmd := exec.Command("./sec_test_bin", "rm", "new-category/renamed-key", "--profile", profile)
	rmSingleCmd.Env = testEnv
	if err := rmSingleCmd.Run(); err != nil {
		t.Fatalf("sec rm single key failed: %v", err)
	}

	// 6o. Test '--env-alias' and 'sec export --format template'
	aliasSetCmd := exec.Command("./sec_test_bin", "set", "aliased/key", "secret-value", "--env-alias", "CUSTOM_BGP_ENV", "--profile", profile)
	aliasSetCmd.Env = testEnv
	if err := aliasSetCmd.Run(); err != nil {
		t.Fatalf("sec set --env-alias failed: %v", err)
	}

	envAliasCmd := exec.Command("./sec_test_bin", "env", "aliased", "--profile", profile)
	envAliasCmd.Env = testEnv
	aliasOut, err := envAliasCmd.Output()
	if err != nil || !strings.Contains(string(aliasOut), "CUSTOM_BGP_ENV=") {
		t.Fatalf("sec env with --env-alias failed: %v, output: %s", err, string(aliasOut))
	}

	tmplCmd := exec.Command("./sec_test_bin", "export", "--format", "template", "--profile", profile)
	tmplCmd.Env = testEnv
	tmplOut, err := tmplCmd.Output()
	if err != nil || !strings.Contains(string(tmplOut), "<migrated_to_sec>") {
		t.Fatalf("sec export --format template failed: %v, output: %s", err, string(tmplOut))
	}

	rmPrefixCmd := exec.Command("./sec_test_bin", "rm", "provider-v2", "--prefix", "--profile", profile)
	rmPrefixCmd.Env = testEnv
	if err := rmPrefixCmd.Run(); err != nil {
		t.Fatalf("sec rm --prefix failed: %v", err)
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
