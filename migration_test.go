package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secure_secrets/config"
	"secure_secrets/daemon"
	"secure_secrets/store"
)

func TestJSONHelpSchema(t *testing.T) {
	// Build the CLI binary
	buildCmd := exec.Command("go", "build", "-o", "sec_migration_test_bin", "main.go")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("failed to build test binary: %v", err)
	}
	defer os.Remove("sec_migration_test_bin")

	// Query help with format json
	helpCmd := exec.Command("./sec_migration_test_bin", "help", "--format", "json")
	out, err := helpCmd.Output()
	if err != nil {
		t.Fatalf("failed to query json help: %v", err)
	}

	var schema map[string]interface{}
	if err := json.Unmarshal(out, &schema); err != nil {
		t.Fatalf("failed to parse help output as JSON: %v. Output:\n%s", err, string(out))
	}

	if schema["tool"] != "sec" {
		t.Errorf("expected tool name 'sec', got %v", schema["tool"])
	}

	commands, exists := schema["commands"].(map[string]interface{})
	if !exists {
		t.Fatalf("expected 'commands' section in help schema")
	}

	if _, ok := commands["migrate-local"]; !ok {
		t.Errorf("expected 'migrate-local' command in commands section")
	}
}

func TestLocalDotenvMigrationAndExport(t *testing.T) {
	profile := "migration-test-profile"
	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	os.Remove(sockPath)
	os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	// Build the CLI binary
	buildCmd := exec.Command("go", "build", "-o", "sec_migration_test_bin2", "main.go")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("failed to build test binary: %v", err)
	}
	defer os.Remove("sec_migration_test_bin2")

	// Spin up test daemon
	d, err := daemon.NewDaemon(profile, 30*time.Second, "v1.0.0")
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}
	d.SetMasterKeyForTest([]byte("00000000000000000000000000000000"))
	d.SetSessionTokenForTest("test-migration-token")
	d.SetSecretsForTest(map[string]store.SecretEntry{})
	go func() {
		_ = d.Start()
	}()
	defer d.Stop()

	// Wait for socket
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Create temporary dotenv file
	tempDir, err := os.MkdirTemp("", "sec-dotenv-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dotenvPath := filepath.Join(tempDir, ".env")
	dotenvContent := `
# Sample dotenv configuration
PORT=8080
DB_PASSWORD="my-super-secret-password-123"
STRIPE_KEY='sk_live_stripe_secret_key'
EMPTY_VAL=
`
	if err := os.WriteFile(dotenvPath, []byte(dotenvContent), 0644); err != nil {
		t.Fatalf("failed to write dotenv test file: %v", err)
	}

	// Run migrate-local
	migrateCmd := exec.Command("./sec_migration_test_bin2", "migrate-local", dotenvPath, "--profile", profile, "--prefix", "app-secrets")
	migrateCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN=test-migration-token")
	migrateOut, err := migrateCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("migrate-local failed: %v. Output:\n%s", err, string(migrateOut))
	}

	// Verify dotenv values are sanitized in file
	sanitizedBytes, err := os.ReadFile(dotenvPath)
	if err != nil {
		t.Fatalf("failed to read sanitized dotenv file: %v", err)
	}
	sanitizedContent := string(sanitizedBytes)
	if strings.Contains(sanitizedContent, "my-super-secret-password-123") {
		t.Errorf("dotenv file still contains raw DB_PASSWORD secret")
	}
	if strings.Contains(sanitizedContent, "sk_live_stripe_secret_key") {
		t.Errorf("dotenv file still contains raw STRIPE_KEY secret")
	}
	if !strings.Contains(sanitizedContent, `DB_PASSWORD="<migrated_to_sec>"`) {
		t.Errorf("expected DB_PASSWORD value placeholder missing in sanitized dotenv: %s", sanitizedContent)
	}

	// Verify secrets were stored under target prefix
	getCmd := exec.Command("./sec_migration_test_bin2", "get", "app-secrets/db-password", "--profile", profile)
	getCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN=test-migration-token")
	getOut, err := getCmd.Output()
	if err != nil {
		t.Fatalf("get secret failed: %v", err)
	}
	if strings.TrimSpace(string(getOut)) != "my-super-secret-password-123" {
		t.Errorf("stored secret value mismatch, got %q", string(getOut))
	}

	// Test export --format doppler
	dopplerCmd := exec.Command("./sec_migration_test_bin2", "export", "--format", "doppler", "--profile", profile)
	dopplerCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN=test-migration-token")
	dopplerOut, err := dopplerCmd.Output()
	if err != nil {
		t.Fatalf("export doppler failed: %v", err)
	}
	var dopplerMap map[string]string
	if err := json.Unmarshal(dopplerOut, &dopplerMap); err != nil {
		t.Fatalf("failed to parse Doppler output JSON: %v", err)
	}
	if dopplerMap["APP_SECRETS_DB_PASSWORD"] != "my-super-secret-password-123" {
		t.Errorf("Doppler format key APP_SECRETS_DB_PASSWORD mapping error, got %v", dopplerMap)
	}
	if dopplerMap["APP_SECRETS_STRIPE_KEY"] != "sk_live_stripe_secret_key" {
		t.Errorf("Doppler format key APP_SECRETS_STRIPE_KEY mapping error, got %v", dopplerMap)
	}

	// Test export --format aws
	awsCmd := exec.Command("./sec_migration_test_bin2", "export", "--format", "aws", "--profile", profile)
	awsCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN=test-migration-token")
	awsOut, err := awsCmd.Output()
	if err != nil {
		t.Fatalf("export aws failed: %v", err)
	}
	type AWSSecret struct {
		SecretId     string `json:"SecretId"`
		SecretString string `json:"SecretString"`
	}
	var awsList []AWSSecret
	if err := json.Unmarshal(awsOut, &awsList); err != nil {
		t.Fatalf("failed to parse AWS output JSON: %v", err)
	}
	foundDB := false
	for _, item := range awsList {
		if item.SecretId == "app-secrets/db-password" {
			foundDB = true
			if item.SecretString != "my-super-secret-password-123" {
				t.Errorf("AWS format value mismatch for db-password, got %q", item.SecretString)
			}
		}
	}
	if !foundDB {
		t.Errorf("AWS format SecretId 'app-secrets/db-password' missing in export")
	}

	// Test --json-errors mapping by calling query with invalid token
	errCmd := exec.Command("./sec_migration_test_bin2", "get", "app-secrets/db-password", "--profile", profile, "--json-errors")
	errCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN=incorrect-token-value")
	errOut, err := errCmd.CombinedOutput()
	if err == nil {
		t.Errorf("expected command execution to fail with incorrect token, but succeeded")
	}
	var errResp JSONErrorResponse
	if errJson := json.Unmarshal(errOut, &errResp); errJson != nil {
		t.Fatalf("failed to parse json error output: %v. Output:\n%s", errJson, string(errOut))
	}
	if errResp.Success {
		t.Errorf("expected success to be false in error response")
	}
	if errResp.Error.Code != "INVALID_TOKEN" {
		t.Errorf("expected error code 'INVALID_TOKEN', got %q", errResp.Error.Code)
	}
	if !strings.Contains(errResp.Error.Remediation, "eval $(sec open)") {
		t.Errorf("expected remediation hint to contain 'eval $(sec open)', got %q", errResp.Error.Remediation)
	}

	// Test version output when daemon matches
	verCmd := exec.Command("./sec_migration_test_bin2", "version", "--profile", profile)
	verCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN=test-migration-token")
	verOut, err := verCmd.Output()
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}
	verStr := string(verOut)
	if !strings.Contains(verStr, "sec-agent CLI:") {
		t.Errorf("expected version output to contain 'sec-agent CLI:', got:\n%s", verStr)
	}
	if !strings.Contains(verStr, "sec-agent Daemon:   v1.0.0") {
		t.Errorf("expected version output to contain daemon version v1.0.0, got:\n%s", verStr)
	}
}
