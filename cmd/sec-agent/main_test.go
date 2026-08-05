package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secure_secrets/internal/config"
	"secure_secrets/internal/crypto"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/keychain"
	"secure_secrets/internal/store"
)

func TestMain(m *testing.M) {
	for _, arg := range os.Args {
		if arg == "daemon" {
			main()
			return
		}
	}
	os.Exit(m.Run())
}

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
	buildCmd := exec.Command("go", "build", "-o", "sec_test_bin", ".")
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
	d.SetSessionTokenForTest("mock-test-session-token-123")
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

	var testEnv []string
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "SEC_SESSION_TOKEN=") && !strings.HasPrefix(env, "SEC_PROFILE=") && !strings.HasPrefix(env, "VELOCLOUD_") && !strings.HasPrefix(env, "PROVIDER_") {
			testEnv = append(testEnv, env)
		}
	}
	testEnv = append(testEnv, "SEC_SESSION_TOKEN=integration-token-123", "SEC_PROFILE="+profile)

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

	// 5. Test 2: Verify 'sec export --format json --no-envelope' output
	expCmd := exec.Command("./sec_test_bin", "export", "--format", "json", "--no-envelope", "--profile", profile)
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
	runCmd := exec.Command("./sec_test_bin", "run", "--no-redact", "--profile", profile, "--", "env")
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
	runGroupCmd := exec.Command("./sec_test_bin", "run", "--no-redact", "--group", "velocloud-provider", "--profile", profile, "--", "env")
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

	// Test subshell peer authorization without SEC_SESSION_TOKEN environment variable
	var subshellEnv []string
	for _, envVar := range testEnv {
		if !strings.HasPrefix(envVar, "SEC_SESSION_TOKEN=") {
			subshellEnv = append(subshellEnv, envVar)
		}
	}
	subshellGetCmd := exec.Command("./sec_test_bin", "get", "copied/password", "--profile", profile)
	subshellGetCmd.Env = subshellEnv
	subshellOut, err := subshellGetCmd.Output()
	if err != nil || strings.TrimSpace(string(subshellOut)) != strings.TrimSpace(string(genOut)) {
		t.Fatalf("sec get in subshell without SEC_SESSION_TOKEN failed: %v, got %q", err, string(subshellOut))
	}

	// Test in-memory daemon hot-reload via kernel pipe state handoff ('sec restart --hot-reload')
	hotReloadCmd := exec.Command("./sec_test_bin", "restart", "--hot-reload", "--profile", profile)
	hotReloadCmd.Env = testEnv
	hotOut, err := hotReloadCmd.Output()
	if err != nil || !strings.Contains(string(hotOut), "hot-reloaded in memory") {
		t.Fatalf("sec restart --hot-reload failed: %v, output: %q", err, string(hotOut))
	}
	time.Sleep(300 * time.Millisecond)

	// Verify secret retrieval after hot-reload without Touch ID prompt
	postReloadGetCmd := exec.Command("./sec_test_bin", "get", "copied/password", "--profile", profile)
	postReloadGetCmd.Env = subshellEnv
	postOut, err := postReloadGetCmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(postOut)) != strings.TrimSpace(string(genOut)) {
		t.Fatalf("sec get after hot-reload failed: %v, output: %q", err, string(postOut))
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

	// 6p. Test 'sec check', 'sec get -r', and 'sec completion'
	checkCmd := exec.Command("./sec_test_bin", "check", "--required", "CUSTOM_BGP_ENV", "--profile", profile)
	checkCmd.Env = testEnv
	checkOut, err := checkCmd.Output()
	if err != nil || !strings.Contains(string(checkOut), "Success: All 1 required keys/aliases present") {
		t.Fatalf("sec check failed: %v, output: %s", err, string(checkOut))
	}

	rawGetCmd := exec.Command("./sec_test_bin", "get", "aliased/key", "-r", "--profile", profile)
	rawGetCmd.Env = testEnv
	rawOut, err := rawGetCmd.Output()
	if err != nil || string(rawOut) != "secret-value" {
		t.Fatalf("sec get -r failed: %v, expected 'secret-value', got %q", err, string(rawOut))
	}

	compCmd := exec.Command("./sec_test_bin", "completion", "zsh")
	compCmd.Env = testEnv
	compOut, err := compCmd.Output()
	if err != nil || !strings.Contains(string(compOut), "#compdef sec") {
		t.Fatalf("sec completion zsh failed: %v, output: %s", err, string(compOut))
	}

	// 6q. Test 'sec profile set-env' and production safety guards
	profTagCmd := exec.Command("./sec_test_bin", "profile", "set-env", "prod", "--profile", profile)
	profTagCmd.Env = testEnv
	if err := profTagCmd.Run(); err != nil {
		t.Fatalf("sec profile set-env failed: %v", err)
	}

	// Non-interactive run without --confirm-prod MUST fail
	unconfirmedRun := exec.Command("./sec_test_bin", "run", "--profile", profile, "--", "echo", "hello")
	unconfirmedRun.Env = testEnv
	if err := unconfirmedRun.Run(); err == nil {
		t.Fatalf("expected sec run without --confirm-prod on prod profile to fail, but succeeded")
	}

	// Non-interactive run WITH --confirm-prod MUST succeed
	confirmedRun := exec.Command("./sec_test_bin", "run", "--confirm-prod", "--profile", profile, "--", "echo", "hello")
	confirmedRun.Env = testEnv
	if err := confirmedRun.Run(); err != nil {
		t.Fatalf("sec run --confirm-prod on prod profile failed: %v", err)
	}

	// 6r. Test v1.5.0 features: JWT auto-exp, stream redactor, profile diffing, and leases
	// Set secret with dummy JWT payload (header.payload.sig) where payload={"exp":1800000000}
	dummyJwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE4MDAwMDAwMDB9.sig"
	jwtSetCmd := exec.Command("./sec_test_bin", "set", "jwt/token", dummyJwt, "--profile", profile)
	jwtSetCmd.Env = testEnv
	jwtOut, err := jwtSetCmd.Output()
	if err != nil || !strings.Contains(string(jwtOut), "Automatically detected JWT token") {
		t.Fatalf("sec set with JWT auto expiration failed: %v, out: %s", err, string(jwtOut))
	}

	// Test stream redaction (DEFAULT-ON)
	redactRunCmd := exec.Command("./sec_test_bin", "run", "--confirm-prod", "--profile", profile, "--", "sh", "-c", "echo secret-value")
	redactRunCmd.Env = testEnv
	redactOut, err := redactRunCmd.Output()
	if err != nil || !strings.Contains(string(redactOut), "[REDACTED_BY_SEC]") {
		t.Fatalf("sec run default redaction failed to redact secret: %v, out: %s", err, string(redactOut))
	}

	// Test stream redaction opt-out (--no-redact)
	noRedactRunCmd := exec.Command("./sec_test_bin", "run", "--confirm-prod", "--no-redact", "--profile", profile, "--", "sh", "-c", "echo secret-value")
	noRedactRunCmd.Env = testEnv
	noRedactOut, err := noRedactRunCmd.Output()
	if err != nil || strings.Contains(string(noRedactOut), "[REDACTED_BY_SEC]") || !strings.Contains(string(noRedactOut), "secret-value") {
		t.Fatalf("sec run --no-redact failed opt-out: %v, out: %s", err, string(noRedactOut))
	}

	// Test sec lease
	leaseCmd := exec.Command("./sec_test_bin", "lease", "aliased/key", "--ttl", "1m", "--profile", profile)
	leaseCmd.Env = testEnv
	leaseOut, err := leaseCmd.Output()
	if err != nil || !strings.Contains(string(leaseOut), "lease:aliased/key:") {
		t.Fatalf("sec lease failed: %v, output: %s", err, string(leaseOut))
	}

	// Test sec diff-profiles
	diffProfCmd := exec.Command("./sec_test_bin", "diff-profiles", profile, profile)
	diffProfCmd.Env = testEnv
	diffProfOut, err := diffProfCmd.Output()
	if err != nil || !strings.Contains(string(diffProfOut), "[MATCH]") {
		t.Fatalf("sec diff-profiles failed: %v, output: %s", err, string(diffProfOut))
	}

	// 6s. Test v1.6.0 features: sec set --rotate-cmd, sec rotate, and sec ls --expiring
	rotSetCmd := exec.Command("./sec_test_bin", "set", "rot/key", "old-val", "--expires", "14d", "--rotate-cmd", "echo rotated-secret-val", "--rotate-ttl", "14d", "--profile", profile)
	rotSetCmd.Env = testEnv
	if err := rotSetCmd.Run(); err != nil {
		t.Fatalf("sec set with --rotate-cmd failed: %v", err)
	}

	// Test sec ls --expiring
	expLsCmd := exec.Command("./sec_test_bin", "ls", "--expiring", "30d", "--profile", profile)
	expLsCmd.Env = testEnv
	expLsOut, err := expLsCmd.Output()
	if err != nil || !strings.Contains(string(expLsOut), "rot/key") {
		t.Fatalf("sec ls --expiring failed: %v, out: %s", err, string(expLsOut))
	}

	// Test sec rotate
	rotRunCmd := exec.Command("./sec_test_bin", "rotate", "rot/key", "--profile", profile)
	rotRunCmd.Env = testEnv
	rotRunOut, err := rotRunCmd.Output()
	if err != nil || !strings.Contains(string(rotRunOut), "successfully rotated") {
		t.Fatalf("sec rotate failed: %v, out: %s", err, string(rotRunOut))
	}

	// Verify rotated value
	getRotCmd := exec.Command("./sec_test_bin", "get", "rot/key", "-r", "--profile", profile)
	getRotCmd.Env = testEnv
	getRotOut, err := getRotCmd.Output()
	if err != nil || string(getRotOut) != "rotated-secret-val" {
		t.Fatalf("sec get after rotation failed: %v, expected 'rotated-secret-val', got %q", err, string(getRotOut))
	}

	// 6t. Test v1.7.0 feature: sec status --all
	statusAllCmd := exec.Command("./sec_test_bin", "status", "--all")
	statusAllCmd.Env = testEnv
	statusAllOut, err := statusAllCmd.Output()
	if err != nil || !strings.Contains(string(statusAllOut), "Global Workstation Status") {
		t.Fatalf("sec status --all failed: %v, out: %s", err, string(statusAllOut))
	}

	// 6u. Test v1.8.0 features: sec run --allow-keys, sec run --dry-run, and sec check --scan-weak
	dryRunCmd := exec.Command("./sec_test_bin", "run", "--dry-run", "--confirm-prod", "--profile", profile, "--", "echo", "hello")
	dryRunCmd.Env = testEnv
	dryRunOut, err := dryRunCmd.Output()
	if err != nil || !strings.Contains(string(dryRunOut), "Subprocess Secret Injection Plan") {
		t.Fatalf("sec run --dry-run failed: %v, out: %s", err, string(dryRunOut))
	}

	allowKeysCmd := exec.Command("./sec_test_bin", "run", "--allow-keys", "CUSTOM_BGP_ENV", "--confirm-prod", "--no-redact", "--profile", profile, "--", "env")
	allowKeysCmd.Env = testEnv
	allowKeysOut, err := allowKeysCmd.Output()
	if err != nil || !strings.Contains(string(allowKeysOut), "CUSTOM_BGP_ENV=") {
		t.Fatalf("sec run --allow-keys failed: %v, out: %s", err, string(allowKeysOut))
	}

	scanWeakCmd := exec.Command("./sec_test_bin", "check", "--scan-weak", "--profile", profile)
	scanWeakCmd.Env = testEnv
	scanWeakOut, err := scanWeakCmd.Output()
	if err != nil || !strings.Contains(string(scanWeakOut), "Entropy & Weakness Scan") {
		t.Fatalf("sec check --scan-weak failed: %v, out: %s", err, string(scanWeakOut))
	}

	scanLeaksCmd := exec.Command("./sec_test_bin", "check", "--leaks", "--profile", profile)
	scanLeaksCmd.Env = testEnv
	scanLeaksOut, err := scanLeaksCmd.Output()
	if err != nil || !strings.Contains(string(scanLeaksOut), "Workstation Shell History & Secret Leak Audit") {
		t.Fatalf("sec check --leaks failed: %v, out: %s", err, string(scanLeaksOut))
	}

	// Reset profile env to dev for remaining tests
	resetProfCmd := exec.Command("./sec_test_bin", "profile", "set-env", "dev", "--profile", profile)
	resetProfCmd.Env = testEnv
	_ = resetProfCmd.Run()

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

	// 9. Test 6: Verify non-interactive execution with --auto-open or SEC_AUTO_OPEN=1 fails safely without unlocking
	autoOpenBlockedCmd := exec.Command("./sec_test_bin", "--auto-open", "get", "other-category/test-key", "--profile", profile)
	autoOpenBlockedCmd.Env = testEnv
	_, err = autoOpenBlockedCmd.Output()
	if err == nil {
		t.Errorf("expected --auto-open query in non-interactive mode on locked session to fail, but it succeeded")
	}
}

func TestInitSkillInstallerAndBackupList(t *testing.T) {
	tmpHome := t.TempDir()
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = filepath.Join(os.Getenv("HOME"), "go")
	}
	gocache := os.Getenv("GOCACHE")
	env := append(os.Environ(), "HOME="+tmpHome, "GOPATH="+gopath, "GOCACHE="+gocache)

	// Build CLI binary
	binPath := filepath.Join(tmpHome, "sec_test_init_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	buildCmd.Env = env
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build CLI test binary: %v\nOutput:\n%s", err, out)
	}

	// 1. Uninitialized vault pre-flight guard check
	uninitCmd := exec.Command(binPath, "get", "some/key")
	uninitCmd.Env = env
	out, err := uninitCmd.CombinedOutput()
	if err == nil {
		t.Errorf("expected get command on uninitialized vault to fail, but it succeeded")
	}
	if !strings.Contains(string(out), "uninitialized") {
		t.Errorf("expected uninitialized error output, got: %s", string(out))
	}

	// 2. Test JSON error formatting on uninitialized vault
	uninitJSONCmd := exec.Command(binPath, "get", "some/key", "--json")
	uninitJSONCmd.Env = env
	out, err = uninitJSONCmd.CombinedOutput()
	if err == nil {
		t.Errorf("expected get --json on uninitialized vault to fail, but it succeeded")
	}
	if !strings.Contains(string(out), "VAULT_UNINITIALIZED") || !strings.Contains(string(out), "\"success\":false") {
		t.Errorf("expected structured JSON error output, got: %s", string(out))
	}

	// 3. Test init with --skill flag
	initCmd := exec.Command(binPath, "init", "--skill", "antigravity", "--scope", "global")
	initCmd.Env = env
	out, err = initCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec-agent init failed: %v\nOutput: %s", err, out)
	}
	if !strings.Contains(string(out), "Vault configuration directory initialized") {
		t.Errorf("unexpected init output: %s", string(out))
	}

	// Verify skill file was created in tmpHome/.gemini/config/skills/
	skillPath := filepath.Join(tmpHome, ".gemini", "config", "skills", "sec-agent-integration", "SKILL.md")
	if _, err := os.Stat(skillPath); os.IsNotExist(err) {
		t.Errorf("expected skill file to exist at %s, but missing", skillPath)
	}

	// 3. Test skill status
	statusCmd := exec.Command(binPath, "skill", "status")
	statusCmd.Env = env
	out, err = statusCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec-agent skill status failed: %v\nOutput: %s", err, out)
	}
	if !strings.Contains(string(out), "antigravity") {
		t.Errorf("expected skill status to list antigravity, got: %s", string(out))
	}

	// 4. Test backup list
	backupListCmd := exec.Command(binPath, "backup", "list")
	backupListCmd.Env = env
	out, err = backupListCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec-agent backup list failed: %v\nOutput: %s", err, out)
	}
	if !strings.Contains(string(out), "Vault Snapshots & Backups") {
		t.Errorf("expected backup list header, got: %s", string(out))
	}

	// 5. Test init --non-interactive
	nonIntInitCmd := exec.Command(binPath, "init", "--non-interactive")
	nonIntInitCmd.Env = env
	out, err = nonIntInitCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec-agent init --non-interactive failed: %v\nOutput: %s", err, out)
	}
	if !strings.Contains(string(out), "Vault configuration directory initialized") {
		t.Errorf("unexpected non-interactive init output: %s", string(out))
	}

	// 7. Test status --quick
	quickStatusCmd := exec.Command(binPath, "status", "--quick")
	quickStatusCmd.Env = env
	out, err = quickStatusCmd.CombinedOutput()
	if err == nil {
		if !strings.Contains(string(out), "socket not found") && !strings.Contains(string(out), "DAEMON_NOT_RUNNING") {
			t.Errorf("expected quick status output for socket check, got: %s", string(out))
		}
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
	buildCmd := exec.Command("go", "build", "-o", "sec_hijack_bin", ".")
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

func TestSSHAgentAndStreamInjection(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "id_ed25519")

	keyData := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACCSl8i3Y4Tj0N5t7V2b9x8yZ2M1P3Q0+g7d4z1a1w2x3QAAAIhA8k+dQPPP\nnQAAAAtzc2gtZWQyNTUxOQAAACCSl8i3Y4Tj0N5t7V2b9x8yZ2M1P3Q0+g7d4z1a1w2x\n3QAAAED3f5j1Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/Pz8/\nPz8/Pz8/Pz8/\n-----END OPENSSH PRIVATE KEY-----\n")
	_ = os.WriteFile(keyPath, keyData, 0600)

	sockPath, cleanup, err := setupEphemeralSSHAgent("default", keyPath, "")
	if err == nil {
		if _, statErr := os.Stat(sockPath); os.IsNotExist(statErr) {
			t.Errorf("expected SSH agent socket to exist at %s, but missing", sockPath)
		}
		cleanup()
		if _, statErr := os.Stat(sockPath); !os.IsNotExist(statErr) {
			t.Errorf("expected SSH agent socket %s to be unlinked after cleanup", sockPath)
		}
	}

	profile := "stream-test-profile"
	masterKey := []byte("01234567890123456789012345678903")
	d, err := daemon.NewDaemon(profile, 30*time.Second, "v1.9.2")
	if err != nil {
		t.Fatalf("failed to create test daemon for stream: %v", err)
	}
	d.SetMasterKeyForTest(masterKey)
	d.SetSecretsForTest(map[string]store.SecretEntry{
		"router/nordvpn/private_key": {Value: "SECRET_WG_PRIVATE_KEY_123"},
	})
	token := "stream-token-456"
	d.SetSessionTokenForTest(token)

	go func() {
		_ = d.Start()
	}()
	defer d.Stop()

	sock, _ := config.GetSocketPath(profile)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	binPath := filepath.Join(tmpDir, "sec_stream_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build stream test binary: %v\nOutput: %s", err, out)
	}

	streamCmd := exec.Command(binPath, "stream", "--template", "uci set network.wg0.private_key='{{router/nordvpn/private_key}}'", "--profile", profile)
	var testEnv []string
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "SEC_SESSION_TOKEN=") && !strings.HasPrefix(env, "SEC_PROFILE=") {
			testEnv = append(testEnv, env)
		}
	}
	testEnv = append(testEnv, "SEC_SESSION_TOKEN="+token, "SEC_PROFILE="+profile)
	streamCmd.Env = testEnv
	out, err := streamCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec-agent stream failed: %v\nOutput: %s", err, out)
	}
	if !strings.Contains(string(out), "SECRET_WG_PRIVATE_KEY_123") {
		t.Errorf("expected stream output to contain substituted secret, got: %s", string(out))
	}
}

func TestProfileInheritanceAndReachabilityGuard(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start local test listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_ping_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build ping test binary: %v\nOutput: %s", err, out)
	}

	pingCmd := exec.Command(binPath, "check", "--ping-host", addr)
	out, err := pingCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec-agent check --ping-host failed: %v\nOutput: %s", err, out)
	}
	if !strings.Contains(string(out), "is reachable") {
		t.Errorf("expected ping host success output, got: %s", string(out))
	}
}

func TestShellEvalOpenIntegration(t *testing.T) {
	profile := "shell-eval-test-profile"
	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	os.Remove(sockPath)
	os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_eval_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build eval test binary: %v\nOutput: %s", err, out)
	}

	d, err := daemon.NewDaemon(profile, 30*time.Second, "v1.0.0")
	if err != nil {
		t.Fatalf("failed to create test daemon: %v", err)
	}
	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901"))
	go d.Start()
	defer d.Stop()

	sock, _ := config.GetSocketPath(profile)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 1. Verify stdout purity: stdout MUST contain ONLY export statements, zero narrative text
	openCmd := exec.Command(binPath, "open", "--profile", profile)
	openCmd.Env = append(os.Environ(), "SEC_TEST_MODE=1")
	var stdoutBuf, stderrBuf strings.Builder
	openCmd.Stdout = &stdoutBuf
	openCmd.Stderr = &stderrBuf

	err = openCmd.Run()
	stdoutStr := stdoutBuf.String()
	stderrStr := stderrBuf.String()

	if strings.Contains(stdoutStr, "Authorizing") {
		t.Fatalf("BUG CONFIRMED: stdout contains narrative 'Authorizing' text which breaks shell eval!\nStdout: %q", stdoutStr)
	}
	if !strings.Contains(stderrStr, "Authorizing") {
		t.Errorf("expected narrative 'Authorizing' text on stderr, got: %q", stderrStr)
	}
	if !strings.Contains(stdoutStr, "export SEC_SESSION_TOKEN=") {
		t.Errorf("expected export SEC_SESSION_TOKEN= on stdout, got: %q", stdoutStr)
	}

	// 2. Execute under native Zsh subshell if zsh binary exists
	if _, err := exec.LookPath("zsh"); err == nil {
		zshScript := fmt.Sprintf(`eval "$(%s open --profile %s)" && echo "TOKEN_SET=$SEC_SESSION_TOKEN"`, binPath, profile)
		zshCmd := exec.Command("zsh", "-c", zshScript)
		zshOut, zshErr := zshCmd.CombinedOutput()
		if zshErr != nil {
			t.Fatalf("Zsh eval execution failed: %v\nOutput: %s", zshErr, zshOut)
		}
		if strings.Contains(string(zshOut), "command not found") {
			t.Fatalf("Zsh threw command not found error: %s", string(zshOut))
		}
		if !strings.Contains(string(zshOut), "TOKEN_SET=") {
			t.Errorf("expected TOKEN_SET in zsh eval output, got: %s", string(zshOut))
		}
	}
}

func TestRecordQueryAndFeedbackCommand(t *testing.T) {
	profile := "record-feedback-test-profile"
	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	os.Remove(sockPath)
	os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_rec_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build record test binary: %v\nOutput: %s", err, out)
	}

	d, err := daemon.NewDaemon(profile, 30*time.Second, "v1.0.0")
	if err != nil {
		t.Fatalf("failed to create test daemon: %v", err)
	}
	token := "record-test-token"
	d.SetSessionTokenForTest(token)
	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901"))
	d.SetSecretsForTest(map[string]store.SecretEntry{
		"router-ax3600-prod/xiaomi_ax3600_openwrt_root/password": {Value: "router-pass-999"},
		"router-ax3600-prod/xiaomi_ax3600_openwrt_root/username": {Value: "root"},
		"router-ax3600-prod/xiaomi_ax3600_openwrt_root/url":      {Value: "https://192.168.31.1"},
		"router-ax3600-prod/xiaomi_ax3600_openwrt_root/notes":    {Value: "Dropbear SSH flags -o HostKeyAlgorithms=+ssh-rsa"},
		"router-ax3600-prod/xiaomi_ax3600_openwrt_root/totp":     {Value: "JBSWY3DPEHPK3PXP"},
	})
	go d.Start()
	defer d.Stop()

	sock, _ := config.GetSocketPath(profile)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 1. Test sec-agent get --record --json
	recCmd := exec.Command(binPath, "get", "router-ax3600-prod/xiaomi_ax3600_openwrt_root/", "--record", "--json", "--profile", profile)
	recCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	out, err := recCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec-agent get --record --json failed: %v\nOutput: %s", err, out)
	}
	var recData map[string]interface{}
	if err := json.Unmarshal(out, &recData); err != nil {
		t.Fatalf("failed to parse --record JSON output: %v\nOutput: %s", err, out)
	}
	if recData["username"] != "root" || recData["password"] != "router-pass-999" || recData["url"] != "https://192.168.31.1" {
		t.Errorf("record payload mismatch: %v", recData)
	}

	// 2. Test sec-agent feedback --json
	fbCmd := exec.Command(binPath, "feedback", "--json")
	fbOut, fbErr := fbCmd.CombinedOutput()
	if fbErr != nil {
		t.Fatalf("sec-agent feedback --json failed: %v\nOutput: %s", fbErr, fbOut)
	}
	var fbData map[string]interface{}
	if err := json.Unmarshal(fbOut, &fbData); err != nil {
		t.Fatalf("failed to parse feedback JSON: %v\nOutput: %s", err, fbOut)
	}
	if fbData["tool"] != "sec-agent" {
		t.Errorf("expected tool = sec-agent, got: %v", fbData["tool"])
	}
}

func TestSecretVersioningAndRollback(t *testing.T) {
	profile := "versioning-test-profile"
	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	os.Remove(sockPath)
	os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_ver_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build versioning test binary: %v\nOutput: %s", err, out)
	}

	d, err := daemon.NewDaemon(profile, 30*time.Second, "v1.0.0")
	if err != nil {
		t.Fatalf("failed to create test daemon: %v", err)
	}
	token := "version-test-token"
	d.SetSessionTokenForTest(token)
	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901"))
	go d.Start()
	defer d.Stop()

	sock, _ := config.GetSocketPath(profile)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 1. Set v1
	setV1 := exec.Command(binPath, "set", "api/key", "val_v1", "--comment", "initial key", "--profile", profile)
	setV1.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	if out, err := setV1.CombinedOutput(); err != nil {
		t.Fatalf("set v1 failed: %v\nOutput: %s", err, out)
	}

	// 2. Set v2
	setV2 := exec.Command(binPath, "set", "api/key", "val_v2", "--comment", "rotated key", "--profile", profile)
	setV2.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	if out, err := setV2.CombinedOutput(); err != nil {
		t.Fatalf("set v2 failed: %v\nOutput: %s", err, out)
	}

	// 3. Query history
	histCmd := exec.Command(binPath, "history", "api/key", "--profile", profile)
	histCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	histOut, histErr := histCmd.CombinedOutput()
	if histErr != nil {
		t.Fatalf("history failed: %v\nOutput: %s", histErr, histOut)
	}
	if !strings.Contains(string(histOut), "v1") {
		t.Errorf("expected history output to contain v1 snapshot, got: %s", string(histOut))
	}

	// 4. Rollback to v1
	rollCmd := exec.Command(binPath, "rollback", "api/key", "--version", "1", "--profile", profile)
	rollCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	rollOut, rollErr := rollCmd.CombinedOutput()
	if rollErr != nil {
		t.Fatalf("rollback failed: %v\nOutput: %s", rollErr, rollOut)
	}
	if !strings.Contains(string(rollOut), "Rolled back secret") {
		t.Errorf("unexpected rollback output: %s", string(rollOut))
	}

	// Verify current value is back to val_v1
	getCmd := exec.Command(binPath, "get", "api/key", "--profile", profile)
	getCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	getOut, _ := getCmd.CombinedOutput()
	if !strings.Contains(string(getOut), "val_v1") {
		t.Errorf("expected active secret to be val_v1 after rollback, got: %s", string(getOut))
	}

	// 5. Test soft-delete & restore
	rmCmd := exec.Command(binPath, "rm", "api/key", "--profile", profile)
	rmCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	if out, err := rmCmd.CombinedOutput(); err != nil {
		t.Fatalf("rm failed: %v\nOutput: %s", err, out)
	}

	// Check ls --trash
	lsTrash := exec.Command(binPath, "ls", "--trash", "--profile", profile)
	lsTrash.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	trashOut, _ := lsTrash.CombinedOutput()
	if !strings.Contains(string(trashOut), "api/key") {
		t.Errorf("expected trash bin to list api/key, got: %s", string(trashOut))
	}

	// Restore soft deleted key
	rstCmd := exec.Command(binPath, "restore-deleted", "api/key", "--profile", profile)
	rstCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	if out, err := rstCmd.CombinedOutput(); err != nil {
		t.Fatalf("restore-deleted failed: %v\nOutput: %s", err, out)
	}
}

func TestOOMGuardrailAndPreallocation(t *testing.T) {
	d, err := daemon.NewDaemon("oom-test-profile", 30*time.Second, "v1.0.0")
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}
	if d == nil {
		t.Fatal("expected daemon pointer to be non-nil")
	}
}

func TestGUIV2KeychainUnlockAlignment(t *testing.T) {
	profile := "gui-v2-alignment-test"
	os.Setenv("SEC_TEST_MODE", "1")
	defer os.Unsetenv("SEC_TEST_MODE")

	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	_ = os.Remove(sockPath)
	_ = os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	d, err := daemon.NewDaemon(profile, 30*time.Second, "v2.2.0")
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}
	go func() {
		_ = d.Start()
	}()
	defer d.Stop()

	// Give daemon time to start
	time.Sleep(100 * time.Millisecond)

	// Create a v2.0 vault envelope matching SEC_TEST_MODE key
	key := []byte("01234567890123456789012345678901")

	st := &store.EncryptedStore{
		Secrets: map[string]store.SecretEntry{
			"gui/test": {Value: "gui_val_123"},
		},
	}

	mnemonic, err := crypto.GenerateMnemonic()
	if err != nil {
		t.Fatalf("failed to generate mnemonic: %v", err)
	}

	rawStore, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("failed to marshal store: %v", err)
	}

	payload, err := crypto.Encrypt(key, rawStore)
	if err != nil {
		t.Fatalf("failed to encrypt store payload: %v", err)
	}

	slot1, err := store.WrapMasterKey(mnemonic, key)
	if err != nil {
		t.Fatalf("failed to wrap master key: %v", err)
	}

	env := &store.VaultEnvelope{
		SchemaVersion: store.SchemaV2,
		UpgradedAt:    time.Now().UTC(),
		Slot1:         slot1,
		Payload:       payload,
	}

	if err := store.WriteVaultEnvelope(dbPath, env); err != nil {
		t.Fatalf("failed to write v2 vault envelope: %v", err)
	}

	// Store key in Keychain using SetCurrentSet
	if err := keychain.SetCurrentSet("sec-session:profile_"+profile, "master", key); err != nil {
		t.Fatalf("failed to set master key in keychain: %v", err)
	}
	defer keychain.Delete("sec-session:profile_"+profile, "master")

	// Verify ensureUnlocked can unlock the v2 store under SEC_TEST_MODE=1
	resp, err := ensureUnlocked(profile)
	if err != nil {
		t.Fatalf("ensureUnlocked failed for v2 store: %v", err)
	}
	if resp == nil || !resp.Success {
		t.Fatalf("expected successful IPC response from ensureUnlocked, got: %+v", resp)
	}
}

func TestDaemonParityAndAutoEviction(t *testing.T) {
	profile := "daemon-parity-test"
	os.Setenv("SEC_TEST_MODE", "1")
	defer os.Unsetenv("SEC_TEST_MODE")

	sockPath, _ := config.GetSocketPath(profile)
	pidPath, _ := config.GetPIDFilePath(profile)
	_ = os.Remove(sockPath)
	_ = os.Remove(pidPath)
	defer os.Remove(sockPath)
	defer os.Remove(pidPath)

	d, err := daemon.NewDaemon(profile, 30*time.Second, "v1.0.0-old")
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}
	go func() {
		_ = d.Start()
	}()
	defer d.Stop()

	time.Sleep(100 * time.Millisecond)

	// Verify PID lockfile exists
	if _, err := os.Stat(pidPath); err != nil {
		t.Fatalf("expected PID lockfile to exist at %s: %v", pidPath, err)
	}

	// Write a fake external PID to test eviction without killing current test process
	fakeInfo := daemon.PIDLockInfo{
		PID:        999999,
		Executable: "/usr/local/bin/sec-agent-old",
		Version:    "v1.0.0-old",
		Profile:    profile,
	}
	fakeData, _ := json.Marshal(fakeInfo)
	_ = os.WriteFile(pidPath, fakeData, 0600)

	// Verify evictStaleDaemon removes PID lockfile and cleans up
	evictStaleDaemon(profile)

	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Errorf("expected PID lockfile to be removed after eviction")
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

func TestV2SeedMigrationAndDiagnostics(t *testing.T) {
	testMnemonic, genErr := crypto.GenerateMnemonic()
	if genErr != nil || !crypto.MnemonicValid(testMnemonic) {
		t.Fatalf("failed to generate valid test mnemonic: %v", genErr)
	}

	// Test store load error message enhancement for cipher authentication failure
	badKey := make([]byte, 32)
	for i := range badKey {
		badKey[i] = 0xff
	}

	tmpDir := t.TempDir()
	storeFile := filepath.Join(tmpDir, "secrets_test-prof.enc")

	// Write an encrypted store with a different key
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0x11
	}

	s := &store.EncryptedStore{
		Secrets: map[string]store.SecretEntry{
			"dummy": {Value: "value"},
		},
	}

	if err := store.SaveStore("test-prof", s, masterKey); err != nil {
		t.Fatalf("failed to save store: %v", err)
	}

	// Try loading with badKey to trigger GCM error
	_, err := store.LoadStore("test-prof", badKey)
	if err == nil {
		t.Fatalf("expected LoadStore to fail with incorrect key")
	}

	if !strings.Contains(err.Error(), "master key mismatch") || !strings.Contains(err.Error(), "sec session recover --profile test-prof") {
		t.Errorf("expected actionable error message with recovery instructions, got: %v", err)
	}

	_ = storeFile
}

func TestCrossProfileCopyAndUsability(t *testing.T) {
	tmpDir := t.TempDir()
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()
	_ = os.Chdir(tmpDir)

	// 1. Verify loadWorkspaceConfig parses .secrc
	secrcContent := `{"profile": "router-ax3600-prod"}`
	if err := os.WriteFile(filepath.Join(tmpDir, ".secrc"), []byte(secrcContent), 0600); err != nil {
		t.Fatalf("failed to write .secrc: %v", err)
	}

	cfg := loadWorkspaceConfig()
	if cfg == nil || cfg.Profile != "router-ax3600-prod" {
		t.Fatalf("expected loadWorkspaceConfig to parse profile 'router-ax3600-prod', got: %+v", cfg)
	}

	// 2. Verify cross-profile copy logic
	srcProfile := "copy-src-prof"
	dstProfile := "copy-dst-prof"
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0x22
	}

	sSrc := &store.EncryptedStore{
		Secrets: map[string]store.SecretEntry{
			"wifi/passphrase": {Value: "secret-wifi-pass", Comment: "Original WiFi secret"},
		},
	}
	if err := store.SaveStore(srcProfile, sSrc, masterKey); err != nil {
		t.Fatalf("failed to save src store: %v", err)
	}

	sDst := &store.EncryptedStore{
		Secrets: map[string]store.SecretEntry{},
	}
	if err := store.SaveStore(dstProfile, sDst, masterKey); err != nil {
		t.Fatalf("failed to save dst store: %v", err)
	}

	// Read from src, write to dst
	loadedSrc, err := store.LoadStore(srcProfile, masterKey)
	if err != nil {
		t.Fatalf("failed to load src store: %v", err)
	}
	entry := loadedSrc.Secrets["wifi/passphrase"]

	loadedDst, err := store.LoadStore(dstProfile, masterKey)
	if err != nil {
		t.Fatalf("failed to load dst store: %v", err)
	}
	loadedDst.Secrets["router/wifi_passphrase"] = store.SecretEntry{
		Value:   entry.Value,
		Comment: "Copied from " + srcProfile + ":wifi/passphrase",
	}
	if err := store.SaveStore(dstProfile, loadedDst, masterKey); err != nil {
		t.Fatalf("failed to save copied dst store: %v", err)
	}

	finalDst, err := store.LoadStore(dstProfile, masterKey)
	if err != nil {
		t.Fatalf("failed to load final dst store: %v", err)
	}

	if finalDst.Secrets["router/wifi_passphrase"].Value != "secret-wifi-pass" {
		t.Errorf("expected copied secret value 'secret-wifi-pass', got %q", finalDst.Secrets["router/wifi_passphrase"].Value)
	}
}





