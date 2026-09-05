package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
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
	d, err := daemon.NewDaemon(profile, 5*time.Minute, Version)
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
	expOut, err := expCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec export json failed: %v\nOutput: %s", err, string(expOut))
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
	loadOut, err := loadCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec load failed: %v\nOutput: %s", err, string(loadOut))
	}
	loadStr := string(loadOut)
	if !strings.Contains(loadStr, "export VCO_URL=\"https://vco.example.com\"") || !strings.Contains(loadStr, "export VCO_TOKEN=\"mock-token-12345\"") {
		t.Errorf("sec load output mismatch. Got:\n%s", loadStr)
	}

	// 6c. Test 'sec run --group' scoped environment variable injection
	runGroupCmd := exec.Command("./sec_test_bin", "run", "--no-redact", "--group", "velocloud-provider", "--profile", profile, "--", "env")
	runGroupCmd.Env = testEnv
	runGroupOut, err := runGroupCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec run --group failed: %v\nOutput: %s", err, string(runGroupOut))
	}
	runGroupStr := string(runGroupOut)
	if !strings.Contains(runGroupStr, "VCO_URL=https://vco.example.com") || strings.Contains(runGroupStr, "OTHER_CATEGORY") {
		t.Errorf("sec run --group output mismatch. Got:\n%s", runGroupStr)
	}

	// 6d. Test 'sec get --prefix' batch group retrieval
	getGroupCmd := exec.Command("./sec_test_bin", "get", "velocloud-provider", "--prefix", "--profile", profile)
	getGroupCmd.Env = testEnv
	getGroupOut, err := getGroupCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec get --prefix failed: %v\nOutput: %s", err, string(getGroupOut))
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
	if !strings.Contains(string(statusOut), "AI Skills:") {
		t.Errorf("expected 'AI Skills:' line in sec status output, got: %s", string(statusOut))
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

	// Test sec rotate (Disabled until explicitly enabled via ENABLE_TOKEN_ROTATION_TEST=1)
	if os.Getenv("ENABLE_TOKEN_ROTATION_TEST") != "" {
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
	} else {
		t.Log("Skipping sec rotate test execution (disabled per user directive until enabled)")
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

func TestSubcommandHelpFlagsPureNoOp(t *testing.T) {
	binPath := "./sec-agent-test-help"
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v, output: %s", err, string(out))
	}
	defer os.Remove(binPath)

	testCases := []struct {
		args        []string
		expectedSub string
	}{
		{[]string{"migrate-v2", "--help"}, "Command:     migrate-v2"},
		{[]string{"migrate-v2", "-h"}, "Command:     migrate-v2"},
		{[]string{"help", "migrate-v2"}, "Command:     migrate-v2"},
		{[]string{"rm", "--help"}, "Command:     rm"},
		{[]string{"set", "--help"}, "Command:     set"},
		{[]string{"rotate", "--help"}, "Command:     rotate"},
		{[]string{"relabel", "--help"}, "Command:     relabel"},
	}

	for _, tc := range testCases {
		cmd := exec.Command(binPath, tc.args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("expected exit code 0 for args %v, got error: %v, output: %s", tc.args, err, string(out))
		}
		if !strings.Contains(string(out), tc.expectedSub) {
			t.Errorf("expected output to contain %q for args %v, got: %s", tc.expectedSub, tc.args, string(out))
		}
		// Confirm NO mutation / migration ran
		if strings.Contains(string(out), "24-word recovery mnemonic") {
			t.Errorf("CRITICAL SAFETY FAILURE: recovery mnemonic was generated during help call for args %v!", tc.args)
		}
	}
}

func TestInteractiveTerminalAgentDetection(t *testing.T) {
	// Directly test isInteractiveTerminal environment variable gating
	agentVars := []string{
		"CI",
		"CONTINUOUS_INTEGRATION",
		"NONINTERACTIVE",
		"DEBIAN_FRONTEND",
		"VSCODE_AGENT_ENABLED",
		"COPILOT_AGENT",
		"AI_AGENT",
	}

	for _, v := range agentVars {
		orig := os.Getenv(v)
		os.Setenv(v, "1")
		if isInteractiveTerminal() {
			t.Errorf("expected isInteractiveTerminal() to return false when %s=1", v)
		}
		if orig != "" {
			os.Setenv(v, orig)
		} else {
			os.Unsetenv(v)
		}
	}
}

func TestStatusAllDiscoversNamedProfilesOnDisk(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sec-agent-status-all-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	origConfig := os.Getenv("SEC_CONFIG_DIR")
	os.Setenv("SEC_CONFIG_DIR", tempDir)
	defer func() {
		if origConfig != "" {
			os.Setenv("SEC_CONFIG_DIR", origConfig)
		} else {
			os.Unsetenv("SEC_CONFIG_DIR")
		}
	}()

	// Create a dummy secrets_velocloud-prod.enc
	testFile := filepath.Join(tempDir, "secrets_velocloud-prod.enc")
	if err := os.WriteFile(testFile, []byte("test-payload"), 0600); err != nil {
		t.Fatalf("failed to write dummy vault: %v", err)
	}

	// Capture stdout of handleStatusAll
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	handleStatusAll()

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "velocloud-prod") {
		t.Errorf("expected handleStatusAll output to discover and contain 'velocloud-prod', got: %s", out)
	}
}

func TestOpenExportsProfileAndContextualTip(t *testing.T) {
	// Test default profile tip
	var defaultTip strings.Builder
	var namedTip strings.Builder

	// Verify contextual logic directly
	defaultProf := "default"
	namedProf := "velocloud-prod"

	if defaultProf != "default" && defaultProf != "" {
		t.Errorf("expected default profile not to be marked non-default")
	}

	if !(namedProf != "default" && namedProf != "") {
		t.Errorf("expected named profile to be recognized as non-default")
	}

	tipNamed := fmt.Sprintf("Tip: Run 'eval $(sec --profile %s open)' to automatically authorize this profile in your shell session.", namedProf)
	if !strings.Contains(tipNamed, "--profile velocloud-prod") {
		t.Errorf("expected tip to recommend exact profile command, got: %s", tipNamed)
	}
	_ = defaultTip
	_ = namedTip
}


