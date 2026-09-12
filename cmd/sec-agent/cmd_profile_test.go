package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"secure_secrets/internal/crypto"
	"secure_secrets/internal/store"
)

func TestProfileNewNonInteractiveBlocked(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_profile_test_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v, output: %s", err, string(out))
	}

	// In non-interactive mode without --seed, profile new should exit 78 with ASCII blocker
	cmd := exec.Command(binPath, "profile", "new", "testblocked")
	cmd.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir, "NONINTERACTIVE=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected profile new to fail in non-interactive mode without seed, but succeeded")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 78 {
		t.Errorf("expected exit code 78, got: %v (exit code: %d)", err, exitErr.ExitCode())
	}

	outStr := string(out)
	if !strings.Contains(outStr, "+------------------------------------------+") {
		t.Errorf("expected output to contain ASCII box border '+------------------------------------------+', got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "INTERACTIVE TERMINAL REQUIRED") {
		t.Errorf("expected output to contain 'INTERACTIVE TERMINAL REQUIRED', got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "sec-agent profile new testblocked") {
		t.Errorf("expected output to recommend running 'sec-agent profile new testblocked', got:\n%s", outStr)
	}
}

func TestProfileNewWithSeedAndSecrc(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %v", err)
	}

	binPath := filepath.Join(tmpDir, "sec_profile_test_bin2")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v, output: %s", err, string(out))
	}

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir to tmpDir: %v", err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	mnemonic, err := crypto.GenerateMnemonic()
	if err != nil {
		t.Fatalf("failed to generate mnemonic: %v", err)
	}

	// Run profile new testnode --seed "<mnemonic>" --secrc in SEC_TEST_MODE=1
	cmd := exec.Command(binPath, "profile", "new", "testnode", "--seed", mnemonic, "--secrc")
	cmd.Env = append(os.Environ(),
		"SEC_CONFIG_DIR="+tmpDir,
		"SEC_TEST_MODE=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("profile new failed: %v, output:\n%s", err, string(out))
	}

	outStr := string(out)
	if !strings.Contains(outStr, "Dual-Slot Touch ID + BIP39 recovery key") {
		t.Errorf("expected success message with Dual-Slot Touch ID + BIP39 recovery key, got:\n%s", outStr)
	}
	expectedSecrc := filepath.Join(tmpDir, ".secrc")
	if !strings.Contains(outStr, expectedSecrc) {
		t.Errorf("expected success message to contain absolute path %s, got:\n%s", expectedSecrc, outStr)
	}
	if !strings.Contains(outStr, "does not appear to be a Git repository") {
		t.Errorf("expected warning about missing Git repository marker, got:\n%s", outStr)
	}

	// 1. Verify vault file was created with complete v2.0 envelope
	vaultPath := filepath.Join(tmpDir, "secrets_testnode.enc")
	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatalf("vault file %s was not created: %v", vaultPath, err)
	}
	env, err := store.ReadVaultEnvelope(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault envelope: %v", err)
	}
	if !env.HasSlot1() || env.Slot1 == nil {
		t.Errorf("expected created vault to have Slot1 enrolled, got: %+v", env)
	}

	// 2. Verify .secrc file was written
	secrcPath := filepath.Join(tmpDir, ".secrc")
	secrcData, err := os.ReadFile(secrcPath)
	if err != nil {
		t.Fatalf("failed to read .secrc: %v", err)
	}
	if !strings.Contains(string(secrcData), `"profile": "testnode"`) {
		t.Errorf("expected .secrc to contain profile testnode, got:\n%s", string(secrcData))
	}

	// 3. Test sec profile ls
	lsCmd := exec.Command(binPath, "profile", "ls")
	lsCmd.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir)
	lsOut, err := lsCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("profile ls failed: %v, output: %s", err, string(lsOut))
	}
	if !strings.Contains(string(lsOut), "testnode") {
		t.Errorf("expected profile ls to show 'testnode', got:\n%s", string(lsOut))
	}

	// 4. Test duplicate creation fails
	dupCmd := exec.Command(binPath, "profile", "new", "testnode", "--seed", mnemonic)
	dupCmd.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir, "SEC_TEST_MODE=1")
	dupOut, dupErr := dupCmd.CombinedOutput()
	if dupErr == nil {
		t.Errorf("expected duplicate profile new to fail, but succeeded with output: %s", string(dupOut))
	}
	if !strings.Contains(string(dupOut), "already exists") {
		t.Errorf("expected duplicate profile error message to mention 'already exists', got:\n%s", string(dupOut))
	}
}

func TestProfileNewDefaultProfileRejection(t *testing.T) {
	binPath := "./sec_profile_def_test"
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v, output: %s", err, string(out))
	}
	defer os.Remove(binPath)

	cmd := exec.Command(binPath, "profile", "new", "default")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected profile new default to fail, but succeeded")
	}
	if !strings.Contains(string(out), "cannot create profile named 'default'") {
		t.Errorf("expected error message rejecting 'default', got:\n%s", string(out))
	}
}

func TestDoctorSkipKeychainAndHeadless(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SEC_CONFIG_DIR", tmpDir)

	binPath := "./sec_doctor_test_bin"
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v, output: %s", err, string(out))
	}
	defer os.Remove(binPath)

	// Test with --skip-keychain flag
	cmd := exec.Command(binPath, "doctor", "--skip-keychain")
	cmd.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("doctor --skip-keychain failed: %v, output:\n%s", err, string(out))
	}

	outStr := string(out)
	if !strings.Contains(outStr, "Skipped live Touch ID Keychain probe") {
		t.Errorf("expected skipped Touch ID Keychain probe message, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "--skip-keychain flag supplied") {
		t.Errorf("expected mention of --skip-keychain flag, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "All system diagnostic checks complete!") {
		t.Errorf("expected completion message, got:\n%s", outStr)
	}
}

func TestDoctorNestedEnvelopeDetectionAndRepair(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SEC_CONFIG_DIR", tmpDir)

	binPath := filepath.Join(tmpDir, "sec_doctor_repair_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v, output: %s", err, string(out))
	}

	// 1. Create a 4-level nested vault file in tmpDir
	vaultPath := filepath.Join(tmpDir, "secrets_test-nested.enc")
	currPayload := []byte("dummy-ciphertext-bytes")
	for level := 1; level <= 4; level++ {
		env := &store.VaultEnvelope{
			SchemaVersion: store.SchemaV2,
			Payload:       currPayload,
		}
		currPayload, _ = json.Marshal(env)
	}
	if err := os.WriteFile(vaultPath, currPayload, 0600); err != nil {
		t.Fatalf("failed to write nested vault file: %v", err)
	}

	if d := store.InspectVaultNesting(vaultPath); d != 4 {
		t.Fatalf("expected initial depth 4, got %d", d)
	}

	// 2. Execute `sec doctor --skip-keychain` and verify detection
	docCmd := exec.Command(binPath, "doctor", "--skip-keychain")
	docCmd.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir)
	docOut, err := docCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("doctor --skip-keychain failed: %v, output:\n%s", err, string(docOut))
	}
	docStr := string(docOut)
	if !strings.Contains(docStr, "Nested Envelope Detected (Depth: 4)") {
		t.Errorf("expected doctor output to detect depth 4 nesting, got:\n%s", docStr)
	}
	if !strings.Contains(docStr, "Run 'sec doctor --repair' to auto-heal") {
		t.Errorf("expected doctor output to suggest --repair, got:\n%s", docStr)
	}

	// 3. Execute `sec doctor --repair` and verify flattening
	repairCmd := exec.Command(binPath, "doctor", "--repair")
	repairCmd.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir)
	repairOut, err := repairCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("doctor --repair failed: %v, output:\n%s", err, string(repairOut))
	}
	repStr := string(repairOut)
	if !strings.Contains(repStr, "Flattened from depth 4 to 1") {
		t.Errorf("expected repair output to mention flattening from depth 4 to 1, got:\n%s", repStr)
	}
	if !strings.Contains(repStr, "Successfully repaired 1 nested vault envelope(s)") {
		t.Errorf("expected 1 repaired vault message, got:\n%s", repStr)
	}

	// Check backup file exists
	bakPath := vaultPath + ".bak_nested"
	if _, statErr := os.Stat(bakPath); statErr != nil {
		t.Errorf("expected backup file %s to exist: %v", bakPath, statErr)
	}

	// Check new depth is 1
	if d := store.InspectVaultNesting(vaultPath); d != 1 {
		t.Errorf("expected depth 1 after repair, got %d", d)
	}

	// 4. Re-running `doctor --repair` on clean vaults reports all clean
	rerunCmd := exec.Command(binPath, "doctor", "--repair")
	rerunCmd.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir)
	rerunOut, err := rerunCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("second doctor --repair failed: %v, output:\n%s", err, string(rerunOut))
	}
	if !strings.Contains(string(rerunOut), "All vault envelopes are already clean") {
		t.Errorf("expected clean message on rerun, got:\n%s", string(rerunOut))
	}
}

