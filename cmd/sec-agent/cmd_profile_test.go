package main

import (
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
	if !strings.Contains(outStr, "Created .secrc bound to profile \"testnode\"") {
		t.Errorf("expected success message with .secrc creation, got:\n%s", outStr)
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
