package main

import (
	"bytes"
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

func TestLongestSecretPrefixSuffix(t *testing.T) {
	secrets := []string{
		"azure_devops_pat_secret_123456789012345678901234567890",
		"super_secret_token",
	}
	maxLen := len(secrets[0])

	// 1. Text has no suffix matching any secret prefix
	prompt := "Apply to 3 item(s)? [y/N] "
	L := longestSecretPrefixSuffix(prompt, secrets, maxLen)
	if L != 0 {
		t.Fatalf("expected L=0 for interactive prompt, got %d", L)
	}

	// 2. Text ends with exact prefix "azure_" (6 chars)
	textWithPrefix := "Some output before azure_"
	L = longestSecretPrefixSuffix(textWithPrefix, secrets, maxLen)
	if L != 6 {
		t.Fatalf("expected L=6 for prefix 'azure_', got %d", L)
	}

	// 3. Text ends with "s" matching prefix of "super_secret_token"
	textEndsWithS := "Enter choice s"
	L = longestSecretPrefixSuffix(textEndsWithS, secrets, maxLen)
	if L != 1 {
		t.Fatalf("expected L=1 for trailing 's', got %d", L)
	}
}

func TestRedactWriterImmediatePromptFlush(t *testing.T) {
	var buf bytes.Buffer
	// 52-char secret token
	azurePAT := "oiv45abcdefghijklmnopqrstuvwxyz1234567890abcdefghij"
	w := newRedactWriter(&buf, []string{azurePAT})

	prompt := "Apply to 3 item(s)? [y/N] "
	n, err := w.Write([]byte(prompt))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != len(prompt) {
		t.Fatalf("expected n=%d, got %d", len(prompt), n)
	}

	// Because prompt does not end with any prefix of azurePAT,
	// it MUST be flushed immediately to buf without waiting for Flush()!
	if buf.String() != prompt {
		t.Fatalf("expected prompt to flush immediately, got %q in buffer", buf.String())
	}
}

func TestRedactWriterBoundaryCrossingRedaction(t *testing.T) {
	var buf bytes.Buffer
	secret := "TOP_SECRET_API_KEY_12345"
	w := newRedactWriter(&buf, []string{secret})

	// Chunk 1: partial prefix
	chunk1 := "Header: TOP_SEC"
	_, _ = w.Write([]byte(chunk1))

	// Should flush "Header: " immediately, retaining "TOP_SEC"
	if buf.String() != "Header: " {
		t.Fatalf("expected buf to have 'Header: ', got %q", buf.String())
	}

	// Chunk 2: rest of secret + trailing message
	chunk2 := "RET_API_KEY_12345 -- finished."
	_, _ = w.Write([]byte(chunk2))

	expected := "Header: [REDACTED_BY_SEC] -- finished."
	if buf.String() != expected {
		t.Fatalf("expected %q, got %q", expected, buf.String())
	}
}

func TestRedactWriterIdleTimerFlush(t *testing.T) {
	var buf bytes.Buffer
	secret := "SECRET_TOKEN"
	w := newRedactWriter(&buf, []string{secret})
	w.idleTimeout = 10 * time.Millisecond

	// Writes text that ends with "S", matching the prefix of "SECRET_TOKEN"
	_, _ = w.Write([]byte("Target: S"))

	// "Target: " should be flushed immediately, "S" buffered
	if buf.String() != "Target: " {
		t.Fatalf("expected 'Target: ', got %q", buf.String())
	}

	// Wait for idle timer
	time.Sleep(30 * time.Millisecond)

	// Now "Target: S" should be fully flushed
	if buf.String() != "Target: S" {
		t.Fatalf("expected 'Target: S' after idle timeout, got %q", buf.String())
	}
}

func TestRecoverySeedWarningBanner(t *testing.T) {
	if !bytes.Contains([]byte(recoverySeedWarningBanner), []byte("CRITICAL SECURITY WARNING")) {
		t.Errorf("expected recoverySeedWarningBanner to contain 'CRITICAL SECURITY WARNING'")
	}
	if !bytes.Contains([]byte(recoverySeedWarningBanner), []byte("NEVER paste this recovery seed phrase")) {
		t.Errorf("expected recoverySeedWarningBanner to contain 'NEVER paste this recovery seed phrase'")
	}
	if !bytes.Contains([]byte(recoverySeedWarningBanner), []byte("chat, AI prompt")) {
		t.Errorf("expected recoverySeedWarningBanner to warn about chat and AI prompts")
	}
}

func TestRunStdinKeyInjection(t *testing.T) {
	profile := "stdinkey-test-profile"
	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	os.Remove(sockPath)
	os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_stdin_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v\nOutput: %s", err, out)
	}

	d, err := daemon.NewDaemon(profile, 30*time.Second, Version)
	if err != nil {
		t.Fatalf("failed to create test daemon: %v", err)
	}
	token := "stdinkey-test-token"
	d.SetSessionTokenForTest(token)
	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901"))
	d.SetSecretsForTest(map[string]store.SecretEntry{
		"kdbx/pass": {Value: "kdbx-secret-password-xyz"},
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

	// 1. Default with --no-redact: appends newline \n
	cmd1 := exec.Command(binPath, "run", "--stdin-key", "kdbx/pass", "--no-redact", "--profile", profile, "--", "cat")
	cmd1.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	out1, err1 := cmd1.CombinedOutput()
	if err1 != nil {
		t.Fatalf("sec run --stdin-key failed: %v\nOutput: %s", err1, out1)
	}
	if string(out1) != "kdbx-secret-password-xyz\n" {
		t.Errorf("expected 'kdbx-secret-password-xyz\\n', got %q", string(out1))
	}

	// 2. Raw: without newline, with --no-redact
	cmd2 := exec.Command(binPath, "run", "--stdin-key", "kdbx/pass", "--stdin-raw", "--no-redact", "--profile", profile, "--", "cat")
	cmd2.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	out2, err2 := cmd2.CombinedOutput()
	if err2 != nil {
		t.Fatalf("sec run --stdin-key --stdin-raw failed: %v\nOutput: %s", err2, out2)
	}
	if string(out2) != "kdbx-secret-password-xyz" {
		t.Errorf("expected 'kdbx-secret-password-xyz', got %q", string(out2))
	}

	// 2b. Default with redaction: masks echoed secret
	cmd2b := exec.Command(binPath, "run", "--stdin-key", "kdbx/pass", "--profile", profile, "--", "cat")
	cmd2b.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	out2b, err2b := cmd2b.CombinedOutput()
	if err2b != nil {
		t.Fatalf("sec run --stdin-key with redaction failed: %v\nOutput: %s", err2b, out2b)
	}
	if string(out2b) != "[REDACTED_BY_SEC]\n" {
		t.Errorf("expected '[REDACTED_BY_SEC]\\n', got %q", string(out2b))
	}

	// 3. Missing secret key: fails before executing child with exit code 2
	cmd3 := exec.Command(binPath, "run", "--stdin-key", "nonexistent/key", "--profile", profile, "--", "cat")
	cmd3.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	out3, err3 := cmd3.CombinedOutput()
	if err3 == nil {
		t.Fatalf("expected missing stdin key to fail, but succeeded with output: %s", out3)
	}
	exitErr, ok := err3.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 2 {
		t.Errorf("expected exit code 2 for missing stdin key, got: %v (exit code %d), output:\n%s", err3, exitErr.ExitCode(), out3)
	}
	if !strings.Contains(string(out3), "failed to fetch stdin key \"nonexistent/key\"") {
		t.Errorf("expected error to explain missing stdin key, got: %s", out3)
	}
}

