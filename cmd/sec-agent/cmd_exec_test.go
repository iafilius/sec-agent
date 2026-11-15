package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"
	"strings"
	"testing"
	"time"
)

func TestExecInMemoryStdinAndPositionalArgs(t *testing.T) {
	workDir := t.TempDir()
	realWorkDir, err := filepath.EvalSymlinks(workDir)
	if err != nil {
		realWorkDir = workDir
	}

	sentinelSecretCmd := "STEALTH_SENTINEL_192_168_31_125_SECRET_BODY"
	script := strings.Join([]string{
		"set -e",
		"# " + sentinelSecretCmd,
		"PS_CMD=$(ps -o command= -p $$)",
		"printf 'PS=%s\\n' \"$PS_CMD\"",
		"printf 'PWD=%s\\n' \"$(pwd -P)\"",
		"printf 'ARG1=%s\\n' \"$1\"",
		"printf 'ARG2=%s\\n' \"$2\"",
	}, "\n")

	var stdout, stderr bytes.Buffer
	err = executeScriptInMemory(script, "/bin/sh", workDir, []string{"--dry-run", "prod-target"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("executeScriptInMemory failed: %v (stderr: %s)", err, stderr.String())
	}

	out := stdout.String()
	if strings.Contains(out, sentinelSecretCmd) {
		t.Fatalf("expected child process argv (ps) NOT to contain script body sentinel %q, got output:\n%s", sentinelSecretCmd, out)
	}
	if !strings.Contains(out, "-s") {
		t.Errorf("expected child shell ps command line to include '-s', got:\n%s", out)
	}
	if !strings.Contains(out, "PWD="+realWorkDir) {
		t.Errorf("expected working directory %q, got:\n%s", realWorkDir, out)
	}
	if !strings.Contains(out, "ARG1=--dry-run") || !strings.Contains(out, "ARG2=prod-target") {
		t.Errorf("expected positional args $1=--dry-run and $2=prod-target, got:\n%s", out)
	}

	// Ensure zero temporary script files were created in workDir
	entries, err := os.ReadDir(workDir)
	if err != nil {
		t.Fatalf("failed reading workDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 files created in workDir, found %d", len(entries))
	}

	// Verify non-zero exit code propagation
	err = executeScriptInMemory("exit 42", "/bin/sh", workDir, nil, &stdout, &stderr)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 42 {
		t.Fatalf("expected ExitError with code 42, got: %v", err)
	}
}

func TestExecVaultSaveShowAndRunNoTrace(t *testing.T) {
	// Use /tmp to keep Unix domain socket path well below macOS 104-byte sun_path limit.
	tmpCfgDir, err := os.MkdirTemp("/tmp", "sec_exec_*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpCfgDir)

	t.Setenv("SEC_CONFIG_DIR", tmpCfgDir)
	t.Setenv("SEC_TEST_MODE", "1")

	profile := "exectest"
	sockPath, err := config.GetSocketPath(profile)
	if err != nil {
		t.Fatalf("GetSocketPath failed: %v", err)
	}
	defer os.Remove(sockPath)

	d, err := daemon.NewDaemon(profile, 5*time.Minute, Version)
	if err != nil {
		t.Fatalf("NewDaemon failed: %v", err)
	}
	d.IsTestInstance = true
	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901"))
	d.SetSessionTokenForTest("exec-test-session-token")
	d.SetSecretsForTest(map[string]store.SecretEntry{
		"api/token": {
			Value: "super-secret-token-9999",
		},
	})
	t.Setenv("SEC_SESSION_TOKEN", "exec-test-session-token")

	go func() {
		_ = d.Start()
	}()
	defer d.Stop()

	for i := 0; i < 40; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	// 1. Save a stealth command script under short name "my-job" -> should normalize to "exec/my-job"
	scriptContent := "echo \"running job with token={{api/token}} and arg=$1\""
	vaultKey, err := saveExecScript(profile, "my-job", scriptContent, "Nightly stealth job")
	if err != nil {
		t.Fatalf("saveExecScript failed: %v", err)
	}
	if vaultKey != "exec/my-job" {
		t.Fatalf("expected vault key 'exec/my-job', got %q", vaultKey)
	}

	// Remove any audit.log entries created by the initial SET so we cleanly measure NoTrace execution
	auditPath := filepath.Join(tmpCfgDir, "audit.log")
	_ = os.Remove(auditPath)

	// 2. Resolve the stored command script with NoTrace: true
	resolvedScript, resolvedKey, err := resolveExecScript(profile, "my-job", true)
	if err != nil {
		t.Fatalf("resolveExecScript failed: %v", err)
	}
	if resolvedKey != "exec/my-job" {
		t.Errorf("expected resolved key 'exec/my-job', got %q", resolvedKey)
	}
	if resolvedScript != scriptContent {
		t.Errorf("expected script %q, got %q", scriptContent, resolvedScript)
	}

	// 3. Expand inline secrets and execute with dynamic redaction and NoTrace: true
	expandedScript, inlineSecrets, err := expandInlineScriptSecrets(profile, resolvedScript, true)
	if err != nil {
		t.Fatalf("expandInlineScriptSecrets failed: %v", err)
	}
	if !strings.Contains(expandedScript, "super-secret-token-9999") {
		t.Fatalf("expected inline placeholder {{api/token}} to expand in memory, got %q", expandedScript)
	}

	secretVals := collectRedactionSecrets(profile, true)
	secretVals = append(secretVals, inlineSecrets...)

	var rawOut, rawErr bytes.Buffer
	redactOut := newRedactWriter(&rawOut, secretVals)
	if err := executeScriptInMemory(expandedScript, "/bin/sh", "", []string{"slice-1"}, redactOut, &rawErr); err != nil {
		t.Fatalf("executeScriptInMemory failed: %v (stderr: %s)", err, rawErr.String())
	}
	_ = redactOut.Flush()

	outputStr := rawOut.String()
	if strings.Contains(outputStr, "super-secret-token-9999") {
		t.Errorf("expected secret value to be redacted from stdout, got: %q", outputStr)
	}
	if !strings.Contains(outputStr, "[REDACTED_BY_SEC]") || !strings.Contains(outputStr, "arg=slice-1") {
		t.Errorf("expected redacted output with arg=slice-1, got: %q", outputStr)
	}

	// 4. Verify audit.log has zero GET or GET_GROUP entries when NoTrace: true
	if data, err := os.ReadFile(auditPath); err == nil && len(data) > 0 {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var entry daemon.AuditLogEntry
			if jsonErr := json.Unmarshal([]byte(line), &entry); jsonErr == nil {
				if entry.Action == daemon.AuditEventGet || entry.Action == daemon.AuditEventGetGroup {
					t.Errorf("expected zero GET/GET_GROUP audit log entries with NoTrace: true, found: %s", line)
				}
			}
		}
	}

	// 5. Verify that when NoTrace: false (--trace), GET is logged as expected
	_, _, err = resolveExecScript(profile, "my-job", false)
	if err != nil {
		t.Fatalf("resolveExecScript with NoTrace=false failed: %v", err)
	}
	auditBytes, err := os.ReadFile(auditPath)
	if err != nil || !strings.Contains(string(auditBytes), `"action":"GET"`) {
		t.Errorf("expected audit.log to record GET when NoTrace=false, got: %s (err: %v)", string(auditBytes), err)
	}
}
