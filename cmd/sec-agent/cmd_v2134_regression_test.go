package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
)

func TestDaemonSubshellDetachmentAndSurvival(t *testing.T) {
	profile := "subshell-detach-test-profile"
	sockPath, _ := config.GetSocketPath(profile)
	pidPath, _ := config.GetPIDFilePath(profile)
	_ = os.Remove(sockPath)
	_ = os.Remove(pidPath)
	defer func() {
		_ = os.Remove(sockPath)
		_ = os.Remove(pidPath)
	}()

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_detach_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v\nOutput: %s", err, out)
	}

	// Launch daemon inside a temporary bash subshell that terminates immediately.
	// In the past, SIGHUP on subshell exit killed the child daemon.
	logPath := filepath.Join(tmpDir, "daemon.log")
	subshellCmd := exec.Command("sh", "-c", binPath+" --profile "+profile+" daemon >"+logPath+" 2>&1 &")
	subshellCmd.Env = append(os.Environ(), "SEC_PROFILE="+profile, "SEC_TEST_MODE=1")
	if out, err := subshellCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to spawn daemon in subshell: %v\nOutput: %s", err, out)
	}

	// Wait for socket to appear
	daemonRunning := false
	for i := 0; i < 60; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			daemonRunning = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !daemonRunning {
		logData, _ := os.ReadFile(logPath) // #nosec G304 G703
		t.Fatalf("daemon socket %s failed to initialize. Daemon log:\n%s", sockPath, string(logData))
	}

	// Sleep 250ms to allow subshell process to completely exit and kernel to send SIGHUP
	time.Sleep(250 * time.Millisecond)

	// Verify daemon is STILL running past subshell exit and responding over IPC
	resp, err := queryDaemonRaw(profile, daemon.IPCRequest{Action: daemon.IPCActionPing})
	if err != nil || resp == nil {
		t.Fatalf("daemon died after subshell termination! Error: %v", err)
	}
	if !resp.Success && resp.Error != "Session locked" {
		t.Fatalf("unexpected daemon ping error: %s", resp.Error)
	}

	// Clean up daemon
	if pidData, err := os.ReadFile(pidPath); err == nil { // #nosec G304 G703
		var lockInfo daemon.PIDLockInfo
		if json.Unmarshal(pidData, &lockInfo) == nil && lockInfo.PID > 0 {
			_ = syscall.Kill(lockInfo.PID, syscall.SIGTERM)
		}
	}
}

func TestReadOnlyCommandsPureNonMutation(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_readonly_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v\nOutput: %s", err, out)
	}

	// Create a mock workspace with .github/copilot-instructions.md containing old content
	workspaceDir := filepath.Join(tmpDir, "test_workspace")
	githubDir := filepath.Join(workspaceDir, ".github")
	if err := os.MkdirAll(githubDir, 0700); err != nil {
		t.Fatalf("failed to create mock workspace: %v", err)
	}
	skillPath := filepath.Join(githubDir, "copilot-instructions.md")
	oldContent := []byte("# OLD COPILOT INSTRUCTIONS v1.0.0\nDo not modify me.")
	if err := os.WriteFile(skillPath, oldContent, 0600); err != nil {
		t.Fatalf("failed to write mock skill: %v", err)
	}

	statBefore, err := os.Stat(skillPath)
	if err != nil {
		t.Fatalf("failed to stat skill: %v", err)
	}

	// 1. Run sec-agent --version inside mock workspace
	verCmd := exec.Command(binPath, "--version")
	verCmd.Dir = workspaceDir
	verCmd.Env = append(os.Environ(), "SEC_TEST_MODE=1")
	var stdoutBuf, stderrBuf bytes.Buffer
	verCmd.Stdout = &stdoutBuf
	verCmd.Stderr = &stderrBuf
	if err := verCmd.Run(); err != nil {
		t.Fatalf("sec-agent --version failed: %v\nStderr: %s", err, stderrBuf.String())
	}

	if !strings.Contains(stdoutBuf.String(), "sec-agent CLI:") {
		t.Errorf("expected version output, got: %s", stdoutBuf.String())
	}
	if stderrBuf.Len() > 0 {
		t.Errorf("expected clean stderr on --version, got: %s", stderrBuf.String())
	}

	// Verify file was NOT modified
	contentAfter, _ := os.ReadFile(skillPath) // #nosec G304 G703
	if !bytes.Equal(contentAfter, oldContent) {
		t.Fatalf("CRITICAL: sec-agent --version mutated %s!", skillPath)
	}
	statAfter, _ := os.Stat(skillPath)
	if statAfter.ModTime() != statBefore.ModTime() {
		t.Fatalf("CRITICAL: sec-agent --version updated modification time of %s!", skillPath)
	}

	// 2. Run sec-agent --help inside mock workspace
	helpCmd := exec.Command(binPath, "--help")
	helpCmd.Dir = workspaceDir
	helpCmd.Env = append(os.Environ(), "SEC_TEST_MODE=1")
	stdoutBuf.Reset()
	stderrBuf.Reset()
	helpCmd.Stdout = &stdoutBuf
	helpCmd.Stderr = &stderrBuf
	if err := helpCmd.Run(); err != nil {
		t.Fatalf("sec-agent --help failed: %v\nStderr: %s", err, stderrBuf.String())
	}

	contentAfterHelp, _ := os.ReadFile(skillPath) // #nosec G304 G703
	if !bytes.Equal(contentAfterHelp, oldContent) {
		t.Fatalf("CRITICAL: sec-agent --help mutated %s!", skillPath)
	}
}

func TestGlobalVerboseFlagExecution(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_verbose_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v\nOutput: %s", err, out)
	}

	// 1. Standalone --verbose
	cmdStandalone := exec.Command(binPath, "--verbose")
	var stdoutBuf, stderrBuf bytes.Buffer
	cmdStandalone.Stdout = &stdoutBuf
	cmdStandalone.Stderr = &stderrBuf
	if err := cmdStandalone.Run(); err != nil {
		t.Fatalf("sec-agent --verbose failed with exit code: %v\nStderr: %s", err, stderrBuf.String())
	}
	outStr := stdoutBuf.String()
	if !strings.Contains(outStr, "=== Runtime Configuration & Diagnostics ===") {
		t.Errorf("missing Runtime Configuration in standalone --verbose output: %s", outStr)
	}
	if !strings.Contains(outStr, "=== Global Flags ===") {
		t.Errorf("missing Global Flags in standalone --verbose output: %s", outStr)
	}
	if !strings.Contains(outStr, "=== Categorized Commands ===") {
		t.Errorf("missing Categorized Commands in standalone --verbose output: %s", outStr)
	}

	// 2. Leading --verbose with subcommand: sec-agent --verbose status
	cmdLeading := exec.Command(binPath, "--verbose", "status")
	stdoutBuf.Reset()
	stderrBuf.Reset()
	cmdLeading.Stdout = &stdoutBuf
	cmdLeading.Stderr = &stderrBuf
	_ = cmdLeading.Run()
	errStr := stderrBuf.String()
	if strings.Contains(errStr, "Unknown command: --verbose") {
		t.Fatalf("sec-agent --verbose status returned Unknown command: --verbose!")
	}
	if !strings.Contains(errStr, "[VERBOSE]") {
		t.Errorf("expected [VERBOSE] diagnostics on stderr, got: %s", errStr)
	}

	// 3. Trailing --verbose with subcommand: sec-agent status --verbose
	cmdTrailing := exec.Command(binPath, "status", "--verbose")
	stdoutBuf.Reset()
	stderrBuf.Reset()
	cmdTrailing.Stdout = &stdoutBuf
	cmdTrailing.Stderr = &stderrBuf
	_ = cmdTrailing.Run()
	errTrailingStr := stderrBuf.String()
	if !strings.Contains(errTrailingStr, "[VERBOSE]") {
		t.Errorf("expected [VERBOSE] diagnostics on stderr for trailing flag, got: %s", errTrailingStr)
	}
}

func TestScopeVeracityAndSelfHealing(t *testing.T) {
	// Verify determineSkillScope returns "workspace" for repository paths
	repoSkillPath := "/Users/test/workspace/personal-project/.github/copilot-instructions.md"
	scope := determineSkillScope("copilot", repoSkillPath)
	if scope != "workspace" {
		t.Errorf("expected scope 'workspace' for %s, got %s", repoSkillPath, scope)
	}

	cursorSkillPath := "/Users/test/workspace/personal-project/.cursor/rules/sec-agent.mdc"
	scopeCursor := determineSkillScope("cursor", cursorSkillPath)
	if scopeCursor != "workspace" {
		t.Errorf("expected scope 'workspace' for %s, got %s", cursorSkillPath, scopeCursor)
	}

	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		globalGemini := filepath.Join(homeDir, ".gemini", "config", "skills", "sec-agent-integration", "SKILL.md")
		scopeGlobal := determineSkillScope("antigravity", globalGemini)
		if scopeGlobal != "global" {
			t.Errorf("expected scope 'global' for %s, got %s", globalGemini, scopeGlobal)
		}
	}
}
