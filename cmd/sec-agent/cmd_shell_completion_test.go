package main

import (
	"bytes"
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

	d, err := daemon.NewDaemon(profile, 30*time.Second, Version)
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
		zshCmd.Env = append(os.Environ(), "SEC_TEST_MODE=1")
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

func TestInitShellAndWorkspaceStatusIndicator(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// Test init-shell zsh
	rcFile := filepath.Join(tmpDir, ".zshrc")
	handleInitShell([]string{"zsh"})

	contentBytes, err := os.ReadFile(rcFile)
	if err != nil {
		t.Fatalf("failed to read generated .zshrc: %v", err)
	}
	content := string(contentBytes)

	if !strings.Contains(content, "alias sec=sec-agent") || !strings.Contains(content, "shell-completion zsh") {
		t.Errorf("expected .zshrc to contain alias and zsh completions, got:\n%s", content)
	}

	// Re-run handleInitShell (idempotency check)
	handleInitShell([]string{"zsh"})
	contentBytes2, _ := os.ReadFile(rcFile)
	if strings.Count(string(contentBytes2), "alias sec=sec-agent") != 1 {
		t.Errorf("expected idempotent insertion of alias sec=sec-agent, got:\n%s", string(contentBytes2))
	}

	// Test workspace status indicator formatting
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()
	_ = os.Chdir(tmpDir)

	secrcContent := `{"profile": "my-test-workspace-profile"}`
	if err := os.WriteFile(filepath.Join(tmpDir, ".secrc"), []byte(secrcContent), 0600); err != nil {
		t.Fatalf("failed writing .secrc: %v", err)
	}

	cfg, file, dir := loadWorkspaceConfigVerbose()
	evalTmpDir, _ := filepath.EvalSymlinks(tmpDir)
	evalDir, _ := filepath.EvalSymlinks(dir)
	if cfg == nil || cfg.Profile != "my-test-workspace-profile" || file != ".secrc" || evalDir != evalTmpDir {
		t.Errorf("expected loadWorkspaceConfigVerbose to return cfg, .secrc, %s; got cfg=%+v, file=%s, dir=%s", evalTmpDir, cfg, file, evalDir)
	}
}

func TestShellCompletionOutput(t *testing.T) {
	for _, shell := range []string{"zsh", "bash", "fish"} {
		r, w, _ := os.Pipe()
		oldStdout := os.Stdout
		os.Stdout = w

		handleCompletion(shell)

		_ = w.Close()
		os.Stdout = oldStdout

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		out := buf.String()

		if !strings.Contains(out, "sec") {
			t.Errorf("expected shell completion for %s to contain 'sec', got:\n%s", shell, out)
		}
		if !strings.Contains(out, "profile") || !strings.Contains(out, "skill") {
			t.Errorf("expected shell completion for %s to contain subcommands 'profile', 'skill', got:\n%s", shell, out)
		}
		for _, sub := range []string{"install", "status", "update", "list"} {
			if !strings.Contains(out, sub) {
				t.Errorf("expected shell completion for %s to contain skill subcommand %q, got:\n%s", shell, sub, out)
			}
		}
	}
}

func TestCommandRegistryParity(t *testing.T) {
	if len(CommandRegistry) == 0 {
		initRegistry()
	}
	if len(CommandRegistry) == 0 {
		t.Fatalf("CommandRegistry SSOT struct is empty")
	}

	for _, shell := range []string{"zsh", "bash", "fish"} {
		r, w, _ := os.Pipe()
		oldStdout := os.Stdout
		os.Stdout = w

		handleCompletion(shell)

		_ = w.Close()
		os.Stdout = oldStdout

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		out := buf.String()

		for _, cmd := range CommandRegistry {
			if !strings.Contains(out, cmd.Name) {
				t.Errorf("shell completion [%s] missing top-level command %q from CommandRegistry", shell, cmd.Name)
			}
			for _, sub := range cmd.Subcommands {
				if !strings.Contains(out, sub.Name) {
					t.Errorf("shell completion [%s] missing subcommand %q for %q from CommandRegistry", shell, sub.Name, cmd.Name)
				}
			}
		}
	}
}

func TestShellPromptAndInitDirenv(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// 1. Test handlePrompt (idle/locked state when daemon not running)
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	handlePrompt("test-prof", []string{"--format", "plain"})

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "sec:test-prof") || !strings.Contains(output, "locked") {
		t.Errorf("expected handlePrompt output to contain sec:test-prof (locked), got %q", output)
	}

	// 2. Test handleInitDirenv
	handleInitDirenv()
	direnvrcPath := filepath.Join(tmpDir, ".config", "direnv", "direnvrc")
	content, err := os.ReadFile(direnvrcPath)
	if err != nil {
		t.Fatalf("failed reading direnvrc: %v", err)
	}
	if !strings.Contains(string(content), "use_sec_agent()") {
		t.Errorf("expected direnvrc to contain use_sec_agent(), got:\n%s", string(content))
	}
}
