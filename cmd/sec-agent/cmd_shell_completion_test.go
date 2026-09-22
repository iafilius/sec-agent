package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
		if !strings.Contains(out, "use") || !strings.Contains(out, "env") {
			t.Errorf("expected shell completion for %s to contain subcommands 'use', 'env', got:\n%s", shell, out)
		}
		for _, sub := range []string{"install", "status", "update", "list"} {
			if !strings.Contains(out, sub) {
				t.Errorf("expected shell completion for %s to contain skill subcommand %q, got:\n%s", shell, sub, out)
			}
		}
		if !strings.Contains(out, "verbose") {
			t.Errorf("expected shell completion for %s to contain 'verbose', got:\n%s", shell, out)
		}
		if !strings.Contains(out, "confirm-prod") {
			t.Errorf("expected shell completion for %s to contain 'confirm-prod', got:\n%s", shell, out)
		}
		if !strings.Contains(out, "env") {
			t.Errorf("expected shell completion for %s to contain 'env', got:\n%s", shell, out)
		}
		if shell == "fish" {
			if !strings.Contains(out, "-l repair") {
				t.Errorf("expected shell completion for fish to contain '-l repair', got:\n%s", out)
			}
			if !strings.Contains(out, "-s E") {
				t.Errorf("expected shell completion for fish to contain '-s E', got:\n%s", out)
			}
		} else {
			if !strings.Contains(out, "--repair") {
				t.Errorf("expected shell completion for %s to contain '--repair', got:\n%s", shell, out)
			}
			if !strings.Contains(out, "-E") {
				t.Errorf("expected shell completion for %s to contain '-E', got:\n%s", shell, out)
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

var recognizedFlagAliases = map[string]map[string]bool{
	"get": {
		"--show": true, // Backwards-compatible alias for --raw
	},
	"check": {
		"--scan-leaks":   true, // Alias for --leaks
		"--history":      true, // Alias for --leaks
		"--scan-scripts": true, // Alias for --scripts
	},
}

func isRecognizedFlagAlias(cmdName, flag string) bool {
	if aliases, ok := recognizedFlagAliases[cmdName]; ok {
		return aliases[flag]
	}
	return false
}

func TestCommandRegistryFlagParity(t *testing.T) {
	if len(CommandRegistry) == 0 {
		initRegistry()
	}

	for _, cmd := range CommandRegistry {
		for _, flag := range cmd.Flags {
			if strings.HasPrefix(flag, "--") {
				if isRecognizedFlagAlias(cmd.Name, flag) {
					continue
				}
				if !strings.Contains(cmd.Usage, flag) {
					t.Errorf("command %q has flag %q registered in Flags but missing from Usage string %q", cmd.Name, flag, cmd.Usage)
				}
			}
		}
	}
}

func TestCommandRegistryBidirectionalParity(t *testing.T) {
	if len(CommandRegistry) == 0 {
		initRegistry()
	}

	flagPattern := regexp.MustCompile(`--[a-zA-Z0-9-]+`)

	for _, cmd := range CommandRegistry {
		t.Run(cmd.Name, func(t *testing.T) {
			if cmd.Handler == nil {
				t.Fatalf("command %q has nil Handler", cmd.Name)
			}

			// 1. Every flag in Usage MUST be registered in Flags
			usageFlags := flagPattern.FindAllString(cmd.Usage, -1)
			for _, uf := range usageFlags {
				found := false
				for _, f := range cmd.Flags {
					if f == uf {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("command %q has flag %q documented in Usage %q but missing from Flags slice %v", cmd.Name, uf, cmd.Usage, cmd.Flags)
				}
			}

			// 2. Every full flag in Flags MUST appear in Usage or be a recognized alias
			for _, f := range cmd.Flags {
				if strings.HasPrefix(f, "--") {
					if isRecognizedFlagAlias(cmd.Name, f) {
						continue
					}
					if !strings.Contains(cmd.Usage, f) {
						t.Errorf("command %q has flag %q in Flags but missing from Usage %q", cmd.Name, f, cmd.Usage)
					}
				}
			}

			// 3. For subcommands, verify subcommand flags
			for _, sub := range cmd.Subcommands {
				for _, sf := range sub.Flags {
					if strings.HasPrefix(sf, "--") {
						found := false
						for _, f := range cmd.Flags {
							if f == sf {
								found = true
								break
							}
						}
						if !found {
							t.Errorf("command %q subcommand %q has flag %q not registered in top-level Flags", cmd.Name, sub.Name, sf)
						}
					}
				}
			}
		})
	}
}

func TestCommandRegistryFlagExecution(t *testing.T) {
	t.Setenv("SEC_TEST_MODE", "1")
	profile := "flag-exec-test-profile"

	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	_ = os.Remove(sockPath)
	_ = os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_flag_test_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build flag test binary: %v\nOutput: %s", err, out)
	}

	d, err := daemon.NewDaemon(profile, 5*time.Minute, Version)
	if err != nil {
		t.Fatalf("failed to create test daemon: %v", err)
	}
	d.IsTestInstance = true
	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901"))
	d.SetSessionTokenForTest("test-flag-token-123")

	now := time.Now().Truncate(time.Second)
	d.SetSecretsForTest(map[string]store.SecretEntry{
		"app/api-key": {
			Value:        "secret-12345",
			Comment:      "active api key",
			Created:      now.Add(-40 * 24 * time.Hour),
			LastModified: now.Add(-40 * 24 * time.Hour),
		},
		"app/expired-key": {
			Value:        "expired-secret",
			Comment:      "expired api key",
			Created:      now.Add(-10 * time.Hour),
			LastModified: now.Add(-10 * time.Hour),
			Expires:      now.Add(-1 * time.Hour),
		},
		"app/stale-key": {
			Value:        "stale-secret-xyz",
			Comment:      "stale api key",
			Created:      now.Add(-60 * 24 * time.Hour),
			LastModified: now.Add(-60 * 24 * time.Hour),
			LastAccessed: now.Add(-50 * 24 * time.Hour),
		},
	})

	go func() {
		_ = d.Start()
	}()
	defer d.Stop()

	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	var testEnv []string
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "SEC_SESSION_TOKEN=") &&
			!strings.HasPrefix(env, "SEC_PROFILE=") &&
			!strings.HasPrefix(env, "SEC_TEST_MODE=") {
			testEnv = append(testEnv, env)
		}
	}
	testEnv = append(testEnv, "SEC_SESSION_TOKEN=test-flag-token-123", "SEC_PROFILE="+profile, "SEC_TEST_MODE=1")

	runCLI := func(args ...string) (string, error) {
		cmd := exec.Command(binPath, append(args, "--profile", profile)...)
		cmd.Env = testEnv
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// 1. Test get --raw (verifies raw value output without newline or masking)
	t.Run("get --raw", func(t *testing.T) {
		out, err := runCLI("get", "app/api-key", "--raw")
		if err != nil {
			t.Fatalf("get --raw failed: %v, output: %s", err, out)
		}
		if out != "secret-12345" {
			t.Errorf("expected exact raw value %q, got %q", "secret-12345", out)
		}
	})

	// 2. Test get --show (alias for --raw)
	t.Run("get --show", func(t *testing.T) {
		out, err := runCLI("get", "app/api-key", "--show")
		if err != nil {
			t.Fatalf("get --show failed: %v, output: %s", err, out)
		}
		if out != "secret-12345" {
			t.Errorf("expected exact raw value %q, got %q", "secret-12345", out)
		}
	})

	// 3. Test get --show-expired
	t.Run("get --show-expired", func(t *testing.T) {
		out, err := runCLI("get", "app/expired-key", "--show-expired", "--raw")
		if err != nil {
			t.Fatalf("get --show-expired failed: %v, output: %s", err, out)
		}
		if out != "expired-secret" {
			t.Errorf("expected expired secret value %q, got %q", "expired-secret", out)
		}
	})

	// 4. Test set --expires, --rotate-cmd, --rotate-ttl
	t.Run("set --expires and rotate flags", func(t *testing.T) {
		out, err := runCLI("set", "app/rotating-secret", "new-rotating-val", "--expires", "30d", "--rotate-cmd", "echo rotate", "--rotate-ttl", "30d")
		if err != nil {
			t.Fatalf("set with rotate flags failed: %v, output: %s", err, out)
		}
		getOut, getErr := runCLI("get", "app/rotating-secret", "--json")
		if getErr != nil {
			t.Fatalf("get --json failed: %v, output: %s", getErr, getOut)
		}
		var metaResp struct {
			Metadata map[string]string `json:"metadata"`
			Expires  string            `json:"expires"`
		}
		if err := json.Unmarshal([]byte(getOut), &metaResp); err != nil {
			t.Fatalf("failed to unmarshal JSON response: %v\nOutput: %s", err, getOut)
		}
		if metaResp.Metadata["rotate_cmd"] != "echo rotate" {
			t.Errorf("expected rotate_cmd metadata 'echo rotate', got %q", metaResp.Metadata["rotate_cmd"])
		}
		if metaResp.Metadata["rotate_ttl"] != "30d" {
			t.Errorf("expected rotate_ttl metadata '30d', got %q", metaResp.Metadata["rotate_ttl"])
		}
		if metaResp.Expires == "" {
			t.Errorf("expected non-empty expires in JSON response, got empty")
		}
	})

	// 5. Test ls --long
	t.Run("ls --long", func(t *testing.T) {
		out, err := runCLI("ls", "--long")
		if err != nil {
			t.Fatalf("ls --long failed: %v, output: %s", err, out)
		}
		if !strings.Contains(out, "app/api-key") {
			t.Errorf("expected ls --long to contain app/api-key, got:\n%s", out)
		}
	})

	// 6. Test ls --stale
	t.Run("ls --stale", func(t *testing.T) {
		out, err := runCLI("ls", "--stale", "30")
		if err != nil {
			t.Fatalf("ls --stale failed: %v, output: %s", err, out)
		}
		if !strings.Contains(out, "app/stale-key") {
			t.Errorf("expected ls --stale to list unaccessed app/stale-key, got:\n%s", out)
		}
	})

	// 7. Test export --all-profiles
	t.Run("export --all-profiles", func(t *testing.T) {
		out, err := runCLI("export", "--format", "json", "--all-profiles")
		if err != nil {
			t.Fatalf("export --all-profiles failed: %v, output: %s", err, out)
		}
		if !strings.Contains(out, "app/api-key") {
			t.Errorf("expected export output to contain app/api-key, got:\n%s", out)
		}
	})

	// 8. Test backup export and backup import roundtrip
	kdbxPath := filepath.Join(tmpDir, "cli_test_backup.kdbx")
	t.Run("backup export and backup import", func(t *testing.T) {
		exportOut, exportErr := runCLI("backup", "export", kdbxPath, "-p", "kdbx-test-pass-456")
		if exportErr != nil {
			t.Fatalf("backup export failed: %v, output: %s", exportErr, exportOut)
		}
		if !strings.Contains(exportOut, "[✓] Backup created at:") {
			t.Errorf("expected backup confirmation in output, got: %s", exportOut)
		}
		if _, statErr := os.Stat(kdbxPath); statErr != nil {
			t.Fatalf("expected KDBX file at %s: %v", kdbxPath, statErr)
		}

		importOut, importErr := runCLI("backup", "import", kdbxPath, "-p", "kdbx-test-pass-456", "--merge")
		if importErr != nil {
			t.Fatalf("backup import failed: %v, output: %s", importErr, importOut)
		}
		if !strings.Contains(importOut, "Secrets restored successfully") {
			t.Errorf("expected restore confirmation in output, got: %s", importOut)
		}
	})

	// 9. Test restore command
	t.Run("restore command", func(t *testing.T) {
		restoreOut, restoreErr := runCLI("restore", kdbxPath, "-p", "kdbx-test-pass-456", "--overwrite")
		if restoreErr != nil {
			t.Fatalf("restore failed: %v, output: %s", restoreErr, restoreOut)
		}
		if !strings.Contains(restoreOut, "Secrets restored successfully") {
			t.Errorf("expected restore confirmation in output, got: %s", restoreOut)
		}
	})
}



