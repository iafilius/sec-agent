package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
)

func TestParseOpaqueCommandPayload_JSONAndShell(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr string
	}{
		{
			name:  "json array with spaces and special chars",
			input: `["backup", "run", "home-nas", "Photos - 2026"]`,
			want:  []string{"backup", "run", "home-nas", "Photos - 2026"},
		},
		{
			name:  "json array with leading/trailing whitespace",
			input: "  \n\t[\"--profile\", \"prod\", \"status\", \"--quick\"]\n",
			want:  []string{"--profile", "prod", "status", "--quick"},
		},
		{
			name:  "posix shell-quoted line with double quotes",
			input: `--profile work get "app/my secret key"`,
			want:  []string{"--profile", "work", "get", "app/my secret key"},
		},
		{
			name:  "posix shell-quoted line with single quotes and backslash escapes",
			input: `set 'api/key name' val\ with\ spaces "escaped \"quote\" and \\slash"`,
			want:  []string{"set", "api/key name", "val with spaces", `escaped "quote" and \slash`},
		},
		{
			name:  "posix shell-quoted preserves empty quoted token",
			input: `set api/key ""`,
			want:  []string{"set", "api/key", ""},
		},
		{
			name:    "empty payload rejected",
			input:   "   \n\t  ",
			wantErr: "empty",
		},
		{
			name:    "empty json array rejected",
			input:   `[]`,
			wantErr: "at least one argument",
		},
		{
			name:    "invalid json array rejected",
			input:   `["unterminated`,
			wantErr: "invalid opaque JSON command array",
		},
		{
			name:    "unterminated double quote rejected",
			input:   `get "unclosed`,
			wantErr: "unterminated double quote",
		},
		{
			name:    "unterminated single quote rejected",
			input:   `get 'unclosed`,
			wantErr: "unterminated single quote",
		},
		{
			name:    "trailing backslash rejected",
			input:   `get foo\`,
			wantErr: "trailing unescaped backslash",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseOpaqueCommandPayload([]byte(tc.input))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got err=%v args=%v", tc.wantErr, err, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestReadOpaqueCommandArgs_LimitsAndRecursionGuard(t *testing.T) {
	// 1. Oversized payload (> 64 KiB) rejected
	oversized := bytes.Repeat([]byte("a"), maxOpaqueCmdBytes+1)
	if _, err := readOpaqueCommandArgs(bytes.NewReader(oversized)); err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("expected oversized payload error, got: %v", err)
	}

	// 2. Recursive invocations rejected
	for _, payload := range []string{`["-"]`, `["--cmd-fd", "3"]`, `["--cmd-fd=3"]`, `-`, `--cmd-fd 4`} {
		if _, err := readOpaqueCommandArgs(strings.NewReader(payload)); err == nil || !strings.Contains(err.Error(), "recursive opaque command invocation") {
			t.Fatalf("expected recursive invocation rejection for %q, got: %v", payload, err)
		}
	}
}

func TestResolveOpaqueArgs_Validation(t *testing.T) {
	// Normal args pass through untouched
	normal := []string{"sec", "status", "--quick"}
	got, err := resolveOpaqueArgs(normal)
	if err != nil || !reflect.DeepEqual(got, normal) {
		t.Fatalf("expected normal args unchanged, got %v (err=%v)", got, err)
	}

	// Invalid FD values (< 3 or non-numeric)
	for _, args := range [][]string{
		{"sec", "--cmd-fd", "0"},
		{"sec", "--cmd-fd", "1"},
		{"sec", "--cmd-fd", "2"},
		{"sec", "--cmd-fd", "-1"},
		{"sec", "--cmd-fd", "abc"},
		{"sec", "--cmd-fd=2"},
		{"sec", "--cmd-fd"},
		{"sec", "--cmd-fd", "3", "extra"},
		{"sec", "--cmd-fd=3", "extra"},
		{"sec", "-", "extra"},
	} {
		if _, err := resolveOpaqueArgs(args); err == nil {
			t.Errorf("expected error for invalid args %v, got nil", args)
		}
	}
}

func TestOpaqueCLIInvocationAndHiddenDaemonE2E(t *testing.T) {
	// Use a short /tmp path so the Unix domain socket stays well under macOS's 104-byte sun_path limit.
	tmpCfgDir, err := os.MkdirTemp("/tmp", "sec-op-")
	if err != nil {
		t.Fatalf("failed creating short temp config dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpCfgDir) })
	binPath := filepath.Join(t.TempDir(), "sec-agent-opaque-test")

	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed building test binary: %v\n%s", err, string(out))
	}

	// Unique secret profile name that MUST NEVER appear in ps output
	secretProfile := fmt.Sprintf("opaque-secret-prof-%d", os.Getpid())
	baseEnv := func() []string {
		var env []string
		for _, kv := range os.Environ() {
			if strings.HasPrefix(kv, "SEC_PROFILE=") || strings.HasPrefix(kv, "SEC_SESSION_TOKEN=") {
				continue
			}
			env = append(env, kv)
		}
		return append(env, "SEC_CONFIG_DIR="+tmpCfgDir, "SEC_TEST_MODE=1", "SEC_NO_SOUND=1")
	}

	t.Setenv("SEC_CONFIG_DIR", tmpCfgDir)
	pidPath, err := config.GetPIDFilePath(secretProfile)
	if err != nil {
		t.Fatalf("failed resolving PID lockfile path: %v", err)
	}

	// Ensure daemon cleanup at test end
	t.Cleanup(func() {
		lockCmd := exec.Command(binPath, "-")
		lockCmd.Env = baseEnv()
		lockCmd.Stdin = strings.NewReader(fmt.Sprintf(`["--profile", %q, "lock"]`, secretProfile))
		_ = lockCmd.Run()
		if pidData, err := os.ReadFile(pidPath); err == nil {
			var info daemon.PIDLockInfo
			if json.Unmarshal(pidData, &info) == nil && info.PID > 0 {
				_ = syscall.Kill(info.PID, syscall.SIGTERM)
			}
		}
	})

	// 1. Open vault via `sec -` (JSON array on stdin) -> spawns background daemon via --cmd-fd 3
	openCmd := exec.Command(binPath, "-")
	openCmd.Env = baseEnv()
	openCmd.Stdin = strings.NewReader(fmt.Sprintf(`["--profile", %q, "open"]`, secretProfile))
	openOut, err := openCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("opaque `sec -` open failed: %v\nOutput:\n%s", err, string(openOut))
	}

	// Extract session token from eval export output
	var token string
	for _, line := range strings.Split(string(openOut), "\n") {
		if strings.HasPrefix(line, "export SEC_SESSION_TOKEN=") {
			token = strings.Trim(strings.TrimPrefix(line, "export SEC_SESSION_TOKEN="), `"' `)
		}
	}

	// 2. Inspect PID lockfile and verify live `ps -Ao pid=,command=` and `ps eww -p <pid>`
	pidData, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatalf("failed reading daemon PID lockfile: %v", err)
	}
	var pidInfo daemon.PIDLockInfo
	if err := json.Unmarshal(pidData, &pidInfo); err != nil || pidInfo.PID <= 0 {
		t.Fatalf("invalid PID lockfile content: %s (err=%v)", string(pidData), err)
	}

	psCmdOut, err := exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(pidInfo.PID)).Output()
	if err != nil {
		t.Fatalf("failed querying ps command for daemon PID %d: %v", pidInfo.PID, err)
	}
	psCmdLine := strings.TrimSpace(string(psCmdOut))
	if !strings.Contains(psCmdLine, "--cmd-fd") {
		t.Errorf("expected daemon ps command line to contain --cmd-fd, got: %q", psCmdLine)
	}
	if strings.Contains(psCmdLine, secretProfile) {
		t.Errorf("LEAK: daemon ps command line exposed profile name %q: %q", secretProfile, psCmdLine)
	}
	if strings.Contains(psCmdLine, " daemon") {
		t.Errorf("LEAK: daemon ps command line exposed 'daemon' subcommand: %q", psCmdLine)
	}

	// Also check process environment via `ps eww -p <pid>` for SEC_PROFILE leakage
	psEnvOut, err := exec.Command("ps", "eww", "-p", strconv.Itoa(pidInfo.PID)).Output()
	if err == nil && strings.Contains(string(psEnvOut), "SEC_PROFILE="+secretProfile) {
		t.Errorf("LEAK: daemon process environment exposed SEC_PROFILE=%s", secretProfile)
	}

	// 3. Verify `sec daemon list --json` still discovers and reports the opaque daemon
	listCmd := exec.Command(binPath, "-")
	listCmd.Env = baseEnv()
	listCmd.Stdin = strings.NewReader(`daemon list --json`) // also exercises POSIX shell-quoted fallback!
	listOut, err := listCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("opaque `daemon list --json` failed: %v\nOutput:\n%s", err, string(listOut))
	}
	if !strings.Contains(string(listOut), secretProfile) || !strings.Contains(string(listOut), strconv.Itoa(pidInfo.PID)) {
		t.Errorf("expected `sec daemon list --json` to detect opaque daemon PID %d (%s), got:\n%s", pidInfo.PID, secretProfile, string(listOut))
	}

	// 4. Verify `sec --cmd-fd 3` keeps stdin (FD 0) intact for `set --stdin`
	fdR, fdW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed creating command pipe: %v", err)
	}
	cmdVec, _ := json.Marshal([]string{"--profile", secretProfile, "set", "opaque/fd_secret", "--stdin", "--quick"})
	_, _ = fdW.Write(append(cmdVec, '\n'))
	_ = fdW.Close()

	setCmd := exec.Command(binPath, "--cmd-fd", "3")
	envWithToken := baseEnv()
	if token != "" {
		envWithToken = append(envWithToken, "SEC_SESSION_TOKEN="+token)
	}
	setCmd.Env = envWithToken
	setCmd.ExtraFiles = []*os.File{fdR}
	setCmd.Stdin = strings.NewReader("super-secret-via-stdin-fd0")
	setOut, err := setCmd.CombinedOutput()
	_ = fdR.Close()
	if err != nil {
		t.Fatalf("`sec --cmd-fd 3` with `set --stdin` failed: %v\nOutput:\n%s", err, string(setOut))
	}

	// Read back the stored secret via `sec -` (POSIX shell-quoted line)
	getCmd := exec.Command(binPath, "-")
	getCmd.Env = envWithToken
	getCmd.Stdin = strings.NewReader(fmt.Sprintf(`--profile %q get "opaque/fd_secret" --raw`, secretProfile))
	getOut, err := getCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("opaque `sec -` get failed: %v\nOutput:\n%s", err, string(getOut))
	}
	if strings.TrimSpace(string(getOut)) != "super-secret-via-stdin-fd0" {
		t.Errorf("expected secret value %q, got %q", "super-secret-via-stdin-fd0", strings.TrimSpace(string(getOut)))
	}

	// 5. Verify invalid / recursive opaque payload exits with code 2
	badCmd := exec.Command(binPath, "-")
	badCmd.Env = baseEnv()
	badCmd.Stdin = strings.NewReader(`["-"]`)
	badErr := badCmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(badErr, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("expected exit code 2 for recursive opaque payload, got err=%v", badErr)
	}
}
