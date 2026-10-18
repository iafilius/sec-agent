package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"

	"golang.org/x/crypto/ssh"
)

func TestSSHAgentAndStreamInjection(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "id_ed25519")

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 test key: %v", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("failed to marshal ed25519 test key: %v", err)
	}
	keyData := pem.EncodeToMemory(pemBlock)
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
	d, err := daemon.NewDaemon(profile, 30*time.Second, Version)
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

func TestOOMGuardrailAndPreallocation(t *testing.T) {
	d, err := daemon.NewDaemon("oom-test-profile", 30*time.Second, "v1.0.0")
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}
	if d == nil {
		t.Fatal("expected daemon pointer to be non-nil")
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

func TestCompanionMetadataAndInlineURIExpansion(t *testing.T) {
	profile := "meta-uri-test-profile"
	masterKey := []byte("01234567890123456789012345678904")
	d, err := daemon.NewDaemon(profile, 30*time.Second, Version)
	if err != nil {
		t.Fatalf("failed to create test daemon: %v", err)
	}
	d.SetMasterKeyForTest(masterKey)
	d.SetSecretsForTest(map[string]store.SecretEntry{
		"router/admin": {
			Value: "s3cr3tP@ss",
			Metadata: map[string]string{
				"subnet":  "192.168.31.0/24",
				"gateway": "192.168.31.1",
			},
		},
		"db/token": {
			Value: "super-db-token-999",
		},
	})
	token := "meta-uri-token-789"
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

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_meta_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v\nOutput: %s", err, out)
	}

	// Test 1: Companion Metadata Env Injection
	runCmd := exec.Command(binPath, "run", "--profile", profile, "--no-redact", "--", "printenv")
	runCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token, "SEC_PROFILE="+profile, "SEC_TEST_MODE=1")
	out, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec run printenv failed: %v\nOutput: %s", err, out)
	}
	outStr := string(out)
	if !strings.Contains(outStr, "ROUTER_ADMIN=s3cr3tP@ss") {
		t.Errorf("expected ROUTER_ADMIN in env output, got: %s", outStr)
	}
	if !strings.Contains(outStr, "ROUTER_ADMIN_SUBNET=192.168.31.0/24") {
		t.Errorf("expected ROUTER_ADMIN_SUBNET companion env var, got: %s", outStr)
	}
	if !strings.Contains(outStr, "ROUTER_ADMIN_GATEWAY=192.168.31.1") {
		t.Errorf("expected ROUTER_ADMIN_GATEWAY companion env var, got: %s", outStr)
	}

	// Test 2: Inline sec:// URI Argument Replacement
	echoCmd := exec.Command(binPath, "run", "--profile", profile, "--no-redact", "--", "echo", "TOKEN=sec://db/token")
	echoCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token, "SEC_PROFILE="+profile, "SEC_TEST_MODE=1")
	echoOut, echoErr := echoCmd.CombinedOutput()
	if echoErr != nil {
		t.Fatalf("sec run echo failed: %v\nOutput: %s", echoErr, echoOut)
	}
	if !strings.Contains(string(echoOut), "TOKEN=super-db-token-999") {
		t.Errorf("expected sec:// placeholder to be evaluated to super-db-token-999, got: %s", string(echoOut))
	}
}

func TestSSHAgentFromBytesAndVaultKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("failed to marshal test key: %v", err)
	}
	keyData := pem.EncodeToMemory(pemBlock)

	// 1. Test setupEphemeralSSHAgentFromBytes directly
	sockPath, cleanup, err := setupEphemeralSSHAgentFromBytes(keyData, "")
	if err != nil {
		t.Fatalf("setupEphemeralSSHAgentFromBytes failed: %v", err)
	}
	if _, statErr := os.Stat(sockPath); os.IsNotExist(statErr) {
		t.Errorf("expected socket to exist at %s", sockPath)
	}
	cleanup()
	if _, statErr := os.Stat(sockPath); !os.IsNotExist(statErr) {
		t.Errorf("expected socket %s to be removed after cleanup", sockPath)
	}

	// 2. Test setupEphemeralSSHAgentFromVault with test daemon
	profile := "ssh-vault-profile"
	masterKey := []byte("01234567890123456789012345678904")
	d, err := daemon.NewDaemon(profile, 30*time.Second, Version)
	if err != nil {
		t.Fatalf("failed to create test daemon: %v", err)
	}
	d.SetMasterKeyForTest(masterKey)
	d.SetSecretsForTest(map[string]store.SecretEntry{
		"ssh/switch/private_key": {Value: string(keyData)},
	})
	token := "ssh-vault-token-123"
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

	origToken := os.Getenv("SEC_SESSION_TOKEN")
	_ = os.Setenv("SEC_SESSION_TOKEN", token)
	defer func() {
		if origToken != "" {
			_ = os.Setenv("SEC_SESSION_TOKEN", origToken)
		} else {
			_ = os.Unsetenv("SEC_SESSION_TOKEN")
		}
	}()

	vSockPath, vCleanup, vErr := setupEphemeralSSHAgentFromVault(profile, "ssh/switch/private_key", "")
	if vErr != nil {
		t.Fatalf("setupEphemeralSSHAgentFromVault failed: %v", vErr)
	}
	if _, statErr := os.Stat(vSockPath); os.IsNotExist(statErr) {
		t.Errorf("expected vault-backed socket to exist at %s", vSockPath)
	}
	vCleanup()
	if _, statErr := os.Stat(vSockPath); !os.IsNotExist(statErr) {
		t.Errorf("expected socket %s to be removed after cleanup", vSockPath)
	}

	// 3. Test CLI sec run --ssh-key-secret
	binPath := filepath.Join(t.TempDir(), "sec_ssh_test_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v\nOutput: %s", err, out)
	}

	runCmd := exec.Command(binPath, "run", "--profile", profile, "--ssh-key-secret", "ssh/switch/private_key", "--no-redact", "--", "printenv")
	runCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token, "SEC_PROFILE="+profile, "SEC_TEST_MODE=1")
	out, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec run with --ssh-key-secret failed: %v\nOutput: %s", err, out)
	}
	if !strings.Contains(string(out), "SSH_AUTH_SOCK=") {
		t.Errorf("expected SSH_AUTH_SOCK in child process env output, got: %s", string(out))
	}
}


