package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
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

func TestSSHTargetResolutionAndSecrc(t *testing.T) {
	tmpDir := t.TempDir()

	secrcPath := filepath.Join(tmpDir, ".secrc")
	cfg := WorkspaceConfig{
		Profile: "router-prod",
		SSHTargets: map[string]SSHTarget{
			"ax3600": {
				Host:          "192.168.31.1",
				User:          "root",
				Port:          22,
				IdentityFile:  "~/.ssh/id_ed25519_ax3600",
				PassphraseKey: "ssh/ax3600_passphrase",
			},
			"vps": {
				Host: "cloud.example.com",
				User: "deploy",
				Port: 2222,
			},
		},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal WorkspaceConfig: %v", err)
	}
	if err := os.WriteFile(secrcPath, data, 0600); err != nil {
		t.Fatalf("failed to write .secrc: %v", err)
	}

	// Read and verify
	var parsed WorkspaceConfig
	readData, err := os.ReadFile(secrcPath)
	if err != nil {
		t.Fatalf("failed to read .secrc: %v", err)
	}
	if err := json.Unmarshal(readData, &parsed); err != nil {
		t.Fatalf("failed to unmarshal .secrc: %v", err)
	}

	if len(parsed.SSHTargets) != 2 {
		t.Fatalf("expected 2 SSH targets, got %d", len(parsed.SSHTargets))
	}

	routerTarget, ok := parsed.SSHTargets["ax3600"]
	if !ok {
		t.Fatalf("target 'ax3600' missing from parsed targets")
	}
	if routerTarget.Host != "192.168.31.1" || routerTarget.User != "root" || routerTarget.PassphraseKey != "ssh/ax3600_passphrase" {
		t.Errorf("unexpected target config: %+v", routerTarget)
	}

	vpsTarget, ok := parsed.SSHTargets["vps"]
	if !ok {
		t.Fatalf("target 'vps' missing from parsed targets")
	}
	if vpsTarget.Port != 2222 || vpsTarget.User != "deploy" {
		t.Errorf("unexpected vps target config: %+v", vpsTarget)
	}
}

func TestRunNativeSSHWithPassword(t *testing.T) {
	// Generate ephemeral host key
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "testuser" && string(pass) == "secretpass123" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected")
		},
	}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		nConn, err := listener.Accept()
		if err != nil {
			return
		}
		defer nConn.Close()

		sConn, chans, reqs, err := ssh.NewServerConn(nConn, serverConfig)
		if err != nil {
			return
		}
		defer sConn.Close()
		go ssh.DiscardRequests(reqs)

		for newChannel := range chans {
			if newChannel.ChannelType() != "session" {
				_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				return
			}
			go func(in <-chan *ssh.Request) {
				for req := range in {
					switch req.Type {
					case "exec":
						_ = req.Reply(true, nil)
						_, _ = channel.Write([]byte("command executed successfully\n"))
						// send exit-status 0
						_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						_ = channel.Close()
						return
					default:
						_ = req.Reply(false, nil)
					}
				}
			}(requests)
		}
	}()

	err = runNativeSSH("default", "test-target", "127.0.0.1", port, "testuser", "secretpass123", nil, "", []string{"uptime"}, hostKeyOptions{insecure: true})
	if err != nil {
		t.Fatalf("runNativeSSH failed: %v", err)
	}
}

func TestRunNativeSSHWithVaultStoredKey(t *testing.T) {
	// 1. Generate client key pair
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	clientSSHPub, err := ssh.NewPublicKey(clientPub)
	if err != nil {
		t.Fatalf("failed to create client ssh pub key: %v", err)
	}
	clientPEMBlock, err := ssh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		t.Fatalf("failed to marshal client private key: %v", err)
	}
	clientKeyBytes := pem.EncodeToMemory(clientPEMBlock)

	// 2. Generate host key
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("failed to create host signer: %v", err)
	}

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == "keyuser" && string(pubKey.Marshal()) == string(clientSSHPub.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("public key rejected")
		},
	}
	serverConfig.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		nConn, err := listener.Accept()
		if err != nil {
			return
		}
		defer nConn.Close()

		sConn, chans, reqs, err := ssh.NewServerConn(nConn, serverConfig)
		if err != nil {
			return
		}
		defer sConn.Close()
		go ssh.DiscardRequests(reqs)

		for newChannel := range chans {
			if newChannel.ChannelType() != "session" {
				_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				return
			}
			go func(in <-chan *ssh.Request) {
				for req := range in {
					switch req.Type {
					case "exec":
						_ = req.Reply(true, nil)
						_, _ = channel.Write([]byte("key auth success\n"))
						_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						_ = channel.Close()
						return
					default:
						_ = req.Reply(false, nil)
					}
				}
			}(requests)
		}
	}()

	// Connect using pure in-memory keyBytes (zero disk read)
	err = runNativeSSH("default", "test-key-target", "127.0.0.1", port, "keyuser", "", clientKeyBytes, "", []string{"whoami"}, hostKeyOptions{insecure: true})
	if err != nil {
		t.Fatalf("runNativeSSH with clientKeyBytes failed: %v", err)
	}
}

func TestVaultHostKeyCallbackTOFUAndMismatch(t *testing.T) {
	profile := "tofu-test-profile"
	masterKey := []byte("01234567890123456789012345678905")
	d, err := daemon.NewDaemon(profile, 30*time.Second, Version)
	if err != nil {
		t.Fatalf("failed to create test daemon: %v", err)
	}
	d.SetMasterKeyForTest(masterKey)
	d.SetSecretsForTest(map[string]store.SecretEntry{})
	token := "tofu-test-token-789"
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

	// Generate Host Key 1
	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate host key 1: %v", err)
	}
	sshPub1, _ := ssh.NewPublicKey(pub1)
	fp1 := ssh.FingerprintSHA256(sshPub1)

	// Generate Host Key 2 (attacker or rebuilt appliance)
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate host key 2: %v", err)
	}
	sshPub2, _ := ssh.NewPublicKey(pub2)

	target := "switch-test"
	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:22")

	// 1. First connection without TOFU flag in headless mode should fail
	cbFail := vaultHostKeyCallback(profile, target, "127.0.0.1", 22, hostKeyOptions{trustOnFirstUse: false})
	if err := cbFail("127.0.0.1", addr, sshPub1); err == nil {
		t.Errorf("expected untrusted host error without TOFU flag, but succeeded")
	}

	// 2. First connection with TOFU flag should pin key to vault
	cbTOFU := vaultHostKeyCallback(profile, target, "127.0.0.1", 22, hostKeyOptions{trustOnFirstUse: true})
	if err := cbTOFU("127.0.0.1", addr, sshPub1); err != nil {
		t.Fatalf("expected TOFU pinning to succeed, got: %v", err)
	}

	// Verify fingerprint is now in vault
	resp, err := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: "ssh/" + target + "/host_fingerprint"})
	if err != nil || !resp.Success || resp.Value != fp1 {
		t.Fatalf("expected vault to store %s, got: %+v (err: %v)", fp1, resp, err)
	}

	// 3. Second connection with same key should succeed quietly
	cbVerify := vaultHostKeyCallback(profile, target, "127.0.0.1", 22, hostKeyOptions{})
	if err := cbVerify("127.0.0.1", addr, sshPub1); err != nil {
		t.Fatalf("expected second connection with matching host key to succeed, got: %v", err)
	}

	// 4. Connection with changed host key must abort with HOST_KEY_MISMATCH
	if err := cbVerify("127.0.0.1", addr, sshPub2); err == nil || !strings.Contains(err.Error(), "HOST_KEY_MISMATCH") {
		t.Fatalf("expected HOST_KEY_MISMATCH error, got: %v", err)
	}

	// 5. Update host key with --update-host-key
	cbUpdate := vaultHostKeyCallback(profile, target, "127.0.0.1", 22, hostKeyOptions{updateHostKey: true})
	if err := cbUpdate("127.0.0.1", addr, sshPub2); err != nil {
		t.Fatalf("expected updateHostKey to succeed, got: %v", err)
	}
	resp2, _ := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: "ssh/" + target + "/host_fingerprint"})
	fp2 := ssh.FingerprintSHA256(sshPub2)
	if resp2.Value != fp2 {
		t.Fatalf("expected updated fingerprint %s, got: %s", fp2, resp2.Value)
	}

	// 6. Test reset-host-key
	handleSSHResetHostKey(profile, []string{target})
	respReset, _ := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: "ssh/" + target + "/host_fingerprint"})
	if respReset.Success && respReset.Value != "" {
		t.Errorf("expected host_fingerprint to be removed after reset, got: %s", respReset.Value)
	}
}

func TestSSHTargetNameValidation(t *testing.T) {
	validTargets := []string{"ax3600", "t430", "prod-server", "db_primary"}
	for _, tgt := range validTargets {
		if err := validateSSHTargetName(tgt); err != nil {
			t.Errorf("expected valid target name %q, got error: %v", tgt, err)
		}
	}

	invalidTargets := []string{"bad target", "bad/target", "bad..target", "bad\\target", ""}
	for _, tgt := range invalidTargets {
		if err := validateSSHTargetName(tgt); err == nil {
			t.Errorf("expected validation failure for target name %q", tgt)
		}
	}
}

func TestBuildOpenSSHArgs(t *testing.T) {
	// Standard delegated args without --no-trace
	argsStd := buildOpenSSHArgs("/usr/bin/ssh", 22, false, "root@10.0.0.1", []string{"uptime"})
	joinedStd := strings.Join(argsStd, " ")
	if strings.Contains(joinedStd, "UserKnownHostsFile=/dev/null") {
		t.Errorf("unexpected UserKnownHostsFile=/dev/null in standard args: %s", joinedStd)
	}

	// Zero-trace delegated args with --no-trace
	argsNoTrace := buildOpenSSHArgs("/usr/bin/ssh", 2222, true, "deploy@router", []string{"uci", "show"})
	joinedNoTrace := strings.Join(argsNoTrace, " ")
	expectedFlags := []string{
		"-o UserKnownHostsFile=/dev/null",
		"-o StrictHostKeyChecking=no",
		"-o LogLevel=ERROR",
		"-o IdentitiesOnly=yes",
	}
	for _, flag := range expectedFlags {
		if !strings.Contains(joinedNoTrace, flag) {
			t.Errorf("expected flag %q in zero-trace args: %s", flag, joinedNoTrace)
		}
	}
	if !strings.Contains(joinedNoTrace, "-p 2222") || !strings.Contains(joinedNoTrace, "deploy@router uci show") {
		t.Errorf("unexpected arg structure: %s", joinedNoTrace)
	}
}

func TestShredFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "secret_key.pem")

	secretContent := "SUPER_SECRET_PRIVATE_KEY_DATA_1234567890"
	if err := os.WriteFile(filePath, []byte(secretContent), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Shred the file
	if err := shredFile(filePath); err != nil {
		t.Fatalf("shredFile failed: %v", err)
	}

	// Verify file does not exist
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Errorf("expected shredded file to be deleted, got err: %v", err)
	}

	// Verify directory error
	dirPath := filepath.Join(tmpDir, "some_dir")
	if err := os.Mkdir(dirPath, 0700); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}
	if err := shredFile(dirPath); err == nil {
		t.Errorf("expected shredFile on directory to return error, got nil")
	}
}

func TestSanitizeKnownHosts(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")
	oldPath := khPath + ".old"

	// Create dummy hashed entry for 192.168.122.20
	salt := make([]byte, 20)
	_, _ = rand.Read(salt)
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte("192.168.122.20"))
	hashB64 := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	hashedLineSwitch2 := fmt.Sprintf("|1|%s|%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI1111111111111111111111111111111111111111111 switch2", saltB64, hashB64)

	// Create dummy hashed entry for github.com
	saltGithub := make([]byte, 20)
	_, _ = rand.Read(saltGithub)
	saltGithubB64 := base64.StdEncoding.EncodeToString(saltGithub)
	macGithub := hmac.New(sha1.New, saltGithub)
	macGithub.Write([]byte("github.com"))
	hashGithubB64 := base64.StdEncoding.EncodeToString(macGithub.Sum(nil))
	hashedLineGithub := fmt.Sprintf("|1|%s|%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI2222222222222222222222222222222222222222222 github", saltGithubB64, hashGithubB64)

	initialContent := strings.Join([]string{
		"# Global known hosts",
		"switch1,192.168.122.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI3333333333333333333333333333333333333333333",
		"[switch1]:2222,[192.168.122.10]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI4444444444444444444444444444444444444444444",
		"router.local,192.168.1.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI5555555555555555555555555555555555555555555",
		hashedLineSwitch2,
		hashedLineGithub,
		"",
	}, "\n")

	if err := os.WriteFile(khPath, []byte(initialContent), 0600); err != nil {
		t.Fatalf("failed to write initial known_hosts: %v", err)
	}
	if err := os.WriteFile(oldPath, []byte("old backup content"), 0600); err != nil {
		t.Fatalf("failed to write known_hosts.old: %v", err)
	}

	// Sanitize switch1, 192.168.122.10, and switch2's IP 192.168.122.20
	targets := []string{"switch1", "192.168.122.10", "[switch1]:2222", "192.168.122.20"}
	removed, err := sanitizeKnownHosts(khPath, targets)
	if err != nil {
		t.Fatalf("sanitizeKnownHosts failed: %v", err)
	}

	if removed != 3 {
		t.Errorf("expected 3 entries removed, got %d", removed)
	}

	// Verify known_hosts.old was removed
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Errorf("expected known_hosts.old to be unlinked, got err: %v", err)
	}

	// Read updated content
	updatedData, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("failed to read updated known_hosts: %v", err)
	}
	updatedStr := string(updatedData)

	if strings.Contains(updatedStr, "switch1") || strings.Contains(updatedStr, "192.168.122.10") {
		t.Errorf("expected switch1 and 192.168.122.10 to be purged, got:\n%s", updatedStr)
	}
	if strings.Contains(updatedStr, saltB64) {
		t.Errorf("expected hashed switch2 line to be purged, got:\n%s", updatedStr)
	}
	if !strings.Contains(updatedStr, "router.local,192.168.1.1") {
		t.Errorf("expected router.local to be preserved, got:\n%s", updatedStr)
	}
	if !strings.Contains(updatedStr, saltGithubB64) {
		t.Errorf("expected hashed github line to be preserved, got:\n%s", updatedStr)
	}
}

func TestSSHImportKeyAndShredIntegration(t *testing.T) {
	profile := "test-ssh-import-shred"
	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	_ = os.Remove(sockPath)
	_ = os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_ssh_test_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v\nOutput: %s", err, out)
	}

	d, err := daemon.NewDaemon(profile, 30*time.Second, Version)
	if err != nil {
		t.Fatalf("failed to create test daemon: %v", err)
	}
	token := "test-ssh-import-shred-token"
	d.SetSessionTokenForTest(token)
	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901"))
	t.Setenv("SEC_SESSION_TOKEN", token)
	go d.Start()
	defer d.Stop()

	sock, _ := config.GetSocketPath(profile)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Generate valid ed25519 key
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	keyBytes, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	pemData := pem.EncodeToMemory(keyBytes)

	// 1. Test normal import without --shred
	normalKeyPath := filepath.Join(tmpDir, "id_ed25519_normal")
	if err := os.WriteFile(normalKeyPath, pemData, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	cmdImport := exec.Command(binPath, "ssh", "import-key", "leaf01", normalKeyPath, "--profile", profile, "--no-sanitize")
	cmdImport.Env = append(os.Environ(), "SEC_TEST_MODE=1", "SEC_SESSION_TOKEN="+token)
	out, err := cmdImport.CombinedOutput()
	if err != nil {
		t.Fatalf("import-key failed: %v\nOutput: %s", err, string(out))
	}

	// Verify key was stored in vault
	resp, qErr := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: "ssh/leaf01/private_key"})
	if qErr != nil || !resp.Success || resp.Value != string(pemData) {
		t.Fatalf("expected vault key to match imported pem data, got value: %q, err: %v", resp.Value, qErr)
	}
	// Verify normal file still exists
	if _, err := os.Stat(normalKeyPath); os.IsNotExist(err) {
		t.Errorf("expected normalKeyPath to NOT be shredded without --shred flag")
	}

	// 2. Test import with --shred
	shredKeyPath := filepath.Join(tmpDir, "id_ed25519_shred")
	if err := os.WriteFile(shredKeyPath, pemData, 0600); err != nil {
		t.Fatalf("failed to write shred key file: %v", err)
	}

	cmdShred := exec.Command(binPath, "ssh", "import-key", "leaf02", shredKeyPath, "--shred", "--profile", profile, "--no-sanitize")
	cmdShred.Env = append(os.Environ(), "SEC_TEST_MODE=1", "SEC_SESSION_TOKEN="+token)
	out, err = cmdShred.CombinedOutput()
	if err != nil {
		t.Fatalf("import-key with --shred failed: %v\nOutput: %s", err, string(out))
	}

	// Verify key was stored in vault
	resp2, qErr := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: "ssh/leaf02/private_key"})
	if qErr != nil || !resp2.Success || resp2.Value != string(pemData) {
		t.Fatalf("expected vault key for leaf02 to match imported pem data, got value: %q, err: %v", resp2.Value, qErr)
	}
	// Verify shredKeyPath was shredded and deleted from disk
	if _, err := os.Stat(shredKeyPath); !os.IsNotExist(err) {
		t.Errorf("expected shredKeyPath to be securely deleted, got err: %v", err)
	}

	// 3. Test safety guardrail: corrupted key file MUST NOT be shredded even if --shred is passed
	corruptKeyPath := filepath.Join(tmpDir, "id_corrupt")
	corruptContent := []byte("NOT_A_VALID_SSH_PRIVATE_KEY_RANDOM_GARBAGE")
	if err := os.WriteFile(corruptKeyPath, corruptContent, 0600); err != nil {
		t.Fatalf("failed to write corrupt key file: %v", err)
	}

	cmdCorrupt := exec.Command(binPath, "ssh", "import-key", "leaf03", corruptKeyPath, "--shred", "--profile", profile, "--no-sanitize")
	cmdCorrupt.Env = append(os.Environ(), "SEC_TEST_MODE=1", "SEC_SESSION_TOKEN="+token)
	_, err = cmdCorrupt.CombinedOutput()
	if err == nil {
		t.Fatalf("expected import-key to fail on corrupt key file, but it succeeded")
	}

	// CRITICAL SAFETY CHECK: Corrupt file MUST STILL EXIST on disk!
	if _, err := os.Stat(corruptKeyPath); os.IsNotExist(err) {
		t.Fatalf("CRITICAL SAFETY VIOLATION: corrupt key file was shredded despite failed validation!")
	}
	// Verify contents are untouched
	dataAfter, _ := os.ReadFile(corruptKeyPath)
	if string(dataAfter) != string(corruptContent) {
		t.Errorf("expected corrupt file content to remain intact, got: %q", string(dataAfter))
	}
}

func TestSSHSanitizeCommandIntegration(t *testing.T) {
	profile := "test-ssh-sanitize-cmd"
	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	_ = os.Remove(sockPath)
	_ = os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_ssh_test_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v\nOutput: %s", err, out)
	}

	d, err := daemon.NewDaemon(profile, 30*time.Second, Version)
	if err != nil {
		t.Fatalf("failed to create test daemon: %v", err)
	}
	token := "test-ssh-sanitize-token"
	d.SetSessionTokenForTest(token)
	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901"))
	t.Setenv("SEC_SESSION_TOKEN", token)
	go d.Start()
	defer d.Stop()

	sock, _ := config.GetSocketPath(profile)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Configure target in vault: ssh/leaf10/host = 192.168.122.10
	_, _ = queryDaemon(profile, daemon.IPCRequest{Action: "set", Path: "ssh/leaf10/host", Value: "192.168.122.10"})
	_, _ = queryDaemon(profile, daemon.IPCRequest{Action: "set", Path: "ssh/leaf10/port", Value: "22"})

	// Setup known_hosts for sanitize testing
	khFile := filepath.Join(tmpDir, "test_known_hosts")
	khContent := "leaf10,192.168.122.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI111\notherhost,10.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI222\n"
	if err := os.WriteFile(khFile, []byte(khContent), 0600); err != nil {
		t.Fatalf("failed to write test known_hosts: %v", err)
	}

	// Run sanitize command for leaf10
	cmdSanitize := exec.Command(binPath, "ssh", "sanitize", "leaf10", "--profile", profile)
	cmdSanitize.Env = append(os.Environ(), "SEC_TEST_MODE=1", "SEC_SESSION_TOKEN="+token, "SEC_KNOWN_HOSTS_PATH="+khFile)
	out, err := cmdSanitize.CombinedOutput()
	if err != nil {
		t.Fatalf("sanitize failed: %v\nOutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "Sanitized 1 known_hosts entries") {
		t.Errorf("unexpected output: %s", string(out))
	}

	// Verify known_hosts after sanitize
	data, _ := os.ReadFile(khFile)
	if strings.Contains(string(data), "leaf10") || strings.Contains(string(data), "192.168.122.10") {
		t.Errorf("expected leaf10 to be removed, got:\n%s", string(data))
	}
	if !strings.Contains(string(data), "otherhost,10.0.0.1") {
		t.Errorf("expected otherhost to remain, got:\n%s", string(data))
	}
}

func TestSSHInitImportKeyShred(t *testing.T) {
	profile := "test-ssh-init-import"
	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	_ = os.Remove(sockPath)
	_ = os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_ssh_test_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v\nOutput: %s", err, out)
	}

	d, err := daemon.NewDaemon(profile, 30*time.Second, Version)
	if err != nil {
		t.Fatalf("failed to create test daemon: %v", err)
	}
	token := "test-ssh-init-token"
	d.SetSessionTokenForTest(token)
	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901"))
	t.Setenv("SEC_SESSION_TOKEN", token)
	go d.Start()
	defer d.Stop()

	sock, _ := config.GetSocketPath(profile)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Generate key
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	keyBytes, _ := ssh.MarshalPrivateKey(privKey, "")
	pemData := pem.EncodeToMemory(keyBytes)

	keyToShred := filepath.Join(tmpDir, "init_key_to_shred")
	if err := os.WriteFile(keyToShred, pemData, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	khFile := filepath.Join(tmpDir, "init_known_hosts")
	_ = os.WriteFile(khFile, []byte("switch99,192.168.122.99 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI999\n"), 0600)

	cmdInit := exec.Command(binPath, "ssh", "init", "switch99",
		"--host", "192.168.122.99",
		"--user", "admin",
		"--port", "22",
		"--import-key", keyToShred,
		"--shred",
		"--no-secrc",
		"--profile", profile,
	)
	cmdInit.Env = append(os.Environ(), "SEC_TEST_MODE=1", "SEC_SESSION_TOKEN="+token, "SEC_KNOWN_HOSTS_PATH="+khFile)
	out, err := cmdInit.CombinedOutput()
	if err != nil {
		t.Fatalf("sec ssh init with --import-key --shred failed: %v\nOutput: %s", err, string(out))
	}

	// Verify key was stored in vault
	resp, qErr := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: "ssh/switch99/private_key"})
	if qErr != nil || !resp.Success || resp.Value != string(pemData) {
		t.Fatalf("expected vault key to match imported pem data, got value: %q, err: %v", resp.Value, qErr)
	}

	// Verify keyToShred was shredded and removed
	if _, err := os.Stat(keyToShred); !os.IsNotExist(err) {
		t.Errorf("expected keyToShred to be unlinked after --shred, got err: %v", err)
	}

	// Verify known_hosts entry for switch99 was sanitized
	khData, _ := os.ReadFile(khFile)
	if strings.Contains(string(khData), "switch99") || strings.Contains(string(khData), "192.168.122.99") {
		t.Errorf("expected switch99 to be sanitized from known_hosts, got:\n%s", string(khData))
	}
}

func TestSSHImportKeyCompanionPubShred(t *testing.T) {
	profile := "test-companion-pub"
	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	_ = os.Remove(sockPath)
	_ = os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_ssh_test_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v\nOutput: %s", err, out)
	}

	d, err := daemon.NewDaemon(profile, 30*time.Second, Version)
	if err != nil {
		t.Fatalf("failed to create test daemon: %v", err)
	}
	token := "test-companion-token"
	d.SetSessionTokenForTest(token)
	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901"))
	t.Setenv("SEC_SESSION_TOKEN", token)
	go d.Start()
	defer d.Stop()

	sock, _ := config.GetSocketPath(profile)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Generate key
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	keyBytes, _ := ssh.MarshalPrivateKey(privKey, "")
	pemData := pem.EncodeToMemory(keyBytes)

	// 1. Test companion .pub and -cert.pub shredding
	keyPath := filepath.Join(tmpDir, "id_ed25519_test")
	pubPath := keyPath + ".pub"
	certPath := keyPath + "-cert.pub"
	_ = os.WriteFile(keyPath, pemData, 0600)
	_ = os.WriteFile(pubPath, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI_pub admin@test\n"), 0644)
	_ = os.WriteFile(certPath, []byte("ssh-ed25519-cert-v01@openssh.com AAAAC3NzaC1lZDI1NTE5 admin@test\n"), 0644)

	cmdShred := exec.Command(binPath, "ssh", "import-key", "spine01", keyPath, "--shred", "--profile", profile, "--no-sanitize")
	cmdShred.Env = append(os.Environ(), "SEC_TEST_MODE=1", "SEC_SESSION_TOKEN="+token)
	out, err := cmdShred.CombinedOutput()
	if err != nil {
		t.Fatalf("import-key with --shred failed: %v\nOutput: %s", err, string(out))
	}

	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Errorf("expected private key %s to be shredded", keyPath)
	}
	if _, err := os.Stat(pubPath); !os.IsNotExist(err) {
		t.Errorf("expected companion public key %s to be shredded", pubPath)
	}
	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Errorf("expected companion cert key %s to be shredded", certPath)
	}

	// 2. Test --keep-pub flag
	keyKeepPath := filepath.Join(tmpDir, "id_keep")
	pubKeepPath := keyKeepPath + ".pub"
	_ = os.WriteFile(keyKeepPath, pemData, 0600)
	_ = os.WriteFile(pubKeepPath, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI_keep\n"), 0644)

	cmdKeep := exec.Command(binPath, "ssh", "import-key", "spine02", keyKeepPath, "--shred", "--keep-pub", "--profile", profile, "--no-sanitize")
	cmdKeep.Env = append(os.Environ(), "SEC_TEST_MODE=1", "SEC_SESSION_TOKEN="+token)
	out, err = cmdKeep.CombinedOutput()
	if err != nil {
		t.Fatalf("import-key with --keep-pub failed: %v\nOutput: %s", err, string(out))
	}

	if _, err := os.Stat(keyKeepPath); !os.IsNotExist(err) {
		t.Errorf("expected private key to be shredded")
	}
	if _, err := os.Stat(pubKeepPath); os.IsNotExist(err) {
		t.Errorf("expected public key to be preserved when --keep-pub is passed")
	}

	// 3. Test safety invariant: corrupt key leaves companion .pub intact
	corruptKey := filepath.Join(tmpDir, "id_corrupt")
	corruptPub := corruptKey + ".pub"
	_ = os.WriteFile(corruptKey, []byte("GARBAGE"), 0600)
	_ = os.WriteFile(corruptPub, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI_corrupt\n"), 0644)

	cmdCorrupt := exec.Command(binPath, "ssh", "import-key", "spine03", corruptKey, "--shred", "--profile", profile, "--no-sanitize")
	cmdCorrupt.Env = append(os.Environ(), "SEC_TEST_MODE=1", "SEC_SESSION_TOKEN="+token)
	_, err = cmdCorrupt.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error on corrupt key, got success")
	}
	if _, err := os.Stat(corruptKey); os.IsNotExist(err) {
		t.Errorf("safety violation: corrupt private key was deleted")
	}
	if _, err := os.Stat(corruptPub); os.IsNotExist(err) {
		t.Errorf("safety violation: companion .pub was deleted on corrupt private key failure")
	}
}

func TestSSHSharedKeySecretAndInit(t *testing.T) {
	profile := "test-shared-key"
	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	_ = os.Remove(sockPath)
	_ = os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_ssh_test_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v\nOutput: %s", err, out)
	}

	d, err := daemon.NewDaemon(profile, 30*time.Second, Version)
	if err != nil {
		t.Fatalf("failed to create test daemon: %v", err)
	}
	token := "test-shared-token"
	d.SetSessionTokenForTest(token)
	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901"))
	t.Setenv("SEC_SESSION_TOKEN", token)
	go d.Start()
	defer d.Stop()

	sock, _ := config.GetSocketPath(profile)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Generate key
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	keyBytes, _ := ssh.MarshalPrivateKey(privKey, "")
	pemData := pem.EncodeToMemory(keyBytes)

	deployKeyPath := filepath.Join(tmpDir, "id_deploy")
	_ = os.WriteFile(deployKeyPath, pemData, 0600)

	// 1. Ingest standalone shared key
	cmdShared := exec.Command(binPath, "ssh", "import-key", "--shared", "sonic_fabric", deployKeyPath, "--profile", profile)
	cmdShared.Env = append(os.Environ(), "SEC_TEST_MODE=1", "SEC_SESSION_TOKEN="+token)
	out, err := cmdShared.CombinedOutput()
	if err != nil {
		t.Fatalf("import-key --shared failed: %v\nOutput: %s", err, string(out))
	}

	resp, qErr := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: "ssh/shared/sonic_fabric/private_key"})
	if qErr != nil || !resp.Success || resp.Value != string(pemData) {
		t.Fatalf("expected shared key to be stored at ssh/shared/sonic_fabric/private_key, got value: %q, err: %v", resp.Value, qErr)
	}

	// 2. Initialize target with shorthand key-secret
	cmdInit := exec.Command(binPath, "ssh", "init", "leaf20",
		"--host", "192.168.122.20",
		"--user", "admin",
		"--key-secret", "sonic_fabric",
		"--no-secrc",
		"--profile", profile,
	)
	cmdInit.Env = append(os.Environ(), "SEC_TEST_MODE=1", "SEC_SESSION_TOKEN="+token)
	out, err = cmdInit.CombinedOutput()
	if err != nil {
		t.Fatalf("sec ssh init with --key-secret failed: %v\nOutput: %s", err, string(out))
	}

	resp2, qErr2 := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: "ssh/leaf20/key_secret"})
	if qErr2 != nil || !resp2.Success || resp2.Value != "ssh/shared/sonic_fabric/private_key" {
		t.Fatalf("expected leaf20/key_secret to expand to ssh/shared/sonic_fabric/private_key, got value: %q, err: %v", resp2.Value, qErr2)
	}

	// 3. Initialize target with explicit key-secret path
	cmdInitExplicit := exec.Command(binPath, "ssh", "init", "leaf21",
		"--host", "192.168.122.21",
		"--user", "admin",
		"--key-secret", "custom/infra/deploy_key",
		"--no-secrc",
		"--profile", profile,
	)
	cmdInitExplicit.Env = append(os.Environ(), "SEC_TEST_MODE=1", "SEC_SESSION_TOKEN="+token)
	out, err = cmdInitExplicit.CombinedOutput()
	if err != nil {
		t.Fatalf("sec ssh init with explicit --key-secret failed: %v\nOutput: %s", err, string(out))
	}

	resp3, qErr3 := queryDaemon(profile, daemon.IPCRequest{Action: "get", Path: "ssh/leaf21/key_secret"})
	if qErr3 != nil || !resp3.Success || resp3.Value != "custom/infra/deploy_key" {
		t.Fatalf("expected leaf21/key_secret to be custom/infra/deploy_key, got value: %q, err: %v", resp3.Value, qErr3)
	}
}
