package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
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


