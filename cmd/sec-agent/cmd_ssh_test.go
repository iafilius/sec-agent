package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

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

	err = runNativeSSH("127.0.0.1", port, "testuser", "secretpass123", nil, "", []string{"uptime"})
	if err != nil {
		t.Fatalf("runNativeSSH failed: %v", err)
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


