package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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
