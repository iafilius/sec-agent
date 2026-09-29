package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"secure_secrets/internal/config"
	"secure_secrets/internal/keychain"
)

func TestKeychainStatusAndJSON(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("SEC_CONFIG_DIR", tempDir)
	t.Setenv("SEC_TEST_MODE", "1")

	// Set version marker in config
	if err := config.SetLastKnownVersion("v2.14.4"); err != nil {
		t.Fatalf("failed to set version: %v", err)
	}

	// 1. Test text output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	handleKeychainStatus("default", []string{})

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	textOut := buf.String()

	if !strings.Contains(textOut, "=== macOS Keychain Biometric Binding Status ===") {
		t.Errorf("expected header in output, got: %s", textOut)
	}
	if !strings.Contains(textOut, "Profile:                default") {
		t.Errorf("expected default profile in output, got: %s", textOut)
	}

	// 2. Test JSON output
	rJSON, wJSON, _ := os.Pipe()
	os.Stdout = wJSON

	handleKeychainStatus("default", []string{"--json"})

	_ = wJSON.Close()
	os.Stdout = oldStdout

	var jsonBuf bytes.Buffer
	_, _ = io.Copy(&jsonBuf, rJSON)

	var dto KeychainStatusDTO
	if err := json.Unmarshal(jsonBuf.Bytes(), &dto); err != nil {
		t.Fatalf("failed to parse json output: %v; raw: %s", err, jsonBuf.String())
	}

	if dto.Profile != "default" {
		t.Errorf("expected profile 'default', got %q", dto.Profile)
	}
	if dto.ActiveVersion == "" {
		t.Errorf("expected non-empty active_version")
	}
}

func TestKeychainPruneTestMode(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("SEC_CONFIG_DIR", tempDir)
	t.Setenv("SEC_TEST_MODE", "1")

	profile := "test-prune-prof"
	secret := []byte("prune-secret-key-32-bytes-long!!")

	// Seed test keychain
	if err := keychain.SetCurrentSet("sec-test-session:profile_"+profile, "master", secret); err != nil {
		t.Fatalf("SetCurrentSet failed: %v", err)
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	handleKeychainPrune("default", []string{"--profile", profile})

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "re-sealed") {
		t.Errorf("expected re-sealed message in output, got: %s", out)
	}

	// Clean up
	_ = keychain.Delete("sec-test-session:profile_"+profile, "master")
}
