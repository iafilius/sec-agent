package daemon

import (
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"secure_secrets/internal/config"
	"secure_secrets/internal/store"
)

func TestDaemonExpirationBlock(t *testing.T) {
	profile := "expire-test"
	sockPath, _ := config.GetSocketPath(profile)
	os.Remove(sockPath)
	defer os.Remove(sockPath)

	d, err := NewDaemon(profile, 10*time.Second, "v1.0.0")
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

	// Unlock daemon and load test secrets programmatically
	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901"))
	d.SetSessionTokenForTest("expire-test-token")
	d.SetSecretsForTest(map[string]store.SecretEntry{
		"test/expired": {
			Value:   "old-secret",
			Expires: time.Now().Add(-5 * time.Minute), // Expired 5 minutes ago
		},
		"test/active": {
			Value:   "current-secret",
			Expires: time.Now().Add(5 * time.Minute), // Expires in 5 minutes
		},
	})

	go func() {
		_ = d.Start()
	}()
	defer d.Stop()

	// Wait for socket
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 1. Query expired secret without show-expired flag -> MUST fail
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial daemon: %v", err)
	}
	_ = json.NewEncoder(conn).Encode(IPCRequest{
		Action: "get",
		Path:   "test/expired",
		Token:  "expire-test-token",
	})
	var resp1 IPCResponse
	_ = json.NewDecoder(conn).Decode(&resp1)
	conn.Close()

	if resp1.Success {
		t.Errorf("expected query on expired secret to fail, but it succeeded")
	}
	if resp1.Error != "Secret has expired" {
		t.Errorf("expected error 'Secret has expired', got %q", resp1.Error)
	}

	// 2. Query expired secret WITH show-expired flag -> MUST succeed
	conn, err = net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	_ = json.NewEncoder(conn).Encode(IPCRequest{
		Action:      "get",
		Path:        "test/expired",
		ShowExpired: true,
		Token:       "expire-test-token",
	})
	var resp2 IPCResponse
	_ = json.NewDecoder(conn).Decode(&resp2)
	conn.Close()

	if !resp2.Success {
		t.Errorf("expected query with show-expired flag to succeed, but it failed: %s", resp2.Error)
	}
	if resp2.Value != "old-secret" {
		t.Errorf("expected value 'old-secret', got %q", resp2.Value)
	}

	// 3. Query active secret -> MUST succeed
	conn, err = net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	_ = json.NewEncoder(conn).Encode(IPCRequest{
		Action: "get",
		Path:   "test/active",
		Token:  "expire-test-token",
	})
	var resp3 IPCResponse
	_ = json.NewDecoder(conn).Decode(&resp3)
	conn.Close()

	if !resp3.Success {
		t.Errorf("expected query on active secret to succeed, but it failed: %s", resp3.Error)
	}
	if resp3.Value != "current-secret" {
		t.Errorf("expected value 'current-secret', got %q", resp3.Value)
	}
}
