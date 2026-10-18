package daemon

import (
	"encoding/json"
	"net"
	"os"
	"strings"
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

func TestDaemonSlidingTTLAndStatus(t *testing.T) {
	profile := "sliding-test"
	sockPath, _ := config.GetSocketPath(profile)
	os.Remove(sockPath)
	defer os.Remove(sockPath)

	d, err := NewDaemon(profile, 2*time.Second, "v2.16.0")
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}
	d.graceTTL = 5 * time.Second

	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901"))
	d.SetSessionTokenForTest("slide-token")
	d.SetSecretsForTest(map[string]store.SecretEntry{
		"test/foo": {Value: "bar"},
	})

	// Set session start to 3 seconds ago (exceeding 2s hard TTL)
	// but lastUsed to 1 second ago (well within 5s grace window)
	oldStart := time.Now().Add(-3 * time.Second)
	d.sessionStart = oldStart
	d.lastUsed = time.Now().Add(-1 * time.Second)

	if d.isExpired() {
		t.Fatalf("expected session not to be expired within grace window")
	}

	go func() {
		_ = d.Start()
	}()
	defer d.Stop()

	for i := 0; i < 20; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 1. Query status and check remaining TTL fields
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	_ = json.NewEncoder(conn).Encode(IPCRequest{
		Action: "status",
		Token:  "slide-token",
	})
	var stResp IPCResponse
	_ = json.NewDecoder(conn).Decode(&stResp)
	conn.Close()

	if !stResp.Success || stResp.StatusInfo == nil {
		t.Fatalf("status request failed: %v", stResp.Error)
	}
	if stResp.StatusInfo.RemainingSeconds <= 0 {
		t.Errorf("expected RemainingSeconds > 0, got %d", stResp.StatusInfo.RemainingSeconds)
	}
	if stResp.StatusInfo.RemainingTTL == "" {
		t.Errorf("expected non-empty RemainingTTL")
	}
	if stResp.StatusInfo.ExpiresAt == "" {
		t.Errorf("expected non-empty ExpiresAt")
	}

	// 2. Query secret -> should trigger sliding TTL refresh
	conn, err = net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	_ = json.NewEncoder(conn).Encode(IPCRequest{
		Action: "get",
		Path:   "test/foo",
		Token:  "slide-token",
	})
	var getResp IPCResponse
	_ = json.NewDecoder(conn).Decode(&getResp)
	conn.Close()

	if !getResp.Success {
		t.Fatalf("expected get to succeed, got %v", getResp.Error)
	}

	d.mu.Lock()
	newStart := d.sessionStart
	d.mu.Unlock()

	if !newStart.After(oldStart) {
		t.Errorf("expected sliding TTL to advance sessionStart: old=%v new=%v", oldStart, newStart)
	}

	// 3. Test expired session error formatting
	d.mu.Lock()
	d.sessionStart = time.Now().Add(-2 * time.Hour)
	d.lastUsed = time.Now().Add(-2 * time.Hour)
	d.mu.Unlock()

	conn, err = net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	_ = json.NewEncoder(conn).Encode(IPCRequest{
		Action: "get",
		Path:   "test/foo",
		Token:  "slide-token",
	})
	var expResp IPCResponse
	_ = json.NewDecoder(conn).Decode(&expResp)
	conn.Close()

	if expResp.Success {
		t.Fatalf("expected expired request to fail")
	}
	expectedSubstring := "Session locked or expired"
	if !strings.Contains(expResp.Error, expectedSubstring) || !strings.Contains(expResp.Error, "ago") {
		t.Errorf("expected error containing %q and 'ago', got %q", expectedSubstring, expResp.Error)
	}
}

