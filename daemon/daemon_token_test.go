package daemon

import (
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"secure_secrets/config"
)

func TestDaemonSessionTokenVerification(t *testing.T) {
	profile := "token-test"
	sockPath, _ := config.GetSocketPath(profile)
	os.Remove(sockPath)
	defer os.Remove(sockPath)

	d, err := NewDaemon(profile, 10*time.Second, "v1.0.0")
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

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

	// 1. Initial Unlock (generates a token)
	masterKey := []byte("11111111111111111111111111111111")
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial daemon: %v", err)
	}
	_ = json.NewEncoder(conn).Encode(IPCRequest{
		Action: "open",
		Key:    masterKey,
	})
	var respOpen1 IPCResponse
	_ = json.NewDecoder(conn).Decode(&respOpen1)
	conn.Close()

	if !respOpen1.Success {
		t.Fatalf("failed to open session: %s", respOpen1.Error)
	}
	token1 := respOpen1.Token
	if len(token1) != 32 {
		t.Fatalf("expected 32-character hex token, got %q (len %d)", token1, len(token1))
	}

	// 2. Query with valid token -> Should succeed
	conn, err = net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	_ = json.NewEncoder(conn).Encode(IPCRequest{
		Action: "get",
		Path:   "nonexistent",
		Token:  token1,
	})
	var respGetValid IPCResponse
	_ = json.NewDecoder(conn).Decode(&respGetValid)
	conn.Close()

	// Even if path is nonexistent, validation passes (we get a secret-not-found error, not token error)
	if respGetValid.Success {
		t.Errorf("expected secret to not be found, but request succeeded")
	}
	if respGetValid.Error == "ACCESS DENIED: Invalid or missing session token" {
		t.Errorf("expected token validation to pass, but got: %s", respGetValid.Error)
	}

	// 3. Query with invalid token -> Should fail
	conn, err = net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	_ = json.NewEncoder(conn).Encode(IPCRequest{
		Action: "get",
		Path:   "nonexistent",
		Token:  "invalid-token-value-abc-123",
	})
	var respGetInvalid IPCResponse
	_ = json.NewDecoder(conn).Decode(&respGetInvalid)
	conn.Close()

	if respGetInvalid.Success {
		t.Errorf("expected query with invalid token to fail, but it succeeded")
	}
	if respGetInvalid.Error != "ACCESS DENIED: Invalid or missing session token" {
		t.Errorf("expected access denied error, got %q", respGetInvalid.Error)
	}

	// 4. Re-open (retrieve same token) -> Should require same key, and return same token
	conn, err = net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	_ = json.NewEncoder(conn).Encode(IPCRequest{
		Action: "open",
		Key:    masterKey,
	})
	var respOpen2 IPCResponse
	_ = json.NewDecoder(conn).Decode(&respOpen2)
	conn.Close()

	if !respOpen2.Success {
		t.Fatalf("re-open failed: %s", respOpen2.Error)
	}
	if respOpen2.Token != token1 {
		t.Errorf("expected re-open to return existing token %q, got %q", token1, respOpen2.Token)
	}

	// 5. Wipe memory (simulate session lock/expiry) -> Should return Session locked or expired error
	d.wipeMemory()
	conn, err = net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	_ = json.NewEncoder(conn).Encode(IPCRequest{
		Action: "get",
		Path:   "nonexistent",
		Token:  token1,
	})
	var respGetExpired IPCResponse
	_ = json.NewDecoder(conn).Decode(&respGetExpired)
	conn.Close()

	if respGetExpired.Success {
		t.Errorf("expected query on locked session to fail, but it succeeded")
	}
	if respGetExpired.Error != "Session locked or expired. Please run 'sec open' to authorize." {
		t.Errorf("expected locked error message, got %q", respGetExpired.Error)
	}
}
