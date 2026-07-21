package daemon

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"secure_secrets/internal/config"
	"secure_secrets/internal/crypto"
	"secure_secrets/internal/store"
)

func TestDaemonConcurrency(t *testing.T) {
	profile := "concurrency-test"
	ttl := 10 * time.Second

	// Clean up any stale files
	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	os.Remove(sockPath)
	os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	// Create and start daemon
	d, err := NewDaemon(profile, ttl, "v1.0.0")
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

	go func() {
		if err := d.Start(); err != nil {
			t.Logf("daemon stopped with error: %v", err)
		}
	}()
	defer d.Stop()

	// Wait for socket
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Generate key and open session
	masterKey, err := crypto.GenerateRandomKey()
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial daemon socket: %v", err)
	}
	openReq := IPCRequest{
		Action: "open",
		Key:    masterKey,
	}
	if err := json.NewEncoder(conn).Encode(openReq); err != nil {
		t.Fatalf("failed to send open request: %v", err)
	}
	var openResp IPCResponse
	if err := json.NewDecoder(conn).Decode(&openResp); err != nil {
		t.Fatalf("failed to decode open response: %v", err)
	}
	conn.Close()

	if !openResp.Success {
		t.Fatalf("failed to open session: %s", openResp.Error)
	}

	token := openResp.Token

	// Launch concurrent readers and writers
	var wg sync.WaitGroup
	numWriters := 20
	numReaders := 20
	opsPerGoroutine := 20

	// Track writer completion to verify data integrity later
	writtenKeys := make(map[string]string)
	var mapMu sync.Mutex

	// Writers
	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				key := fmt.Sprintf("db/writer-%d/key-%d", writerID, i)
				val := fmt.Sprintf("val-%d-%d", writerID, i)

				c, err := net.Dial("unix", sockPath)
				if err != nil {
					t.Errorf("writer dial failed: %v", err)
					return
				}
				req := IPCRequest{
					Action:  "set",
					Path:    key,
					Value:   val,
					Comment: "concurrency test writing",
					Token:   token,
				}
				if err := json.NewEncoder(c).Encode(req); err != nil {
					t.Errorf("writer send failed: %v", err)
					c.Close()
					return
				}
				var resp IPCResponse
				if err := json.NewDecoder(c).Decode(&resp); err != nil {
					t.Errorf("writer decode failed: %v", err)
				} else if !resp.Success {
					t.Errorf("writer set failed: %s", resp.Error)
				}
				c.Close()

				mapMu.Lock()
				writtenKeys[key] = val
				mapMu.Unlock()

				time.Sleep(5 * time.Millisecond) // Yield
			}
		}(w)
	}

	// Readers
	for r := 0; r < numReaders; r++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				// Query some dynamic key paths
				key := fmt.Sprintf("db/writer-%d/key-%d", readerID%numWriters, i)

				c, err := net.Dial("unix", sockPath)
				if err != nil {
					// It's possible the key is not written yet, but the connection must succeed
					t.Errorf("reader dial failed: %v", err)
					return
				}
				req := IPCRequest{
					Action: "get",
					Path:   key,
					Token:  token,
				}
				if err := json.NewEncoder(c).Encode(req); err != nil {
					t.Errorf("reader send failed: %v", err)
					c.Close()
					return
				}
				var resp IPCResponse
				if err := json.NewDecoder(c).Decode(&resp); err != nil {
					t.Errorf("reader decode failed: %v", err)
				}
				// Note: if the writer hasn't written this key yet, success will be false.
				// This is expected and doesn't constitute a failure, but the socket transaction must complete cleanly.
				c.Close()

				time.Sleep(3 * time.Millisecond)
			}
		}(r)
	}

	wg.Wait()

	// Verify all written values exist on disk store
	diskStore, err := store.LoadStore(profile, masterKey)
	if err != nil {
		t.Fatalf("failed to load database file from disk after concurrent writes: %v", err)
	}

	for k, expectedVal := range writtenKeys {
		entry, exists := diskStore.Secrets[k]
		if !exists {
			t.Errorf("expected key %q to exist on disk store, but it was missing", k)
			continue
		}
		if entry.Value != expectedVal {
			t.Errorf("key %q value mismatch on disk store: expected %q, got %q", k, expectedVal, entry.Value)
		}
	}
}

func TestDaemonConcurrencySameKey(t *testing.T) {
	profile := "concurrency-same-key"
	ttl := 10 * time.Second

	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	os.Remove(sockPath)
	os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	d, err := NewDaemon(profile, ttl, "v1.0.0")
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
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

	masterKey, _ := crypto.GenerateRandomKey()
	conn, _ := net.Dial("unix", sockPath)
	_ = json.NewEncoder(conn).Encode(IPCRequest{Action: "open", Key: masterKey})
	var openResp IPCResponse
	_ = json.NewDecoder(conn).Decode(&openResp)
	conn.Close()

	token := openResp.Token

	// 50 goroutines trying to write different values to the EXACT SAME path concurrently
	var wg sync.WaitGroup
	numGoroutines := 50
	path := "shared/config/password"

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c, err := net.Dial("unix", sockPath)
			if err != nil {
				t.Errorf("dial failed: %v", err)
				return
			}
			defer c.Close()

			req := IPCRequest{
				Action: "set",
				Path:   path,
				Value:  fmt.Sprintf("secret-val-%d", id),
				Token:  token,
			}
			_ = json.NewEncoder(c).Encode(req)
			var resp IPCResponse
			_ = json.NewDecoder(c).Decode(&resp)
			if !resp.Success {
				t.Errorf("concurrent set failed: %s", resp.Error)
			}
		}(g)
	}

	wg.Wait()

	// Verify database file is not corrupted and is readable
	diskStore, err := store.LoadStore(profile, masterKey)
	if err != nil {
		t.Fatalf("database file corrupted after concurrent writes on same key: %v", err)
	}

	// Value must be one of the written values
	finalVal := diskStore.Secrets[path].Value
	valid := false
	for i := 0; i < numGoroutines; i++ {
		if finalVal == fmt.Sprintf("secret-val-%d", i) {
			valid = true
			break
		}
	}
	if !valid {
		t.Errorf("final database value %q is invalid or corrupted", finalVal)
	}
}
