package daemon

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"secure_secrets/internal/config"
	"secure_secrets/internal/crypto"
	"secure_secrets/internal/store"
)

func TestMain(m *testing.M) {
	for i, arg := range os.Args {
		if arg == "daemon" {
			if os.Getenv("SEC_TEST_REEXEC_HANG") == "1" {
				time.Sleep(10 * time.Second)
				os.Exit(0)
			}
			prof := os.Getenv("SEC_PROFILE")
			for j := 0; j < i; j++ {
				if os.Args[j] == "--profile" && j+1 < len(os.Args) {
					prof = os.Args[j+1]
				}
			}
			if prof == "" {
				prof = "default"
			}
			d, err := NewDaemon(prof, 5*time.Minute, "v2.19.4-reexec")
			if err != nil {
				os.Exit(1)
			}
			_ = d.Start()
			return
		}
	}
	os.Exit(m.Run())
}

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
		entry, exists := diskStore.Secrets[store.SecretKey(k)]
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
	finalVal := diskStore.Secrets[store.SecretKey(path)].Value
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

func TestDaemonRelabel(t *testing.T) {
	profile := "relabel-test"
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
	go func() { _ = d.Start() }()
	defer d.Stop()

	for i := 0; i < 20; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	masterKey, err := crypto.GenerateRandomKey()
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	// 1. Open session
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	_ = json.NewEncoder(conn).Encode(IPCRequest{Action: "open", Key: masterKey})
	var openResp IPCResponse
	_ = json.NewDecoder(conn).Decode(&openResp)
	conn.Close()
	if !openResp.Success {
		t.Fatalf("open failed: %s", openResp.Error)
	}
	token := openResp.Token

	// 2. Set initial secret
	conn, _ = net.Dial("unix", sockPath)
	_ = json.NewEncoder(conn).Encode(IPCRequest{
		Action:  "set",
		Path:    "velocloud/token",
		Value:   "super-secret-token",
		Comment: "Initial Comment",
		Token:   token,
	})
	var setResp IPCResponse
	_ = json.NewDecoder(conn).Decode(&setResp)
	conn.Close()
	if !setResp.Success {
		t.Fatalf("set failed: %s", setResp.Error)
	}

	// 3. Relabel secret (add env_alias, update comment, add metadata tag)
	conn, _ = net.Dial("unix", sockPath)
	_ = json.NewEncoder(conn).Encode(IPCRequest{
		Action:   "relabel",
		Path:     "velocloud/token",
		Comment:  "Updated Comment",
		Metadata: map[string]string{"env_alias": "VCO_API_TOKEN", "tier": "prod"},
		Token:    token,
	})
	var relabelResp IPCResponse
	_ = json.NewDecoder(conn).Decode(&relabelResp)
	conn.Close()
	if !relabelResp.Success {
		t.Fatalf("relabel failed: %s", relabelResp.Error)
	}

	// 4. Verify disk persistence and value preservation
	diskStore, err := store.LoadStore(profile, masterKey)
	if err != nil {
		t.Fatalf("failed to load store: %v", err)
	}
	entry, ok := diskStore.Secrets[store.SecretKey("velocloud/token")]
	if !ok {
		t.Fatalf("secret missing from store")
	}
	if entry.Value != "super-secret-token" {
		t.Errorf("entry.Value altered during relabel: got %q, want 'super-secret-token'", entry.Value)
	}
	if entry.Comment != "Updated Comment" {
		t.Errorf("entry.Comment mismatch: got %q, want 'Updated Comment'", entry.Comment)
	}
	if entry.Metadata["env_alias"] != "VCO_API_TOKEN" {
		t.Errorf("entry.Metadata['env_alias'] mismatch: got %q, want 'VCO_API_TOKEN'", entry.Metadata["env_alias"])
	}
	if entry.Metadata["tier"] != "prod" {
		t.Errorf("entry.Metadata['tier'] mismatch: got %q, want 'prod'", entry.Metadata["tier"])
	}

	// 5. Test ClearAlias
	conn, _ = net.Dial("unix", sockPath)
	_ = json.NewEncoder(conn).Encode(IPCRequest{
		Action:     "relabel",
		Path:       "velocloud/token",
		ClearAlias: true,
		Token:      token,
	})
	var clearResp IPCResponse
	_ = json.NewDecoder(conn).Decode(&clearResp)
	conn.Close()
	if !clearResp.Success {
		t.Fatalf("clear alias failed: %s", clearResp.Error)
	}

	diskStore2, _ := store.LoadStore(profile, masterKey)
	entry2 := diskStore2.Secrets[store.SecretKey("velocloud/token")]
	if _, exists := entry2.Metadata["env_alias"]; exists {
		t.Errorf("env_alias should have been cleared")
	}
	if entry2.Metadata["tier"] != "prod" {
		t.Errorf("tier metadata lost when clearing alias")
	}
	if entry2.Value != "super-secret-token" {
		t.Errorf("secret value altered when clearing alias")
	}

	// 6. Relabel non-existent secret
	conn, _ = net.Dial("unix", sockPath)
	_ = json.NewEncoder(conn).Encode(IPCRequest{
		Action:  "relabel",
		Path:    "non/existent",
		Comment: "foo",
		Token:   token,
	})
	var errResp IPCResponse
	_ = json.NewDecoder(conn).Decode(&errResp)
	conn.Close()
	if errResp.Success {
		t.Errorf("expected error for non-existent secret, got success")
	}
}

func TestHotReloadLargePayloadOver64KBAndConcurrentStatus(t *testing.T) {
	tmpCfgDir, err := os.MkdirTemp("/tmp", "sec_hr64_*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpCfgDir)
	t.Setenv("SEC_CONFIG_DIR", tmpCfgDir)
	t.Setenv("SEC_TEST_MODE", "1")

	profile := "hr64"
	sockPath, _ := config.GetSocketPath(profile)
	masterKey := []byte("01234567890123456789012345678901")

	// Seed > 100 KB of secrets (> 64 KB macOS pipe buffer)
	largeSecrets := make(map[string]store.SecretEntry)
	chunk := strings.Repeat("A", 8192)
	for i := 0; i < 15; i++ {
		largeSecrets[fmt.Sprintf("bulk/secret_%02d", i)] = store.SecretEntry{
			Value:       fmt.Sprintf("%d-%s", i, chunk),
			Comment:     "large payload secret",
			Description: "exceeds 64 KB pipe buffer when combined",
		}
	}

	d, err := NewDaemon(profile, 5*time.Minute, "v2.19.3-initial")
	if err != nil {
		t.Fatalf("NewDaemon failed: %v", err)
	}
	d.IsTestInstance = true
	d.SetMasterKeyForTest(masterKey)
	d.SetSessionTokenForTest("hr64-token")
	d.SetSecretsForTest(largeSecrets)

	go func() {
		_ = d.Start()
	}()
	defer d.Stop()

	for i := 0; i < 40; i++ {
		if _, sErr := os.Stat(sockPath); sErr == nil {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}

	sendIPC := func(req IPCRequest) (IPCResponse, error) {
		c, dialErr := net.DialTimeout("unix", sockPath, 1*time.Second)
		if dialErr != nil {
			return IPCResponse{}, dialErr
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if encErr := json.NewEncoder(c).Encode(req); encErr != nil {
			return IPCResponse{}, encErr
		}
		var resp IPCResponse
		if decErr := json.NewDecoder(c).Decode(&resp); decErr != nil {
			return IPCResponse{}, decErr
		}
		return resp, nil
	}

	// Concurrently fire status requests while hot-reload is running
	statusDone := make(chan error, 1)
	go func() {
		for i := 0; i < 5; i++ {
			time.Sleep(10 * time.Millisecond)
			resp, sErr := sendIPC(IPCRequest{Action: IPCActionStatus, Token: "hr64-token"})
			if sErr == nil && !resp.Success {
				statusDone <- fmt.Errorf("concurrent status returned Success=false: %s", resp.Error)
				return
			}
		}
		statusDone <- nil
	}()

	reexecResp, reexecErr := sendIPC(IPCRequest{Action: IPCActionReexec, Token: "hr64-token"})
	if reexecErr != nil || !reexecResp.Success {
		t.Fatalf("expected >64KB hot-reload to succeed without deadlock, got err=%v resp=%+v", reexecErr, reexecResp)
	}

	if sErr := <-statusDone; sErr != nil {
		t.Errorf("concurrent status check failed during hot-reload: %v", sErr)
	}

	// Verify replacement daemon is serving the >100 KB state and reports the new version
	var postResp IPCResponse
	var postErr error
	for i := 0; i < 30; i++ {
		postResp, postErr = sendIPC(IPCRequest{Action: IPCActionStatus, Token: "hr64-token"})
		if postErr == nil && postResp.Success && postResp.StatusInfo != nil && postResp.StatusInfo.Version == "v2.19.4-reexec" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if postErr != nil || !postResp.Success || postResp.StatusInfo == nil {
		t.Fatalf("post-reload status failed: err=%v resp=%+v", postErr, postResp)
	}
	if postResp.StatusInfo.Version != "v2.19.4-reexec" {
		t.Errorf("expected replacement daemon version 'v2.19.4-reexec', got %q", postResp.StatusInfo.Version)
	}
	if postResp.StatusInfo.TotalSecrets != 15 {
		t.Errorf("expected replacement daemon to preserve all 15 secrets, got %d", postResp.StatusInfo.TotalSecrets)
	}

	// Stop the replacement child daemon cleanly by sending Clear
	_, _ = sendIPC(IPCRequest{Action: IPCActionClear, Token: "hr64-token"})
}

func TestHotReloadStuckReplacementProcessAbortsAndKeepsDaemonServing(t *testing.T) {
	tmpCfgDir, err := os.MkdirTemp("/tmp", "sec_hrhang_*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpCfgDir)
	t.Setenv("SEC_CONFIG_DIR", tmpCfgDir)
	t.Setenv("SEC_TEST_MODE", "1")
	t.Setenv("SEC_TEST_REEXEC_HANG", "1")

	profile := "hrhang"
	sockPath, _ := config.GetSocketPath(profile)
	masterKey := []byte("01234567890123456789012345678901")

	// Seed > 100 KB of secrets so pipe write itself would block without deadline
	largeSecrets := make(map[string]store.SecretEntry)
	chunk := strings.Repeat("B", 8192)
	for i := 0; i < 15; i++ {
		largeSecrets[fmt.Sprintf("bulk/hang_%02d", i)] = store.SecretEntry{
			Value: fmt.Sprintf("%d-%s", i, chunk),
		}
	}

	d, err := NewDaemon(profile, 5*time.Minute, "v2.19.3-stay-alive")
	if err != nil {
		t.Fatalf("NewDaemon failed: %v", err)
	}
	d.IsTestInstance = true
	d.ReexecTimeout = 250 * time.Millisecond
	d.SetMasterKeyForTest(masterKey)
	d.SetSessionTokenForTest("hrhang-token")
	d.SetSecretsForTest(largeSecrets)

	go func() {
		_ = d.Start()
	}()
	defer d.Stop()

	for i := 0; i < 40; i++ {
		if _, sErr := os.Stat(sockPath); sErr == nil {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}

	sendIPC := func(req IPCRequest) (IPCResponse, error) {
		c, dialErr := net.DialTimeout("unix", sockPath, 1*time.Second)
		if dialErr != nil {
			return IPCResponse{}, dialErr
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if encErr := json.NewEncoder(c).Encode(req); encErr != nil {
			return IPCResponse{}, encErr
		}
		var resp IPCResponse
		if decErr := json.NewDecoder(c).Decode(&resp); decErr != nil {
			return IPCResponse{}, decErr
		}
		return resp, nil
	}

	reexecResp, reexecErr := sendIPC(IPCRequest{Action: IPCActionReexec, Token: "hrhang-token"})
	if reexecErr != nil {
		t.Fatalf("expected structured error response from aborted reexec, got transport error: %v", reexecErr)
	}
	if reexecResp.Success {
		t.Fatalf("expected reexecResp.Success == false when replacement process never reads pipe")
	}
	if !strings.Contains(reexecResp.Error, "hot-reload handoff failed") {
		t.Errorf("expected error message to mention 'hot-reload handoff failed', got %q", reexecResp.Error)
	}

	// Verify current daemon is STILL alive and serving requests with its full state
	statusResp, statusErr := sendIPC(IPCRequest{Action: IPCActionStatus, Token: "hrhang-token"})
	if statusErr != nil || !statusResp.Success || statusResp.StatusInfo == nil {
		t.Fatalf("expected original daemon to keep serving after aborted reexec, got err=%v resp=%+v", statusErr, statusResp)
	}
	if statusResp.StatusInfo.Version != "v2.19.3-stay-alive" || statusResp.StatusInfo.TotalSecrets != 15 {
		t.Errorf("unexpected status after aborted reexec: %+v", statusResp.StatusInfo)
	}

	// Verify audit log recorded a failed REEXEC entry
	auditPath := filepath.Join(tmpCfgDir, "audit.log")
	auditBytes, aErr := os.ReadFile(auditPath)
	if aErr != nil {
		t.Fatalf("expected audit log to be written at %s: %v", auditPath, aErr)
	}
	if !strings.Contains(string(auditBytes), `"action":"REEXEC"`) || !strings.Contains(string(auditBytes), `"success":false`) {
		t.Errorf("expected failed REEXEC audit entry in audit.log, got:\n%s", string(auditBytes))
	}
}
