package daemon

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secure_secrets/internal/config"
)

// TestIsHijacked_RemotePairingDoesNotTrigger guards against regressing the
// false-positive where Apple's Continuity/RemotePairing daemon (remotepairingd),
// which runs persistently on most Macs regardless of any active remote
// session, was treated as a hijack signal.
func TestIsHijacked_RemotePairingDoesNotTrigger(t *testing.T) {
	if err := exec.Command("pgrep", "remotepairingd").Run(); err != nil {
		t.Skip("remotepairingd not running on this host; false-positive condition cannot be exercised here")
	}

	d := &Daemon{}
	hijacked, reason := d.isHijacked(os.Getpid())
	if hijacked {
		t.Fatalf("expected remotepairingd presence alone not to trigger hijack detection, got reason: %q", reason)
	}
}

// TestLogAudit_HijackDenialRecordsReason verifies a hijack denial writes an
// audit-log entry recording the triggering signal, so a denial is diagnosable
// after the fact instead of leaving no trace on disk.
func TestLogAudit_HijackDenialRecordsReason(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SEC_CONFIG_DIR", tmpDir)

	d := &Daemon{profile: "hijack-audit-test"}
	reason := "ssh_ancestry:sshd pid=4242"
	d.logAudit(AuditEventHijack, "", 4242, false, reason)

	data, err := os.ReadFile(filepath.Join(tmpDir, "audit.log"))
	if err != nil {
		t.Fatalf("expected audit.log to be written, got error: %v", err)
	}

	line := strings.TrimSpace(string(data))
	var entry AuditLogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("failed to parse audit.log entry: %v, raw: %s", err, line)
	}

	if entry.Action != AuditEventHijack {
		t.Errorf("expected action %q, got %q", AuditEventHijack, entry.Action)
	}
	if entry.Success {
		t.Errorf("expected hijack denial entry to record success=false")
	}
	if entry.Error != reason {
		t.Errorf("expected reason %q recorded, got %q", reason, entry.Error)
	}
	if entry.PeerPID != 4242 {
		t.Errorf("expected peer_pid 4242 recorded, got %d", entry.PeerPID)
	}
}

// TestDaemonProductionConfirmation verifies IPCActionConfirmProd transitions
// the session state and persists ProductionConfirmed across ping and status,
// and resets on wipeMemory.
func TestDaemonProductionConfirmation(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SEC_CONFIG_DIR", tmpDir)

	d := &Daemon{
		profile:        "prod-test",
		version:        "v2.13.0",
		masterKey:      make([]byte, 32),
		sessionToken:   "test-token",
		sessionTTL:     time.Hour,
		IsTestInstance: true,
	}

	sendReq := func(req IPCRequest) IPCResponse {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()

		var resp IPCResponse
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = json.NewDecoder(clientConn).Decode(&resp)
		}()

		d.processRequest(serverConn, req, 1234)
		_ = serverConn.Close()
		<-done
		return resp
	}

	// 1. Initial ping: session active, but production unconfirmed
	ping1 := sendReq(IPCRequest{Action: IPCActionPing, Token: "test-token"})
	if !ping1.Success {
		t.Fatalf("expected ping1 success, got error: %s", ping1.Error)
	}
	if ping1.ProductionConfirmed {
		t.Errorf("expected initial ping ProductionConfirmed=false, got true")
	}

	// 2. Confirm production
	confirmResp := sendReq(IPCRequest{Action: IPCActionConfirmProd, Token: "test-token"})
	if !confirmResp.Success {
		t.Fatalf("expected confirmResp success, got error: %s", confirmResp.Error)
	}
	if !confirmResp.ProductionConfirmed {
		t.Errorf("expected confirmResp ProductionConfirmed=true, got false")
	}

	// 3. Ping again: should report production confirmed
	ping2 := sendReq(IPCRequest{Action: IPCActionPing, Token: "test-token"})
	if !ping2.Success {
		t.Fatalf("expected ping2 success, got error: %s", ping2.Error)
	}
	if !ping2.ProductionConfirmed {
		t.Errorf("expected ping2 ProductionConfirmed=true, got false")
	}

	// 4. Status should also reflect ProductionConfirmed
	statusResp := sendReq(IPCRequest{Action: IPCActionStatus, Token: "test-token"})
	if !statusResp.Success {
		t.Fatalf("expected statusResp success, got error: %s", statusResp.Error)
	}
	if !statusResp.ProductionConfirmed {
		t.Errorf("expected statusResp ProductionConfirmed=true, got false")
	}
	if statusResp.StatusInfo == nil || !statusResp.StatusInfo.ProductionConfirmed {
		t.Errorf("expected statusResp.StatusInfo.ProductionConfirmed=true")
	}

	// 5. Memory wipe resets production confirmation
	d.mu.Lock()
	d.wipeMemory()
	d.mu.Unlock()

	ping3 := sendReq(IPCRequest{Action: IPCActionPing})
	if ping3.ProductionConfirmed {
		t.Errorf("expected post-wipe ping ProductionConfirmed=false, got true")
	}
}

// TestDaemonFlockMutualExclusion verifies that a second daemon process attempting
// to start for the same profile fails immediately via advisory flock, without
// trampling or unlinking the active socket.
func TestDaemonFlockMutualExclusion(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "sec-flock")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	t.Setenv("SEC_CONFIG_DIR", tmpDir)

	profile := "f-test"
	sockPath, err := config.GetSocketPath(profile)
	if err != nil {
		t.Fatalf("failed to get socket path: %v", err)
	}

	d1, err := NewDaemon(profile, time.Hour, "v2.13.0")
	if err != nil {
		t.Fatalf("failed to create daemon 1: %v", err)
	}
	d1.IsTestInstance = true

	d1ErrChan := make(chan error, 1)
	go func() {
		d1ErrChan <- d1.Start()
	}()
	defer d1.Stop()

	// Wait for d1 socket to be ready
	for i := 0; i < 40; i++ {
		select {
		case err := <-d1ErrChan:
			t.Fatalf("d1.Start failed early: %v", err)
		default:
		}
		if _, statErr := os.Stat(sockPath); statErr == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	if _, statErr := os.Stat(sockPath); statErr != nil {
		t.Fatalf("expected d1 socket %s to be created: %v", sockPath, statErr)
	}

	// Now attempt to start a second daemon for the same profile
	d2, err := NewDaemon(profile, time.Hour, "v2.13.0")
	if err != nil {
		t.Fatalf("failed to create daemon 2: %v", err)
	}
	d2.IsTestInstance = true

	err2 := d2.Start()
	if err2 == nil {
		t.Fatalf("expected d2.Start() to fail with advisory lock error, but it succeeded")
	}
	if !strings.Contains(err2.Error(), "another daemon instance is already running") {
		t.Errorf("expected lock error message, got: %v", err2)
	}

	// Verify d1's socket was NOT deleted by d2's failed start attempt
	if _, statErr := os.Stat(sockPath); statErr != nil {
		t.Errorf("d1 socket was deleted after d2 failed launch: %v", statErr)
	}
}

func TestDaemonAutoTermination(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "sec-term")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	t.Setenv("SEC_CONFIG_DIR", tmpDir)

	profile := "t-term"
	d, err := NewDaemon(profile, time.Hour, "v2.13.0")
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}
	d.IsTestInstance = true

	dErrChan := make(chan error, 1)
	go func() {
		dErrChan <- d.Start()
	}()
	defer d.Stop()

	sockPath, err := config.GetSocketPath(profile)
	if err != nil {
		t.Fatalf("failed to get socket path: %v", err)
	}

	for i := 0; i < 40; i++ {
		select {
		case err := <-dErrChan:
			t.Fatalf("d.Start failed: %v", err)
		default:
		}
		if _, statErr := os.Stat(sockPath); statErr == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	// 1. Initially healthy daemon should NOT terminate
	if d.ShouldAutoTerminate() {
		t.Fatalf("expected fresh daemon NOT to auto-terminate")
	}

	// 2. Idle timeout expired when locked/unauthenticated
	d.SetIdleTimeout(50 * time.Millisecond)
	d.mu.Lock()
	d.lastActivity = time.Now().Add(-100 * time.Millisecond)
	d.mu.Unlock()

	if !d.ShouldAutoTerminate() {
		t.Fatalf("expected daemon to auto-terminate after exceeding idle timeout while locked")
	}

	// Reset activity
	d.mu.Lock()
	d.lastActivity = time.Now()
	d.mu.Unlock()
	d.SetIdleTimeout(time.Hour)

	if d.ShouldAutoTerminate() {
		t.Fatalf("expected daemon NOT to auto-terminate after resetting activity")
	}

	// 3. Displaced socket file triggers auto-termination
	if err := os.Remove(sockPath); err != nil {
		t.Fatalf("failed to remove socket file: %v", err)
	}

	if !d.ShouldAutoTerminate() {
		t.Fatalf("expected daemon to auto-terminate when socket file is removed/displaced")
	}
}

