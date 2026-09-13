package daemon

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
