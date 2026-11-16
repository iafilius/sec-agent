package store

import (
	"errors"
	"testing"
)

func TestBackupBatchJobRequiresTransportOptions(t *testing.T) {
	valid := BackupBatchJob{
		Name: "docs", Source: "/src/docs", Dest: "/dst/docs",
		BackupDir: "/bak/{date}", LogFile: "/log/docs.log",
		RsyncTimeout: 600, SSHOptions: "-o ServerAliveInterval=30",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid job rejected: %v", err)
	}

	noTimeout := valid
	noTimeout.RsyncTimeout = 0
	if err := noTimeout.Validate(); !errors.Is(err, ErrInvalidBackupManifest) {
		t.Fatalf("job without rsync_timeout: got %v, want ErrInvalidBackupManifest", err)
	}

	noSSH := valid
	noSSH.SSHOptions = "  "
	if err := noSSH.Validate(); !errors.Is(err, ErrInvalidBackupManifest) {
		t.Fatalf("job without ssh_options: got %v, want ErrInvalidBackupManifest", err)
	}
}
