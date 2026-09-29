package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLastKnownVersionLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("SEC_CONFIG_DIR", tempDir)

	// 1. Initial state: file does not exist
	ver, err := GetLastKnownVersion()
	if err != nil {
		t.Fatalf("GetLastKnownVersion failed on missing file: %v", err)
	}
	if ver != "" {
		t.Errorf("expected empty version initially, got %q", ver)
	}

	// 2. Set version
	if err := SetLastKnownVersion("v2.14.4"); err != nil {
		t.Fatalf("SetLastKnownVersion failed: %v", err)
	}

	// 3. Read back version
	ver, err = GetLastKnownVersion()
	if err != nil {
		t.Fatalf("GetLastKnownVersion failed after write: %v", err)
	}
	if ver != "v2.14.4" {
		t.Errorf("expected version 'v2.14.4', got %q", ver)
	}

	// 4. Update to newer version
	if err := SetLastKnownVersion("v2.15.0"); err != nil {
		t.Fatalf("SetLastKnownVersion update failed: %v", err)
	}
	ver, err = GetLastKnownVersion()
	if err != nil {
		t.Fatalf("GetLastKnownVersion failed after second write: %v", err)
	}
	if ver != "v2.15.0" {
		t.Errorf("expected version 'v2.15.0', got %q", ver)
	}

	// Verify file permissions
	info, err := os.Stat(filepath.Join(tempDir, ".last_version"))
	if err != nil {
		t.Fatalf("failed to stat .last_version: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600 permissions, got %v", info.Mode().Perm())
	}
}
