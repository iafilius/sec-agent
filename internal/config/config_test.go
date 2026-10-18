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
	if err := SetLastKnownVersion("v2.16.0"); err != nil {
		t.Fatalf("SetLastKnownVersion update failed: %v", err)
	}
	ver, err = GetLastKnownVersion()
	if err != nil {
		t.Fatalf("GetLastKnownVersion failed after second write: %v", err)
	}
	if ver != "v2.16.0" {
		t.Errorf("expected version 'v2.16.0', got %q", ver)
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

func TestPromptTimeoutResolution(t *testing.T) {
	// 1. Default fallback when nothing is set
	t.Setenv("SEC_PROMPT_TIMEOUT", "")
	d, err := ResolvePromptTimeout("", "")
	if err != nil {
		t.Fatalf("unexpected error resolving default timeout: %v", err)
	}
	if d != DefaultPromptTimeout {
		t.Errorf("expected %v, got %v", DefaultPromptTimeout, d)
	}

	// 2. Fallback to SEC_PROMPT_TIMEOUT env var
	t.Setenv("SEC_PROMPT_TIMEOUT", "45s")
	d, err = ResolvePromptTimeout("", "")
	if err != nil {
		t.Fatalf("unexpected error resolving env timeout: %v", err)
	}
	if d != 45*1000*1000*1000 {
		t.Errorf("expected 45s, got %v", d)
	}

	// 3. Fallback to SEC_PROMPT_TIMEOUT as pure integer (seconds)
	t.Setenv("SEC_PROMPT_TIMEOUT", "60")
	d, err = ResolvePromptTimeout("", "")
	if err != nil {
		t.Fatalf("unexpected error resolving integer env timeout: %v", err)
	}
	if d != 60*1000*1000*1000 {
		t.Errorf("expected 60s, got %v", d)
	}

	// 4. .secrc config overrides env var
	d, err = ResolvePromptTimeout("", "90s")
	if err != nil {
		t.Fatalf("unexpected error resolving secrc timeout: %v", err)
	}
	if d != 90*1000*1000*1000 {
		t.Errorf("expected 90s, got %v", d)
	}

	// 5. CLI flag overrides both .secrc and env var
	d, err = ResolvePromptTimeout("30s", "90s")
	if err != nil {
		t.Fatalf("unexpected error resolving flag timeout: %v", err)
	}
	if d != 30*1000*1000*1000 {
		t.Errorf("expected 30s, got %v", d)
	}

	// 6. Invalid durations return error
	if _, err := ParsePromptTimeout("invalid"); err == nil {
		t.Errorf("expected error for invalid timeout string")
	}
	if _, err := ParsePromptTimeout("-10s"); err == nil {
		t.Errorf("expected error for negative timeout")
	}
	if _, err := ParsePromptTimeout("0s"); err == nil {
		t.Errorf("expected error for zero timeout")
	}
}

