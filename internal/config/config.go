package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// IsConfigDirInitialized returns true if ~/.config/sec-agent/ or legacy ~/.config/sec/ exists.
func IsConfigDirInitialized() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	dir := filepath.Join(home, ".config", "sec-agent")
	legacyDir := filepath.Join(home, ".config", "sec")
	if _, err := os.Stat(dir); err == nil {
		return true
	}
	if _, err := os.Stat(legacyDir); err == nil {
		return true
	}
	return false
}

// GetConfigDir returns the path to ~/.config/sec-agent/, automatically migrating from ~/.config/sec/ if present.
func GetConfigDir() (string, error) {
	if custom := os.Getenv("SEC_CONFIG_DIR"); custom != "" {
		// #nosec G304 G703
		if err := os.MkdirAll(custom, 0700); err != nil {
			return "", err
		}
		return custom, nil
	}
	if os.Getenv("SEC_TEST_MODE") != "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		tmpDir := filepath.Join(home, ".config", "sec-agent")
		if err := os.MkdirAll(tmpDir, 0700); err != nil {
			return "", err
		}
		return tmpDir, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	legacyDir := filepath.Join(home, ".config", "sec")
	dir := filepath.Join(home, ".config", "sec-agent")

	// Automatic Migration check
	if _, err := os.Stat(legacyDir); err == nil {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			_ = os.Rename(legacyDir, dir)
		}
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create config directory %s: %w", dir, err)
	}

	_ = ensureConfigReadme(dir)

	return dir, nil
}

func ensureConfigReadme(dir string) error {
	readmePath := filepath.Join(dir, "README.md")
	if _, err := os.Stat(readmePath); err == nil {
		return nil
	}

	content := `# sec-agent Local User Data & Vault Configuration Directory

This directory (~/.config/sec-agent/) was automatically created by **sec-agent** (macOS Enclave-Bound Session Agent).

## 🛠️ Tool & Repository Information

* **Tool Name**: sec-agent
* **Official Repository**: https://github.com/iafilius/sec-agent
* **Documentation**: https://github.com/iafilius/sec-agent/tree/master/docs
* **License**: MIT License (Copyright (c) 2026 Arjan Filius)

---

## 📁 Directory Contents & Purpose

* **secrets.enc**: AES-256-GCM encrypted database store holding your local secret keys and configuration entries. Encrypted at rest using a master key sealed inside the macOS **Secure Enclave** (SecAccessControl).
* **secrets.enc.bak**: Automatic atomic backup copy created before database write operations.
* **sec-agent.sock** (or sec-agent_<profile>.sock): Unix domain socket used for IPC communication between the sec-agent CLI utility and background session daemons.
* **audit.log**: Security audit log tracking authentication events, query access counts, and session lock history.

---

## ⚠️ Security Notes

1. **Do not delete secrets.enc**: Deleting this file will erase your stored encrypted credentials.
2. **Secure Enclave Protection**: Secrets in secrets.enc cannot be decrypted without Touch ID console authentication on this hardware laptop.
`
	return os.WriteFile(readmePath, []byte(content), 0600)
}

// GetSocketPath returns the path to the Unix domain socket for the daemon.
func GetSocketPath(profile string) (string, error) {
	dir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	if profile == "" || profile == "default" {
		return filepath.Join(dir, "sec-agent.sock"), nil
	}
	return filepath.Join(dir, fmt.Sprintf("sec-agent_%s.sock", profile)), nil
}

// GetPIDFilePath returns the path to the PID lockfile for the given profile.
func GetPIDFilePath(profile string) (string, error) {
	dir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	if profile == "" || profile == "default" {
		return filepath.Join(dir, "sec-agent.pid"), nil
	}
	return filepath.Join(dir, fmt.Sprintf("sec-agent_%s.pid", profile)), nil
}

// PurgeAllSessionTokenFiles removes any legacy or active session.token or session_*.token files from ~/.config/sec-agent/
func PurgeAllSessionTokenFiles() {
	dir, err := GetConfigDir()
	if err != nil {
		return
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, f := range files {
		if !f.IsDir() && (f.Name() == "session.token" || (strings.HasPrefix(f.Name(), "session_") && strings.HasSuffix(f.Name(), ".token"))) {
			_ = os.Remove(filepath.Join(dir, f.Name()))
		}
	}
}

// GetSessionTokenPath is deprecated and returns empty string. Zero token files are written to disk.
func GetSessionTokenPath(profile string) (string, error) {
	return "", nil
}

// SaveSessionToken is a no-op that purges lingering disk tokens and returns nil.
func SaveSessionToken(profile string, token string) error {
	PurgeAllSessionTokenFiles()
	return nil
}

// LoadSessionToken returns empty string (zero disk token loading).
func LoadSessionToken(profile string) string {
	return ""
}

// ClearSessionToken purges any lingering token files from disk.
func ClearSessionToken(profile string) error {
	PurgeAllSessionTokenFiles()
	return nil
}
