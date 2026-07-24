package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// GetConfigDir returns the path to ~/.config/sec-agent/, automatically migrating from ~/.config/sec/ if present.
func GetConfigDir() (string, error) {
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

	return dir, nil
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
