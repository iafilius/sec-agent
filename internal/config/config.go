package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// GetConfigDir returns the path to ~/.config/sec/, creating it if it doesn't exist.
func GetConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	dir := filepath.Join(home, ".config", "sec")
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
		return filepath.Join(dir, "sec.sock"), nil
	}
	return filepath.Join(dir, fmt.Sprintf("sec_%s.sock", profile)), nil
}
