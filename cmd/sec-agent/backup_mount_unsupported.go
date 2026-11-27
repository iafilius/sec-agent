//go:build !darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func verifyLocalBackupMount(destPath string) error {
	clean := filepath.Clean(strings.TrimSpace(destPath))
	if !strings.HasPrefix(clean, "/Volumes/") {
		return nil
	}
	rest := strings.TrimPrefix(clean, "/Volumes/")
	parts := strings.SplitN(rest, "/", 2)
	mountName := strings.TrimSpace(parts[0])
	if mountName == "" {
		return fmt.Errorf("destination path %q under /Volumes must specify a mounted volume name", destPath)
	}
	mountRoot := filepath.Join("/Volumes", mountName)
	// #nosec G703
	fi, err := os.Stat(mountRoot)
	if err != nil || !fi.IsDir() {
		return fmt.Errorf("destination volume %q is not mounted", mountName)
	}
	return nil
}
