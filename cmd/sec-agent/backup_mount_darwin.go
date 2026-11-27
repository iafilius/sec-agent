//go:build darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// verifyLocalBackupMount ensures that a local destination under /Volumes/<MountName>/...
// points to an actually mounted filesystem (distinct statfs Fsid from /Volumes) rather than
// a stale stub directory on the macOS boot volume. Paths outside /Volumes/ return nil.
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
		return fmt.Errorf("destination volume %q is not mounted (connect the drive before running backup)", mountName)
	}

	var mountStat, parentStat unix.Statfs_t
	if err := unix.Statfs(mountRoot, &mountStat); err != nil {
		return fmt.Errorf("failed to inspect destination volume %q mount state: %w", mountName, err)
	}
	if err := unix.Statfs("/Volumes", &parentStat); err != nil {
		return fmt.Errorf("failed to inspect /Volumes mount state: %w", err)
	}
	if mountStat.Fsid == parentStat.Fsid {
		return fmt.Errorf("destination volume %q is not mounted (found unmounted stub directory on root filesystem — aborting to prevent writing to boot drive)", mountName)
	}
	return nil
}
