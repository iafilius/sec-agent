//go:build darwin

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	defaultNetworkMountRsyncTimeout      = 180
	defaultNetworkMountNoProgressTimeout = 15 * time.Minute
	networkMountPreFlightTimeout         = 5 * time.Second
	networkMountPostStallTimeout         = 3 * time.Second
)

var smbAutoExcludes = []string{"$RECYCLE.BIN", "System Volume Information", "Thumbs.db"}

// detectFilesystemType returns the lowercase macOS filesystem type name for path
// (e.g. "apfs", "exfat", "smbfs", "nfs", "afpfs", "webdav") via unix.Statfs.
func detectFilesystemType(path string) string {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return ""
	}
	var b strings.Builder
	for _, ch := range st.Fstypename {
		if ch == 0 {
			break
		}
		b.WriteByte(byte(ch))
	}
	return strings.ToLower(strings.TrimSpace(b.String()))
}

func isNetworkFilesystemType(fsType string) bool {
	switch strings.ToLower(strings.TrimSpace(fsType)) {
	case "smbfs", "cifs", "nfs", "afpfs", "webdav":
		return true
	default:
		return false
	}
}

func isSMBFilesystemType(fsType string) bool {
	switch strings.ToLower(strings.TrimSpace(fsType)) {
	case "smbfs", "cifs":
		return true
	default:
		return false
	}
}

// probeDirectoryResponsive verifies that dir responds to a lightweight directory read
// (os.Open + Readdirnames(1)) within timeout, failing fast on frozen SMB/NFS mounts.
func probeDirectoryResponsive(dir string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = networkMountPreFlightTimeout
	}
	errCh := make(chan error, 1)
	go func() {
		// #nosec G304 G703
		f, err := os.Open(dir)
		if err != nil {
			errCh <- err
			return
		}
		_, rErr := f.Readdirnames(1)
		_ = f.Close()
		if rErr != nil && rErr != io.EOF {
			errCh <- rErr
			return
		}
		errCh <- nil
	}()
	select {
	case err := <-errCh:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("mount read probe timed out after %s (unresponsive network mount)", timeout)
	}
}

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
