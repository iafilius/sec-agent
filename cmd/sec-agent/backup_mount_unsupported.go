//go:build !darwin

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultNetworkMountRsyncTimeout      = 180
	defaultNetworkMountNoProgressTimeout = 15 * time.Minute
	networkMountPreFlightTimeout         = 5 * time.Second
	networkMountPostStallTimeout         = 3 * time.Second
)

var smbAutoExcludes = []string{"$RECYCLE.BIN", "System Volume Information", "Thumbs.db"}

func detectFilesystemType(path string) string {
	_ = path
	return ""
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
