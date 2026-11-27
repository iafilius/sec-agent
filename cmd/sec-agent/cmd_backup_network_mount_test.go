package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"secure_secrets/internal/store"
)

func TestNetworkFilesystemClassification(t *testing.T) {
	for _, fs := range []string{"smbfs", "SMBFS", "cifs", "nfs", "afpfs", "webdav"} {
		if !isNetworkFilesystemType(fs) {
			t.Errorf("expected %q to be classified as network filesystem", fs)
		}
	}
	for _, fs := range []string{"apfs", "exfat", "hfs", "ext4", ""} {
		if isNetworkFilesystemType(fs) {
			t.Errorf("expected %q NOT to be classified as network filesystem", fs)
		}
	}
	if !isSMBFilesystemType("smbfs") || !isSMBFilesystemType("cifs") || isSMBFilesystemType("nfs") {
		t.Errorf("unexpected SMB filesystem classification")
	}
}

func TestProbeDirectoryResponsive(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/hello.txt", []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := probeDirectoryResponsive(dir, 2*time.Second); err != nil {
		t.Fatalf("expected healthy directory probe to succeed, got: %v", err)
	}
	if err := probeDirectoryResponsive(dir+"/does-not-exist", 2*time.Second); err == nil {
		t.Fatalf("expected missing directory probe to fail, got nil")
	}
}

func TestApplyNetworkMountSafeguards(t *testing.T) {
	baseManifest := store.BackupManifest{
		Name:       store.BackupJobName("smb-job"),
		SSHTarget:  "backup@host",
		LocalBase:  "~",
		RemoteBase: "/Volumes/Backup",
		Folders:    []store.BackupFolderSpec{{Source: "share"}},
	}
	baseManifest.ApplyDefaults()
	baseFolder := baseManifest.Folders[0]

	// 1. Local APFS folder: untouched
	mAPFS, fAPFS, npAPFS, notesAPFS := applyNetworkMountSafeguards(baseManifest, baseFolder, "apfs", 0, false, false)
	if fAPFS.Timeout != 0 || npAPFS != 0 || len(notesAPFS) != 0 || len(fAPFS.Excludes) != 0 {
		t.Fatalf("expected APFS folder untouched, got timeout=%d np=%s notes=%v excludes=%v (m=%+v)", fAPFS.Timeout, npAPFS, notesAPFS, fAPFS.Excludes, mAPFS)
	}

	// 2. SMB folder with GNU rsync and unset timeouts: gets auto-excludes + 180s timeout + 15m watchdog
	mSMB, fSMB, npSMB, notesSMB := applyNetworkMountSafeguards(baseManifest, baseFolder, "smbfs", 0, false, false)
	if fSMB.Timeout != defaultNetworkMountRsyncTimeout {
		t.Errorf("expected SMB default rsync timeout %d, got %d", defaultNetworkMountRsyncTimeout, fSMB.Timeout)
	}
	if npSMB != defaultNetworkMountNoProgressTimeout {
		t.Errorf("expected SMB default no-progress timeout %s, got %s", defaultNetworkMountNoProgressTimeout, npSMB)
	}
	if mSMB.NoProgressTimeout != defaultNetworkMountNoProgressTimeout.String() {
		t.Errorf("expected manifest NoProgressTimeout updated for rsync --info flags, got %q", mSMB.NoProgressTimeout)
	}
	effExcl := strings.Join(fSMB.EffectiveExcludes(mSMB.Excludes), ",")
	for _, want := range []string{"$RECYCLE.BIN", "System Volume Information", "Thumbs.db", ".DS_Store", "._*"} {
		if !strings.Contains(effExcl, want) {
			t.Errorf("expected SMB EffectiveExcludes to contain %q, got %s", want, effExcl)
		}
	}
	if len(notesSMB) == 0 {
		t.Errorf("expected concise safeguard notes for SMB folder")
	}

	// 3. Explicit --no-progress-timeout 0 override is respected
	_, fDis, npDis, _ := applyNetworkMountSafeguards(baseManifest, baseFolder, "smbfs", 0, true, false)
	if npDis != 0 {
		t.Errorf("expected explicit --no-progress-timeout 0 to stay disabled, got %s", npDis)
	}
	if fDis.Timeout != defaultNetworkMountRsyncTimeout {
		t.Errorf("expected rsync timeout still defaulted to %d, got %d", defaultNetworkMountRsyncTimeout, fDis.Timeout)
	}

	// 4. openrsync gracefully applies --timeout=180 without enabling unsupported watchdog
	_, fOpen, npOpen, notesOpen := applyNetworkMountSafeguards(baseManifest, baseFolder, "smbfs", 0, false, true)
	if npOpen != 0 || fOpen.Timeout != defaultNetworkMountRsyncTimeout {
		t.Errorf("expected openrsync to skip watchdog (got %s) and apply timeout %d (got %d)", npOpen, defaultNetworkMountRsyncTimeout, fOpen.Timeout)
	}
	if !strings.Contains(strings.Join(notesOpen, " "), "openrsync") {
		t.Errorf("expected openrsync hint note, got %v", notesOpen)
	}
}
