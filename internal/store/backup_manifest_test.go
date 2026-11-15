package store

import (
	"errors"
	"testing"
)

func TestBackupManifestValidationAndDefaults(t *testing.T) {
	// 1. BackupJobName validation & VaultKey
	jobName, err := NewBackupJobName("  work-sync  ")
	if err != nil {
		t.Fatalf("expected valid BackupJobName, got error: %v", err)
	}
	if jobName.String() != "work-sync" {
		t.Fatalf("expected trimmed name 'work-sync', got %q", jobName.String())
	}
	if got := jobName.VaultKey(); got != SecretKey("backup/work-sync") {
		t.Fatalf("expected VaultKey 'backup/work-sync', got %q", got)
	}

	if _, err := NewBackupJobName("   "); !errors.Is(err, ErrEmptyBackupJobName) {
		t.Fatalf("expected ErrEmptyBackupJobName for empty job name, got: %v", err)
	}

	invalidNames := []string{
		"bad/name",
		"bad\\name",
		"bad..name",
		"bad name",
		"bad\tname",
		"bad\nname",
	}
	for _, bad := range invalidNames {
		if _, err := NewBackupJobName(bad); !errors.Is(err, ErrInvalidBackupJobName) {
			t.Errorf("NewBackupJobName(%q): expected ErrInvalidBackupJobName, got %v", bad, err)
		}
	}

	// 2. ApplyDefaults and Validate on a valid BackupManifest
	m := BackupManifest{
		Name:       jobName,
		SSHTarget:  "backupuser@10.0.0.50",
		LocalBase:  "/Users/backupuser/CloudStorage",
		RemoteBase: "/Volumes/BackupDrive/Work",
		Folders: []BackupFolderSpec{
			{Source: "CloudFolder - Work"},
		},
	}
	m.ApplyDefaults()

	if m.RemoteRsyncBin != "/opt/homebrew/bin/rsync" {
		t.Errorf("expected default RemoteRsyncBin '/opt/homebrew/bin/rsync', got %q", m.RemoteRsyncBin)
	}
	if m.ModifyWindow != 2 {
		t.Errorf("expected default ModifyWindow 2, got %d", m.ModifyWindow)
	}
	if m.PartialDir != ".rsync-partial" {
		t.Errorf("expected default PartialDir '.rsync-partial', got %q", m.PartialDir)
	}
	if len(m.Excludes) != 2 || m.Excludes[0] != ".DS_Store" || m.Excludes[1] != ".Trash*" {
		t.Errorf("expected default Excludes ['.DS_Store', '.Trash*'], got %v", m.Excludes)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("expected valid manifest to pass Validate(), got: %v", err)
	}

	// 3. Invalid manifest scenarios
	invalidManifests := []struct {
		name     string
		manifest BackupManifest
	}{
		{
			name: "empty job name",
			manifest: BackupManifest{
				SSHTarget:  "backupuser@10.0.0.50",
				LocalBase:  "/Users/backupuser",
				RemoteBase: "/Volumes/BackupDrive",
			},
		},
		{
			name: "empty ssh_target",
			manifest: BackupManifest{
				Name:       "work",
				LocalBase:  "/Users/backupuser",
				RemoteBase: "/Volumes/BackupDrive",
			},
		},
		{
			name: "empty local_base",
			manifest: BackupManifest{
				Name:       "work",
				SSHTarget:  "backupuser@10.0.0.50",
				RemoteBase: "/Volumes/BackupDrive",
			},
		},
		{
			name: "empty remote_base",
			manifest: BackupManifest{
				Name:      "work",
				SSHTarget: "backupuser@10.0.0.50",
				LocalBase: "/Users/backupuser",
			},
		},
		{
			name: "folder with path traversal",
			manifest: BackupManifest{
				Name:       "work",
				SSHTarget:  "backupuser@10.0.0.50",
				LocalBase:  "/Users/backupuser",
				RemoteBase: "/Volumes/BackupDrive",
				Folders:    []BackupFolderSpec{{Source: "../secrets"}},
			},
		},
		{
			name: "folder with empty source",
			manifest: BackupManifest{
				Name:       "work",
				SSHTarget:  "backupuser@10.0.0.50",
				LocalBase:  "/Users/backupuser",
				RemoteBase: "/Volumes/BackupDrive",
				Folders:    []BackupFolderSpec{{Source: "   "}},
			},
		},
	}

	for _, tc := range invalidManifests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.manifest.Validate()
			if !errors.Is(err, ErrInvalidBackupManifest) {
				t.Errorf("expected ErrInvalidBackupManifest for %s, got: %v", tc.name, err)
			}
		})
	}
}

func TestBackupFolderSpecOneLevelHigherDerivation(t *testing.T) {
	remoteBase := "/Volumes/BackupDrive/Work"
	localBase := "/Users/backupuser/CloudStorage"
	dateStr := "2026-11-15"
	datetimeStr := "2026-11-15_1205"

	folder := BackupFolderSpec{
		Source: "CloudFolder - Work",
	}

	if got, want := folder.ResolveLocalDir(localBase), "/Users/backupuser/CloudStorage/CloudFolder - Work"; got != want {
		t.Errorf("ResolveLocalDir() = %q, want %q", got, want)
	}
	if got, want := folder.EffectiveDestName(), "CloudFolder - Work"; got != want {
		t.Errorf("EffectiveDestName() = %q, want %q", got, want)
	}
	if got, want := folder.DeriveHistoryPrefix(), "CloudFolder"; got != want {
		t.Errorf("DeriveHistoryPrefix() = %q, want %q", got, want)
	}
	if got, want := folder.DeriveSlug(), "clouddrive"; false {
		_ = got
		_ = want
	}
	if got, want := folder.DeriveSlug(), "cloudfolder"; got != want {
		t.Errorf("DeriveSlug() = %q, want %q", got, want)
	}
	if got, want := folder.DeriveRemoteDest(remoteBase), "/Volumes/BackupDrive/Work/CloudFolder - Work/"; got != want {
		t.Errorf("DeriveRemoteDest() = %q, want %q", got, want)
	}
	if got, want := folder.DeriveHistoryDir(remoteBase, dateStr), "/Volumes/BackupDrive/Work/CloudFolder-History/2026-11-15"; got != want {
		t.Errorf("DeriveHistoryDir() = %q, want %q", got, want)
	}
	if got, want := folder.DeriveRemoteLogPath(remoteBase, datetimeStr), "/Volumes/BackupDrive/Work/rsync_cloudfolder_2026-11-15_1205.log"; got != want {
		t.Errorf("DeriveRemoteLogPath() = %q, want %q", got, want)
	}

	// Verify explicit overrides and absolute Source handling
	overrideFolder := BackupFolderSpec{
		Source:        "/Users/backupuser/Documents/Work Projects",
		Dest:          "Work Projects - Archive",
		HistoryPrefix: "WorkCustom",
		Slug:          "work_custom",
	}
	if got, want := overrideFolder.ResolveLocalDir(localBase), "/Users/backupuser/Documents/Work Projects"; got != want {
		t.Errorf("ResolveLocalDir(abs) = %q, want %q", got, want)
	}
	if got, want := overrideFolder.DeriveRemoteDest(remoteBase+"/"), "/Volumes/BackupDrive/Work/Work Projects - Archive/"; got != want {
		t.Errorf("DeriveRemoteDest(override) = %q, want %q", got, want)
	}
	if got, want := overrideFolder.DeriveHistoryDir(remoteBase+"/", dateStr), "/Volumes/BackupDrive/Work/WorkCustom-History/2026-11-15"; got != want {
		t.Errorf("DeriveHistoryDir(override) = %q, want %q", got, want)
	}
	if got, want := overrideFolder.DeriveRemoteLogPath(remoteBase+"/", datetimeStr), "/Volumes/BackupDrive/Work/rsync_work_custom_2026-11-15_1205.log"; got != want {
		t.Errorf("DeriveRemoteLogPath(override) = %q, want %q", got, want)
	}
}
