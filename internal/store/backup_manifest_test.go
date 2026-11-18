package store

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestBackupManifestValidationAndDefaults(t *testing.T) {
	// 1. BackupJobName validation & VaultKey
	jobName, err := NewBackupJobName("  home-nas  ")
	if err != nil {
		t.Fatalf("expected valid BackupJobName, got error: %v", err)
	}
	if jobName.String() != "home-nas" {
		t.Fatalf("expected trimmed name 'home-nas', got %q", jobName.String())
	}
	if got := jobName.VaultKey(); got != SecretKey("backup/home-nas") {
		t.Fatalf("expected VaultKey 'backup/home-nas', got %q", got)
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
		LocalBase:  "/Users/backupuser/Media",
		RemoteBase: "/Volumes/MediaArchive/Backups",
		Folders: []BackupFolderSpec{
			{Source: "Photos - 2026"},
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
	if m.MaxAttempts != DefaultBackupMaxAttempts {
		t.Errorf("expected default MaxAttempts %d, got %d", DefaultBackupMaxAttempts, m.MaxAttempts)
	}
	// Timeout and ServerAlive* MUST remain 0 (unset) by default — never hardcoded!
	if m.Timeout != 0 || m.ServerAliveInterval != 0 || m.ServerAliveCountMax != 0 {
		t.Errorf("expected zero defaults for Timeout (%d), ServerAliveInterval (%d), ServerAliveCountMax (%d)", m.Timeout, m.ServerAliveInterval, m.ServerAliveCountMax)
	}
	if len(m.Excludes) != 3 || m.Excludes[0] != ".DS_Store" || m.Excludes[1] != ".Trash*" || m.Excludes[2] != "._*" {
		t.Errorf("expected default Excludes ['.DS_Store', '.Trash*', '._*'], got %v", m.Excludes)
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
				RemoteBase: "/Volumes/MediaArchive",
			},
		},
		{
			name: "empty ssh_target",
			manifest: BackupManifest{
				Name:       "home-nas",
				LocalBase:  "/Users/backupuser",
				RemoteBase: "/Volumes/MediaArchive",
			},
		},
		{
			name: "empty local_base",
			manifest: BackupManifest{
				Name:       "home-nas",
				SSHTarget:  "backupuser@10.0.0.50",
				RemoteBase: "/Volumes/MediaArchive",
			},
		},
		{
			name: "empty remote_base",
			manifest: BackupManifest{
				Name:      "home-nas",
				SSHTarget: "backupuser@10.0.0.50",
				LocalBase: "/Users/backupuser",
			},
		},
		{
			name: "folder with path traversal",
			manifest: BackupManifest{
				Name:       "home-nas",
				SSHTarget:  "backupuser@10.0.0.50",
				LocalBase:  "/Users/backupuser",
				RemoteBase: "/Volumes/MediaArchive",
				Folders:    []BackupFolderSpec{{Source: "../secrets"}},
			},
		},
		{
			name: "folder with empty source",
			manifest: BackupManifest{
				Name:       "home-nas",
				SSHTarget:  "backupuser@10.0.0.50",
				LocalBase:  "/Users/backupuser",
				RemoteBase: "/Volumes/MediaArchive",
				Folders:    []BackupFolderSpec{{Source: "   "}},
			},
		},
		{
			name: "negative timeout on manifest",
			manifest: BackupManifest{
				Name:       "home-nas",
				SSHTarget:  "backupuser@10.0.0.50",
				LocalBase:  "/Users/backupuser",
				RemoteBase: "/Volumes/MediaArchive",
				Timeout:    -10,
			},
		},
		{
			name: "negative server_alive_interval on folder",
			manifest: BackupManifest{
				Name:       "home-nas",
				SSHTarget:  "backupuser@10.0.0.50",
				LocalBase:  "/Users/backupuser",
				RemoteBase: "/Volumes/MediaArchive",
				Folders:    []BackupFolderSpec{{Source: "Photos", ServerAliveInterval: -5}},
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
	remoteBase := "/Volumes/MediaArchive/Backups"
	localBase := "/Users/backupuser/Media"
	dateStr := "2026-11-15"
	datetimeStr := "2026-11-15_1205"

	folder := BackupFolderSpec{
		Source: "Photos - 2026",
	}

	if got, want := folder.ResolveLocalDir(localBase), "/Users/backupuser/Media/Photos - 2026"; got != want {
		t.Errorf("ResolveLocalDir() = %q, want %q", got, want)
	}
	if got, want := folder.EffectiveDestName(), "Photos - 2026"; got != want {
		t.Errorf("EffectiveDestName() = %q, want %q", got, want)
	}
	if got, want := folder.DeriveHistoryPrefix(), "Photos"; got != want {
		t.Errorf("DeriveHistoryPrefix() = %q, want %q", got, want)
	}
	if got, want := folder.DeriveSlug(), "photos"; got != want {
		t.Errorf("DeriveSlug() = %q, want %q", got, want)
	}
	if got, want := folder.DeriveRemoteDest(remoteBase), "/Volumes/MediaArchive/Backups/Photos - 2026/"; got != want {
		t.Errorf("DeriveRemoteDest() = %q, want %q", got, want)
	}
	if got, want := folder.DeriveHistoryDir(remoteBase, dateStr), "/Volumes/MediaArchive/Backups/Photos-History/2026-11-15"; got != want {
		t.Errorf("DeriveHistoryDir() = %q, want %q", got, want)
	}
	if got, want := folder.DeriveRemoteLogPath(remoteBase, datetimeStr), "/Volumes/MediaArchive/Backups/rsync_photos_2026-11-15_1205.log"; got != want {
		t.Errorf("DeriveRemoteLogPath() = %q, want %q", got, want)
	}

	// Verify explicit overrides and absolute Source handling
	overrideFolder := BackupFolderSpec{
		Source:        "/Users/backupuser/Documents/Media Library",
		Dest:          "Media Library - Archive",
		HistoryPrefix: "MediaCustom",
		Slug:          "media_custom",
	}
	if got, want := overrideFolder.ResolveLocalDir(localBase), "/Users/backupuser/Documents/Media Library"; got != want {
		t.Errorf("ResolveLocalDir(abs) = %q, want %q", got, want)
	}
	if got, want := overrideFolder.DeriveRemoteDest(remoteBase+"/"), "/Volumes/MediaArchive/Backups/Media Library - Archive/"; got != want {
		t.Errorf("DeriveRemoteDest(override) = %q, want %q", got, want)
	}
	if got, want := overrideFolder.DeriveHistoryDir(remoteBase+"/", dateStr), "/Volumes/MediaArchive/Backups/MediaCustom-History/2026-11-15"; got != want {
		t.Errorf("DeriveHistoryDir(override) = %q, want %q", got, want)
	}
	if got, want := overrideFolder.DeriveRemoteLogPath(remoteBase+"/", datetimeStr), "/Volumes/MediaArchive/Backups/rsync_media_custom_2026-11-15_1205.log"; got != want {
		t.Errorf("DeriveRemoteLogPath(override) = %q, want %q", got, want)
	}

	// Verify home directory ("~/" and "~") source with custom Dest ("home-archive")
	homeFolder := BackupFolderSpec{
		Source:              "~/",
		Dest:                "home-archive",
		Timeout:             180,
		ServerAliveInterval: 30,
		ServerAliveCountMax: 4,
	}
	if got, want := homeFolder.ResolveLocalDir("/Users/backupuser"), "/Users/backupuser"; got != want {
		t.Errorf("ResolveLocalDir(~/)= %q, want %q", got, want)
	}
	if got, want := homeFolder.DeriveRemoteDest(remoteBase), "/Volumes/MediaArchive/Backups/home-archive/"; got != want {
		t.Errorf("DeriveRemoteDest(home-archive) = %q, want %q", got, want)
	}
	if got, want := homeFolder.DeriveHistoryDir(remoteBase, dateStr), "/Volumes/MediaArchive/Backups/home-archive-History/2026-11-15"; got != want {
		t.Errorf("DeriveHistoryDir(home-archive) = %q, want %q", got, want)
	}
	if got, want := homeFolder.DeriveRemoteLogPath(remoteBase, datetimeStr), "/Volumes/MediaArchive/Backups/rsync_home_archive_2026-11-15_1205.log"; got != want {
		t.Errorf("DeriveRemoteLogPath(home-archive) = %q, want %q", got, want)
	}
	if got := homeFolder.EffectiveTimeout(60); got != 180 {
		t.Errorf("EffectiveTimeout(override) = %d, want 180", got)
	}
	if got := (BackupFolderSpec{Source: "Music"}).EffectiveTimeout(60); got != 60 {
		t.Errorf("EffectiveTimeout(manifest fallback) = %d, want 60", got)
	}
	if got := (BackupFolderSpec{Source: "Music"}).EffectiveServerAliveInterval(0, 30); got != 30 {
		t.Errorf("EffectiveServerAliveInterval(target fallback) = %d, want 30", got)
	}
	if got := (BackupFolderSpec{Source: "Music"}).EffectiveServerAliveCountMax(0, 4); got != 4 {
		t.Errorf("EffectiveServerAliveCountMax(target fallback) = %d, want 4", got)
	}
}

func TestBackupFolderSpecTemplateOverridesAndSparse(t *testing.T) {
	rawJSON := `{
		"name": "media-batch",
		"ssh_target": "backupuser@10.0.0.50",
		"timeout": 120,
		"server_alive_interval": 30,
		"server_alive_count_max": 4,
		"jobs": [
			{
				"name": "photos-library",
				"source": "~/Photos - 2026",
				"dest": "/Volumes/MediaArchive/Backups/Photos - 2026/",
				"backup_dir": "/Volumes/MediaArchive/Backups/Photos-History/{date}",
				"log_file": "/Volumes/MediaArchive/Backups/rsync_photos_{datetime}.log",
				"sparse": true,
				"excludes": [".DS_Store", "*.tmp"]
			}
		]
	}`

	var m BackupManifest
	if err := json.Unmarshal([]byte(rawJSON), &m); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	m.ApplyDefaults()
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate() after ApplyDefaults failed: %v", err)
	}

	if m.MaxAttempts != 5 {
		t.Errorf("expected MaxAttempts = 5, got %d", m.MaxAttempts)
	}
	if m.Timeout != 120 || m.ServerAliveInterval != 30 || m.ServerAliveCountMax != 4 {
		t.Errorf("expected Timeout=120, ServerAliveInterval=30, ServerAliveCountMax=4, got %d/%d/%d", m.Timeout, m.ServerAliveInterval, m.ServerAliveCountMax)
	}
	if len(m.Folders) != 1 {
		t.Fatalf("expected 1 folder migrated from jobs, got %d", len(m.Folders))
	}
	f := m.Folders[0]
	if f.Source != "~/Photos - 2026" {
		t.Errorf("expected Source '~/Photos - 2026', got %q", f.Source)
	}
	if !f.Sparse {
		t.Errorf("expected Sparse = true")
	}
	if got, want := f.DeriveRemoteDest(m.RemoteBase), "/Volumes/MediaArchive/Backups/Photos - 2026/"; got != want {
		t.Errorf("DeriveRemoteDest() = %q, want %q", got, want)
	}
	if got, want := f.DeriveHistoryDir(m.RemoteBase, "2026-11-16"), "/Volumes/MediaArchive/Backups/Photos-History/2026-11-16"; got != want {
		t.Errorf("DeriveHistoryDir() = %q, want %q", got, want)
	}
	if got, want := f.DeriveRemoteLogPath(m.RemoteBase, "2026-11-16_1905"), "/Volumes/MediaArchive/Backups/rsync_photos_2026-11-16_1905.log"; got != want {
		t.Errorf("DeriveRemoteLogPath() = %q, want %q", got, want)
	}
	excludes := f.EffectiveExcludes(m.Excludes)
	foundAppleDouble := false
	for _, ex := range excludes {
		if ex == "._*" {
			foundAppleDouble = true
			break
		}
	}
	if !foundAppleDouble {
		t.Errorf("expected EffectiveExcludes to include '._*', got %v", excludes)
	}
}
