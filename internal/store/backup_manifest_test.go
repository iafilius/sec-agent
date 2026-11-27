package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
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

func TestBackupManifestLegacyRsyncTimeoutAndSSHOptionsNormalization(t *testing.T) {
	rawJSON := `{
		"name": "example-batch",
		"ssh_target": "backupuser@10.0.0.50",
		"rsync_timeout": 300,
		"ssh_options": "-o ServerAliveInterval=45 -o ServerAliveCountMax=3",
		"jobs": [
			{
				"name": "example-home",
				"source": "~/",
				"dest": "/Volumes/MediaArchive/Backups/home-archive/",
				"backup_dir": "/Volumes/MediaArchive/Backups/home-archive-History/{date}",
				"log_file": "/Volumes/MediaArchive/Backups/rsync_home_archive_{datetime}.log",
				"rsync_timeout": 600,
				"ssh_options": "-o ServerAliveInterval=30 -o ServerAliveCountMax=4"
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

	if m.Timeout != 300 || m.ServerAliveInterval != 45 || m.ServerAliveCountMax != 3 {
		t.Errorf("expected manifest Timeout=300, ServerAliveInterval=45, ServerAliveCountMax=3, got %d/%d/%d", m.Timeout, m.ServerAliveInterval, m.ServerAliveCountMax)
	}
	if m.LegacyRsyncTimeout != 0 || m.LegacySSHOptions != "" {
		t.Errorf("expected manifest legacy fields cleared after ApplyDefaults(), got %d / %q", m.LegacyRsyncTimeout, m.LegacySSHOptions)
	}
	if len(m.Folders) != 1 {
		t.Fatalf("expected 1 folder migrated from jobs, got %d", len(m.Folders))
	}
	f := m.Folders[0]
	if f.Timeout != 600 || f.ServerAliveInterval != 30 || f.ServerAliveCountMax != 4 {
		t.Errorf("expected folder Timeout=600, ServerAliveInterval=30, ServerAliveCountMax=4, got %d/%d/%d", f.Timeout, f.ServerAliveInterval, f.ServerAliveCountMax)
	}
	if f.LegacyRsyncTimeout != 0 || f.LegacySSHOptions != "" {
		t.Errorf("expected folder legacy fields cleared after Normalize(), got %d / %q", f.LegacyRsyncTimeout, f.LegacySSHOptions)
	}
}

func TestBackupManifestNoProgressTimeout(t *testing.T) {
	t.Run("ParseNoProgressTimeout valid and disabled values", func(t *testing.T) {
		cases := []struct {
			raw  string
			want time.Duration
		}{
			{"", 0},
			{"   ", 0},
			{"0", 0},
			{"0s", 0},
			{"0m", 0},
			{"30m", 30 * time.Minute},
			{"15m30s", 15*time.Minute + 30*time.Second},
			{"600s", 600 * time.Second},
			{"1800", 1800 * time.Second},
			{" 900 ", 900 * time.Second},
		}
		for _, tc := range cases {
			got, err := ParseNoProgressTimeout(tc.raw)
			if err != nil {
				t.Errorf("ParseNoProgressTimeout(%q) unexpected error: %v", tc.raw, err)
				continue
			}
			if got != tc.want {
				t.Errorf("ParseNoProgressTimeout(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		}
	})

	t.Run("ParseNoProgressTimeout invalid and negative values", func(t *testing.T) {
		cases := []struct {
			raw        string
			wantSubstr string
		}{
			{"bogus", "invalid no_progress_timeout"},
			{"-5m", "cannot be negative"},
			{"-10", "cannot be negative"},
			{"-1s", "cannot be negative"},
		}
		for _, tc := range cases {
			_, err := ParseNoProgressTimeout(tc.raw)
			if err == nil {
				t.Errorf("ParseNoProgressTimeout(%q) expected error, got nil", tc.raw)
				continue
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("ParseNoProgressTimeout(%q) error = %q, want substring %q", tc.raw, err.Error(), tc.wantSubstr)
			}
		}
	})

	t.Run("JSON unmarshal string and number formats, defaults, and validation", func(t *testing.T) {
		basePrefix := `{"name":"home-nas","ssh_target":"backupuser@10.0.0.50","local_base":"/Users/backupuser","remote_base":"/Volumes/MediaArchive","folders":[{"src":"Photos"}]`

		// 1. Existing manifest without no_progress_timeout defaults to OFF (0)
		var mDefault BackupManifest
		if err := json.Unmarshal([]byte(basePrefix+`}`), &mDefault); err != nil {
			t.Fatalf("json.Unmarshal(default) failed: %v", err)
		}
		mDefault.ApplyDefaults()
		if mDefault.NoProgressTimeout != "" {
			t.Errorf("expected ApplyDefaults() to leave NoProgressTimeout empty, got %q", mDefault.NoProgressTimeout)
		}
		if err := mDefault.Validate(); err != nil {
			t.Fatalf("Validate() failed for manifest without no_progress_timeout: %v", err)
		}
		if got, err := mDefault.EffectiveNoProgressTimeout(); err != nil || got != 0 {
			t.Errorf("EffectiveNoProgressTimeout() = (%v, %v), want (0, nil)", got, err)
		}

		// 2. Valid JSON string and JSON number values
		validCases := []struct {
			name     string
			fieldVal string
			want     time.Duration
		}{
			{"empty string", `""`, 0},
			{"zero string", `"0"`, 0},
			{"zero seconds string", `"0s"`, 0},
			{"zero number", `0`, 0},
			{"null", `null`, 0},
			{"go duration 30m", `"30m"`, 30 * time.Minute},
			{"go duration 15m30s", `"15m30s"`, 15*time.Minute + 30*time.Second},
			{"go duration 600s", `"600s"`, 600 * time.Second},
			{"integer seconds string", `"1800"`, 1800 * time.Second},
			{"integer seconds number", `1800`, 1800 * time.Second},
		}
		for _, tc := range validCases {
			t.Run(tc.name, func(t *testing.T) {
				raw := basePrefix + `,"no_progress_timeout":` + tc.fieldVal + `}`
				var m BackupManifest
				if err := json.Unmarshal([]byte(raw), &m); err != nil {
					t.Fatalf("json.Unmarshal failed: %v", err)
				}
				m.ApplyDefaults()
				if err := m.Validate(); err != nil {
					t.Fatalf("Validate() failed: %v", err)
				}
				got, err := m.EffectiveNoProgressTimeout()
				if err != nil {
					t.Fatalf("EffectiveNoProgressTimeout() failed: %v", err)
				}
				if got != tc.want {
					t.Errorf("EffectiveNoProgressTimeout() = %v, want %v", got, tc.want)
				}
			})
		}

		// 3. Invalid or negative JSON values fail Validate() with ErrInvalidBackupManifest
		invalidValidationCases := []struct {
			name     string
			fieldVal string
		}{
			{"bogus string", `"bogus"`},
			{"negative duration string", `"-5m"`},
			{"negative integer string", `"-10"`},
			{"negative JSON number", `-5`},
		}
		for _, tc := range invalidValidationCases {
			t.Run(tc.name, func(t *testing.T) {
				raw := basePrefix + `,"no_progress_timeout":` + tc.fieldVal + `}`
				var m BackupManifest
				if err := json.Unmarshal([]byte(raw), &m); err != nil {
					t.Fatalf("expected json.Unmarshal to preserve raw value for Validate(), got error: %v", err)
				}
				err := m.Validate()
				if !errors.Is(err, ErrInvalidBackupManifest) {
					t.Errorf("Validate() error = %v, want ErrInvalidBackupManifest", err)
				}
			})
		}

		// 4. Non-string/non-integer JSON types fail json.Unmarshal
		for _, badVal := range []string{`true`, `{}`, `[]`, `12.5`} {
			raw := basePrefix + `,"no_progress_timeout":` + badVal + `}`
			var m BackupManifest
			if err := json.Unmarshal([]byte(raw), &m); err == nil {
				t.Errorf("expected json.Unmarshal error for no_progress_timeout=%s, got nil", badVal)
			}
		}
	})
}

func TestBackupManifestLocalTransportAndAdditiveExcludes(t *testing.T) {
	rawJSON := `{
		"name": "local-dev",
		"transport": "local",
		"local_base": "~",
		"dest_base": "/Volumes/ExternalBackup/DevBackups",
		"folders": [
			{"src": "personal"},
			{"src": "work", "excludes": ["archived-client/", ".DS_Store"]}
		]
	}`

	var m BackupManifest
	if err := json.Unmarshal([]byte(rawJSON), &m); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	m.ApplyDefaults()
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate() failed for valid local manifest: %v", err)
	}
	if m.EffectiveTransport() != BackupTransportLocal {
		t.Fatalf("expected transport=local, got %q", m.EffectiveTransport())
	}
	if m.RemoteBase != "/Volumes/ExternalBackup/DevBackups" {
		t.Fatalf("expected dest_base normalized into RemoteBase, got %q", m.RemoteBase)
	}

	// Verify additive excludes preserve job defaults (.DS_Store, .Trash*, ._*) AND deduplicate
	workExcludes := m.Folders[1].EffectiveExcludes(m.Excludes)
	want := []string{".DS_Store", ".Trash*", "._*", "archived-client/"}
	if len(workExcludes) != len(want) {
		t.Fatalf("expected additive excludes %v, got %v", want, workExcludes)
	}
	for i := range want {
		if workExcludes[i] != want[i] {
			t.Errorf("workExcludes[%d] = %q, want %q (all=%v)", i, workExcludes[i], want[i], workExcludes)
		}
	}

	// Invalid transport must fail validation
	bad := m
	bad.Transport = BackupTransport("ftp")
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected invalid transport 'ftp' to fail validation")
	}
}

func TestBackupManifestSSHPullTransportAndRemoteSource(t *testing.T) {
	rawJSON := `{
		"name": "remote-box",
		"transport": "ssh-pull",
		"ssh_target": "remote-linux",
		"source_base": "~",
		"dest_base": "/Volumes/ExternalBackup/RemoteBox",
		"folders": [
			{"src": "work"},
			{"src": "~/Projects 2026"},
			{"src": "/var/backups/db"}
		]
	}`

	var m BackupManifest
	if err := json.Unmarshal([]byte(rawJSON), &m); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	m.ApplyDefaults()
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate() failed for ssh-pull manifest: %v", err)
	}
	if m.EffectiveTransport() != BackupTransportSSHPull {
		t.Fatalf("expected transport=ssh-pull, got %q", m.EffectiveTransport())
	}
	if m.RemoteRsyncBin != "rsync" {
		t.Errorf("expected default RemoteRsyncBin='rsync' for ssh-pull, got %q", m.RemoteRsyncBin)
	}
	if m.LocalBase != "~" {
		t.Errorf("expected source_base preserved as '~', got %q", m.LocalBase)
	}
	if got := m.Folders[0].ResolveRemoteSource(m.LocalBase); got != "~/work/" {
		t.Errorf("ResolveRemoteSource(work) = %q, want ~/work/", got)
	}
	if got := m.Folders[1].ResolveRemoteSource(m.LocalBase); got != "~/Projects 2026/" {
		t.Errorf("ResolveRemoteSource(~/Projects 2026) = %q, want ~/Projects 2026/", got)
	}
	if got := m.Folders[2].ResolveRemoteSource(m.LocalBase); got != "/var/backups/db/" {
		t.Errorf("ResolveRemoteSource(/var/backups/db) = %q, want /var/backups/db/", got)
	}

	// Missing ssh_target must fail for ssh-pull
	bad := m
	bad.SSHTarget = ""
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected ssh-pull without ssh_target to fail validation")
	}
}
