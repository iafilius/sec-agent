package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
)

// Validation errors for backup manifests and job names.
var (
	ErrEmptyBackupJobName    = errors.New("backup job name cannot be empty")
	ErrInvalidBackupJobName  = errors.New("backup job name contains invalid characters")
	ErrInvalidBackupManifest = errors.New("invalid backup manifest")
)

const (
	DefaultRemoteRsyncBin = "/opt/homebrew/bin/rsync"
	DefaultModifyWindow   = 2
	DefaultPartialDir     = ".rsync-partial"
)

// DefaultBackupExcludes returns a fresh slice of default rsync exclude patterns.
func DefaultBackupExcludes() []string {
	return []string{".DS_Store", ".Trash*"}
}

// BackupJobName represents a strongly-typed backup job identifier.
type BackupJobName string

// NewBackupJobName creates and validates a new BackupJobName.
func NewBackupJobName(name string) (BackupJobName, error) {
	trimmed := BackupJobName(strings.TrimSpace(name))
	if err := trimmed.Validate(); err != nil {
		return "", err
	}
	return trimmed, nil
}

// String returns the underlying string value of BackupJobName.
func (n BackupJobName) String() string {
	return string(n)
}

// Validate checks whether the BackupJobName satisfies domain constraints.
func (n BackupJobName) Validate() error {
	s := strings.TrimSpace(string(n))
	if s == "" {
		return ErrEmptyBackupJobName
	}
	if strings.Contains(s, "/") || strings.Contains(s, "\\") || strings.Contains(s, "..") {
		return fmt.Errorf("%w: backup job name cannot contain path separators or '..'", ErrInvalidBackupJobName)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return ErrInvalidBackupJobName
		}
	}
	return nil
}

// VaultKey returns the canonical secret key under which this backup manifest is stored in the vault.
func (n BackupJobName) VaultKey() SecretKey {
	return SecretKey("backup/" + strings.TrimSpace(string(n)))
}

// BackupFolderSpec defines a single folder synchronization specification inside a BackupManifest.
type BackupFolderSpec struct {
	Source        string `json:"src"`
	Dest          string `json:"dest,omitempty"`
	HistoryPrefix string `json:"history_prefix,omitempty"`
	Slug          string `json:"slug,omitempty"`
}

// Validate checks that the folder specification has a valid, non-empty Source without path traversal or control characters.
func (f BackupFolderSpec) Validate() error {
	src := strings.TrimSpace(f.Source)
	if src == "" {
		return fmt.Errorf("%w: folder source cannot be empty", ErrInvalidBackupManifest)
	}
	for _, part := range strings.FieldsFunc(src, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return fmt.Errorf("%w: folder source cannot contain '..' path traversal", ErrInvalidBackupManifest)
		}
	}
	if strings.Contains(src, "..") {
		return fmt.Errorf("%w: folder source cannot contain '..' path traversal", ErrInvalidBackupManifest)
	}
	for _, r := range src {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: folder source contains control characters", ErrInvalidBackupManifest)
		}
	}
	return nil
}

// EffectiveDestName returns the destination directory name inside remoteBase.
func (f BackupFolderSpec) EffectiveDestName() string {
	if f.Dest != "" {
		return strings.Trim(f.Dest, "/")
	}
	return filepath.Base(strings.TrimRight(f.Source, "/"))
}

// DeriveHistoryPrefix returns HistoryPrefix if explicitly provided, or strips any trailing " - ..." suffix from EffectiveDestName().
func (f BackupFolderSpec) DeriveHistoryPrefix() string {
	if hp := strings.TrimSpace(f.HistoryPrefix); hp != "" {
		return hp
	}
	dest := f.EffectiveDestName()
	if idx := strings.Index(dest, " - "); idx != -1 {
		if prefix := strings.TrimSpace(dest[:idx]); prefix != "" {
			return prefix
		}
	}
	return dest
}

// DeriveSlug returns Slug if explicitly provided, or derives a lowercase alphanumeric-and-underscore slug from DeriveHistoryPrefix().
func (f BackupFolderSpec) DeriveSlug() string {
	if slug := strings.TrimSpace(f.Slug); slug != "" {
		return slug
	}
	raw := strings.ToLower(f.DeriveHistoryPrefix())
	var b strings.Builder
	prevUnderscore := false
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevUnderscore = false
		} else if !prevUnderscore {
			b.WriteByte('_')
			prevUnderscore = true
		}
	}
	slug := strings.Trim(b.String(), "_")
	if slug == "" {
		return "folder"
	}
	return slug
}

// ResolveLocalDir resolves the local directory path for this folder against localBase.
func (f BackupFolderSpec) ResolveLocalDir(localBase string) string {
	if filepath.IsAbs(f.Source) {
		return filepath.Clean(f.Source)
	}
	return filepath.Join(localBase, f.Source)
}

// DeriveRemoteDest returns the remote destination directory path (with trailing slash) inside remoteBase.
func (f BackupFolderSpec) DeriveRemoteDest(remoteBase string) string {
	return strings.TrimRight(remoteBase, "/") + "/" + f.EffectiveDestName() + "/"
}

// DeriveHistoryDir returns the remote history backup directory one level higher inside remoteBase.
func (f BackupFolderSpec) DeriveHistoryDir(remoteBase, dateStr string) string {
	return strings.TrimRight(remoteBase, "/") + "/" + f.DeriveHistoryPrefix() + "-History/" + dateStr
}

// DeriveRemoteLogPath returns the remote rsync log file path one level higher inside remoteBase.
func (f BackupFolderSpec) DeriveRemoteLogPath(remoteBase, datetimeStr string) string {
	return strings.TrimRight(remoteBase, "/") + "/rsync_" + f.DeriveSlug() + "_" + datetimeStr + ".log"
}

// BackupManifest defines a complete vault-stored backup job configuration.
type BackupManifest struct {
	Name           BackupJobName      `json:"name"`
	SSHTarget      string             `json:"ssh_target"`
	SSHKeySecret   string             `json:"ssh_key_secret,omitempty"`
	SSHPasswordKey string             `json:"ssh_password_key,omitempty"`
	SSHPort        int                `json:"ssh_port,omitempty"`
	LocalBase      string             `json:"local_base"`
	RemoteBase     string             `json:"remote_base"`
	RemoteRsyncBin string             `json:"remote_rsync_bin,omitempty"`
	ModifyWindow   int                `json:"modify_window,omitempty"`
	PartialDir     string             `json:"partial_dir,omitempty"`
	Excludes       []string           `json:"excludes,omitempty"`
	Folders        []BackupFolderSpec `json:"folders"`
}

// ApplyDefaults populates default rsync settings on the manifest when unset.
func (m *BackupManifest) ApplyDefaults() {
	if m == nil {
		return
	}
	if strings.TrimSpace(m.RemoteRsyncBin) == "" {
		m.RemoteRsyncBin = DefaultRemoteRsyncBin
	}
	if m.ModifyWindow == 0 {
		m.ModifyWindow = DefaultModifyWindow
	}
	if strings.TrimSpace(m.PartialDir) == "" {
		m.PartialDir = DefaultPartialDir
	}
	if len(m.Excludes) == 0 {
		m.Excludes = DefaultBackupExcludes()
	}
}

// Validate checks that the manifest has valid required fields and folder specifications.
func (m BackupManifest) Validate() error {
	if err := m.Name.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidBackupManifest, err)
	}
	if strings.TrimSpace(m.SSHTarget) == "" {
		return fmt.Errorf("%w: ssh_target cannot be empty", ErrInvalidBackupManifest)
	}
	if strings.TrimSpace(m.LocalBase) == "" {
		return fmt.Errorf("%w: local_base cannot be empty", ErrInvalidBackupManifest)
	}
	if strings.TrimSpace(m.RemoteBase) == "" {
		return fmt.Errorf("%w: remote_base cannot be empty", ErrInvalidBackupManifest)
	}
	for i, folder := range m.Folders {
		if err := folder.Validate(); err != nil {
			return fmt.Errorf("folder[%d]: %w", i, err)
		}
	}
	return nil
}
