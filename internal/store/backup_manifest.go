package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Validation errors for backup manifests and job names.
var (
	ErrEmptyBackupJobName    = errors.New("backup job name cannot be empty")
	ErrInvalidBackupJobName  = errors.New("backup job name contains invalid characters")
	ErrInvalidBackupManifest = errors.New("invalid backup manifest")
)

const (
	DefaultRemoteRsyncBin    = "/opt/homebrew/bin/rsync"
	DefaultModifyWindow      = 2
	DefaultPartialDir        = ".rsync-partial"
	DefaultBackupMaxAttempts = 5
)

// DefaultBackupExcludes returns a fresh slice of default rsync exclude patterns,
// including macOS Finder metadata (.DS_Store), trash folders (.Trash*), and AppleDouble files (._*).
func DefaultBackupExcludes() []string {
	return []string{".DS_Store", ".Trash*", "._*"}
}

func ensureAppleDoubleExclude(patterns []string) []string {
	out := make([]string, 0, len(patterns)+1)
	hasAppleDouble := false
	for _, p := range patterns {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		if trimmed == "._*" {
			hasAppleDouble = true
		}
		out = append(out, trimmed)
	}
	if !hasAppleDouble {
		out = append(out, "._*")
	}
	return out
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
	Name                string   `json:"name,omitempty"`
	Source              string   `json:"src"`
	LegacySource        string   `json:"source,omitempty"`
	Dest                string   `json:"dest,omitempty"`
	HistoryPrefix       string   `json:"history_prefix,omitempty"`
	Slug                string   `json:"slug,omitempty"`
	Sparse              bool     `json:"sparse,omitempty"`
	BackupDir           string   `json:"backup_dir,omitempty"`
	LogFile             string   `json:"log_file,omitempty"`
	Timeout             int      `json:"timeout,omitempty"`
	LegacyRsyncTimeout  int      `json:"rsync_timeout,omitempty"`
	ServerAliveInterval int      `json:"server_alive_interval,omitempty"`
	ServerAliveCountMax int      `json:"server_alive_count_max,omitempty"`
	LegacySSHOptions    string   `json:"ssh_options,omitempty"`
	Excludes            []string `json:"excludes,omitempty"`
}

// parseSSHAliveOptions extracts ServerAliveInterval and ServerAliveCountMax integer values
// from an OpenSSH options string (such as "-o ServerAliveInterval=30 -o ServerAliveCountMax=4").
func parseSSHAliveOptions(sshOpts string) (interval int, countMax int) {
	fields := strings.Fields(sshOpts)
	for i := 0; i < len(fields); i++ {
		tok := strings.TrimSpace(fields[i])
		if tok == "-o" && i+1 < len(fields) {
			i++
			tok = strings.TrimSpace(fields[i])
		} else if strings.HasPrefix(tok, "-o") && len(tok) > 2 {
			tok = strings.TrimSpace(tok[2:])
		}
		lower := strings.ToLower(tok)
		if strings.HasPrefix(lower, "serveraliveinterval=") {
			valStr := strings.TrimSpace(tok[len("serveraliveinterval="):])
			if v, err := strconv.Atoi(valStr); err == nil && v > 0 {
				interval = v
			}
		} else if strings.HasPrefix(lower, "serveralivecountmax=") {
			valStr := strings.TrimSpace(tok[len("serveralivecountmax="):])
			if v, err := strconv.Atoi(valStr); err == nil && v > 0 {
				countMax = v
			}
		}
	}
	return interval, countMax
}

// Normalize migrates legacy JSON fields (such as "source", "rsync_timeout", and "ssh_options") into canonical fields.
func (f *BackupFolderSpec) Normalize() {
	if f == nil {
		return
	}
	if strings.TrimSpace(f.Source) == "" && strings.TrimSpace(f.LegacySource) != "" {
		f.Source = strings.TrimSpace(f.LegacySource)
	}
	f.LegacySource = ""
	if f.Timeout == 0 && f.LegacyRsyncTimeout > 0 {
		f.Timeout = f.LegacyRsyncTimeout
	}
	f.LegacyRsyncTimeout = 0
	if strings.TrimSpace(f.LegacySSHOptions) != "" {
		sai, sac := parseSSHAliveOptions(f.LegacySSHOptions)
		if f.ServerAliveInterval == 0 && sai > 0 {
			f.ServerAliveInterval = sai
		}
		if f.ServerAliveCountMax == 0 && sac > 0 {
			f.ServerAliveCountMax = sac
		}
		f.LegacySSHOptions = ""
	}
}

// Validate checks that the folder specification has a valid, non-empty Source without path traversal or control characters.
func (f BackupFolderSpec) Validate() error {
	src := strings.TrimSpace(f.Source)
	if src == "" {
		src = strings.TrimSpace(f.LegacySource)
	}
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
	if f.Timeout < 0 || f.ServerAliveInterval < 0 || f.ServerAliveCountMax < 0 {
		return fmt.Errorf("%w: timeout and server_alive_* cannot be negative", ErrInvalidBackupManifest)
	}
	return nil
}

// EffectiveDestName returns the destination directory name inside remoteBase.
func (f BackupFolderSpec) EffectiveDestName() string {
	if f.Dest != "" {
		return strings.Trim(f.Dest, "/")
	}
	src := strings.TrimSpace(f.Source)
	if src == "" {
		src = strings.TrimSpace(f.LegacySource)
	}
	if src == "~" || src == "~/" || src == "." || src == "./" {
		return "home-backup"
	}
	return filepath.Base(strings.TrimRight(src, "/"))
}

// EffectiveTimeout returns the folder-level rsync timeout if > 0, falling back to manifestTimeout, or 0 if unset.
func (f BackupFolderSpec) EffectiveTimeout(manifestTimeout int) int {
	if f.Timeout > 0 {
		return f.Timeout
	}
	if manifestTimeout > 0 {
		return manifestTimeout
	}
	return 0
}

// EffectiveServerAliveInterval returns the folder-level SSH keepalive interval if > 0,
// falling back to manifestInterval or targetInterval, or 0 if unset.
func (f BackupFolderSpec) EffectiveServerAliveInterval(manifestInterval, targetInterval int) int {
	if f.ServerAliveInterval > 0 {
		return f.ServerAliveInterval
	}
	if manifestInterval > 0 {
		return manifestInterval
	}
	if targetInterval > 0 {
		return targetInterval
	}
	return 0
}

// EffectiveServerAliveCountMax returns the folder-level SSH keepalive count max if > 0,
// falling back to manifestCountMax or targetCountMax, or 0 if unset.
func (f BackupFolderSpec) EffectiveServerAliveCountMax(manifestCountMax, targetCountMax int) int {
	if f.ServerAliveCountMax > 0 {
		return f.ServerAliveCountMax
	}
	if manifestCountMax > 0 {
		return manifestCountMax
	}
	if targetCountMax > 0 {
		return targetCountMax
	}
	return 0
}

// DeriveHistoryPrefix returns HistoryPrefix if explicitly provided, or strips any trailing " - ..." suffix from EffectiveDestName().
func (f BackupFolderSpec) DeriveHistoryPrefix() string {
	if hp := strings.TrimSpace(f.HistoryPrefix); hp != "" {
		return hp
	}
	dest := filepath.Base(f.EffectiveDestName())
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
	src := strings.TrimSpace(f.Source)
	if src == "" {
		src = strings.TrimSpace(f.LegacySource)
	}
	if src == "~" || src == "~/" || src == "." || src == "./" {
		return filepath.Clean(localBase)
	}
	if strings.HasPrefix(src, "~/") {
		if strings.TrimSpace(localBase) == "" || localBase == "~" {
			return src
		}
		return filepath.Join(localBase, strings.TrimPrefix(src, "~/"))
	}
	if filepath.IsAbs(src) {
		return filepath.Clean(src)
	}
	return filepath.Join(localBase, src)
}

func expandDatePlaceholders(s, dateStr, datetimeStr string) string {
	if dateStr == "" && len(datetimeStr) >= 10 {
		dateStr = strings.SplitN(datetimeStr, "_", 2)[0]
	}
	if datetimeStr == "" {
		datetimeStr = dateStr
	}
	out := strings.ReplaceAll(s, "{datetime}", datetimeStr)
	out = strings.ReplaceAll(out, "{date}", dateStr)
	return out
}

// ResolveRemoteSource resolves the remote source directory path (with trailing slash)
// against sourceBase without expanding '~' against the local workstation's $HOME.
func (f BackupFolderSpec) ResolveRemoteSource(sourceBase string) string {
	src := strings.TrimSpace(f.Source)
	if src == "" {
		src = strings.TrimSpace(f.LegacySource)
	}
	base := strings.TrimSpace(sourceBase)
	if base == "" {
		base = "~"
	}
	var resolved string
	switch {
	case src == "~" || src == "~/" || src == "." || src == "./":
		resolved = base
	case strings.HasPrefix(src, "~/") || strings.HasPrefix(src, "/"):
		resolved = src
	default:
		resolved = strings.TrimRight(base, "/") + "/" + strings.TrimLeft(src, "/")
	}
	return strings.TrimRight(resolved, "/") + "/"
}

// DeriveRemoteDest returns the remote destination directory path (with trailing slash) inside remoteBase.
func (f BackupFolderSpec) DeriveRemoteDest(remoteBase string) string {
	dest := strings.TrimSpace(f.Dest)
	if strings.HasPrefix(dest, "/") {
		return strings.TrimRight(dest, "/") + "/"
	}
	return strings.TrimRight(remoteBase, "/") + "/" + f.EffectiveDestName() + "/"
}

// DeriveHistoryDir returns the remote history backup directory (either from a custom BackupDir template
// or one level higher inside remoteBase).
func (f BackupFolderSpec) DeriveHistoryDir(remoteBase, dateStr string) string {
	if custom := strings.TrimSpace(f.BackupDir); custom != "" {
		expanded := expandDatePlaceholders(custom, dateStr, dateStr)
		if strings.HasPrefix(expanded, "/") {
			return strings.TrimRight(expanded, "/")
		}
		return strings.TrimRight(remoteBase, "/") + "/" + strings.Trim(expanded, "/")
	}
	return strings.TrimRight(remoteBase, "/") + "/" + f.DeriveHistoryPrefix() + "-History/" + dateStr
}

// DeriveRemoteLogPath returns the remote rsync log file path (either from a custom LogFile template
// or one level higher inside remoteBase).
func (f BackupFolderSpec) DeriveRemoteLogPath(remoteBase, datetimeStr string) string {
	if custom := strings.TrimSpace(f.LogFile); custom != "" {
		datePart := strings.SplitN(datetimeStr, "_", 2)[0]
		expanded := expandDatePlaceholders(custom, datePart, datetimeStr)
		if strings.HasPrefix(expanded, "/") {
			return expanded
		}
		return strings.TrimRight(remoteBase, "/") + "/" + strings.TrimLeft(expanded, "/")
	}
	return strings.TrimRight(remoteBase, "/") + "/rsync_" + f.DeriveSlug() + "_" + datetimeStr + ".log"
}

// BackupTransport identifies how a backup job transfers files ("ssh", "ssh-pull", or "local").
type BackupTransport string

const (
	BackupTransportSSH     BackupTransport = "ssh"
	BackupTransportSSHPull BackupTransport = "ssh-pull"
	BackupTransportLocal   BackupTransport = "local"
)

// Validate checks that the transport is either empty (defaulting to "ssh"), "ssh", "ssh-pull", or "local".
func (t BackupTransport) Validate() error {
	switch strings.ToLower(strings.TrimSpace(string(t))) {
	case "", string(BackupTransportSSH), string(BackupTransportSSHPull), string(BackupTransportLocal):
		return nil
	default:
		return fmt.Errorf("%w: unsupported transport %q (expected %q, %q, or %q)", ErrInvalidBackupManifest, t, BackupTransportSSH, BackupTransportSSHPull, BackupTransportLocal)
	}
}

// EffectiveExcludes merges job-level excludes (or default excludes when empty) with
// folder-specific excludes in order, deduplicating exact matches and always ensuring
// macOS AppleDouble files ("._*") are excluded.
func (f BackupFolderSpec) EffectiveExcludes(manifestExcludes []string) []string {
	base := manifestExcludes
	if len(base) == 0 {
		base = DefaultBackupExcludes()
	}
	merged := make([]string, 0, len(base)+len(f.Excludes)+1)
	seen := make(map[string]bool, len(base)+len(f.Excludes)+1)
	for _, list := range [][]string{base, f.Excludes} {
		for _, p := range list {
			trimmed := strings.TrimSpace(p)
			if trimmed == "" || seen[trimmed] {
				continue
			}
			seen[trimmed] = true
			merged = append(merged, trimmed)
		}
	}
	return ensureAppleDoubleExclude(merged)
}

// BackupManifest defines a complete vault-stored backup job configuration.
type BackupManifest struct {
	Name                BackupJobName      `json:"name"`
	Transport           BackupTransport    `json:"transport,omitempty"`
	SSHTarget           string             `json:"ssh_target,omitempty"`
	SSHKeySecret        string             `json:"ssh_key_secret,omitempty"`
	SSHPasswordKey      string             `json:"ssh_password_key,omitempty"`
	SSHPort             int                `json:"ssh_port,omitempty"`
	LocalBase           string             `json:"local_base"`
	SourceBase          string             `json:"source_base,omitempty"`
	RemoteBase          string             `json:"remote_base"`
	DestBase            string             `json:"dest_base,omitempty"`
	RemoteRsyncBin      string             `json:"remote_rsync_bin,omitempty"`
	ModifyWindow        int                `json:"modify_window,omitempty"`
	PartialDir          string             `json:"partial_dir,omitempty"`
	MaxAttempts         int                `json:"max_attempts,omitempty"`
	Timeout             int                `json:"timeout,omitempty"`
	NoProgressTimeout   string             `json:"no_progress_timeout,omitempty"`
	LegacyRsyncTimeout  int                `json:"rsync_timeout,omitempty"`
	ServerAliveInterval int                `json:"server_alive_interval,omitempty"`
	ServerAliveCountMax int                `json:"server_alive_count_max,omitempty"`
	LegacySSHOptions    string             `json:"ssh_options,omitempty"`
	Excludes            []string           `json:"excludes,omitempty"`
	Folders             []BackupFolderSpec `json:"folders"`
	LegacyJobs          []BackupFolderSpec `json:"jobs,omitempty"`
}

// EffectiveTransport returns the normalized transport for this manifest ("ssh" by default).
func (m BackupManifest) EffectiveTransport() BackupTransport {
	switch strings.ToLower(strings.TrimSpace(string(m.Transport))) {
	case string(BackupTransportLocal):
		return BackupTransportLocal
	case string(BackupTransportSSHPull):
		return BackupTransportSSHPull
	default:
		return BackupTransportSSH
	}
}

// UnmarshalJSON decodes a BackupManifest while accepting no_progress_timeout as either
// a JSON string (e.g. "30m", "900s", "1800", "0", "") or a JSON integer number of seconds
// (e.g. 1800, 0, -5), preserving the raw value for Validate() to enforce domain constraints.
func (m *BackupManifest) UnmarshalJSON(data []byte) error {
	type alias BackupManifest
	aux := struct {
		*alias
		NoProgressTimeout json.RawMessage `json:"no_progress_timeout,omitempty"`
	}{
		alias: (*alias)(m),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	raw := strings.TrimSpace(string(aux.NoProgressTimeout))
	if raw == "" || raw == "null" {
		m.NoProgressTimeout = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(aux.NoProgressTimeout, &s); err == nil {
		m.NoProgressTimeout = s
		return nil
	}
	var n int64
	if err := json.Unmarshal(aux.NoProgressTimeout, &n); err == nil {
		m.NoProgressTimeout = strconv.FormatInt(n, 10)
		return nil
	}
	return fmt.Errorf("invalid no_progress_timeout: expected duration string or integer seconds, got %s", raw)
}

// ParseNoProgressTimeout parses a manifest or CLI no-progress watchdog timeout string.
// Empty string, "0", or "0s" (and other zero durations) return 0, nil (watchdog disabled).
// Plain integer strings are interpreted as seconds; otherwise Go time.ParseDuration syntax is used.
func ParseNoProgressTimeout(raw string) (time.Duration, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "0" || trimmed == "0s" {
		return 0, nil
	}
	if secs, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		if secs < 0 {
			return 0, fmt.Errorf("no_progress_timeout cannot be negative: %q", trimmed)
		}
		if secs == 0 {
			return 0, nil
		}
		if secs > math.MaxInt64/int64(time.Second) {
			return 0, fmt.Errorf("invalid no_progress_timeout %q: duration overflow", trimmed)
		}
		return time.Duration(secs) * time.Second, nil
	}
	d, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, fmt.Errorf("invalid no_progress_timeout %q: %w", trimmed, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("no_progress_timeout cannot be negative: %q", trimmed)
	}
	if d == 0 {
		return 0, nil
	}
	return d, nil
}

// EffectiveNoProgressTimeout returns the parsed no-progress watchdog timeout duration (0 means disabled).
func (m BackupManifest) EffectiveNoProgressTimeout() (time.Duration, error) {
	return ParseNoProgressTimeout(m.NoProgressTimeout)
}

// ApplyDefaults populates default rsync settings on the manifest when unset.
func (m *BackupManifest) ApplyDefaults() {
	if m == nil {
		return
	}
	if strings.TrimSpace(string(m.Transport)) == "" {
		m.Transport = BackupTransportSSH
	} else {
		m.Transport = BackupTransport(strings.ToLower(strings.TrimSpace(string(m.Transport))))
	}
	if strings.TrimSpace(m.LocalBase) == "" && strings.TrimSpace(m.SourceBase) != "" {
		m.LocalBase = strings.TrimSpace(m.SourceBase)
	}
	m.SourceBase = ""
	if strings.TrimSpace(m.RemoteBase) == "" && strings.TrimSpace(m.DestBase) != "" {
		m.RemoteBase = strings.TrimSpace(m.DestBase)
	}
	m.DestBase = ""
	if m.Timeout == 0 && m.LegacyRsyncTimeout > 0 {
		m.Timeout = m.LegacyRsyncTimeout
	}
	m.LegacyRsyncTimeout = 0
	if strings.TrimSpace(m.LegacySSHOptions) != "" {
		sai, sac := parseSSHAliveOptions(m.LegacySSHOptions)
		if m.ServerAliveInterval == 0 && sai > 0 {
			m.ServerAliveInterval = sai
		}
		if m.ServerAliveCountMax == 0 && sac > 0 {
			m.ServerAliveCountMax = sac
		}
		m.LegacySSHOptions = ""
	}
	if len(m.Folders) == 0 && len(m.LegacyJobs) > 0 {
		m.Folders = m.LegacyJobs
		m.LegacyJobs = nil
	}
	for i := range m.Folders {
		m.Folders[i].Normalize()
	}
	if strings.TrimSpace(m.LocalBase) == "" && len(m.Folders) > 0 {
		allAbsOrTilde := true
		for _, f := range m.Folders {
			s := strings.TrimSpace(f.Source)
			if !filepath.IsAbs(s) && !strings.HasPrefix(s, "~/") && s != "~" && s != "." {
				allAbsOrTilde = false
				break
			}
		}
		if allAbsOrTilde {
			m.LocalBase = "~"
		}
	}
	if strings.TrimSpace(m.RemoteBase) == "" && len(m.Folders) > 0 {
		allAbsRemote := true
		for _, f := range m.Folders {
			if !strings.HasPrefix(strings.TrimSpace(f.Dest), "/") ||
				(strings.TrimSpace(f.BackupDir) != "" && !strings.HasPrefix(strings.TrimSpace(f.BackupDir), "/")) ||
				(strings.TrimSpace(f.LogFile) != "" && !strings.HasPrefix(strings.TrimSpace(f.LogFile), "/")) {
				allAbsRemote = false
				break
			}
		}
		if allAbsRemote {
			m.RemoteBase = "/"
		}
	}
	if m.EffectiveTransport() == BackupTransportSSHPull && strings.TrimSpace(m.LocalBase) == "" {
		m.LocalBase = "~"
	}
	if strings.TrimSpace(m.RemoteRsyncBin) == "" {
		if m.EffectiveTransport() == BackupTransportSSHPull {
			m.RemoteRsyncBin = "rsync"
		} else {
			m.RemoteRsyncBin = DefaultRemoteRsyncBin
		}
	}
	if m.ModifyWindow == 0 {
		m.ModifyWindow = DefaultModifyWindow
	}
	if strings.TrimSpace(m.PartialDir) == "" {
		m.PartialDir = DefaultPartialDir
	}
	if m.MaxAttempts <= 0 {
		m.MaxAttempts = DefaultBackupMaxAttempts
	}
	if len(m.Excludes) == 0 {
		m.Excludes = DefaultBackupExcludes()
	} else {
		m.Excludes = ensureAppleDoubleExclude(m.Excludes)
	}
}

// Validate checks that the manifest has valid required fields and folder specifications.
func (m BackupManifest) Validate() error {
	if err := m.Name.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidBackupManifest, err)
	}
	if err := m.Transport.Validate(); err != nil {
		return err
	}
	if (m.EffectiveTransport() == BackupTransportSSH || m.EffectiveTransport() == BackupTransportSSHPull) && strings.TrimSpace(m.SSHTarget) == "" {
		return fmt.Errorf("%w: ssh_target cannot be empty for %s transport", ErrInvalidBackupManifest, m.EffectiveTransport())
	}
	if strings.TrimSpace(m.LocalBase) == "" {
		return fmt.Errorf("%w: local_base cannot be empty", ErrInvalidBackupManifest)
	}
	if strings.TrimSpace(m.RemoteBase) == "" && strings.TrimSpace(m.DestBase) == "" {
		return fmt.Errorf("%w: remote_base (or dest_base) cannot be empty", ErrInvalidBackupManifest)
	}
	if m.Timeout < 0 || m.ServerAliveInterval < 0 || m.ServerAliveCountMax < 0 {
		return fmt.Errorf("%w: timeout and server_alive_* cannot be negative", ErrInvalidBackupManifest)
	}
	if _, err := ParseNoProgressTimeout(m.NoProgressTimeout); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidBackupManifest, err)
	}
	for i, folder := range m.Folders {
		if err := folder.Validate(); err != nil {
			return fmt.Errorf("folder[%d]: %w", i, err)
		}
	}
	return nil
}
