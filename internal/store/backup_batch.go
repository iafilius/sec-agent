package store

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
)

const (
	// DefaultBatchMaxAttempts is the number of attempts per batch job when none is configured.
	DefaultBatchMaxAttempts = 5
)

// BackupBatch is an ordered sequence of rsync jobs run together as one named batch.
// It is stored encrypted in the vault under BackupBatch.VaultKey().
type BackupBatch struct {
	Name        BackupJobName `json:"name"`
	SSHTarget   string        `json:"ssh_target"`
	MaxAttempts int           `json:"max_attempts,omitempty"`
	// SSHPasswordKey is an optional vault key holding the SSH password for SSHTarget. It is read
	// when the batch runs, never stored in the batch itself.
	SSHPasswordKey string           `json:"ssh_password_key,omitempty"`
	Jobs           []BackupBatchJob `json:"jobs"`
}

// BackupBatchJob is one rsync transfer inside a BackupBatch. Values are stored
// exactly as given; date placeholders are resolved once per batch run.
type BackupBatchJob struct {
	Name     string   `json:"name"`
	Source   string   `json:"source"`
	Dest     string   `json:"dest"`
	Excludes []string `json:"excludes,omitempty"`
	// Sparse copies files with holes (e.g. VM disk images) as sparse files instead of full size.
	Sparse    bool   `json:"sparse,omitempty"`
	BackupDir string `json:"backup_dir"`
	LogFile   string `json:"log_file"`
}

// VaultKey returns the vault key under which the batch is stored. The prefix is distinct from
// the "backup/" prefix used by stealth backup manifests so batches stay out of `sec backup jobs`.
func (b BackupBatch) VaultKey() SecretKey {
	return SecretKey("backup-batch/" + strings.TrimSpace(string(b.Name)))
}

// ApplyDefaults fills unset optional fields with their defaults.
func (b *BackupBatch) ApplyDefaults() {
	if b.MaxAttempts == 0 {
		b.MaxAttempts = DefaultBatchMaxAttempts
	}
}

// Validate checks that the batch and every job are complete and safe to run.
func (b BackupBatch) Validate() error {
	if err := b.Name.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(b.SSHTarget) == "" || strings.IndexFunc(b.SSHTarget, unicode.IsSpace) >= 0 {
		return fmt.Errorf("%w: ssh_target must be a non-empty host without whitespace", ErrInvalidBackupManifest)
	}
	if strings.IndexFunc(b.SSHPasswordKey, unicode.IsSpace) >= 0 {
		return fmt.Errorf("%w: ssh_password_key must contain no whitespace", ErrInvalidBackupManifest)
	}
	if b.MaxAttempts < 1 {
		return fmt.Errorf("%w: max_attempts must be at least 1", ErrInvalidBackupManifest)
	}
	if len(b.Jobs) == 0 {
		return fmt.Errorf("%w: batch %q has no jobs", ErrInvalidBackupManifest, b.Name)
	}
	seen := make(map[string]bool, len(b.Jobs))
	for i, job := range b.Jobs {
		if err := job.Validate(); err != nil {
			return fmt.Errorf("job %d: %w", i+1, err)
		}
		if seen[job.Name] {
			return fmt.Errorf("%w: duplicate job name %q", ErrInvalidBackupManifest, job.Name)
		}
		seen[job.Name] = true
	}
	return nil
}

// Validate checks a single batch job.
func (j BackupBatchJob) Validate() error {
	if strings.TrimSpace(j.Name) == "" {
		return fmt.Errorf("%w: job name cannot be empty", ErrInvalidBackupManifest)
	}
	src := strings.TrimSpace(j.Source)
	if !(filepath.IsAbs(src) || strings.HasPrefix(src, "~/")) {
		return fmt.Errorf("%w: job %q source must be an absolute path or start with ~/", ErrInvalidBackupManifest, j.Name)
	}
	if strings.TrimSpace(j.Dest) == "" {
		return fmt.Errorf("%w: job %q dest cannot be empty", ErrInvalidBackupManifest, j.Name)
	}
	// backup_dir is sent as an unquoted rsync argument, so it must not contain whitespace.
	if strings.TrimSpace(j.BackupDir) == "" || strings.IndexFunc(j.BackupDir, unicode.IsSpace) >= 0 {
		return fmt.Errorf("%w: job %q backup_dir must be non-empty and contain no whitespace", ErrInvalidBackupManifest, j.Name)
	}
	if strings.TrimSpace(j.LogFile) == "" {
		return fmt.Errorf("%w: job %q log_file cannot be empty", ErrInvalidBackupManifest, j.Name)
	}
	return nil
}
