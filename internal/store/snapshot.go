package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"secure_secrets/internal/config"
	"secure_secrets/internal/crypto"
)

// SnapshotMeta holds indexed metadata for a point-in-time vault snapshot.
type SnapshotMeta struct {
	ID              string    `json:"id"`
	Profile         string    `json:"profile"`
	CreatedAt       time.Time `json:"created_at"`
	TriggerReason   string    `json:"trigger_reason"`
	Actor           string    `json:"actor"`
	MasterKeySHA256 string    `json:"master_key_sha256"`
	SchemaVersion   string    `json:"schema_version"`
	SecretCount     int       `json:"secret_count"`
	FilePath        string    `json:"file_path"`
	Comment         string    `json:"comment,omitempty"`
	KeyMatch        bool      `json:"key_match"`
}

// GetSnapshotDir returns the snapshots directory path for a profile.
func GetSnapshotDir(profile string) (string, error) {
	dir, err := config.GetConfigDir()
	if err != nil {
		return "", err
	}
	if profile == "" {
		profile = "default"
	}
	return filepath.Join(dir, "snapshots", profile), nil
}

// DEPRECATED / MIGRATION MARKER:
// Added: 2026-08-10 (v2.5.0 release)
// Target Deprecation & Deletion Date: 2027-08-10 (v3.0.0 release)
// Purpose: Sweeps all profile subdirectories under ~/.config/sec-agent/backups/,
// migrates all legacy backup files to ~/.config/sec-agent/snapshots/<profile>/,
// and deletes the legacy ~/.config/sec-agent/backups/ parent directory completely.
// Once all users have upgraded to v2.5.0+, this helper function can be safely removed in v3.0.0.
func MigrateAllLegacyBackups() error {
	dir, err := config.GetConfigDir()
	if err != nil {
		return err
	}
	backupsParent := filepath.Join(dir, "backups")
	if _, err := os.Stat(backupsParent); os.IsNotExist(err) {
		return nil
	}

	entries, err := os.ReadDir(backupsParent)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			_ = MigrateLegacyBackupsToSnapshots(entry.Name())
		}
	}

	// Remove top-level backups parent dir if empty
	_ = os.Remove(backupsParent)
	return nil
}

// MigrateLegacyBackupsToSnapshots automatically migrates any legacy backup files
// located in ~/.config/sec-agent/backups/ to ~/.config/sec-agent/snapshots/ with zero data loss.
func MigrateLegacyBackupsToSnapshots(profile string) error {
	dir, err := config.GetConfigDir()
	if err != nil {
		return err
	}
	if profile == "" {
		profile = "default"
	}
	legacyDir := filepath.Join(dir, "backups", profile)
	if _, err := os.Stat(legacyDir); os.IsNotExist(err) {
		return nil
	}

	snapDir, err := GetSnapshotDir(profile)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(snapDir, 0700); err != nil {
		return err
	}

	entries, err := os.ReadDir(legacyDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "secrets.enc.") {
			continue
		}
		oldPath := filepath.Join(legacyDir, entry.Name())
		tsNanoStr := strings.TrimPrefix(entry.Name(), "secrets.enc.")

		// Create snapshot ID and metadata
		snapID := fmt.Sprintf("snap-%s", tsNanoStr)
		newEncPath := filepath.Join(snapDir, fmt.Sprintf("%s.enc", snapID))
		newMetaPath := filepath.Join(snapDir, fmt.Sprintf("%s.meta.json", snapID))

		// Copy file if not already present
		if _, statErr := os.Stat(newEncPath); os.IsNotExist(statErr) {
			// #nosec G304 G703
			data, readErr := os.ReadFile(oldPath)
			if readErr == nil {
				// #nosec G304 G703
				_ = os.WriteFile(newEncPath, data, 0600)

				// Determine schema version
				isV2 := IsV2Vault(newEncPath)
				schemaVer := "1.0"
				if isV2 {
					schemaVer = "2.0"
				}

				meta := SnapshotMeta{
					ID:              snapID,
					Profile:         profile,
					CreatedAt:       time.Now(),
					TriggerReason:   "migrated-legacy-backup",
					Actor:           "system",
					MasterKeySHA256: "unknown",
					SchemaVersion:   schemaVer,
					SecretCount:     -1,
					FilePath:        newEncPath,
					Comment:         "Automatically migrated from legacy backups directory",
				}
				metaBytes, _ := json.MarshalIndent(meta, "", "  ")
				_ = os.WriteFile(newMetaPath, metaBytes, 0600)
			}
		}

		// Remove old legacy backup file
		_ = os.Remove(oldPath)
	}

	// Remove legacy dir if empty
	_ = os.Remove(legacyDir)
	return nil
}

// CreateSnapshot creates a fresh point-in-time snapshot of the profile's active vault database.
func CreateSnapshot(profile, triggerReason, actor, comment string, activeKey []byte) (*SnapshotMeta, error) {
	if profile == "" {
		profile = "default"
	}
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		return nil, err
	}

	vaultPath := filepath.Join(cfgDir, "secrets.enc")
	if profile != "default" {
		vaultPath = filepath.Join(cfgDir, fmt.Sprintf("secrets_%s.enc", profile))
	}

	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("no vault database found for profile %q", profile)
	}

	// Ensure migration of all legacy backups runs first
	_ = MigrateAllLegacyBackups()

	snapDir, err := GetSnapshotDir(profile)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(snapDir, 0700); err != nil {
		return nil, err
	}

	// #nosec G304 G703
	vaultData, err := os.ReadFile(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault file for snapshot: %w", err)
	}

	now := time.Now()
	snapID := fmt.Sprintf("snap-%s-%d", now.Format("20060102-150405"), now.Nanosecond()/1e6)
	encPath := filepath.Join(snapDir, fmt.Sprintf("%s.enc", snapID))
	metaPath := filepath.Join(snapDir, fmt.Sprintf("%s.meta.json", snapID))

	// #nosec G304 G703
	if err := os.WriteFile(encPath, vaultData, 0600); err != nil {
		return nil, fmt.Errorf("failed to write snapshot enc file: %w", err)
	}

	fp := crypto.MasterKeyFingerprint(activeKey)
	isV2 := IsV2Vault(encPath)
	schemaVer := "1.0"
	if isV2 {
		schemaVer = "2.0"
	}

	// Calculate secret count if key is active
	secCount := -1
	if len(activeKey) > 0 {
		if isV2 {
			if env, readErr := ReadVaultEnvelope(encPath); readErr == nil {
				env.MasterKeySHA256 = fp
				_ = WriteVaultEnvelope(encPath, env)
				if dec, decErr := crypto.Decrypt(activeKey, env.Payload); decErr == nil {
					var s EncryptedStore
					if json.Unmarshal(dec, &s) == nil {
						secCount = len(s.Secrets)
					}
				}
			}
		} else {
			if dec, decErr := crypto.Decrypt(activeKey, vaultData); decErr == nil {
				var s EncryptedStore
				if json.Unmarshal(dec, &s) == nil {
					secCount = len(s.Secrets)
				}
			}
		}
	}

	if actor == "" {
		actor = "terminal"
	}

	meta := SnapshotMeta{
		ID:              snapID,
		Profile:         profile,
		CreatedAt:       now,
		TriggerReason:   triggerReason,
		Actor:           actor,
		MasterKeySHA256: fp,
		SchemaVersion:   schemaVer,
		SecretCount:     secCount,
		FilePath:        encPath,
		Comment:         comment,
		KeyMatch:        len(activeKey) > 0 && fp != "none",
	}

	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err == nil {
		_ = os.WriteFile(metaPath, metaBytes, 0600)
	}

	return &meta, nil
}

// ListSnapshots scans the profile's snapshot directory and returns all indexed snapshots sorted by date descending.
func ListSnapshots(profile string, activeKey []byte) ([]*SnapshotMeta, error) {
	if profile == "" {
		profile = "default"
	}
	_ = MigrateAllLegacyBackups()

	snapDir, err := GetSnapshotDir(profile)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(snapDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*SnapshotMeta{}, nil
		}
		return nil, err
	}

	activeFP := crypto.MasterKeyFingerprint(activeKey)
	var snapshots []*SnapshotMeta

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".enc") {
			continue
		}

		encPath := filepath.Join(snapDir, entry.Name())
		snapID := strings.TrimSuffix(entry.Name(), ".enc")
		metaPath := filepath.Join(snapDir, fmt.Sprintf("%s.meta.json", snapID))

		var meta SnapshotMeta
		// #nosec G304 G703
		metaData, readErr := os.ReadFile(metaPath)
		if readErr == nil {
			_ = json.Unmarshal(metaData, &meta)
		}

		meta.ID = snapID
		meta.Profile = profile
		meta.FilePath = encPath
		if meta.CreatedAt.IsZero() {
			if fi, statErr := entry.Info(); statErr == nil {
				meta.CreatedAt = fi.ModTime()
			}
		}

		meta.SchemaVersion = "1.0"
		if IsV2Vault(encPath) {
			meta.SchemaVersion = "2.0"
		}

		// Verify key match and update secret count if active key available
		needsRepair := false
		if len(activeKey) > 0 && activeFP != "none" {
			if meta.MasterKeySHA256 == activeFP {
				meta.KeyMatch = true
			}

			// Perform decryption check to update secret count if missing/negative
			if meta.SchemaVersion == "2.0" {
				if env, envErr := ReadVaultEnvelope(encPath); envErr == nil {
					if dec, decErr := crypto.Decrypt(activeKey, env.Payload); decErr == nil {
						meta.KeyMatch = true
						if meta.MasterKeySHA256 == "" || meta.MasterKeySHA256 == "unknown" {
							meta.MasterKeySHA256 = activeFP
							needsRepair = true
						}
						var s EncryptedStore
						if json.Unmarshal(dec, &s) == nil {
							if meta.SecretCount != len(s.Secrets) {
								meta.SecretCount = len(s.Secrets)
								needsRepair = true
							}
						}
					}
				}
			} else {
				// #nosec G304 G703
				if fileBytes, fErr := os.ReadFile(encPath); fErr == nil {
					if dec, decErr := crypto.Decrypt(activeKey, fileBytes); decErr == nil {
						meta.KeyMatch = true
						if meta.MasterKeySHA256 == "" || meta.MasterKeySHA256 == "unknown" {
							meta.MasterKeySHA256 = activeFP
							needsRepair = true
						}
						var s EncryptedStore
						if json.Unmarshal(dec, &s) == nil {
							if meta.SecretCount != len(s.Secrets) {
								meta.SecretCount = len(s.Secrets)
								needsRepair = true
							}
						}
					}
				}
			}

			// Persist repaired sidecar metadata to disk if repaired
			if needsRepair {
				if metaBytes, mErr := json.MarshalIndent(meta, "", "  "); mErr == nil {
					_ = os.WriteFile(metaPath, metaBytes, 0600)
				}
			}
		}

		snapshots = append(snapshots, &meta)
	}

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].CreatedAt.After(snapshots[j].CreatedAt)
	})

	return snapshots, nil
}

// ListAllSnapshots scans all profile directories under ~/.config/sec-agent/snapshots/
// and returns all indexed snapshots sorted by creation timestamp descending.
func ListAllSnapshots(activeKey []byte) ([]*SnapshotMeta, error) {
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		return nil, err
	}
	baseSnapDir := filepath.Join(cfgDir, "snapshots")

	entries, err := os.ReadDir(baseSnapDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*SnapshotMeta{}, nil
		}
		return nil, err
	}

	var allSnapshots []*SnapshotMeta
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		profile := entry.Name()
		profileSnaps, pErr := ListSnapshots(profile, activeKey)
		if pErr == nil {
			allSnapshots = append(allSnapshots, profileSnaps...)
		}
	}

	sort.Slice(allSnapshots, func(i, j int) bool {
		return allSnapshots[i].CreatedAt.After(allSnapshots[j].CreatedAt)
	})

	return allSnapshots, nil
}
