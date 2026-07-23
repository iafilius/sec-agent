package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"secure_secrets/internal/config"
	"secure_secrets/internal/crypto"
	"sort"
	"strings"
	"time"
)

// SecretEntry represents a single secret with value, comment, metadata, and timestamps.
type SecretEntry struct {
	Value        string            `json:"value"`
	Comment      string            `json:"comment,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Created      time.Time         `json:"created"`
	LastModified time.Time         `json:"last_modified"`
	Expires      time.Time         `json:"expires,omitempty"`
}

// EncryptedStore represents the local store.
type EncryptedStore struct {
	Secrets map[string]SecretEntry `json:"secrets"`
}

// UnmarshalJSON implements custom unmarshaling to migrate legacy stores cleanly.
func (es *EncryptedStore) UnmarshalJSON(data []byte) error {
	// Try the new structure first
	type Alias EncryptedStore
	var aux Alias
	if err := json.Unmarshal(data, &aux); err == nil && aux.Secrets != nil {
		es.Secrets = aux.Secrets
		return nil
	}

	// Fallback to legacy format: map[string]string
	var legacy struct {
		Secrets map[string]string `json:"secrets"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return fmt.Errorf("failed to unmarshal store JSON: %w", err)
	}

	es.Secrets = make(map[string]SecretEntry)
	for k, v := range legacy.Secrets {
		es.Secrets[k] = SecretEntry{
			Value:        v,
			Created:      time.Now(),
			LastModified: time.Now(),
		}
	}
	return nil
}

// GetStorePath returns the path to ~/.config/sec/secrets.enc.
func GetStorePath(profile string) (string, error) {
	dir, err := config.GetConfigDir()
	if err != nil {
		return "", err
	}
	if profile == "" || profile == "default" {
		return filepath.Join(dir, "secrets.enc"), nil
	}
	return filepath.Join(dir, fmt.Sprintf("secrets_%s.enc", profile)), nil
}

// LoadStore reads and decrypts the store from disk using the master key.
// If the store file does not exist, it returns an empty store.
func LoadStore(profile string, masterKey []byte) (*EncryptedStore, error) {
	path, err := GetStorePath(profile)
	if err != nil {
		return nil, err
	}

	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &EncryptedStore{Secrets: make(map[string]SecretEntry)}, nil
		}
		return nil, fmt.Errorf("failed to read store file: %w", err)
	}

	decrypted, err := crypto.Decrypt(masterKey, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt store (incorrect or expired key?): %w", err)
	}

	var store EncryptedStore
	if err := json.Unmarshal(decrypted, &store); err != nil {
		return nil, fmt.Errorf("failed to unmarshal store JSON: %w", err)
	}

	if store.Secrets == nil {
		store.Secrets = make(map[string]SecretEntry)
	}

	for k, entry := range store.Secrets {
		updated := false
		if entry.Created.IsZero() {
			entry.Created = time.Now()
			updated = true
		}
		if entry.LastModified.IsZero() {
			entry.LastModified = time.Now()
			updated = true
		}
		if updated {
			store.Secrets[k] = entry
		}
	}

	return &store, nil
}

// SaveStore encrypts and writes the store to disk using the master key.
// It uses temporary-file writing and atomic renames to prevent corruption
// on disk full, read-only disks, or power outages.
func SaveStore(profile string, store *EncryptedStore, masterKey []byte) error {
	path, err := GetStorePath(profile)
	if err != nil {
		return err
	}

	if store.Secrets == nil {
		store.Secrets = make(map[string]SecretEntry)
	}

	plaintext, err := json.Marshal(store)
	if err != nil {
		return fmt.Errorf("failed to marshal store JSON: %w", err)
	}

	ciphertext, err := crypto.Encrypt(masterKey, plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt store: %w", err)
	}

	dir := filepath.Dir(path)
	// Create temp file in same directory to guarantee atomic rename
	tmpFile, err := os.CreateTemp(dir, "secrets.enc.*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary store file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	// Restrict permissions to owner-only
	if err := tmpFile.Chmod(0600); err != nil {
		return fmt.Errorf("failed to set permissions on temp file: %w", err)
	}

	if _, err := tmpFile.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write encrypted payload to temp file: %w", err)
	}

	// Force storage device sync (fsync)
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp file to disk: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Create backup copy of existing store if it exists
	if _, err := os.Stat(path); err == nil {
		backupDir := filepath.Join(dir, "backups", profile)
		if err := os.MkdirAll(backupDir, 0700); err != nil {
			return fmt.Errorf("failed to create backups directory: %w", err)
		}
		backupPath := filepath.Join(backupDir, fmt.Sprintf("secrets.enc.%d", time.Now().UnixNano()))

		// Read existing data
		// #nosec G304 G703
		existingData, readErr := os.ReadFile(path)
		if readErr == nil {
			// Write backup copy
			// #nosec G304 G703
			_ = os.WriteFile(backupPath, existingData, 0600)
			pruneBackups(backupDir, 10)
		}
	}

	// Atomically replace target database file
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to atomically replace store file: %w", err)
	}

	// Sync parent directory metadata to guarantee persistence on POSIX
	// #nosec G304 G703
	dirFile, err := os.Open(dir)
	if err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}

	return nil
}

func pruneBackups(backupDir string, maxBackups int) {
	files, err := os.ReadDir(backupDir)
	if err != nil {
		return
	}
	var backupFiles []os.DirEntry
	for _, f := range files {
		if !f.IsDir() && strings.HasPrefix(f.Name(), "secrets.enc.") {
			backupFiles = append(backupFiles, f)
		}
	}
	if len(backupFiles) <= maxBackups {
		return
	}
	// Sort by name (nanosecond timestamp makes lexical sort chronological)
	sort.Slice(backupFiles, func(i, j int) bool {
		return backupFiles[i].Name() < backupFiles[j].Name()
	})
	// Remove oldest files
	excess := len(backupFiles) - maxBackups
	for i := 0; i < excess; i++ {
		// #nosec G304 G703
		_ = os.Remove(filepath.Join(backupDir, backupFiles[i].Name()))
	}
}

// InitializeMasterKey checks if a master key is present in the keychain.
// If not, it generates a new one and saves it. Returns the master key.
func InitializeMasterKey(profile string, keychainGetter func() ([]byte, error), keychainSetter func([]byte) error) ([]byte, error) {
	key, err := keychainGetter()
	if err == nil && len(key) > 0 {
		return key, nil
	}

	// Not found or error, let's generate a new one
	newKey, err := crypto.GenerateRandomKey()
	if err != nil {
		return nil, err
	}

	if err := keychainSetter(newKey); err != nil {
		return nil, fmt.Errorf("failed to store generated master key in keychain: %w", err)
	}

	// Create an empty store on disk immediately so it's initialized
	if err := SaveStore(profile, &EncryptedStore{Secrets: make(map[string]SecretEntry)}, newKey); err != nil {
		return nil, err
	}

	return newKey, nil
}

// GetGroup returns a map of all secrets whose paths match the specified prefix.
// If prefix is empty, it returns all secrets in the store.
func (es *EncryptedStore) GetGroup(prefix string) map[string]SecretEntry {
	result := make(map[string]SecretEntry)
	if es == nil || es.Secrets == nil {
		return result
	}
	cleanPrefix := strings.TrimSpace(prefix)
	for k, v := range es.Secrets {
		if cleanPrefix == "" || strings.HasPrefix(k, cleanPrefix) {
			result[k] = v
		}
	}
	return result
}

// RenameSecret renames a secret key path in the store.
func (es *EncryptedStore) RenameSecret(oldPath, newPath string) error {
	if es == nil || es.Secrets == nil {
		return fmt.Errorf("store is uninitialized")
	}
	oldPath = strings.TrimSpace(oldPath)
	newPath = strings.TrimSpace(newPath)
	if oldPath == "" || newPath == "" {
		return fmt.Errorf("old and new paths cannot be empty")
	}
	entry, exists := es.Secrets[oldPath]
	if !exists {
		return fmt.Errorf("secret %q not found", oldPath)
	}
	entry.LastModified = time.Now()
	es.Secrets[newPath] = entry
	delete(es.Secrets, oldPath)
	return nil
}

// RenamePrefix renames all secret paths matching oldPrefix to start with newPrefix.
// Returns the count of renamed secrets.
func (es *EncryptedStore) RenamePrefix(oldPrefix, newPrefix string) (int, error) {
	if es == nil || es.Secrets == nil {
		return 0, fmt.Errorf("store is uninitialized")
	}
	oldPrefix = strings.TrimSpace(oldPrefix)
	newPrefix = strings.TrimSpace(newPrefix)
	if oldPrefix == "" || newPrefix == "" {
		return 0, fmt.Errorf("old and new prefixes cannot be empty")
	}

	count := 0
	toRename := make(map[string]SecretEntry)
	for k, v := range es.Secrets {
		if strings.HasPrefix(k, oldPrefix) {
			toRename[k] = v
		}
	}

	for k, v := range toRename {
		rel := strings.TrimPrefix(k, oldPrefix)
		newKey := newPrefix + rel
		v.LastModified = time.Now()
		es.Secrets[newKey] = v
		delete(es.Secrets, k)
		count++
	}

	return count, nil
}

// DeleteSecret removes a single secret path from the store.
func (es *EncryptedStore) DeleteSecret(path string) error {
	if es == nil || es.Secrets == nil {
		return fmt.Errorf("store is uninitialized")
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("secret path cannot be empty")
	}
	if _, exists := es.Secrets[path]; !exists {
		return fmt.Errorf("secret %q not found", path)
	}
	delete(es.Secrets, path)
	return nil
}

// DeletePrefix removes all secret paths matching prefix from the store.
// Returns the count of deleted secrets.
func (es *EncryptedStore) DeletePrefix(prefix string) (int, error) {
	if es == nil || es.Secrets == nil {
		return 0, fmt.Errorf("store is uninitialized")
	}
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return 0, fmt.Errorf("prefix cannot be empty")
	}

	count := 0
	for k := range es.Secrets {
		if strings.HasPrefix(k, prefix) {
			delete(es.Secrets, k)
			count++
		}
	}
	return count, nil
}

// CopySecret duplicates a secret key path to a new location in the store.
func (es *EncryptedStore) CopySecret(srcPath, dstPath string) error {
	if es == nil || es.Secrets == nil {
		return fmt.Errorf("store is uninitialized")
	}
	srcPath = strings.TrimSpace(srcPath)
	dstPath = strings.TrimSpace(dstPath)
	if srcPath == "" || dstPath == "" {
		return fmt.Errorf("source and destination paths cannot be empty")
	}
	entry, exists := es.Secrets[srcPath]
	if !exists {
		return fmt.Errorf("secret %q not found", srcPath)
	}
	entry.LastModified = time.Now()
	es.Secrets[dstPath] = entry
	return nil
}

// CopyPrefix duplicates all secret paths matching srcPrefix to start with dstPrefix.
// Returns the count of copied secrets.
func (es *EncryptedStore) CopyPrefix(srcPrefix, dstPrefix string) (int, error) {
	if es == nil || es.Secrets == nil {
		return 0, fmt.Errorf("store is uninitialized")
	}
	srcPrefix = strings.TrimSpace(srcPrefix)
	dstPrefix = strings.TrimSpace(dstPrefix)
	if srcPrefix == "" || dstPrefix == "" {
		return 0, fmt.Errorf("source and destination prefixes cannot be empty")
	}

	count := 0
	toCopy := make(map[string]SecretEntry)
	for k, v := range es.Secrets {
		if strings.HasPrefix(k, srcPrefix) {
			toCopy[k] = v
		}
	}

	for k, v := range toCopy {
		rel := strings.TrimPrefix(k, srcPrefix)
		newKey := dstPrefix + rel
		v.LastModified = time.Now()
		es.Secrets[newKey] = v
		count++
	}

	return count, nil
}

