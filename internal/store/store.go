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

// SecretVersion represents a historical snapshot of a secret value, comment, and metadata.
type SecretVersion struct {
	Version      int               `json:"version"`
	Value        string            `json:"value"`
	Comment      string            `json:"comment,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	LastModified time.Time         `json:"last_modified"`
}

// SecretEntry represents a single secret with value, comment, metadata, timestamps, version history, and soft-delete state.
type SecretEntry struct {
	Value        string            `json:"value"`
	Comment      string            `json:"comment,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Created      time.Time         `json:"created"`
	LastModified time.Time         `json:"last_modified"`
	LastAccessed time.Time         `json:"last_accessed,omitempty"`
	AccessCount  uint64            `json:"access_count,omitempty"`
	Expires      time.Time         `json:"expires,omitempty"`
	Version      int               `json:"version,omitempty"`
	History      []SecretVersion   `json:"history,omitempty"`
	DeletedAt    *time.Time        `json:"deleted_at,omitempty"`
}

// EncryptedStore represents the local store.
type EncryptedStore struct {
	Secrets map[SecretKey]SecretEntry `json:"secrets"`
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

	es.Secrets = make(map[SecretKey]SecretEntry)
	for k, v := range legacy.Secrets {
		es.Secrets[SecretKey(k)] = SecretEntry{
			Value:        v,
			Created:      time.Now(),
			LastModified: time.Now(),
		}
	}
	return nil
}

// DeduplicateProfileSecrets copies matching secret keys from srcProfile to dstProfile,
// and deletes them from srcProfile. Returns list of moved key paths.
func DeduplicateProfileSecrets(srcProfile, dstProfile string, prefixes []string, srcMasterKey, dstMasterKey []byte) ([]string, error) {
	srcStore, err := LoadStore(srcProfile, srcMasterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load source profile %q: %w", srcProfile, err)
	}

	dstStore, err := LoadStore(dstProfile, dstMasterKey)
	if err != nil {
		// Attempt auto-repair from latest valid snapshot matching srcMasterKey or dstMasterKey
		snaps, sErr := ListSnapshots(dstProfile, srcMasterKey)
		if sErr == nil {
			for _, snap := range snaps {
				if snap.KeyMatch {
					dstPath, pErr := GetStorePath(dstProfile)
					if pErr == nil {
						// #nosec G304 G703
						if data, rErr := os.ReadFile(snap.FilePath); rErr == nil {
							if writeErr := os.WriteFile(dstPath, data, 0600); writeErr == nil {
								if retriedStore, retryErr := LoadStore(dstProfile, srcMasterKey); retryErr == nil {
									dstStore = retriedStore
									dstMasterKey = srcMasterKey
									err = nil
									break
								}
							}
						}
					}
				}
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load target profile %q: %w", dstProfile, err)
	}

	movedKeys := make([]string, 0)
	keysToDelete := make([]SecretKey, 0)

	for k, entry := range srcStore.Secrets {
		kStr := string(k)
		matchesPrefix := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(kStr, prefix) {
				matchesPrefix = true
				break
			}
		}

		if matchesPrefix {
			dstEntry, exists := dstStore.Secrets[k]
			if !exists || entry.LastModified.After(dstEntry.LastModified) {
				dstStore.Secrets[k] = entry
			}
			keysToDelete = append(keysToDelete, k)
			movedKeys = append(movedKeys, kStr)
		}
	}

	if len(movedKeys) > 0 {
		for _, k := range keysToDelete {
			delete(srcStore.Secrets, k)
		}
		if err := SaveStore(srcProfile, srcStore, srcMasterKey); err != nil {
			return nil, fmt.Errorf("failed to update source profile %q: %w", srcProfile, err)
		}
		if err := SaveStore(dstProfile, dstStore, dstMasterKey); err != nil {
			return nil, fmt.Errorf("failed to update destination profile %q: %w", dstProfile, err)
		}
	}

	sort.Strings(movedKeys)
	return movedKeys, nil
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
	if err := ProfileName(profile).Validate(); err != nil {
		return "", fmt.Errorf("invalid profile path %q: %w", profile, err)
	}
	return filepath.Join(dir, fmt.Sprintf("secrets_%s.enc", profile)), nil
}

// LoadStore reads and decrypts the store from disk using the master key.
// It transparently handles both v1.0 (raw AES-GCM) and v2.0 (JSON envelope) vaults.
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
			return &EncryptedStore{Secrets: make(map[SecretKey]SecretEntry)}, nil
		}
		return nil, fmt.Errorf("failed to read store file: %w", err)
	}

	// v2.0 detection: JSON envelope starts with '{'
	if len(data) > 0 && data[0] == '{' {
		var env VaultEnvelope
		if jsonErr := json.Unmarshal(data, &env); jsonErr == nil && env.Payload != nil {
			data = env.Payload // unwrap to inner AES-GCM ciphertext
		}
	}

	decrypted, err := crypto.Decrypt(masterKey, data)
	if err != nil {
		if strings.Contains(err.Error(), "cipher: message authentication failed") {
			profTag := profile
			if profTag == "" {
				profTag = "default"
			}
			return nil, fmt.Errorf("%w: master key mismatch (Touch ID biometric set changed or key invalidated). If this is a v2.0 vault, run 'sec session recover --profile %s' to restore access with your 24-word seed. If this is a test store, re-initialize with 'rm ~/.config/sec-agent/secrets_%s.enc && sec init --profile %s': %v", ErrMasterKeyMismatch, profTag, profTag, profTag, err)
		}
		return nil, fmt.Errorf("failed to decrypt store (incorrect or expired key?): %w", err)
	}

	var store EncryptedStore
	if err := json.Unmarshal(decrypted, &store); err != nil {
		return nil, fmt.Errorf("failed to unmarshal store JSON: %w", err)
	}

	if store.Secrets == nil {
		store.Secrets = make(map[SecretKey]SecretEntry)
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
		store.Secrets = make(map[SecretKey]SecretEntry)
	}

	plaintext, err := json.Marshal(store)
	if err != nil {
		return fmt.Errorf("failed to marshal store JSON: %w", err)
	}

	ciphertext, err := crypto.Encrypt(masterKey, plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt store: %w", err)
	}

	env := &VaultEnvelope{
		SchemaVersion:   SchemaV2,
		UpgradedAt:      time.Now().UTC(),
		MasterKeySHA256: crypto.MasterKeyFingerprint(masterKey),
		Payload:         ciphertext,
	}

	if IsV2Vault(path) {
		if existingEnv, err := ReadVaultEnvelope(path); err == nil && existingEnv != nil {
			env.UpgradedAt = existingEnv.UpgradedAt
			env.Slot1 = existingEnv.Slot1
		}
	}

	return WriteVaultEnvelope(path, env)
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
	if os.Getenv("SEC_TEST_MODE") == "1" {
		return []byte("01234567890123456789012345678901"), nil
	}

	key, err := keychainGetter()
	if err == nil && len(key) > 0 {
		return key, nil
	}

	// Check if vault store file already exists on disk
	storePath := GetStorePathForProfile(profile)
	if _, statErr := os.Stat(storePath); statErr == nil {
		return nil, fmt.Errorf("master key missing or invalidated in macOS Keychain (Touch ID biometric set changed?). Please run 'sec session recover' to restore access with your 24-word seed")
	}

	// Vault store does NOT exist on disk: this is a brand-new vault initialization
	newKey, err := crypto.GenerateRandomKey()
	if err != nil {
		return nil, err
	}

	if err := keychainSetter(newKey); err != nil {
		return nil, fmt.Errorf("failed to store generated master key in keychain: %w", err)
	}

	// Create an empty store on disk immediately so it's initialized
	if err := SaveStore(profile, &EncryptedStore{Secrets: make(map[SecretKey]SecretEntry)}, newKey); err != nil {
		return nil, err
	}

	return newKey, nil
}

// GetGroup returns a map of all secrets whose paths match the specified prefix.
// If prefix is empty, it returns all secrets in the store.
// GetSecretKey retrieves a secret entry by SecretKey primitive.
func (es *EncryptedStore) GetSecretKey(key SecretKey) (SecretEntry, bool) {
	if es == nil || es.Secrets == nil {
		return SecretEntry{}, false
	}
	entry, exists := es.Secrets[key]
	return entry, exists
}

// SetSecretKey sets a secret entry by SecretKey primitive.
func (es *EncryptedStore) SetSecretKey(key SecretKey, entry SecretEntry) {
	if es == nil {
		return
	}
	if es.Secrets == nil {
		es.Secrets = make(map[SecretKey]SecretEntry)
	}
	es.Secrets[key] = entry
}

// DeleteSecretKey hard-deletes a secret entry by SecretKey primitive.
func (es *EncryptedStore) DeleteSecretKey(key SecretKey) {
	if es == nil || es.Secrets == nil {
		return
	}
	delete(es.Secrets, key)
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
		if cleanPrefix == "" || strings.HasPrefix(string(k), cleanPrefix) {
			result[string(k)] = v
		}
	}
	return result
}

// RenameSecret renames a secret key path in the store.
func (es *EncryptedStore) RenameSecret(oldPath, newPath string) error {
	if es == nil || es.Secrets == nil {
		return fmt.Errorf("%w", ErrStoreUninitialized)
	}
	oldPath = strings.TrimSpace(oldPath)
	newPath = strings.TrimSpace(newPath)
	if oldPath == "" || newPath == "" {
		return fmt.Errorf("%w: old and new paths cannot be empty", ErrPathEmpty)
	}
	entry, exists := es.Secrets[SecretKey(oldPath)]
	if !exists {
		return fmt.Errorf("%w: secret %q not found", ErrSecretNotFound, oldPath)
	}
	entry.LastModified = time.Now()
	es.Secrets[SecretKey(newPath)] = entry
	delete(es.Secrets, SecretKey(oldPath))
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
	toRename := make(map[SecretKey]SecretEntry)
	for k, v := range es.Secrets {
		if strings.HasPrefix(string(k), oldPrefix) {
			toRename[k] = v
		}
	}

	for k, v := range toRename {
		rel := strings.TrimPrefix(string(k), oldPrefix)
		newKey := SecretKey(newPrefix + rel)
		v.LastModified = time.Now()
		es.Secrets[newKey] = v
		delete(es.Secrets, k)
		count++
	}

	return count, nil
}

// DeleteSecret removes a single secret path from the store (soft-deletes unless permanent is true).
func (es *EncryptedStore) DeleteSecret(path string) error {
	return es.SoftDeleteSecret(path)
}

// SoftDeleteSecret marks a secret path as deleted without removing it.
func (es *EncryptedStore) SoftDeleteSecret(path string) error {
	if es == nil || es.Secrets == nil {
		return fmt.Errorf("%w", ErrStoreUninitialized)
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("%w: secret path cannot be empty", ErrPathEmpty)
	}
	sk := SecretKey(path)
	entry, exists := es.Secrets[sk]
	if !exists {
		return fmt.Errorf("%w: secret %q not found", ErrSecretNotFound, path)
	}
	now := time.Now()
	entry.DeletedAt = &now
	entry.LastModified = now
	es.Secrets[sk] = entry
	return nil
}

// HardDeleteSecret permanently removes a secret path from the store.
func (es *EncryptedStore) HardDeleteSecret(path string) error {
	if es == nil || es.Secrets == nil {
		return fmt.Errorf("%w", ErrStoreUninitialized)
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("%w: secret path cannot be empty", ErrPathEmpty)
	}
	sk := SecretKey(path)
	if _, exists := es.Secrets[sk]; !exists {
		return fmt.Errorf("%w: secret %q not found", ErrSecretNotFound, path)
	}
	delete(es.Secrets, sk)
	return nil
}

// RestoreDeletedSecret un-deletes a soft-deleted secret.
func (es *EncryptedStore) RestoreDeletedSecret(path string) error {
	if es == nil || es.Secrets == nil {
		return fmt.Errorf("store is uninitialized")
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("secret path cannot be empty")
	}
	sk := SecretKey(path)
	entry, exists := es.Secrets[sk]
	if !exists {
		return fmt.Errorf("secret %q not found", path)
	}
	if entry.DeletedAt == nil {
		return fmt.Errorf("secret %q is not deleted", path)
	}
	entry.DeletedAt = nil
	entry.LastModified = time.Now()
	es.Secrets[sk] = entry
	return nil
}

// DeletePrefix removes all secret paths matching prefix from the store (soft-deletes unless permanent).
func (es *EncryptedStore) DeletePrefix(prefix string) (int, error) {
	return es.SoftDeletePrefix(prefix)
}

// SoftDeletePrefix soft-deletes all secrets under a prefix.
func (es *EncryptedStore) SoftDeletePrefix(prefix string) (int, error) {
	if es == nil || es.Secrets == nil {
		return 0, fmt.Errorf("store is uninitialized")
	}
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return 0, fmt.Errorf("prefix cannot be empty")
	}

	count := 0
	now := time.Now()
	for k, v := range es.Secrets {
		if strings.HasPrefix(string(k), prefix) && v.DeletedAt == nil {
			v.DeletedAt = &now
			v.LastModified = now
			es.Secrets[k] = v
			count++
		}
	}
	return count, nil
}

// HardDeletePrefix permanently removes all secret paths matching prefix.
func (es *EncryptedStore) HardDeletePrefix(prefix string) (int, error) {
	if es == nil || es.Secrets == nil {
		return 0, fmt.Errorf("store is uninitialized")
	}
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return 0, fmt.Errorf("prefix cannot be empty")
	}

	count := 0
	for k := range es.Secrets {
		if strings.HasPrefix(string(k), prefix) {
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
	srcKey := SecretKey(srcPath)
	entry, exists := es.Secrets[srcKey]
	if !exists {
		return fmt.Errorf("secret %q not found", srcPath)
	}
	entry.LastModified = time.Now()
	es.Secrets[SecretKey(dstPath)] = entry
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
	toCopy := make(map[SecretKey]SecretEntry)
	for k, v := range es.Secrets {
		if strings.HasPrefix(string(k), srcPrefix) {
			toCopy[k] = v
		}
	}

	for k, v := range toCopy {
		rel := strings.TrimPrefix(string(k), srcPrefix)
		newKey := SecretKey(dstPrefix + rel)
		v.LastModified = time.Now()
		es.Secrets[newKey] = v
		count++
	}

	return count, nil
}

// HistoryFile represents a discovered shell history file.
type HistoryFile struct {
	ShellName string
	Path      string
}

// DiscoverShellHistoryFiles searches home directory for .zsh_history, .bash_history, .histfile, and fish_history.
func DiscoverShellHistoryFiles() []HistoryFile {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	candidates := []HistoryFile{
		{ShellName: "zsh", Path: filepath.Join(home, ".zsh_history")},
		{ShellName: "bash", Path: filepath.Join(home, ".bash_history")},
		{ShellName: "zsh", Path: filepath.Join(home, ".histfile")},
		{ShellName: "fish", Path: filepath.Join(home, ".config", "fish", "fish_history")},
	}

	var found []HistoryFile
	for _, c := range candidates {
		if fi, err := os.Stat(c.Path); err == nil && !fi.IsDir() {
			found = append(found, c)
		}
	}
	return found
}

