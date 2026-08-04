package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"secure_secrets/internal/config"
	"secure_secrets/internal/crypto"
	"time"
)

// GetStorePathForProfile returns the vault file path for a profile.
// If the path cannot be determined, returns an empty string.
func GetStorePathForProfile(profile string) string {
	path, err := GetStorePath(profile)
	if err != nil {
		return ""
	}
	return path
}

// ZeroBytes overwrites a byte slice with zeros. Exported for use in command handlers.
func ZeroBytes(b []byte) { zeroBytes(b) }

// VaultFileInfo describes a discovered vault file in the config directory.
type VaultFileInfo struct {
	Path    string // absolute path to the .enc file
	Profile string // derived profile name (e.g. "default", "dev", "prod")
	IsV2    bool   // true if already in v2.0 format
}

// ListVaultFiles scans the sec-agent config directory and returns all *.enc vault files.
// This includes secrets.enc (default profile) and secrets_<name>.enc (named profiles).
func ListVaultFiles() ([]VaultFileInfo, error) {
	dir, err := config.GetConfigDir()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve config dir: %w", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read config dir: %w", err)
	}

	var vaults []VaultFileInfo
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".enc" {
			continue
		}
		absPath := filepath.Join(dir, e.Name())

		var profile string
		name := e.Name()
		switch {
		case name == "secrets.enc":
			profile = "default"
		case len(name) > len("secrets_.enc") && name[:8] == "secrets_" && name[len(name)-4:] == ".enc":
			profile = name[8 : len(name)-4]
		default:
			continue // skip unknown .enc files (e.g. temp files)
		}

		vaults = append(vaults, VaultFileInfo{
			Path:    absPath,
			Profile: profile,
			IsV2:    IsV2Vault(absPath),
		})
	}
	return vaults, nil
}



const (
	SchemaV1 = "1.0" // Legacy: raw AES-GCM ciphertext managed by keychain
	SchemaV2 = "2.0" // Dual-Slot: JSON envelope with Slot0 (Touch ID) + Slot1 (BIP39 seed)
)

// Slot1Header holds the BIP39/Argon2id recovery slot metadata.
// The master key is wrapped (encrypted) using an AES-256-GCM key derived from
// the 24-word seed phrase via Argon2id.
type Slot1Header struct {
	// Argon2Salt is the random 16-byte salt used during Argon2id KDF.
	// It must be stored in plaintext alongside the wrapped key.
	Argon2Salt []byte `json:"argon2_salt"`
	// WrappedKey holds AES-256-GCM(argon2id(seed, salt), masterKey).
	// Nonce is prepended (12 bytes) before the ciphertext.
	WrappedKey []byte `json:"wrapped_key"`
}

// VaultEnvelope is the v2.0 on-disk format.
// Legacy v1.0 files are raw AES-GCM ciphertext (no JSON framing).
// Detection: if the file starts with '{', treat as VaultEnvelope.
type VaultEnvelope struct {
	// SchemaVersion identifies the file format. Must be "2.0".
	SchemaVersion string `json:"schema_version"`
	// UpgradedAt is the UTC timestamp when the vault was migrated to v2.0.
	UpgradedAt time.Time `json:"upgraded_at"`
	// Slot1 is the BIP39/Argon2id recovery slot.
	// Slot0 (Touch ID) master key is kept in the macOS Keychain only (not on disk).
	Slot1 *Slot1Header `json:"slot1,omitempty"`
	// Payload is the existing AES-GCM ciphertext: encrypt(masterKey, json(EncryptedStore)).
	// This is identical to the v1.0 raw file content.
	Payload []byte `json:"payload"`
}

// IsV2Vault returns true if the file at path is a v2.0 VaultEnvelope.
func IsV2Vault(path string) bool {
	// #nosec G304
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 1)
	n, _ := f.Read(buf)
	return n > 0 && buf[0] == '{'
}

// ReadVaultEnvelope reads and parses the v2.0 JSON envelope from disk.
func ReadVaultEnvelope(path string) (*VaultEnvelope, error) {
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault file: %w", err)
	}
	var env VaultEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("failed to parse vault envelope: %w", err)
	}
	if env.SchemaVersion != SchemaV2 {
		return nil, fmt.Errorf("unsupported vault schema version %q (expected %q)", env.SchemaVersion, SchemaV2)
	}
	return &env, nil
}

// WriteVaultEnvelope atomically writes a v2.0 VaultEnvelope to disk.
// Uses the same temp-file + fsync + rename pattern as SaveStore for power-loss safety.
func WriteVaultEnvelope(path string, env *VaultEnvelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to marshal vault envelope: %w", err)
	}

	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, "secrets.enc.*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp vault file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	if err := tmpFile.Chmod(0600); err != nil {
		return fmt.Errorf("failed to set temp vault permissions: %w", err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("failed to write vault envelope: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync vault file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp vault file: %w", err)
	}

	// Backup existing vault before overwriting
	if _, statErr := os.Stat(path); statErr == nil {
		backupDir, err := getBackupDir("default")
		if err == nil {
			_ = os.MkdirAll(backupDir, 0700)
			backupPath := filepath.Join(backupDir, fmt.Sprintf("secrets.enc.%d", time.Now().UnixNano()))
			// #nosec G304 G703
			existing, readErr := os.ReadFile(path)
			if readErr == nil {
				_ = os.WriteFile(backupPath, existing, 0600) // #nosec G703
			}
		}
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to atomically replace vault file: %w", err)
	}

	// Sync parent directory
	// #nosec G304 G703
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}

	return nil
}

// getBackupDir returns the backups directory for the given profile.
func getBackupDir(profile string) (string, error) {
	dir, err := config.GetConfigDir()
	if err != nil {
		return "", err
	}
	if profile == "" {
		profile = "default"
	}
	return filepath.Join(dir, "backups", profile), nil
}

// WrapMasterKey encrypts masterKey using an AES-256-GCM key derived from
// the BIP39 mnemonic and a random Argon2id salt. Returns the Slot1Header.
// The key material is zeroed from Go memory after use (best-effort).
func WrapMasterKey(mnemonic string, masterKey []byte) (*Slot1Header, error) {
	if len(masterKey) == 0 {
		return nil, fmt.Errorf("master key cannot be empty")
	}

	// Generate fresh Argon2id salt
	salt, err := crypto.GenerateArgon2Salt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate argon2 salt: %w", err)
	}

	// Derive wrapping key from mnemonic via Argon2id
	passphrase := crypto.MnemonicToPassphrase(mnemonic)
	wrappingKey, err := crypto.Argon2idKey(passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive wrapping key: %w", err)
	}
	defer zeroBytes(wrappingKey)

	// AES-256-GCM wrap the master key
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher for key wrapping: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM for key wrapping: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce for key wrapping: %w", err)
	}

	// wrapped = nonce || GCM ciphertext
	ciphertext := gcm.Seal(nonce, nonce, masterKey, nil)

	return &Slot1Header{
		Argon2Salt: salt,
		WrappedKey: ciphertext,
	}, nil
}

// UnwrapMasterKey decrypts the wrapped master key from a Slot1Header using the
// provided BIP39 mnemonic and Argon2id KDF.
// The derived wrapping key is zeroed after use (best-effort).
func UnwrapMasterKey(mnemonic string, slot1 *Slot1Header) ([]byte, error) {
	if slot1 == nil {
		return nil, fmt.Errorf("slot1 header is nil — vault has no recovery key enrolled")
	}
	if len(slot1.WrappedKey) == 0 {
		return nil, fmt.Errorf("slot1 wrapped key is empty")
	}

	// Validate mnemonic checksum before expensive KDF
	if !crypto.MnemonicValid(mnemonic) {
		return nil, fmt.Errorf("recovery mnemonic checksum failed — please verify all 24 words carefully")
	}

	passphrase := crypto.MnemonicToPassphrase(mnemonic)
	wrappingKey, err := crypto.Argon2idKey(passphrase, slot1.Argon2Salt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive wrapping key: %w", err)
	}
	defer zeroBytes(wrappingKey)

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher for key unwrapping: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM for key unwrapping: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(slot1.WrappedKey) < nonceSize {
		return nil, fmt.Errorf("slot1 wrapped key is too short")
	}

	nonce := slot1.WrappedKey[:nonceSize]
	wrapped := slot1.WrappedKey[nonceSize:]

	masterKey, err := gcm.Open(nil, nonce, wrapped, nil)
	if err != nil {
		return nil, fmt.Errorf("recovery key decryption failed — wrong mnemonic?")
	}

	return masterKey, nil
}

// MigrateStagePath returns the path to the atomic staging file used during
// multi-profile migration. If this file exists on startup, migration is incomplete.
func MigrateStagePath() (string, error) {
	dir, err := config.GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ".migrate_v2_stage"), nil
}

// MigrateStageWrite writes the migration stage marker with the given payload.
// This is used by the atomic two-phase commit for safe multi-profile migration.
func MigrateStageWrite(stage string) error {
	path, err := MigrateStagePath()
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(stage), 0600)
}

// MigrateStageRead reads the migration stage marker, returning "" if not present.
func MigrateStageRead() (string, error) {
	path, err := MigrateStagePath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path) // #nosec G304
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// MigrateStageRemove removes the migration stage marker once migration is complete.
func MigrateStageRemove() error {
	path, err := MigrateStagePath()
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// zeroBytes overwrites a byte slice with zeros to reduce the window
// in which sensitive key material resides in process memory.
// This is best-effort; Go's GC may have already copied the slice.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
