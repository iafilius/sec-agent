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
	"strings"
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
	Path         string // absolute path to the .enc file
	Profile      string // derived profile name (e.g. "default", "dev", "prod")
	IsV2         bool   // true if in JSON envelope format (starts with '{')
	HasSlot1     bool   // true if Slot1 BIP39 recovery key is enrolled and non-empty
	NestingDepth int    // envelope nesting depth (0 for non-v2, 1 for clean v2.0, >1 for nested)
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

		isV2 := IsV2Vault(absPath)
		hasSlot1 := false
		nestingDepth := 0
		if isV2 {
			nestingDepth = InspectVaultNesting(absPath)
			if env, err := ReadVaultEnvelope(absPath); err == nil && env != nil {
				hasSlot1 = env.HasSlot1()
			}
		}

		vaults = append(vaults, VaultFileInfo{
			Path:         absPath,
			Profile:      profile,
			IsV2:         isV2,
			HasSlot1:     hasSlot1,
			NestingDepth: nestingDepth,
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
	// MasterKeySHA256 is the first 16 hex characters of SHA-256(masterKey)
	MasterKeySHA256 string `json:"master_key_sha256,omitempty"`
	// Slot1 is the BIP39/Argon2id recovery slot.
	// Slot0 (Touch ID) master key is kept in the macOS Keychain only (not on disk).
	Slot1 *Slot1Header `json:"slot1,omitempty"`
	// Payload is the existing AES-GCM ciphertext: encrypt(masterKey, json(EncryptedStore)).
	// This is identical to the v1.0 raw file content.
	Payload []byte `json:"payload"`
}

// HasSlot1 returns true if the envelope contains an enrolled, non-empty Slot 1 recovery key.
func (env *VaultEnvelope) HasSlot1() bool {
	return env != nil && env.Slot1 != nil && len(env.Slot1.WrappedKey) > 0
}

// IsV2Vault returns true if the file at path is a v2.0 VaultEnvelope.
func IsV2Vault(path string) bool {
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || data[0] != '{' {
		return false
	}
	var env VaultEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return false
	}
	return env.SchemaVersion == SchemaV2
}

// InspectVaultNesting reads the vault file at path and counts the envelope nesting depth.
// Returns 0 if not a v2 vault or unreadable, 1 for a normal clean v2 vault, >1 if nested.
func InspectVaultNesting(path string) int {
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || data[0] != '{' {
		return 0
	}
	depth := 0
	curr := data
	for len(curr) > 0 && curr[0] == '{' {
		var env VaultEnvelope
		if jsonErr := json.Unmarshal(curr, &env); jsonErr != nil || env.Payload == nil {
			break
		}
		depth++
		curr = env.Payload
	}
	return depth
}

// FlattenVaultFile audits a vault file, creates a backup if nested (depth > 1),
// and atomically rewrites it as a clean single-layer v2.0 envelope.
// Returns the original nesting depth.
func FlattenVaultFile(path string) (int, error) {
	depth := InspectVaultNesting(path)
	if depth <= 1 {
		return depth, nil
	}

	// 1. Read outer envelope to preserve slot1 and metadata
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		return depth, fmt.Errorf("failed to read vault file: %w", err)
	}

	var outerEnv VaultEnvelope
	if err := json.Unmarshal(data, &outerEnv); err != nil {
		return depth, fmt.Errorf("failed to parse outer envelope: %w", err)
	}

	// 2. Peel down to the innermost payload
	currPayload := outerEnv.Payload
	for len(currPayload) > 0 && currPayload[0] == '{' {
		var innerEnv VaultEnvelope
		if jsonErr := json.Unmarshal(currPayload, &innerEnv); jsonErr == nil && len(innerEnv.Payload) > 0 {
			currPayload = innerEnv.Payload
		} else {
			break
		}
	}

	// 3. Create backup copy with .bak_nested extension
	bakPath := path + ".bak_nested"
	// #nosec G304 G703
	if err := os.WriteFile(bakPath, data, 0600); err != nil {
		return depth, fmt.Errorf("failed to create backup file %s: %w", bakPath, err)
	}

	// 4. Assemble clean single-layer envelope
	cleanEnv := &VaultEnvelope{
		SchemaVersion:   SchemaV2,
		UpgradedAt:      outerEnv.UpgradedAt,
		MasterKeySHA256: outerEnv.MasterKeySHA256,
		Slot1:           outerEnv.Slot1,
		Payload:         currPayload,
	}

	// 5. Write clean envelope
	if err := WriteVaultEnvelope(path, cleanEnv); err != nil {
		return depth, fmt.Errorf("failed to write flattened vault: %w", err)
	}

	return depth, nil
}

// ReadVaultEnvelope reads and parses the v2.0 JSON envelope from disk.
// It defensively peels any nested JSON envelopes down to the innermost ciphertext payload,
// preserving the outermost envelope's recovery slots and schema metadata.
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

	// Defensively peel nested envelopes in a loop
	peeled := env.Payload
	for len(peeled) > 0 && peeled[0] == '{' {
		var inner VaultEnvelope
		if jsonErr := json.Unmarshal(peeled, &inner); jsonErr == nil && len(inner.Payload) > 0 {
			peeled = inner.Payload
		} else {
			break
		}
	}
	env.Payload = peeled
	return &env, nil
}

// WriteVaultEnvelope atomically writes a v2.0 VaultEnvelope to disk.
// Uses the same temp-file + fsync + rename pattern as SaveStore for power-loss safety.
func WriteVaultEnvelope(path string, env *VaultEnvelope) error {
	// Safeguard: Ensure env.Payload is not double-wrapped JSON text (peel iteratively)
	for env != nil && len(env.Payload) > 0 && env.Payload[0] == '{' {
		var innerEnv VaultEnvelope
		if jsonErr := json.Unmarshal(env.Payload, &innerEnv); jsonErr == nil && len(innerEnv.Payload) > 0 {
			env.Payload = innerEnv.Payload
		} else {
			break
		}
	}

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

	// Backup existing vault to snapshots before overwriting
	if _, statErr := os.Stat(path); statErr == nil {
		prof := "default"
		base := filepath.Base(path)
		if strings.HasPrefix(base, "secrets_") && strings.HasSuffix(base, ".enc") {
			prof = strings.TrimSuffix(strings.TrimPrefix(base, "secrets_"), ".enc")
		}
		snapDir, err := GetSnapshotDir(prof)
		if err == nil {
			_ = os.MkdirAll(snapDir, 0700)
			now := time.Now()
			snapID := fmt.Sprintf("snap-%s-%d", now.Format("20060102-150405"), now.Nanosecond()/1e6)
			snapEncPath := filepath.Join(snapDir, fmt.Sprintf("%s.enc", snapID))
			snapMetaPath := filepath.Join(snapDir, fmt.Sprintf("%s.meta.json", snapID))

			// #nosec G304 G703
			existing, readErr := os.ReadFile(path)
			if readErr == nil {
				_ = os.WriteFile(snapEncPath, existing, 0600) // #nosec G703
				meta := SnapshotMeta{
					ID:            snapID,
					Profile:       prof,
					CreatedAt:     now,
					TriggerReason: "auto-presave",
					Actor:         "system",
					SchemaVersion: "2.0",
					SecretCount:   -1,
					FilePath:      snapEncPath,
					Comment:       "Automatic pre-save vault snapshot",
				}
				metaBytes, _ := json.MarshalIndent(meta, "", "  ")
				_ = os.WriteFile(snapMetaPath, metaBytes, 0600)
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
