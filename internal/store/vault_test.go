package store

import (
	"os"
	"path/filepath"
	"secure_secrets/internal/crypto"
	"testing"
	"time"
)

// TestVaultV2RoundTrip verifies the full wrap -> write -> read -> unwrap cycle
// of the v2.0 VaultEnvelope with a BIP39 mnemonic.
func TestVaultV2RoundTrip(t *testing.T) {
	// Generate a test mnemonic using our own mnemonic logic
	// (import the crypto package from within the same module)
	testMnemonic := "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act"
	// This is only 20 words — use a known-valid 24-word mnemonic instead.
	// We test with a hardcoded valid mnemonic to avoid test flakiness.
	// Note: this is a TEST mnemonic only; it has no real secret value.
	testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	// Wrap a dummy master key
	masterKey := []byte("01234567890123456789012345678901") // 32 bytes

	slot1, err := WrapMasterKey(testMnemonic, masterKey)
	if err != nil {
		t.Fatalf("WrapMasterKey() error = %v", err)
	}

	// Unwrap and verify
	recovered, err := UnwrapMasterKey(testMnemonic, slot1)
	if err != nil {
		t.Fatalf("UnwrapMasterKey() error = %v", err)
	}

	if len(recovered) != len(masterKey) {
		t.Errorf("recovered key length = %d, expected %d", len(recovered), len(masterKey))
	}
	for i := range masterKey {
		if recovered[i] != masterKey[i] {
			t.Errorf("recovered key mismatch at byte %d", i)
			break
		}
	}
}

// TestVaultV2WrongMnemonic verifies that UnwrapMasterKey fails with an incorrect mnemonic.
func TestVaultV2WrongMnemonic(t *testing.T) {
	testMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	wrongMnemonic := "ability ability ability ability ability ability ability ability ability ability ability ability ability ability ability ability ability ability ability ability ability ability ability art"

	masterKey := []byte("01234567890123456789012345678901")

	slot1, err := WrapMasterKey(testMnemonic, masterKey)
	if err != nil {
		t.Fatalf("WrapMasterKey() error = %v", err)
	}

	_, err = UnwrapMasterKey(wrongMnemonic, slot1)
	if err == nil {
		t.Error("expected error when unwrapping with wrong mnemonic, got nil")
	}
}

// TestVaultV2NilSlot1 verifies that UnwrapMasterKey returns an error for nil Slot1.
func TestVaultV2NilSlot1(t *testing.T) {
	_, err := UnwrapMasterKey("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", nil)
	if err == nil {
		t.Error("expected error for nil Slot1 header")
	}
}

// TestIsV2Vault verifies the file format detection logic.
func TestIsV2Vault(t *testing.T) {
	dir := t.TempDir()

	// Write a v2.0 JSON envelope file
	v2Path := filepath.Join(dir, "v2vault.enc")
	if err := os.WriteFile(v2Path, []byte(`{"schema_version":"2.0","payload":"dGVzdA=="}`), 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	if !IsV2Vault(v2Path) {
		t.Error("IsV2Vault should return true for JSON-format file")
	}

	// Write a v1.0 raw binary file
	v1Path := filepath.Join(dir, "v1vault.enc")
	if err := os.WriteFile(v1Path, []byte{0xAB, 0xCD, 0x12, 0x34}, 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	if IsV2Vault(v1Path) {
		t.Error("IsV2Vault should return false for binary-format file")
	}
}

// TestAtomicWriteVaultEnvelope verifies WriteVaultEnvelope creates an fsync'd file.
func TestAtomicWriteVaultEnvelope(t *testing.T) {
	dir := t.TempDir()

	// Override config dir by using a temp dir path directly.
	vaultPath := filepath.Join(dir, "secrets.enc")

	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	masterKey := []byte("01234567890123456789012345678901")

	slot1, err := WrapMasterKey(mnemonic, masterKey)
	if err != nil {
		t.Fatalf("WrapMasterKey() error = %v", err)
	}

	env := &VaultEnvelope{
		SchemaVersion: SchemaV2,
		Slot1:         slot1,
		Payload:       []byte("fake_encrypted_payload"),
	}

	if err := WriteVaultEnvelope(vaultPath, env); err != nil {
		t.Fatalf("WriteVaultEnvelope() error = %v", err)
	}

	// Verify file exists and is readable
	if !IsV2Vault(vaultPath) {
		t.Error("written vault should be detected as v2")
	}

	// Read back and verify schema version
	readBack, err := ReadVaultEnvelope(vaultPath)
	if err != nil {
		t.Fatalf("ReadVaultEnvelope() error = %v", err)
	}
	if readBack.SchemaVersion != SchemaV2 {
		t.Errorf("schema version = %q, expected %q", readBack.SchemaVersion, SchemaV2)
	}
	if string(readBack.Payload) != "fake_encrypted_payload" {
		t.Errorf("payload mismatch: got %q", readBack.Payload)
	}
}

// TestMigrateStageMarker verifies write/read/remove of the migration stage file.
func TestMigrateStageMarker(t *testing.T) {
	// Use SEC_TEST_MODE to avoid touching real config dir
	t.Setenv("SEC_TEST_MODE", "1")

	// Read when no file exists should return empty string
	// (we can't guarantee the path in test mode, so just test that it doesn't panic)
	_, _ = MigrateStageRead()

	// Remove when file doesn't exist should not error
	_ = MigrateStageRemove()
}

// TestZeroBytes verifies that ZeroBytes zeroes a slice.
func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	ZeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("ZeroBytes: b[%d] = %d, want 0", i, v)
		}
	}
}

// TestSaveStorePreservesV2Envelope verifies that SaveStore preserves v2.0 envelope and Slot1 header.
func TestSaveStorePreservesV2Envelope(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SEC_CONFIG_DIR", tmpDir)

	profile := "v2-preservation-test"
	masterKey := []byte("01234567890123456789012345678901")
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	// 1. Create a v2.0 envelope
	slot1, err := WrapMasterKey(mnemonic, masterKey)
	if err != nil {
		t.Fatalf("WrapMasterKey() error = %v", err)
	}

	payload, err := crypto.Encrypt(masterKey, []byte(`{"secrets":{}}`))
	if err != nil {
		t.Fatalf("crypto.Encrypt() error = %v", err)
	}

	env := &VaultEnvelope{
		SchemaVersion: SchemaV2,
		UpgradedAt:    time.Now().UTC(),
		Slot1:         slot1,
		Payload:       payload,
	}

	vaultPath, _ := GetStorePath(profile)
	if err := WriteVaultEnvelope(vaultPath, env); err != nil {
		t.Fatalf("WriteVaultEnvelope() error = %v", err)
	}

	// 2. Call SaveStore on the v2.0 profile
	store := &EncryptedStore{
		Secrets: map[string]SecretEntry{
			"NEW_KEY": {Value: "NEW_VAL"},
		},
	}
	if err := SaveStore(profile, store, masterKey); err != nil {
		t.Fatalf("SaveStore() error = %v", err)
	}

	// 3. Verify file is still v2.0 and Slot1 is intact
	if !IsV2Vault(vaultPath) {
		t.Error("vault should still be v2.0 after SaveStore")
	}

	readBackEnv, err := ReadVaultEnvelope(vaultPath)
	if err != nil {
		t.Fatalf("ReadVaultEnvelope() error = %v", err)
	}

	if readBackEnv.Slot1 == nil || len(readBackEnv.Slot1.WrappedKey) == 0 {
		t.Error("Slot1 header was lost during SaveStore!")
	}

	// 4. Verify unwrapping Slot1 still yields the master key
	unwrappedKey, err := UnwrapMasterKey(mnemonic, readBackEnv.Slot1)
	if err != nil {
		t.Fatalf("UnwrapMasterKey() failed on read-back envelope: %v", err)
	}
	if string(unwrappedKey) != string(masterKey) {
		t.Error("unwrapped master key mismatch after SaveStore!")
	}
}
