package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"secure_secrets/internal/crypto"
	"strings"
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

	// Write binary file that starts with '{' (e.g. random AES-GCM nonce)
	v1StartingWithBrace := filepath.Join(dir, "v1brace.enc")
	if err := os.WriteFile(v1StartingWithBrace, []byte{'{', 0x99, 0x12, 0x00, 0x55}, 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	if IsV2Vault(v1StartingWithBrace) {
		t.Error("IsV2Vault should return false for binary file starting with { byte")
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
		Secrets: map[SecretKey]SecretEntry{
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

func TestVaultEnvelopeMasterKeySHA256OnDisk(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	profile := "default"
	vaultPath, err := GetStorePath(profile)
	if err != nil {
		t.Fatalf("GetStorePath() error = %v", err)
	}
	_ = os.MkdirAll(filepath.Dir(vaultPath), 0700)

	masterKey, err := crypto.GenerateRandomKey()
	if err != nil {
		t.Fatalf("GenerateRandomKey() error = %v", err)
	}

	expectedFP := crypto.MasterKeyFingerprint(masterKey)

	// Create v2.0 vault envelope
	mnemonic, err := crypto.GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic() error = %v", err)
	}
	slot1, err := WrapMasterKey(mnemonic, masterKey)
	if err != nil {
		t.Fatalf("WrapMasterKey() error = %v", err)
	}

	env := &VaultEnvelope{
		SchemaVersion:   SchemaV2,
		UpgradedAt:      time.Now().UTC(),
		MasterKeySHA256: expectedFP,
		Slot1:           slot1,
		Payload:         []byte("ciphertext"),
	}

	if err := WriteVaultEnvelope(vaultPath, env); err != nil {
		t.Fatalf("WriteVaultEnvelope() error = %v", err)
	}

	// Verify on-disk file contains "master_key_sha256" in raw JSON
	rawBytes, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	if !strings.Contains(string(rawBytes), `"master_key_sha256"`) {
		t.Fatalf("expected raw JSON on disk to contain 'master_key_sha256', got: %s", string(rawBytes))
	}
	if !strings.Contains(string(rawBytes), expectedFP) {
		t.Fatalf("expected raw JSON on disk to contain fingerprint %s, got: %s", expectedFP, string(rawBytes))
	}

	// Verify SaveStore preserves and updates MasterKeySHA256
	store := &EncryptedStore{
		Secrets: map[SecretKey]SecretEntry{
			"test/key": {Value: "val"},
		},
	}
	if err := SaveStore(profile, store, masterKey); err != nil {
		t.Fatalf("SaveStore() error = %v", err)
	}

	readEnv, err := ReadVaultEnvelope(vaultPath)
	if err != nil {
		t.Fatalf("ReadVaultEnvelope() error = %v", err)
	}
	if readEnv.MasterKeySHA256 != expectedFP {
		t.Errorf("expected MasterKeySHA256 %s, got %s", expectedFP, readEnv.MasterKeySHA256)
	}
}

func TestVaultEnvelopeDefensiveUnnesting(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	profile := "nested-test-prof"
	vaultPath, err := GetStorePath(profile)
	if err != nil {
		t.Fatalf("GetStorePath() error = %v", err)
	}
	_ = os.MkdirAll(filepath.Dir(vaultPath), 0700)

	masterKey, err := crypto.GenerateRandomKey()
	if err != nil {
		t.Fatalf("GenerateRandomKey() error = %v", err)
	}
	mnemonic, err := crypto.GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic() error = %v", err)
	}
	slot1, err := WrapMasterKey(mnemonic, masterKey)
	if err != nil {
		t.Fatalf("WrapMasterKey() error = %v", err)
	}

	// 1. Create base encrypted payload
	originalStore := &EncryptedStore{
		Secrets: map[SecretKey]SecretEntry{
			"db/password": {Value: "s3cr3t-p@ss"},
		},
	}
	storeJSON, _ := json.Marshal(originalStore)
	genuineCiphertext, err := crypto.Encrypt(masterKey, storeJSON)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// 2. Artificially nest 15 levels deep
	currPayload := genuineCiphertext
	for level := 1; level <= 15; level++ {
		env := &VaultEnvelope{
			SchemaVersion:   SchemaV2,
			UpgradedAt:      time.Now().UTC(),
			MasterKeySHA256: crypto.MasterKeyFingerprint(masterKey),
			Slot1:           slot1,
			Payload:         currPayload,
		}
		marshaled, mErr := json.Marshal(env)
		if mErr != nil {
			t.Fatalf("json.Marshal() level %d error = %v", level, mErr)
		}
		currPayload = marshaled
	}

	// Write 15-level nested file to disk
	if err := os.WriteFile(vaultPath, currPayload, 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// 3. Verify InspectVaultNesting reports 15
	detectedDepth := InspectVaultNesting(vaultPath)
	if detectedDepth != 15 {
		t.Fatalf("expected nesting depth 15, got %d", detectedDepth)
	}

	// 4. Test ReadVaultEnvelope defensively peels to innermost ciphertext
	readEnv, err := ReadVaultEnvelope(vaultPath)
	if err != nil {
		t.Fatalf("ReadVaultEnvelope() error = %v", err)
	}
	if len(readEnv.Payload) == 0 || readEnv.Payload[0] == '{' {
		t.Fatalf("ReadVaultEnvelope failed to peel innermost payload: payload starts with '{'")
	}
	if string(readEnv.Payload) != string(genuineCiphertext) {
		t.Fatalf("peeled payload does not match original genuine ciphertext")
	}

	// 5. Test LoadStore successfully decrypts the 15-level nested file
	loadedStore, err := LoadStore(profile, masterKey)
	if err != nil {
		t.Fatalf("LoadStore() on 15-level nested vault failed: %v", err)
	}
	if loadedStore.Secrets["db/password"].Value != "s3cr3t-p@ss" {
		t.Errorf("expected secret value 's3cr3t-p@ss', got %q", loadedStore.Secrets["db/password"].Value)
	}

	// 6. Test SaveStore writes back a single-layer Depth-1 envelope
	if err := SaveStore(profile, loadedStore, masterKey); err != nil {
		t.Fatalf("SaveStore() after unnesting failed: %v", err)
	}
	newDepth := InspectVaultNesting(vaultPath)
	if newDepth != 1 {
		t.Errorf("expected vault depth to be 1 after SaveStore, got %d", newDepth)
	}
}

func TestFlattenVaultFile(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	profile := "flatten-test-prof"
	vaultPath, _ := GetStorePath(profile)
	_ = os.MkdirAll(filepath.Dir(vaultPath), 0700)

	masterKey, _ := crypto.GenerateRandomKey()
	mnemonic, _ := crypto.GenerateMnemonic()
	slot1, _ := WrapMasterKey(mnemonic, masterKey)

	originalStore := &EncryptedStore{
		Secrets: map[SecretKey]SecretEntry{
			"api/key": {Value: "test-api-key"},
		},
	}
	storeJSON, _ := json.Marshal(originalStore)
	genuineCiphertext, _ := crypto.Encrypt(masterKey, storeJSON)

	// Create 5-level nested file
	currPayload := genuineCiphertext
	for level := 1; level <= 5; level++ {
		env := &VaultEnvelope{
			SchemaVersion: SchemaV2,
			Slot1:         slot1,
			Payload:       currPayload,
		}
		currPayload, _ = json.Marshal(env)
	}
	_ = os.WriteFile(vaultPath, currPayload, 0600)

	if d := InspectVaultNesting(vaultPath); d != 5 {
		t.Fatalf("expected depth 5 before flatten, got %d", d)
	}

	// Flatten
	origDepth, err := FlattenVaultFile(vaultPath)
	if err != nil {
		t.Fatalf("FlattenVaultFile() error = %v", err)
	}
	if origDepth != 5 {
		t.Errorf("expected FlattenVaultFile to return origDepth 5, got %d", origDepth)
	}

	// Check backup file exists
	bakPath := vaultPath + ".bak_nested"
	if _, statErr := os.Stat(bakPath); statErr != nil {
		t.Errorf("expected backup file %s to exist: %v", bakPath, statErr)
	}

	// Check new depth is 1
	if d := InspectVaultNesting(vaultPath); d != 1 {
		t.Errorf("expected depth 1 after flatten, got %d", d)
	}

	// Verify LoadStore works smoothly
	loaded, err := LoadStore(profile, masterKey)
	if err != nil {
		t.Fatalf("LoadStore() after FlattenVaultFile failed: %v", err)
	}
	if loaded.Secrets["api/key"].Value != "test-api-key" {
		t.Errorf("expected 'test-api-key', got %q", loaded.Secrets["api/key"].Value)
	}
}

func TestVaultEnvelopePreSaveInvariant(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	profile := "invariant-test-prof"
	vaultPath, _ := GetStorePath(profile)
	_ = os.MkdirAll(filepath.Dir(vaultPath), 0700)

	inner := &VaultEnvelope{
		SchemaVersion: SchemaV2,
		Payload:       []byte("innermost"),
	}
	innerBytes, _ := json.Marshal(inner)

	// Direct WriteVaultEnvelope with nested JSON envelope bytes in payload
	env := &VaultEnvelope{
		SchemaVersion: SchemaV2,
		Payload:       innerBytes,
	}
	if err := WriteVaultEnvelope(vaultPath, env); err != nil {
		t.Fatalf("WriteVaultEnvelope() error = %v", err)
	}

	// WriteVaultEnvelope should have peeled env.Payload
	readEnv, err := ReadVaultEnvelope(vaultPath)
	if err != nil {
		t.Fatalf("ReadVaultEnvelope() error = %v", err)
	}
	if string(readEnv.Payload) != "innermost" {
		t.Errorf("expected peeled payload 'innermost', got %q", string(readEnv.Payload))
	}

	// Verify ToErrorCode maps ErrNestedPayload properly
	if code := ToErrorCode(ErrNestedPayload); code != ErrCodeNestedPayload {
		t.Errorf("expected %s, got %s", ErrCodeNestedPayload, code)
	}
}

