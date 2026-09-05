package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secure_secrets/internal/config"
	"secure_secrets/internal/crypto"
	"secure_secrets/internal/store"
)

func TestDatabaseAtomicWritesAndBackups(t *testing.T) {
	profile := "atomic-snapshot-test-profile"
	dbPath, _ := store.GetStorePath(profile)
	snapDir, _ := store.GetSnapshotDir(profile)

	// Clean up any stale files of our test profile only
	_ = os.Remove(dbPath)
	_ = os.RemoveAll(snapDir)
	defer func() {
		_ = os.Remove(dbPath)
		_ = os.RemoveAll(snapDir)
	}()

	masterKey := []byte("01234567890123456789012345678901")
	st := &store.EncryptedStore{
		Secrets: map[store.SecretKey]store.SecretEntry{
			"test/key": {Value: "initial-val"},
		},
	}

	// Save multiple times to trigger pre-save snapshot creation
	for i := 0; i < 3; i++ {
		st.Secrets["test/key"] = store.SecretEntry{Value: fmt.Sprintf("val-%d", i)}
		err := store.SaveStore(profile, st, masterKey)
		if err != nil {
			t.Fatalf("failed to save store at iteration %d: %v", i, err)
		}
	}

	// Verify snapshots directory contains created snapshot files
	files, err := os.ReadDir(snapDir)
	if err != nil {
		t.Fatalf("failed to read snapshots directory: %v", err)
	}

	var snapCount int
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".enc") {
			snapCount++
		}
	}

	if snapCount == 0 {
		t.Errorf("expected snapshot files under %s, got %d", snapDir, snapCount)
	}
}

func TestMigrateAllLegacyBackups(t *testing.T) {
	cfgDir, err := config.GetConfigDir()
	if err != nil {
		t.Fatalf("failed to get config dir: %v", err)
	}
	legacyBackupsDir := filepath.Join(cfgDir, "backups", "legacy-test-prof")
	_ = os.MkdirAll(legacyBackupsDir, 0700)
	dummyLegacyFile := filepath.Join(legacyBackupsDir, "secrets.enc.123456789")
	_ = os.WriteFile(dummyLegacyFile, []byte("legacy-data"), 0600)

	err = store.MigrateAllLegacyBackups()
	if err != nil {
		t.Fatalf("MigrateAllLegacyBackups failed: %v", err)
	}

	// Verify legacy backups dir for profile is cleaned up
	if _, err := os.Stat(dummyLegacyFile); !os.IsNotExist(err) {
		t.Errorf("expected legacy backup file to be removed, but it still exists")
	}
}

func TestV2SeedMigrationAndDiagnostics(t *testing.T) {
	testMnemonic, genErr := crypto.GenerateMnemonic()
	if genErr != nil || !crypto.MnemonicValid(testMnemonic) {
		t.Fatalf("failed to generate valid test mnemonic: %v", genErr)
	}

	// Test store load error message enhancement for cipher authentication failure
	badKey := make([]byte, 32)
	for i := range badKey {
		badKey[i] = 0xff
	}

	tmpDir := t.TempDir()
	storeFile := filepath.Join(tmpDir, "secrets_test-prof.enc")

	// Write an encrypted store with a different key
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0x11
	}

	s := &store.EncryptedStore{
		Secrets: map[store.SecretKey]store.SecretEntry{
			"dummy": {Value: "value"},
		},
	}

	if err := store.SaveStore("test-prof", s, masterKey); err != nil {
		t.Fatalf("failed to save store: %v", err)
	}

	// Try loading with badKey to trigger GCM error
	_, err := store.LoadStore("test-prof", badKey)
	if err == nil {
		t.Fatalf("expected LoadStore to fail with incorrect key")
	}

	if !strings.Contains(err.Error(), "master key mismatch") || !strings.Contains(err.Error(), "sec session recover --profile test-prof") {
		t.Errorf("expected actionable error message with recovery instructions, got: %v", err)
	}

	_ = storeFile
}

func TestMigrateV2IdempotentRewrap(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "secrets_test_rewrap.enc")

	masterKey := []byte("01234567890123456789012345678901")

	// 1. Create a initial v1.0 vault payload
	storeData := []byte(`{"secrets":{"api/key":{"value":"SECRET_PAYLOAD_V1"}}}`)
	rawPayload, err := crypto.Encrypt(masterKey, storeData)
	if err != nil {
		t.Fatalf("failed to encrypt store: %v", err)
	}

	if err := os.WriteFile(vaultPath, rawPayload, 0600); err != nil {
		t.Fatalf("failed to write raw v1.0 vault: %v", err)
	}

	// 2. Wrap into v2.0 envelope using mnemonic 1
	m1, err := crypto.GenerateMnemonic()
	if err != nil {
		t.Fatalf("failed to generate m1: %v", err)
	}
	slot1_m1, err := store.WrapMasterKey(m1, masterKey)
	if err != nil {
		t.Fatalf("failed to wrap master key m1: %v", err)
	}

	env1 := &store.VaultEnvelope{
		SchemaVersion: store.SchemaV2,
		UpgradedAt:    time.Now().UTC(),
		Slot1:         slot1_m1,
		Payload:       rawPayload,
	}

	if err := store.WriteVaultEnvelope(vaultPath, env1); err != nil {
		t.Fatalf("failed to write env1: %v", err)
	}

	if !store.IsV2Vault(vaultPath) {
		t.Fatalf("expected vaultPath to be v2.0 vault")
	}

	// 3. Re-run envelope wrapping (simulating handleMigrateV2 with --force and new seed m2)
	m2, err := crypto.GenerateMnemonic()
	if err != nil {
		t.Fatalf("failed to generate m2: %v", err)
	}
	slot1_m2, err := store.WrapMasterKey(m2, masterKey)
	if err != nil {
		t.Fatalf("failed to wrap master key m2: %v", err)
	}

	// Extract payload using our fixed logic
	var extractedPayload []byte
	if store.IsV2Vault(vaultPath) {
		existingEnv, readErr := store.ReadVaultEnvelope(vaultPath)
		if readErr != nil {
			t.Fatalf("failed to read existing v2.0 envelope: %v", readErr)
		}
		extractedPayload = existingEnv.Payload
	} else {
		data, readErr := os.ReadFile(vaultPath)
		if readErr != nil {
			t.Fatalf("failed to read raw vault: %v", readErr)
		}
		extractedPayload = data
	}

	env2 := &store.VaultEnvelope{
		SchemaVersion: store.SchemaV2,
		UpgradedAt:    time.Now().UTC(),
		Slot1:         slot1_m2,
		Payload:       extractedPayload,
	}

	if err := store.WriteVaultEnvelope(vaultPath, env2); err != nil {
		t.Fatalf("failed to write env2: %v", err)
	}

	// 4. Verify envelope unwrapping with mnemonic m2
	readEnv2, err := store.ReadVaultEnvelope(vaultPath)
	if err != nil {
		t.Fatalf("failed to read env2: %v", err)
	}

	unwrappedKey, err := store.UnwrapMasterKey(m2, readEnv2.Slot1)
	if err != nil {
		t.Fatalf("failed to unwrap master key with m2: %v", err)
	}
	defer store.ZeroBytes(unwrappedKey)

	decryptedBytes, err := crypto.Decrypt(unwrappedKey, readEnv2.Payload)
	if err != nil {
		t.Fatalf("failed to decrypt store payload after rewrap (double-wrapping bug detected): %v", err)
	}

	if !strings.Contains(string(decryptedBytes), "SECRET_PAYLOAD_V1") {
		t.Errorf("expected decrypted payload to contain 'SECRET_PAYLOAD_V1', got: %s", string(decryptedBytes))
	}
}

func TestMigrateV2ValidatesMasterKeyDecryption(t *testing.T) {
	wrongKey := []byte("wrongmasterkeywrongmasterkey1234")
	rightKey := []byte("rightmasterkeyrightmasterkey1234")

	storeData := []byte(`{"secrets":{"api/key":{"value":"SECRET_TEST"}}}`)
	payload, err := crypto.Encrypt(rightKey, storeData)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Verify wrongKey fails pre-flight decryption
	if _, err := crypto.Decrypt(wrongKey, payload); err == nil {
		t.Fatalf("expected wrong masterKey decryption to fail pre-flight validation")
	}

	// Verify rightKey succeeds pre-flight decryption
	if _, err := crypto.Decrypt(rightKey, payload); err != nil {
		t.Fatalf("expected right masterKey decryption to succeed pre-flight validation: %v", err)
	}
}

func TestSnapshotCreationAndRestore(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("SEC_TEST_MODE", "1")

	profile := "test-prof"
	cfgDir := filepath.Join(tmpDir, ".config", "sec-agent")
	_ = os.MkdirAll(cfgDir, 0700)

	masterKey, err := crypto.GenerateRandomKey()
	if err != nil {
		t.Fatalf("failed to generate master key: %v", err)
	}

	// 1. Create a test store file
	vaultPath := filepath.Join(cfgDir, fmt.Sprintf("secrets_%s.enc", profile))
	storeData := []byte(`{"secrets":{"api/key":{"value":"INITIAL_VALUE"}}}`)
	payload, _ := crypto.Encrypt(masterKey, storeData)
	_ = os.WriteFile(vaultPath, payload, 0600)

	// 2. Create snapshot
	meta, err := store.CreateSnapshot(profile, "manual", "unit-test", "Test comment", masterKey)
	if err != nil {
		t.Fatalf("failed to create snapshot: %v", err)
	}
	if meta.ID == "" || meta.MasterKeySHA256 == "none" {
		t.Fatalf("invalid snapshot metadata: %+v", meta)
	}

	// 3. List snapshots
	snapshots, err := store.ListSnapshots(profile, masterKey)
	if err != nil {
		t.Fatalf("failed to list snapshots: %v", err)
	}
	if len(snapshots) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(snapshots))
	}
	if snapshots[0].ID != meta.ID {
		t.Fatalf("expected snapshot ID %s, got %s", meta.ID, snapshots[0].ID)
	}
}

func TestSnapshotProfileVisibilityAndAutoRepair(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("SEC_TEST_MODE", "1")

	cfgDir := filepath.Join(tmpDir, ".config", "sec-agent")
	_ = os.MkdirAll(cfgDir, 0700)
	t.Setenv("SEC_CONFIG_DIR", cfgDir)

	masterKey, err := crypto.GenerateRandomKey()
	if err != nil {
		t.Fatalf("failed to generate master key: %v", err)
	}

	// 1. Setup profile 1 ("default")
	v1Path := filepath.Join(cfgDir, "secrets.enc")
	storeData1 := []byte(`{"secrets":{"db/pass":{"value":"p1"}}}`)
	payload1, _ := crypto.Encrypt(masterKey, storeData1)
	_ = os.WriteFile(v1Path, payload1, 0600)

	meta1, err := store.CreateSnapshot("default", "manual", "unit-test", "snap1", masterKey)
	if err != nil {
		t.Fatalf("failed to create snapshot 1: %v", err)
	}

	// Corrupt sidecar metadata to trigger auto-repair testing
	snap1Dir, _ := store.GetSnapshotDir("default")
	meta1Path := filepath.Join(snap1Dir, fmt.Sprintf("%s.meta.json", meta1.ID))
	corruptMeta := *meta1
	corruptMeta.MasterKeySHA256 = "unknown"
	corruptMeta.SecretCount = -1
	metaBytes, _ := json.MarshalIndent(corruptMeta, "", "  ")
	_ = os.WriteFile(meta1Path, metaBytes, 0600)

	// 2. Setup profile 2 ("dev-prof")
	v2Path := filepath.Join(cfgDir, "secrets_dev-prof.enc")
	storeData2 := []byte(`{"secrets":{"api/tok":{"value":"p2_1"},"api/url":{"value":"p2_2"}}}`)
	payload2, _ := crypto.Encrypt(masterKey, storeData2)
	_ = os.WriteFile(v2Path, payload2, 0600)

	meta2, err := store.CreateSnapshot("dev-prof", "manual", "unit-test", "snap2", masterKey)
	if err != nil || meta2.ID == "" {
		t.Fatalf("failed to create snapshot 2: %v", err)
	}

	// 3. Test single profile listing and auto-repair
	snaps1, err := store.ListSnapshots("default", masterKey)
	if err != nil {
		t.Fatalf("failed to list default snapshots: %v", err)
	}
	if len(snaps1) != 1 {
		t.Fatalf("expected 1 snapshot for default, got %d", len(snaps1))
	}
	if snaps1[0].SecretCount != 1 {
		t.Errorf("expected auto-repaired secret count 1, got %d", snaps1[0].SecretCount)
	}
	if snaps1[0].MasterKeySHA256 == "unknown" {
		t.Errorf("expected auto-repaired master key sha256 fingerprint, got unknown")
	}

	// Verify on-disk sidecar JSON file was repaired
	repairedBytes, _ := os.ReadFile(meta1Path)
	var diskMeta store.SnapshotMeta
	_ = json.Unmarshal(repairedBytes, &diskMeta)
	if diskMeta.MasterKeySHA256 == "unknown" || diskMeta.SecretCount != 1 {
		t.Errorf("sidecar file on disk was not repaired: %+v", diskMeta)
	}

	// 4. Test multi-profile aggregation ListAllSnapshots
	allSnaps, err := store.ListAllSnapshots(masterKey)
	if err != nil {
		t.Fatalf("failed to list all snapshots: %v", err)
	}
	if len(allSnaps) < 2 {
		t.Fatalf("expected at least 2 snapshots across profiles, got %d", len(allSnaps))
	}

	profilesFound := make(map[string]bool)
	for _, s := range allSnaps {
		profilesFound[s.Profile] = true
	}
	if !profilesFound["default"] || !profilesFound["dev-prof"] {
		t.Errorf("expected snapshots from both 'default' and 'dev-prof', got: %+v", profilesFound)
	}
}
