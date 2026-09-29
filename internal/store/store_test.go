package store

import (
	"bytes"
	"encoding/json"
	"secure_secrets/internal/config"
	"secure_secrets/internal/keychain"
	"testing"
	"time"
)

func TestStoreMigration(t *testing.T) {
	// 1. Verify legacy string map format parses and populates time metadata
	legacyJSON := []byte(`{"secrets": {"db/pass": "legacy-value"}}`)

	var es EncryptedStore
	if err := json.Unmarshal(legacyJSON, &es); err != nil {
		t.Fatalf("failed to unmarshal legacy JSON: %v", err)
	}

	entry, exists := es.Secrets["db/pass"]
	if !exists {
		t.Fatalf("expected key 'db/pass' to exist")
	}
	if entry.Value != "legacy-value" {
		t.Errorf("expected value 'legacy-value', got %q", entry.Value)
	}
	if entry.Created.IsZero() {
		t.Error("expected Created timestamp to be populated for legacy entry")
	}
	if entry.LastModified.IsZero() {
		t.Error("expected LastModified timestamp to be populated for legacy entry")
	}
}

func TestSoftDeleteAndRestore(t *testing.T) {
	es := &EncryptedStore{
		Secrets: map[SecretKey]SecretEntry{
			"prod/db/pass": {Value: "db-pass-v1"},
			"prod/api/key": {Value: "api-key-v1"},
		},
	}

	// 1. Soft Delete single secret
	if err := es.SoftDeleteSecret("prod/db/pass"); err != nil {
		t.Fatalf("SoftDeleteSecret failed: %v", err)
	}
	if es.Secrets["prod/db/pass"].DeletedAt == nil {
		t.Error("expected DeletedAt timestamp to be set")
	}

	// 2. Restore soft-deleted secret
	if err := es.RestoreDeletedSecret("prod/db/pass"); err != nil {
		t.Fatalf("RestoreDeletedSecret failed: %v", err)
	}
	if es.Secrets["prod/db/pass"].DeletedAt != nil {
		t.Error("expected DeletedAt to be nil after restore")
	}

	// 3. Hard Delete single secret
	if err := es.HardDeleteSecret("prod/db/pass"); err != nil {
		t.Fatalf("HardDeleteSecret failed: %v", err)
	}
	if _, exists := es.Secrets["prod/db/pass"]; exists {
		t.Error("expected secret to be permanently removed")
	}
}

func BenchmarkStorePreallocation(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		es := &EncryptedStore{
			Secrets: make(map[SecretKey]SecretEntry, 10000),
		}
		for j := 0; j < 10000; j++ {
			es.Secrets[SecretKey("key/path/"+string(rune(j)))] = SecretEntry{Value: "secret_value"}
		}
	}
}

func TestAccessTrackingAndProfileExport(t *testing.T) {
	es := &EncryptedStore{
		Secrets: make(map[SecretKey]SecretEntry),
	}
	now := time.Now()
	es.Secrets["prod/api/key"] = SecretEntry{
		Value:        "sk_live_12345",
		Created:      now,
		LastModified: now,
		LastAccessed: now,
		AccessCount:  5,
	}

	data, err := json.Marshal(es)
	if err != nil {
		t.Fatalf("failed to marshal store: %v", err)
	}

	var restored EncryptedStore
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal store: %v", err)
	}

	entry := restored.Secrets["prod/api/key"]
	if entry.AccessCount != 5 {
		t.Errorf("expected AccessCount 5, got %d", entry.AccessCount)
	}
	if entry.LastAccessed.IsZero() {
		t.Error("expected LastAccessed to be set")
	}
}

func TestTwoTierMetadataBackwardCompatibility(t *testing.T) {
	// 1. Vault without description/notes must unmarshal with empty strings without error
	legacyVaultJSON := []byte(`{
		"secrets": {
			"db/password": {
				"value": "supersecret",
				"comment": "legacy comment",
				"created": "2026-09-01T12:00:00Z",
				"last_modified": "2026-09-01T12:00:00Z",
				"version": 1
			}
		}
	}`)

	var es EncryptedStore
	if err := json.Unmarshal(legacyVaultJSON, &es); err != nil {
		t.Fatalf("failed to unmarshal legacy vault: %v", err)
	}

	entry, ok := es.Secrets["db/password"]
	if !ok {
		t.Fatalf("expected 'db/password' to exist")
	}
	if entry.Description != "" {
		t.Errorf("expected empty description, got %q", entry.Description)
	}
	if entry.Notes != "" {
		t.Errorf("expected empty notes, got %q", entry.Notes)
	}
	if entry.Comment != "legacy comment" {
		t.Errorf("expected comment 'legacy comment', got %q", entry.Comment)
	}

	// 2. Set description and notes, marshal, and verify round-trip
	entry.Description = "Primary production database master password"
	entry.Notes = "Rotated bi-weekly by DBA automation.\nContact #data-eng for access requests."
	es.Secrets["db/password"] = entry

	data, err := json.Marshal(&es)
	if err != nil {
		t.Fatalf("failed to marshal vault with metadata: %v", err)
	}

	var roundTrip EncryptedStore
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatalf("failed to unmarshal roundtrip vault: %v", err)
	}

	rtEntry := roundTrip.Secrets["db/password"]
	if rtEntry.Description != "Primary production database master password" {
		t.Errorf("unexpected description: %q", rtEntry.Description)
	}
	if rtEntry.Notes != "Rotated bi-weekly by DBA automation.\nContact #data-eng for access requests." {
		t.Errorf("unexpected notes: %q", rtEntry.Notes)
	}
}

func TestInitializeMasterKeyAutoResealOnVersionUpgrade(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("SEC_CONFIG_DIR", tempDir)
	t.Setenv("SEC_TEST_MODE", "1")
	t.Setenv("SEC_TEST_RESEAL", "1")

	// Set initial version in .last_version to an older version
	if err := config.SetLastKnownVersion("v2.14.0"); err != nil {
		t.Fatalf("failed to set initial version: %v", err)
	}

	keychain.SetVersion("v2.14.4")

	profile := "reseal-test-prof"
	dummyMasterKey := []byte("32-byte-master-key-for-test-ok!!")

	getter := func() ([]byte, error) {
		return dummyMasterKey, nil
	}
	setter := func(k []byte) error {
		return nil
	}

	// 1. Calling InitializeMasterKey should detect version mismatch (v2.14.0 vs v2.14.4)
	// and update .last_version to v2.14.4
	retrievedKey, err := InitializeMasterKey(profile, getter, setter)
	if err != nil {
		t.Fatalf("InitializeMasterKey failed: %v", err)
	}
	if !bytes.Equal(retrievedKey, dummyMasterKey) {
		t.Errorf("expected retrieved key to match dummy master key")
	}

	// Verify .last_version was updated
	newVer, err := config.GetLastKnownVersion()
	if err != nil {
		t.Fatalf("GetLastKnownVersion failed: %v", err)
	}
	if newVer != "v2.14.4" {
		t.Errorf("expected updated version 'v2.14.4', got %q", newVer)
	}

	// Clean up any test keychain items
	_ = keychain.Delete("sec-test-session:profile_"+profile, "master")
}


