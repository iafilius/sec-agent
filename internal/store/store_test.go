package store

import (
	"encoding/json"
	"testing"
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
		Secrets: map[string]SecretEntry{
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
			Secrets: make(map[string]SecretEntry, 10000),
		}
		for j := 0; j < 10000; j++ {
			es.Secrets["key/path/"+string(rune(j))] = SecretEntry{Value: "secret_value"}
		}
	}
}
