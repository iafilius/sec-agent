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
