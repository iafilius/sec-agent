package backup

import (
	"os"
	"path/filepath"
	"reflect"
	"secure_secrets/store"
	"testing"
	"time"
)

func TestBackupRestoreRoundtrip(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sec-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	kdbxPath := filepath.Join(tempDir, "test_backup.kdbx")
	password := "super-secure-master-pass"

	now := time.Now().Truncate(time.Second) // Second resolution for XML compat

	// Mock secrets data including comments, custom metadata, and timestamps
	originalSecrets := map[string]store.SecretEntry{
		"database/prod/password": {
			Value:        "db-pass-xyz-123",
			Comment:      "Production database root user credential",
			Created:      now.Add(-10 * time.Hour),
			LastModified: now.Add(-1 * time.Hour),
			Expires:      now.Add(24 * time.Hour),
			Metadata: map[string]string{
				"env":    "prod",
				"owner":  "devops",
				"region": "us-east-1",
			},
		},
		"api/stripe/key": {
			Value:        "sk_live_stripe_secret_key",
			Comment:      "Stripe production gateway key",
			Created:      now.Add(-5 * time.Hour),
			LastModified: now,
			Metadata: map[string]string{
				"department": "billing",
			},
		},
		"simple/key": {
			Value:        "simple-password-no-metadata",
			Created:      now,
			LastModified: now,
		},
	}

	// 1. Export to KDBX
	if err := ExportToKdbx(kdbxPath, password, originalSecrets); err != nil {
		t.Fatalf("ExportToKdbx failed: %v", err)
	}

	// Verify file was written
	if _, err := os.Stat(kdbxPath); err != nil {
		t.Fatalf("KDBX file was not generated: %v", err)
	}

	// 2. Import from KDBX
	importedSecrets, err := ImportFromKdbx(kdbxPath, password)
	if err != nil {
		t.Fatalf("ImportFromKdbx failed: %v", err)
	}

	// 3. Verify equivalency
	if len(importedSecrets) != len(originalSecrets) {
		t.Errorf("imported secrets size mismatch: expected %d, got %d", len(originalSecrets), len(importedSecrets))
	}

	for key, originalEntry := range originalSecrets {
		importedEntry, exists := importedSecrets[key]
		if !exists {
			t.Errorf("expected secret path %q was not found in imported dataset", key)
			continue
		}

		if importedEntry.Value != originalEntry.Value {
			t.Errorf("[%s] value mismatch: expected %q, got %q", key, originalEntry.Value, importedEntry.Value)
		}

		if importedEntry.Comment != originalEntry.Comment {
			t.Errorf("[%s] comment mismatch: expected %q, got %q", key, originalEntry.Comment, importedEntry.Comment)
		}

		// Verify Timestamps
		if importedEntry.Created.Unix() != originalEntry.Created.Unix() {
			t.Errorf("[%s] creation time mismatch: expected %v, got %v", key, originalEntry.Created, importedEntry.Created)
		}
		if importedEntry.LastModified.Unix() != originalEntry.LastModified.Unix() {
			t.Errorf("[%s] modification time mismatch: expected %v, got %v", key, originalEntry.LastModified, importedEntry.LastModified)
		}
		if importedEntry.Expires.Unix() != originalEntry.Expires.Unix() {
			t.Errorf("[%s] expiry time mismatch: expected %v, got %v", key, originalEntry.Expires, importedEntry.Expires)
		}

		// Check metadata map equality
		if len(originalEntry.Metadata) == 0 && len(importedEntry.Metadata) == 0 {
			continue
		}
		if !reflect.DeepEqual(importedEntry.Metadata, originalEntry.Metadata) {
			t.Errorf("[%s] metadata mismatch: expected %v, got %v", key, originalEntry.Metadata, importedEntry.Metadata)
		}
	}
}
