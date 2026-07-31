package backup

import (
	"os"
	"path/filepath"
	"reflect"
	"secure_secrets/internal/store"
	"strings"
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

func TestFullMetadataKdbxImport(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sec-test-fullmeta-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	kdbxPath := filepath.Join(tempDir, "fullmeta_test.kdbx")
	password := "fullmeta-pass"

	originalSecrets := map[string]store.SecretEntry{
		"Xiaomi AX3600 OpenWrt Root": {
			Value:   "router-secret-pass-123",
			Comment: "LuCI Web Admin HTTPS 443 | SSH Dropbear -o HostKeyAlgorithms=+ssh-rsa",
			Metadata: map[string]string{
				"UserName": "root",
				"URL":      "https://192.168.31.1",
				"totp":     "JBSWY3DPEHPK3PXP",
			},
		},
	}

	if err := ExportToKdbx(kdbxPath, password, originalSecrets); err != nil {
		t.Fatalf("ExportToKdbx failed: %v", err)
	}

	fullSecrets, err := ImportFromKdbxFullMetadata(kdbxPath, password)
	if err != nil {
		t.Fatalf("ImportFromKdbxFullMetadata failed: %v", err)
	}

	slug := "xiaomi_ax3600_openwrt_root"
	if passEntry, ok := fullSecrets[slug+"/password"]; !ok || passEntry.Value != "router-secret-pass-123" {
		t.Errorf("expected password sub-key %s/password, got: %v", slug, passEntry)
	}
	if userEntry, ok := fullSecrets[slug+"/username"]; !ok || userEntry.Value != "root" {
		t.Errorf("expected username sub-key %s/username, got: %v", slug, userEntry)
	}
	if urlEntry, ok := fullSecrets[slug+"/url"]; !ok || urlEntry.Value != "https://192.168.31.1" {
		t.Errorf("expected url sub-key %s/url, got: %v", slug, urlEntry)
	}
	if notesEntry, ok := fullSecrets[slug+"/notes"]; !ok || !strings.Contains(notesEntry.Value, "LuCI") {
		t.Errorf("expected notes sub-key %s/notes, got: %v", slug, notesEntry)
	}
	if totpEntry, ok := fullSecrets[slug+"/totp"]; !ok || totpEntry.Value != "JBSWY3DPEHPK3PXP" {
		t.Errorf("expected totp sub-key %s/totp, got: %v", slug, totpEntry)
	}
}

func TestFullMetadataKdbxReaderStream(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sec-test-reader-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	kdbxPath := filepath.Join(tempDir, "stream.kdbx")
	password := "stream-pass"

	originalSecrets := map[string]store.SecretEntry{
		"Stream Test": {
			Value:   "stream-val-456",
			Comment: "In-memory stream test notes",
		},
	}

	if err := ExportToKdbx(kdbxPath, password, originalSecrets); err != nil {
		t.Fatalf("ExportToKdbx failed: %v", err)
	}

	kdbxBytes, err := os.ReadFile(kdbxPath)
	if err != nil {
		t.Fatalf("failed to read kdbx bytes: %v", err)
	}

	// Import from in-memory bytes stream
	readerSecrets, err := ImportFromKdbxFullMetadataReader(strings.NewReader(string(kdbxBytes)), password)
	if err != nil {
		t.Fatalf("ImportFromKdbxFullMetadataReader failed: %v", err)
	}

	if passEntry, ok := readerSecrets["stream_test/password"]; !ok || passEntry.Value != "stream-val-456" {
		t.Errorf("expected stream_test/password = stream-val-456, got: %v", passEntry)
	}
}

func TestKdbxMultiCycleRoundtripFidelity(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sec-test-multicycle-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	kdbxPath1 := filepath.Join(tempDir, "cycle1.kdbx")
	kdbxPath2 := filepath.Join(tempDir, "cycle2.kdbx")
	password := "multicycle-master-pass"

	now := time.Now().Truncate(time.Second)

	originalSecrets := map[string]store.SecretEntry{
		"cloud/aws/production_key": {
			Value:        "AKIAIOSFODNN7EXAMPLE",
			Comment:      "AWS IAM master access key for cloud deployment",
			Created:      now.Add(-48 * time.Hour),
			LastModified: now.Add(-2 * time.Hour),
			Expires:      now.Add(365 * 24 * time.Hour),
			Metadata: map[string]string{
				"env":        "prod",
				"account_id": "123456789012",
				"region":     "eu-west-1",
			},
		},
		"network/openwrt/router": {
			Value:        "Dropbear_SSH_Pass_99!",
			Comment:      "OpenWrt LuCI admin & SSH key",
			Created:      now.Add(-100 * time.Hour),
			LastModified: now.Add(-5 * time.Hour),
			Metadata: map[string]string{
				"UserName": "root",
				"URL":      "https://192.168.1.1",
			},
		},
		"database/postgres/cluster": {
			Value:        "pG_s3cr3t_p@ssw0rd",
			Comment:      "Sovereign PostgreSQL admin password",
			Created:      now,
			LastModified: now,
			Metadata: map[string]string{
				"port": "5432",
			},
		},
	}

	// 1. Export Original Secrets to Cycle 1 KDBX
	if err := ExportToKdbx(kdbxPath1, password, originalSecrets); err != nil {
		t.Fatalf("Cycle 1 ExportToKdbx failed: %v", err)
	}

	// 2. Import Cycle 1 KDBX
	cycle1Secrets, err := ImportFromKdbx(kdbxPath1, password)
	if err != nil {
		t.Fatalf("Cycle 1 ImportFromKdbx failed: %v", err)
	}

	if len(cycle1Secrets) != len(originalSecrets) {
		t.Fatalf("Cycle 1 size mismatch: expected %d, got %d", len(originalSecrets), len(cycle1Secrets))
	}

	// 3. Export Cycle 1 Imported Secrets to Cycle 2 KDBX (Roundtrip 2)
	if err := ExportToKdbx(kdbxPath2, password, cycle1Secrets); err != nil {
		t.Fatalf("Cycle 2 ExportToKdbx failed: %v", err)
	}

	// 4. Import Cycle 2 KDBX
	cycle2Secrets, err := ImportFromKdbx(kdbxPath2, password)
	if err != nil {
		t.Fatalf("Cycle 2 ImportFromKdbx failed: %v", err)
	}

	// 5. Assert 100% Equivalence between Cycle 1 and Cycle 2
	if len(cycle2Secrets) != len(cycle1Secrets) {
		t.Fatalf("Cycle 2 size mismatch: expected %d, got %d", len(cycle1Secrets), len(cycle2Secrets))
	}

	for key, entry1 := range cycle1Secrets {
		entry2, exists := cycle2Secrets[key]
		if !exists {
			t.Errorf("Cycle 2 missing key: %s", key)
			continue
		}
		if entry2.Value != entry1.Value {
			t.Errorf("[%s] Cycle 2 value mismatch: expected %q, got %q", key, entry1.Value, entry2.Value)
		}
		if entry2.Comment != entry1.Comment {
			t.Errorf("[%s] Cycle 2 comment mismatch: expected %q, got %q", key, entry1.Comment, entry2.Comment)
		}
		if entry2.Created.Unix() != entry1.Created.Unix() {
			t.Errorf("[%s] Cycle 2 created time mismatch: expected %v, got %v", key, entry1.Created, entry2.Created)
		}
		if !reflect.DeepEqual(entry1.Metadata, entry2.Metadata) {
			t.Errorf("[%s] Cycle 2 metadata mismatch: expected %v, got %v", key, entry1.Metadata, entry2.Metadata)
		}
	}
}


