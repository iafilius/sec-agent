package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"
)

func TestPathToEnvKey(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"database/prod/password", "DATABASE_PROD_PASSWORD"},
		{"api-key/stripe-key", "API_KEY_STRIPE_KEY"},
		{"nested/some-value_123", "NESTED_SOME_VALUE_123"},
		{"special/!@#$characters", "SPECIAL_CHARACTERS"},
	}

	for _, tt := range tests {
		got := pathToEnvKey(tt.path)
		if got != tt.want {
			t.Errorf("pathToEnvKey(%q) = %q; want %q", tt.path, got, tt.want)
		}
	}
}

func TestRecordQueryAndFeedbackCommand(t *testing.T) {
	profile := "record-feedback-test-profile"
	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	os.Remove(sockPath)
	os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_rec_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build record test binary: %v\nOutput: %s", err, out)
	}

	d, err := daemon.NewDaemon(profile, 30*time.Second, Version)
	if err != nil {
		t.Fatalf("failed to create test daemon: %v", err)
	}
	token := "record-test-token"
	d.SetSessionTokenForTest(token)
	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901"))
	d.SetSecretsForTest(map[string]store.SecretEntry{
		"router-ax3600-prod/xiaomi_ax3600_openwrt_root/password": {Value: "router-pass-999"},
		"router-ax3600-prod/xiaomi_ax3600_openwrt_root/username": {Value: "root"},
		"router-ax3600-prod/xiaomi_ax3600_openwrt_root/url":      {Value: "https://192.168.31.1"},
		"router-ax3600-prod/xiaomi_ax3600_openwrt_root/notes":    {Value: "Dropbear SSH flags -o HostKeyAlgorithms=+ssh-rsa"},
		"router-ax3600-prod/xiaomi_ax3600_openwrt_root/totp":     {Value: "JBSWY3DPEHPK3PXP"},
	})
	go d.Start()
	defer d.Stop()

	sock, _ := config.GetSocketPath(profile)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 1. Test sec-agent get --record --json
	recCmd := exec.Command(binPath, "get", "router-ax3600-prod/xiaomi_ax3600_openwrt_root/", "--record", "--json", "--profile", profile)
	recCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	out, err := recCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec-agent get --record --json failed: %v\nOutput: %s", err, out)
	}
	var recData SecretRecordDTO
	if err := json.Unmarshal(out, &recData); err != nil {
		t.Fatalf("failed to parse --record JSON output: %v\nOutput: %s", err, out)
	}
	if recData.Username != "root" || recData.Password != "router-pass-999" || recData.URL != "https://192.168.31.1" {
		t.Errorf("record payload mismatch: %v", recData)
	}

	// 2. Test sec-agent feedback --json
	fbCmd := exec.Command(binPath, "feedback", "--json")
	fbOut, fbErr := fbCmd.CombinedOutput()
	if fbErr != nil {
		t.Fatalf("sec-agent feedback --json failed: %v\nOutput: %s", fbErr, fbOut)
	}
	var fbData map[string]interface{}
	if err := json.Unmarshal(fbOut, &fbData); err != nil {
		t.Fatalf("failed to parse feedback JSON: %v\nOutput: %s", err, fbOut)
	}
	if fbData["tool"] != "sec-agent" {
		t.Errorf("expected tool = sec-agent, got: %v", fbData["tool"])
	}
}

func TestSecretVersioningAndRollback(t *testing.T) {
	profile := "versioning-test-profile"
	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	os.Remove(sockPath)
	os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_ver_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build versioning test binary: %v\nOutput: %s", err, out)
	}

	d, err := daemon.NewDaemon(profile, 30*time.Second, Version)
	if err != nil {
		t.Fatalf("failed to create test daemon: %v", err)
	}
	token := "version-test-token"
	d.SetSessionTokenForTest(token)
	d.SetMasterKeyForTest([]byte("01234567890123456789012345678901"))
	go d.Start()
	defer d.Stop()

	sock, _ := config.GetSocketPath(profile)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 1. Set v1
	setV1 := exec.Command(binPath, "set", "api/key", "val_v1", "--comment", "initial key", "--profile", profile)
	setV1.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	if out, err := setV1.CombinedOutput(); err != nil {
		t.Fatalf("set v1 failed: %v\nOutput: %s", err, out)
	}

	// 2. Set v2
	setV2 := exec.Command(binPath, "set", "api/key", "val_v2", "--comment", "rotated key", "--profile", profile)
	setV2.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	if out, err := setV2.CombinedOutput(); err != nil {
		t.Fatalf("set v2 failed: %v\nOutput: %s", err, out)
	}

	// 3. Query history
	histCmd := exec.Command(binPath, "history", "api/key", "--profile", profile)
	histCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	histOut, histErr := histCmd.CombinedOutput()
	if histErr != nil {
		t.Fatalf("history failed: %v\nOutput: %s", histErr, histOut)
	}
	if !strings.Contains(string(histOut), "v1") {
		t.Errorf("expected history output to contain v1 snapshot, got: %s", string(histOut))
	}

	// 4. Rollback to v1
	rollCmd := exec.Command(binPath, "rollback", "api/key", "--version", "1", "--profile", profile)
	rollCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	rollOut, rollErr := rollCmd.CombinedOutput()
	if rollErr != nil {
		t.Fatalf("rollback failed: %v\nOutput: %s", rollErr, rollOut)
	}
	if !strings.Contains(string(rollOut), "Rolled back secret") {
		t.Errorf("unexpected rollback output: %s", string(rollOut))
	}

	// Verify current value is back to val_v1
	getCmd := exec.Command(binPath, "get", "api/key", "--profile", profile)
	getCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	getOut, _ := getCmd.CombinedOutput()
	if !strings.Contains(string(getOut), "val_v1") {
		t.Errorf("expected active secret to be val_v1 after rollback, got: %s", string(getOut))
	}

	// 5. Test soft-delete & restore
	rmCmd := exec.Command(binPath, "rm", "api/key", "--profile", profile)
	rmCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	if out, err := rmCmd.CombinedOutput(); err != nil {
		t.Fatalf("rm failed: %v\nOutput: %s", err, out)
	}

	// Check ls --trash
	lsTrash := exec.Command(binPath, "ls", "--trash", "--profile", profile)
	lsTrash.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	trashOut, _ := lsTrash.CombinedOutput()
	if !strings.Contains(string(trashOut), "api/key") {
		t.Errorf("expected trash bin to list api/key, got: %s", string(trashOut))
	}

	// Restore soft deleted key
	rstCmd := exec.Command(binPath, "restore-deleted", "api/key", "--profile", profile)
	rstCmd.Env = append(os.Environ(), "SEC_SESSION_TOKEN="+token)
	if out, err := rstCmd.CombinedOutput(); err != nil {
		t.Fatalf("restore-deleted failed: %v\nOutput: %s", err, out)
	}
}

func TestCrossProfileCopyAndUsability(t *testing.T) {
	tmpDir := t.TempDir()
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()
	_ = os.Chdir(tmpDir)

	// 1. Verify loadWorkspaceConfig parses .secrc
	secrcContent := `{"profile": "router-ax3600-prod"}`
	if err := os.WriteFile(filepath.Join(tmpDir, ".secrc"), []byte(secrcContent), 0600); err != nil {
		t.Fatalf("failed to write .secrc: %v", err)
	}

	cfg := loadWorkspaceConfig()
	if cfg == nil || cfg.Profile != "router-ax3600-prod" {
		t.Fatalf("expected loadWorkspaceConfig to parse profile 'router-ax3600-prod', got: %+v", cfg)
	}

	// 2. Verify cross-profile copy logic
	srcProfile := "copy-src-prof"
	dstProfile := "copy-dst-prof"
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0x22
	}

	sSrc := &store.EncryptedStore{
		Secrets: map[store.SecretKey]store.SecretEntry{
			"wifi/passphrase": {Value: "secret-wifi-pass", Comment: "Original WiFi secret"},
		},
	}
	if err := store.SaveStore(srcProfile, sSrc, masterKey); err != nil {
		t.Fatalf("failed to save src store: %v", err)
	}

	sDst := &store.EncryptedStore{
		Secrets: map[store.SecretKey]store.SecretEntry{},
	}
	if err := store.SaveStore(dstProfile, sDst, masterKey); err != nil {
		t.Fatalf("failed to save dst store: %v", err)
	}

	// Read from src, write to dst
	loadedSrc, err := store.LoadStore(srcProfile, masterKey)
	if err != nil {
		t.Fatalf("failed to load src store: %v", err)
	}
	entry := loadedSrc.Secrets["wifi/passphrase"]

	loadedDst, err := store.LoadStore(dstProfile, masterKey)
	if err != nil {
		t.Fatalf("failed to load dst store: %v", err)
	}
	loadedDst.Secrets["router/wifi_passphrase"] = store.SecretEntry{
		Value:   entry.Value,
		Comment: "Copied from " + srcProfile + ":wifi/passphrase",
	}
	if err := store.SaveStore(dstProfile, loadedDst, masterKey); err != nil {
		t.Fatalf("failed to save copied dst store: %v", err)
	}

	finalDst, err := store.LoadStore(dstProfile, masterKey)
	if err != nil {
		t.Fatalf("failed to load final dst store: %v", err)
	}

	if finalDst.Secrets["router/wifi_passphrase"].Value != "secret-wifi-pass" {
		t.Errorf("expected copied secret value 'secret-wifi-pass', got %q", finalDst.Secrets["router/wifi_passphrase"].Value)
	}
}

func TestUniversalDedupeCommand(t *testing.T) {
	srcProf := "test-universal-src"
	dstProf := "test-universal-dst"
	masterKey := []byte("01234567890123456789012345678901")

	// Cleanup
	s1, _ := store.GetStorePath(srcProf)
	s2, _ := store.GetStorePath(dstProf)
	os.Remove(s1)
	os.Remove(s2)
	defer os.Remove(s1)
	defer os.Remove(s2)

	// Init source store with 2 keys
	srcStore := &store.EncryptedStore{Secrets: make(map[store.SecretKey]store.SecretEntry)}
	srcStore.Secrets[store.SecretKey("aws/access_key")] = store.SecretEntry{Value: "AKIA123", Created: time.Now(), LastModified: time.Now()}
	srcStore.Secrets[store.SecretKey("gcp/token")] = store.SecretEntry{Value: "GCP456", Created: time.Now(), LastModified: time.Now()}
	if err := store.SaveStore(srcProf, srcStore, masterKey); err != nil {
		t.Fatalf("failed to save src store: %v", err)
	}

	// Init dst store
	dstStore := &store.EncryptedStore{Secrets: make(map[store.SecretKey]store.SecretEntry)}
	if err := store.SaveStore(dstProf, dstStore, masterKey); err != nil {
		t.Fatalf("failed to save dst store: %v", err)
	}

	// Perform deduplication with prefix "aws/"
	moved, err := store.DeduplicateProfileSecrets(srcProf, dstProf, []string{"aws/"}, masterKey, masterKey)
	if err != nil {
		t.Fatalf("deduplication failed: %v", err)
	}

	if len(moved) != 1 || moved[0] != "aws/access_key" {
		t.Errorf("expected moved keys [aws/access_key], got: %v", moved)
	}

	// Verify srcStore has gcp/token and not aws/access_key
	reloadedSrc, err := store.LoadStore(srcProf, masterKey)
	if err != nil {
		t.Fatalf("failed to reload src store: %v", err)
	}
	if _, exists := reloadedSrc.Secrets["aws/access_key"]; exists {
		t.Errorf("expected aws/access_key to be removed from srcStore")
	}
	if _, exists := reloadedSrc.Secrets["gcp/token"]; !exists {
		t.Errorf("expected gcp/token to remain in srcStore")
	}

	// Verify dstStore has aws/access_key
	reloadedDst, err := store.LoadStore(dstProf, masterKey)
	if err != nil {
		t.Fatalf("failed to reload dst store: %v", err)
	}
	if entry, exists := reloadedDst.Secrets["aws/access_key"]; !exists || entry.Value != "AKIA123" {
		t.Errorf("expected aws/access_key in dstStore with value AKIA123")
	}
}
