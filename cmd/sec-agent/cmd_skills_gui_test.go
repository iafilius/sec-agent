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
	"secure_secrets/internal/crypto"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/keychain"
	"secure_secrets/internal/store"
)

func TestInitSkillInstallerAndBackupList(t *testing.T) {
	tmpHome := t.TempDir()
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = filepath.Join(os.Getenv("HOME"), "go")
	}
	gocache := os.Getenv("GOCACHE")
	env := append(os.Environ(), "HOME="+tmpHome, "GOPATH="+gopath, "GOCACHE="+gocache)

	// Build CLI binary
	binPath := filepath.Join(tmpHome, "sec_test_init_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	buildCmd.Env = env
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build CLI test binary: %v\nOutput:\n%s", err, out)
	}

	// 1. Uninitialized vault pre-flight guard check
	uninitCmd := exec.Command(binPath, "get", "some/key")
	uninitCmd.Env = env
	out, err := uninitCmd.CombinedOutput()
	if err == nil {
		t.Errorf("expected get command on uninitialized vault to fail, but it succeeded")
	}
	if !strings.Contains(string(out), "uninitialized") {
		t.Errorf("expected uninitialized error output, got: %s", string(out))
	}

	// 2. Test JSON error formatting on uninitialized vault
	uninitJSONCmd := exec.Command(binPath, "get", "some/key", "--json")
	uninitJSONCmd.Env = env
	out, err = uninitJSONCmd.CombinedOutput()
	if err == nil {
		t.Errorf("expected get --json on uninitialized vault to fail, but it succeeded")
	}
	if !strings.Contains(string(out), "VAULT_UNINITIALIZED") || !strings.Contains(string(out), "\"success\":false") {
		t.Errorf("expected structured JSON error output, got: %s", string(out))
	}

	// 3. Test init with --skill flag
	initCmd := exec.Command(binPath, "init", "--skill", "antigravity", "--scope", "global")
	initCmd.Env = env
	out, err = initCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec-agent init failed: %v\nOutput: %s", err, out)
	}
	if !strings.Contains(string(out), "Vault configuration directory initialized") {
		t.Errorf("unexpected init output: %s", string(out))
	}

	// Verify skill file was created in tmpHome/.gemini/config/skills/
	skillPath := filepath.Join(tmpHome, ".gemini", "config", "skills", "sec-agent-integration", "SKILL.md")
	if _, err := os.Stat(skillPath); os.IsNotExist(err) {
		t.Errorf("expected skill file to exist at %s, but missing", skillPath)
	}

	// 3. Test skill status
	statusCmd := exec.Command(binPath, "skill", "status")
	statusCmd.Env = env
	out, err = statusCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec-agent skill status failed: %v\nOutput: %s", err, out)
	}
	if !strings.Contains(string(out), "antigravity") {
		t.Errorf("expected skill status to list antigravity, got: %s", string(out))
	}

	// 4. Test backup list
	backupListCmd := exec.Command(binPath, "backup", "list")
	backupListCmd.Env = env
	out, err = backupListCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec-agent backup list failed: %v\nOutput: %s", err, out)
	}
	if !strings.Contains(string(out), "Vault Snapshots & Backups") {
		t.Errorf("expected backup list header, got: %s", string(out))
	}

	// 5. Test init --non-interactive
	nonIntInitCmd := exec.Command(binPath, "init", "--non-interactive")
	nonIntInitCmd.Env = env
	out, err = nonIntInitCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sec-agent init --non-interactive failed: %v\nOutput: %s", err, out)
	}
	if !strings.Contains(string(out), "Vault configuration directory initialized") {
		t.Errorf("unexpected non-interactive init output: %s", string(out))
	}

	// 7. Test status --quick
	quickStatusCmd := exec.Command(binPath, "status", "--quick")
	quickStatusCmd.Env = env
	out, err = quickStatusCmd.CombinedOutput()
	if err == nil {
		if !strings.Contains(string(out), "socket not found") && !strings.Contains(string(out), "DAEMON_NOT_RUNNING") {
			t.Errorf("expected quick status output for socket check, got: %s", string(out))
		}
	}
}

func TestGUIV2KeychainUnlockAlignment(t *testing.T) {
	profile := "gui-v2-alignment-test"
	os.Setenv("SEC_TEST_MODE", "1")
	defer os.Unsetenv("SEC_TEST_MODE")

	sockPath, _ := config.GetSocketPath(profile)
	dbPath, _ := store.GetStorePath(profile)
	_ = os.Remove(sockPath)
	_ = os.Remove(dbPath)
	defer os.Remove(sockPath)
	defer os.Remove(dbPath)

	d, err := daemon.NewDaemon(profile, 30*time.Second, "v2.2.0")
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}
	go func() {
		_ = d.Start()
	}()
	defer d.Stop()

	// Give daemon time to start
	time.Sleep(100 * time.Millisecond)

	// Create a v2.0 vault envelope matching SEC_TEST_MODE key
	key := []byte("01234567890123456789012345678901")

	st := &store.EncryptedStore{
		Secrets: map[store.SecretKey]store.SecretEntry{
			"gui/test": {Value: "gui_val_123"},
		},
	}

	mnemonic, err := crypto.GenerateMnemonic()
	if err != nil {
		t.Fatalf("failed to generate mnemonic: %v", err)
	}

	rawStore, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("failed to marshal store: %v", err)
	}

	payload, err := crypto.Encrypt(key, rawStore)
	if err != nil {
		t.Fatalf("failed to encrypt store payload: %v", err)
	}

	slot1, err := store.WrapMasterKey(mnemonic, key)
	if err != nil {
		t.Fatalf("failed to wrap master key: %v", err)
	}

	env := &store.VaultEnvelope{
		SchemaVersion: store.SchemaV2,
		UpgradedAt:    time.Now().UTC(),
		Slot1:         slot1,
		Payload:       payload,
	}

	if err := store.WriteVaultEnvelope(dbPath, env); err != nil {
		t.Fatalf("failed to write v2 vault envelope: %v", err)
	}

	// Store key in Keychain using SetCurrentSet
	if err := keychain.SetCurrentSet("sec-session:profile_"+profile, "master", key); err != nil {
		t.Fatalf("failed to set master key in keychain: %v", err)
	}
	defer keychain.Delete("sec-session:profile_"+profile, "master")

	// Verify ensureUnlocked can unlock the v2 store under SEC_TEST_MODE=1
	resp, err := ensureUnlocked(profile)
	if err != nil {
		t.Fatalf("ensureUnlocked failed for v2 store: %v", err)
	}
	if resp == nil || !resp.Success {
		t.Fatalf("expected successful IPC response from ensureUnlocked, got: %+v", resp)
	}
}

func TestNonTTYGUIAutoOpenHandling(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "st")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	t.Setenv("HOME", tmpDir)
	t.Setenv("SEC_TEST_MODE", "1")
	t.Setenv("SEC_AUTO_OPEN", "1")

	prof := "t1"
	masterKey := []byte("01234567890123456789012345678901")

	testStore := &store.EncryptedStore{Secrets: make(map[store.SecretKey]store.SecretEntry)}
	testStore.Secrets[store.SecretKey("db/pass")] = store.SecretEntry{Value: "secret123", Created: time.Now(), LastModified: time.Now()}
	if err := store.SaveStore(prof, testStore, masterKey); err != nil {
		t.Fatalf("failed saving test store: %v", err)
	}

	d, err := daemon.NewDaemon(prof, 30*time.Second, Version)
	if err != nil {
		t.Fatalf("failed creating daemon: %v", err)
	}
	go func() {
		_ = d.Start()
	}()
	defer d.Stop()

	time.Sleep(100 * time.Millisecond)

	// Test non-TTY handleOpenGUI trigger
	ok := handleOpenGUI(prof)
	if !ok {
		t.Fatalf("expected handleOpenGUI to succeed in test mode, got false (SEC_SESSION_TOKEN=%q)", os.Getenv("SEC_SESSION_TOKEN"))
	}

	if os.Getenv("SEC_SESSION_TOKEN") == "" {
		t.Errorf("expected handleOpenGUI to set SEC_SESSION_TOKEN, got empty")
	}
}
