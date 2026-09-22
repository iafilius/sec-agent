package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
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

func TestCopilotSkillCompactFormat(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir to tmpDir: %v", err)
	}
	defer func() { _ = os.Chdir(origWd) }()

	t.Setenv("HOME", tmpDir)

	ok := handleSkillInstallTarget("copilot", "workspace")
	if !ok {
		t.Fatalf("handleSkillInstallTarget failed for copilot")
	}

	copilotFile := filepath.Join(tmpDir, ".github", "copilot-instructions.md")
	data, err := os.ReadFile(copilotFile)
	if err != nil {
		t.Fatalf("failed to read copilot instructions: %v", err)
	}

	content := string(data)
	lines := strings.Split(content, "\n")
	if len(lines) > 50 {
		t.Errorf("copilot instructions too long: got %d lines, want <= 50", len(lines))
	}
	if !strings.Contains(content, "sec-agent — Secret Management Quick Reference") {
		t.Errorf("copilot instructions missing expected header")
	}
	if !strings.Contains(content, "sec run") || !strings.Contains(content, "sec open") {
		t.Errorf("copilot instructions missing essential command patterns")
	}
}

func TestSkillShow(t *testing.T) {
	// Capture stdout when executing handleSkill with "show"
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	handleSkill("default", []string{"show", "--target", "copilot"})

	w.Close()
	outBytes, _ := io.ReadAll(r)
	os.Stdout = rescueStdout

	output := string(outBytes)
	if !strings.Contains(output, "sec-agent — Secret Management Quick Reference") {
		t.Errorf("expected copilot quick reference in skill show output, got: %s", output)
	}
	if !strings.Contains(output, "sec-agent skill show") {
		t.Errorf("expected pointer to skill show in output, got: %s", output)
	}

	// Test default target (defaults to canonical full manual)
	r2, w2, _ := os.Pipe()
	os.Stdout = w2
	handleSkill("default", []string{"show"})
	w2.Close()
	outBytes2, _ := io.ReadAll(r2)
	os.Stdout = rescueStdout

	if !strings.Contains(string(outBytes2), "sec-agent Secrets Management Integration") {
		t.Errorf("expected default skill show to render full canonical manual")
	}
}

func TestInitLegacyVaultSchemaDetection(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir to tmpDir: %v", err)
	}
	defer func() { _ = os.Chdir(origWd) }()

	cfgDir := filepath.Join(tmpDir, ".config", "sec-agent")
	_ = os.MkdirAll(cfgDir, 0700)
	dbPath := filepath.Join(cfgDir, "secrets.enc")

	// 1. Case: No vault store exists
	{
		r, w, _ := os.Pipe()
		oldStdout := os.Stdout
		os.Stdout = w
		handleInit("default", []string{"--non-interactive"})
		_ = w.Close()
		os.Stdout = oldStdout
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		out := buf.String()
		if !strings.Contains(out, "No vault file found") {
			t.Errorf("expected notice when no vault exists, got: %s", out)
		}
	}

	// 2. Case: Legacy v1.0 vault file present (raw binary, not JSON '{')
	if err := os.WriteFile(dbPath, []byte("legacy-v1-ciphertext-content"), 0600); err != nil {
		t.Fatalf("failed to write legacy vault: %v", err)
	}

	{
		r, w, _ := os.Pipe()
		oldStdout := os.Stdout
		os.Stdout = w
		handleInit("default", []string{"--non-interactive"})
		_ = w.Close()
		os.Stdout = oldStdout
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		out := buf.String()
		if !strings.Contains(out, "LEGACY VAULT SCHEMA") {
			t.Errorf("expected legacy warning banner, got: %s", out)
		}
		if !strings.Contains(out, "sec-agent migrate-v2") {
			t.Errorf("expected recommendation to run sec-agent migrate-v2, got: %s", out)
		}
	}

	// 3. Case: v2.0 vault envelope present (starts with '{')
	if err := os.WriteFile(dbPath, []byte("{\"schema_version\":\"2.0\"}"), 0600); err != nil {
		t.Fatalf("failed to write v2 vault: %v", err)
	}

	{
		r, w, _ := os.Pipe()
		oldStdout := os.Stdout
		os.Stdout = w
		handleInit("default", []string{"--non-interactive"})
		_ = w.Close()
		os.Stdout = oldStdout
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		out := buf.String()
		if !strings.Contains(out, "v2.0 Dual-Slot Envelope") {
			t.Errorf("expected v2 envelope confirmation, got: %s", out)
		}
	}
}

func TestSkillManifestLegacyMigration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sec-agent-skill-legacy-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	origConfig := os.Getenv("SEC_CONFIG_DIR")
	os.Setenv("SEC_CONFIG_DIR", tmpDir)
	defer func() {
		if origConfig != "" {
			os.Setenv("SEC_CONFIG_DIR", origConfig)
		} else {
			os.Unsetenv("SEC_CONFIG_DIR")
		}
	}()

	// Write legacy skills.json
	legacyJSON := `{
  "version": "v2.4.4",
  "skills": [
    {
      "target": "copilot",
      "scope": "workspace",
      "path": "/tmp/test-workspace/.github/copilot-instructions.md",
      "version": "v2.4.3"
    }
  ]
}`
	legacyPath := filepath.Join(tmpDir, "skills.json")
	if err := os.WriteFile(legacyPath, []byte(legacyJSON), 0600); err != nil {
		t.Fatalf("failed to write legacy skills.json: %v", err)
	}

	// loadSkillManifest should find skills.json and auto-migrate to skills_manifest.json
	manifest, err := loadSkillManifest()
	if err != nil {
		t.Fatalf("loadSkillManifest failed to load legacy manifest: %v", err)
	}
	if manifest == nil || len(manifest.Skills) != 1 {
		t.Fatalf("expected 1 skill in migrated manifest, got: %v", manifest)
	}
	if manifest.Skills[0].Target != "copilot" {
		t.Errorf("expected copilot skill target, got %s", manifest.Skills[0].Target)
	}

	// Verify skills_manifest.json was written
	migratedPath := filepath.Join(tmpDir, "skills_manifest.json")
	if _, err := os.Stat(migratedPath); err != nil {
		t.Errorf("expected skills_manifest.json to be created after legacy migration, got err: %v", err)
	}

	// In non-interactive test mode, legacy skills.json should be cleaned up automatically
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Errorf("expected legacy skills.json to be cleaned up after migration, but it still exists")
	}
}

func TestCleanupObsoleteSkillsJson(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sec-agent-cleanup-skills-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	origConfig := os.Getenv("SEC_CONFIG_DIR")
	os.Setenv("SEC_CONFIG_DIR", tmpDir)
	defer func() {
		if origConfig != "" {
			os.Setenv("SEC_CONFIG_DIR", origConfig)
		} else {
			os.Unsetenv("SEC_CONFIG_DIR")
		}
	}()

	legacyPath := filepath.Join(tmpDir, "skills.json")
	if err := os.WriteFile(legacyPath, []byte(`{"version":"v2.4.4","skills":[]}`), 0600); err != nil {
		t.Fatalf("failed to write skills.json: %v", err)
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	handleCleanup("default", true)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "skills.json (obsolete legacy manifest)") {
		t.Errorf("expected dry-run to identify skills.json, got: %s", output)
	}

	if _, err := os.Stat(legacyPath); err != nil {
		t.Errorf("skills.json should not be deleted during dry-run: %v", err)
	}

	r2, w2, _ := os.Pipe()
	os.Stdout = w2

	handleCleanup("default", false)

	w2.Close()
	os.Stdout = oldStdout

	var buf2 bytes.Buffer
	_, _ = io.Copy(&buf2, r2)
	output2 := buf2.String()

	if !strings.Contains(output2, "[✓ REMOVED]") {
		t.Errorf("expected actual cleanup to report removal, got: %s", output2)
	}

	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Errorf("skills.json should be deleted after cleanup, but still exists")
	}
}

func TestSkillUpdatePreservesEntryPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sec-agent-skill-path-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	origConfig := os.Getenv("SEC_CONFIG_DIR")
	os.Setenv("SEC_CONFIG_DIR", tmpDir)
	defer func() {
		if origConfig != "" {
			os.Setenv("SEC_CONFIG_DIR", origConfig)
		} else {
			os.Unsetenv("SEC_CONFIG_DIR")
		}
	}()

	// Create workspace dir with .github folder
	wsDir := filepath.Join(tmpDir, "workspace-repo")
	dotGithub := filepath.Join(wsDir, ".github")
	if err := os.MkdirAll(dotGithub, 0700); err != nil {
		t.Fatalf("failed to create workspace .github: %v", err)
	}
	targetFile := filepath.Join(dotGithub, "copilot-instructions.md")
	if err := os.WriteFile(targetFile, []byte("old-v2.4.3-content"), 0600); err != nil {
		t.Fatalf("failed to write targetFile: %v", err)
	}

	// Write skills_manifest.json with exact entry.Path
	manifest := &SkillManifest{
		Version: "v2.4.4",
		Skills: []InstalledSkillEntry{
			{
				Target:  "copilot",
				Scope:   "workspace",
				Path:    targetFile,
				Version: "v2.4.3",
			},
		},
	}
	if err := saveSkillManifest(manifest); err != nil {
		t.Fatalf("failed to save manifest: %v", err)
	}

	// Execute skill update from another directory (e.g. tmpDir root, NOT wsDir)
	origWd, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(origWd) }()

	handleSkill("default", []string{"update"})

	// Verify targetFile was updated with v2.9.1 copilot quick reference
	updatedContent, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}
	if !strings.Contains(string(updatedContent), "sec-agent — Secret Management Quick Reference") {
		t.Errorf("expected targetFile to be updated with new copilot instructions, got:\n%s", string(updatedContent))
	}

	// Verify no bogus ~/.github or ./github was created in tmpDir
	bogusFile := filepath.Join(tmpDir, ".github", "copilot-instructions.md")
	if _, err := os.Stat(bogusFile); err == nil {
		t.Errorf("CRITICAL DRIFT FAILURE: bogus skill file was created at %s instead of respecting entry.Path!", bogusFile)
	}
}

func TestStatusAndVersionSkillDriftAlerts(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sec-agent-drift-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	origConfig := os.Getenv("SEC_CONFIG_DIR")
	os.Setenv("SEC_CONFIG_DIR", tempDir)
	defer func() {
		if origConfig != "" {
			os.Setenv("SEC_CONFIG_DIR", origConfig)
		} else {
			os.Unsetenv("SEC_CONFIG_DIR")
		}
	}()

	manifest := &SkillManifest{
		Version: "v2.4.4",
		Skills: []InstalledSkillEntry{
			{
				Target:  "copilot",
				Scope:   "workspace",
				Path:    "/some/path",
				Version: "v2.4.3",
			},
		},
	}
	if err := saveSkillManifest(manifest); err != nil {
		t.Fatalf("failed to save manifest: %v", err)
	}

	// Build binary to run sec-agent version
	binPath := "./sec_test_bin_drift"
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v, output: %s", err, string(out))
	}
	defer os.Remove(binPath)

	verCmd := exec.Command(binPath, "version")
	verCmd.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tempDir)
	out, err := verCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version command failed: %v, output: %s", err, string(out))
	}
	outStr := string(out)
	if !strings.Contains(outStr, "AI SKILL DRIFT") {
		t.Errorf("expected version output to contain 'AI SKILL DRIFT', got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "run 'sec-agent skill update'") && !strings.Contains(outStr, "Run 'sec-agent skill update'") {
		t.Errorf("expected remediation advice to run skill update, got:\n%s", outStr)
	}
}

func TestFeedbackTemplateAndSchema(t *testing.T) {
	binPath := "./sec_test_bin_feedback"
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v, output: %s", err, string(out))
	}
	defer os.Remove(binPath)

	// 1. Test feedback --example
	exCmd := exec.Command(binPath, "feedback", "--example")
	exOut, err := exCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("feedback --example failed: %v, output: %s", err, string(exOut))
	}
	exStr := string(exOut)

	requiredSnippets := []string{
		"Client & Environment Fingerprint",
		"Code Editor & Version:",
		"AI Assistant & Extension:",
		"Active Model:",
		"Execution Mode:",
		"Situation Sketch (Workflow / Architecture Diagram)",
		"Tier 0: Critical Security Leak",
		"Tier 1: Architectural / Boundary Violation",
		"Tier 2: Agent Friction / Stall",
		"Tier 3: Ergonomics / Token Budget Waste",
	}
	for _, snip := range requiredSnippets {
		if !strings.Contains(exStr, snip) {
			t.Errorf("expected feedback --example output to contain %q, got:\n%s", snip, exStr)
		}
	}

	// 2. Test feedback --json
	jsonCmd := exec.Command(binPath, "feedback", "--json")
	jsonOut, err := jsonCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("feedback --json failed: %v, output: %s", err, string(jsonOut))
	}

	var dto AgentFeedbackDTO
	if err := json.Unmarshal(jsonOut, &dto); err != nil {
		t.Fatalf("failed to parse feedback JSON: %v, output: %s", err, string(jsonOut))
	}

	if dto.Tool != "sec-agent" {
		t.Errorf("expected tool = 'sec-agent', got %q", dto.Tool)
	}
	if len(dto.ImpactTierDefinitions) != 4 {
		t.Errorf("expected 4 impact tier definitions, got %d", len(dto.ImpactTierDefinitions))
	}
	if len(dto.SketchFormatGuide) == 0 {
		t.Errorf("expected non-empty sketch_format_guide")
	}

	foundTelemetryCat := false
	for _, cat := range dto.DesiredFeedbackCategories {
		if cat == "client_editor_and_assistant_telemetry" {
			foundTelemetryCat = true
			break
		}
	}
	if !foundTelemetryCat {
		t.Errorf("expected client_editor_and_assistant_telemetry in desired categories, got: %v", dto.DesiredFeedbackCategories)
	}
}

func TestSyncInstalledSkillsIfOutdated_UpgradeDirective(t *testing.T) {
	tempDir := t.TempDir()
	origConfig := os.Getenv("SEC_CONFIG_DIR")
	os.Setenv("SEC_CONFIG_DIR", tempDir)
	defer func() {
		if origConfig != "" {
			os.Setenv("SEC_CONFIG_DIR", origConfig)
		} else {
			os.Unsetenv("SEC_CONFIG_DIR")
		}
	}()

	// Create skill target directory and file
	skillDir := filepath.Join(tempDir, "skills", "sec-agent-integration")
	if err := os.MkdirAll(skillDir, 0700); err != nil {
		t.Fatalf("failed to create skillDir: %v", err)
	}
	skillFile := filepath.Join(skillDir, "SKILL.md")
	if err := os.WriteFile(skillFile, []byte("---\nname: sec-agent-integration\nversion: v2.9.1\n---\nOld content"), 0600); err != nil {
		t.Fatalf("failed to write skill file: %v", err)
	}

	manifest := &SkillManifest{
		Version: "v2.9.1",
		Skills: []InstalledSkillEntry{
			{
				Target:  "antigravity",
				Scope:   "global",
				Path:    skillFile,
				Version: "v2.9.1",
			},
		},
	}
	if err := saveSkillManifest(manifest); err != nil {
		t.Fatalf("failed to save manifest: %v", err)
	}

	origWd, _ := os.Getwd()
	_ = os.Chdir(tempDir)
	defer func() { _ = os.Chdir(origWd) }()

	// 1. Initial check: skill trails binary version. syncInstalledSkillsIfOutdated should NOT overwrite disk,
	// but should print the advisory notice to stderr prompting sec-agent skill update.
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	syncInstalledSkillsIfOutdated()

	_ = w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "[sec-agent] 💡 Active workspace AI skill instructions trail CLI version") {
		t.Errorf("expected advisory notice in stderr, got:\n%s", errOutput)
	}
	if !strings.Contains(errOutput, "Run 'sec-agent skill update' to refresh.") {
		t.Errorf("expected instruction to run 'sec-agent skill update' in stderr, got:\n%s", errOutput)
	}

	// Verify skill file was NOT overwritten during passive sync
	dataBeforeUpdate, err := os.ReadFile(skillFile)
	if err != nil {
		t.Fatalf("failed to read skill file: %v", err)
	}
	if !strings.Contains(string(dataBeforeUpdate), "Old content") {
		t.Errorf("expected skill file to remain untouched before update, got:\n%s", string(dataBeforeUpdate))
	}

	// 2. Explicit update: run handleSkill with "update"
	rUp, wUp, _ := os.Pipe()
	os.Stderr = wUp
	handleSkill("default", []string{"update"})
	_ = wUp.Close()
	os.Stderr = oldStderr

	var bufUp bytes.Buffer
	_, _ = io.Copy(&bufUp, rUp)
	upErrOutput := bufUp.String()

	if !strings.Contains(upErrOutput, "[sec-agent] 🔄 AI Skill Reload Directive:") {
		t.Errorf("expected AI Skill Reload Directive on explicit update, got:\n%s", upErrOutput)
	}
	if !strings.Contains(upErrOutput, skillFile) {
		t.Errorf("expected updated skill path in reload directive, got:\n%s", upErrOutput)
	}

	// Verify manifest and skill file were updated
	updatedManifest, err := loadSkillManifest()
	if err != nil {
		t.Fatalf("failed to load updated manifest: %v", err)
	}
	if updatedManifest.Version != Version {
		t.Errorf("expected manifest version %s, got %s", Version, updatedManifest.Version)
	}

	dataAfterUpdate, err := os.ReadFile(skillFile)
	if err != nil {
		t.Fatalf("failed to read updated skill file: %v", err)
	}
	if !strings.Contains(string(dataAfterUpdate), "sec-agent") {
		t.Errorf("expected skill file to contain updated content, got:\n%s", string(dataAfterUpdate))
	}

	// 3. Second invocation: on-disk content is already identical, so stderr should be clean!
	r2, w2, _ := os.Pipe()
	os.Stderr = w2

	syncInstalledSkillsIfOutdated()

	_ = w2.Close()
	os.Stderr = oldStderr

	var buf2 bytes.Buffer
	_, _ = io.Copy(&buf2, r2)
	errOutput2 := buf2.String()

	if errOutput2 != "" {
		t.Errorf("expected zero stderr output when skill is already identical, got:\n%s", errOutput2)
	}
}

func TestSyncInstalledSkills_NoOpWhenIdentical(t *testing.T) {
	tempDir := t.TempDir()
	origConfig := os.Getenv("SEC_CONFIG_DIR")
	os.Setenv("SEC_CONFIG_DIR", tempDir)
	defer func() {
		if origConfig != "" {
			os.Setenv("SEC_CONFIG_DIR", origConfig)
		} else {
			os.Unsetenv("SEC_CONFIG_DIR")
		}
	}()

	skillPath := filepath.Join(tempDir, "copilot-instructions.md")
	// Write exact candidate content for copilot
	if err := os.WriteFile(skillPath, []byte(copilotInstructionsTemplate), 0600); err != nil {
		t.Fatalf("failed to write copilot skill: %v", err)
	}

	manifest := &SkillManifest{
		Version: "v2.9.1",
		Skills: []InstalledSkillEntry{
			{
				Target:  "copilot",
				Scope:   "workspace",
				Path:    skillPath,
				Version: "v2.9.1",
			},
		},
	}
	if err := saveSkillManifest(manifest); err != nil {
		t.Fatalf("failed to save manifest: %v", err)
	}

	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	syncInstalledSkillsIfOutdated()

	_ = w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if output != "" {
		t.Errorf("expected empty output when skill content was already identical, got: %s", output)
	}

	m, err := loadSkillManifest()
	if err != nil {
		t.Fatalf("failed to reload manifest: %v", err)
	}
	if m.Version != Version {
		t.Errorf("expected manifest version to be silently aligned to %s, got %s", Version, m.Version)
	}
	if m.Skills[0].Version != Version {
		t.Errorf("expected skill entry version to be %s, got %s", Version, m.Skills[0].Version)
	}
}

func TestHandleStatusQuick_SkillReporting(t *testing.T) {
	tempDir, err := os.MkdirTemp("/tmp", "sq-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	origConfig := os.Getenv("SEC_CONFIG_DIR")
	os.Setenv("SEC_CONFIG_DIR", tempDir)
	defer func() {
		if origConfig != "" {
			os.Setenv("SEC_CONFIG_DIR", origConfig)
		} else {
			os.Unsetenv("SEC_CONFIG_DIR")
		}
	}()

	profile := "p"
	sockPath, err := config.GetSocketPath(profile)
	if err != nil {
		t.Fatalf("failed to get socket path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(sockPath), 0700); err != nil {
		t.Fatalf("failed to create socket dir: %v", err)
	}
	_ = os.Remove(sockPath)

	// Spin up a responsive mock unix socket listener
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}
	defer l.Close()
	defer os.Remove(sockPath)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			var req daemon.IPCRequest
			_ = json.NewDecoder(conn).Decode(&req)
			resp := daemon.IPCResponse{Success: true, Version: Version}
			_ = json.NewEncoder(conn).Encode(resp)
			_ = conn.Close()
		}
	}()

	skillPath := filepath.Join(tempDir, "SKILL.md")
	manifest := &SkillManifest{
		Version: Version,
		Skills: []InstalledSkillEntry{
			{
				Target:  "antigravity",
				Scope:   "global",
				Path:    skillPath,
				Version: Version,
			},
		},
	}
	if err := saveSkillManifest(manifest); err != nil {
		t.Fatalf("failed to save manifest: %v", err)
	}

	// 1. Test text output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	jsonErrors = false
	handleStatusQuick(profile)

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	textOut := buf.String()

	if !strings.Contains(textOut, "[✓] AI Skill Doc:   "+skillPath+" ("+Version+": Synced)") {
		t.Errorf("expected skill line in status --quick, got:\n%s", textOut)
	}
	if !strings.Contains(textOut, "[✓] Socket Status:  ACTIVE (IPC socket responsive)") {
		t.Errorf("expected active socket responsive status, got:\n%s", textOut)
	}

	// 2. Test JSON output
	r2, w2, _ := os.Pipe()
	os.Stdout = w2

	jsonErrors = true
	handleStatusQuick(profile)
	jsonErrors = false

	_ = w2.Close()
	os.Stdout = oldStdout

	var buf2 bytes.Buffer
	_, _ = io.Copy(&buf2, r2)
	jsonOut := buf2.Bytes()

	var res map[string]interface{}
	if err := json.Unmarshal(jsonOut, &res); err != nil {
		t.Fatalf("failed to parse JSON from handleStatusQuick: %v, raw:\n%s", err, string(jsonOut))
	}
	if res["skill_path"] != skillPath {
		t.Errorf("expected skill_path %s, got %v", skillPath, res["skill_path"])
	}
	if res["skill_version"] != Version {
		t.Errorf("expected skill_version %s, got %v", Version, res["skill_version"])
	}
	if res["skill_synced"] != true {
		t.Errorf("expected skill_synced == true, got %v", res["skill_synced"])
	}
	if res["status"] != "ACTIVE" {
		t.Errorf("expected status == ACTIVE, got %v", res["status"])
	}
}

// TestHandleStatusQuick_HijackDeniedReportsDenied verifies that a ping denied by
// the daemon's hijack detector is reported as denied/locked, not active - guards
// against the false-healthy report where status --quick ignored pingResp.Success.
func TestHandleStatusQuick_HijackDeniedReportsDenied(t *testing.T) {
	tempDir, err := os.MkdirTemp("/tmp", "sq-hijack-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	origConfig := os.Getenv("SEC_CONFIG_DIR")
	os.Setenv("SEC_CONFIG_DIR", tempDir)
	defer func() {
		if origConfig != "" {
			os.Setenv("SEC_CONFIG_DIR", origConfig)
		} else {
			os.Unsetenv("SEC_CONFIG_DIR")
		}
	}()

	profile := "hijack-denied-quick-test"
	sockPath, err := config.GetSocketPath(profile)
	if err != nil {
		t.Fatalf("failed to get socket path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(sockPath), 0700); err != nil {
		t.Fatalf("failed to create socket dir: %v", err)
	}
	_ = os.Remove(sockPath)

	// Mock daemon that denies every ping, as the hijack detector would.
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}
	defer l.Close()
	defer os.Remove(sockPath)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			var req daemon.IPCRequest
			_ = json.NewDecoder(conn).Decode(&req)
			resp := daemon.IPCResponse{Success: false, Error: "ACCESS DENIED: Remote session hijacking or screen sharing detected."}
			_ = json.NewEncoder(conn).Encode(resp)
			_ = conn.Close()
		}
	}()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	jsonErrors = false
	handleStatusQuick(profile)

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	textOut := buf.String()

	if strings.Contains(textOut, "ACTIVE (IPC socket responsive)") {
		t.Errorf("expected hijack-denied ping not to report ACTIVE, got:\n%s", textOut)
	}
	if !strings.Contains(textOut, "DENIED") {
		t.Errorf("expected hijack-denied ping to report DENIED status, got:\n%s", textOut)
	}

	r2, w2, _ := os.Pipe()
	os.Stdout = w2

	jsonErrors = true
	handleStatusQuick(profile)
	jsonErrors = false

	_ = w2.Close()
	os.Stdout = oldStdout

	var buf2 bytes.Buffer
	_, _ = io.Copy(&buf2, r2)

	var res2 map[string]interface{}
	if err := json.Unmarshal(buf2.Bytes(), &res2); err != nil {
		t.Fatalf("failed to parse JSON from handleStatusQuick: %v, raw:\n%s", err, buf2.String())
	}
	if res2["status"] == "ACTIVE" {
		t.Errorf("expected JSON status not to be ACTIVE on hijack denial, got %v", res2["status"])
	}
}

func TestHandleStatusQuick_OrphanedSocketDetection(t *testing.T) {
	tempDir := t.TempDir()
	profile := "orphaned-socket-test-profile"

	sockPath, err := config.GetSocketPath(profile)
	if err != nil {
		t.Fatalf("failed to get socket path: %v", err)
	}
	_ = os.Remove(sockPath)
	if err := os.MkdirAll(filepath.Dir(sockPath), 0700); err != nil {
		t.Fatalf("failed to create socket dir: %v", err)
	}

	// Create an orphaned regular file at the socket path (no process listening)
	if err := os.WriteFile(sockPath, []byte(""), 0600); err != nil {
		t.Fatalf("failed to write dummy socket file: %v", err)
	}
	defer os.Remove(sockPath)

	// Build sec binary
	binPath := filepath.Join(tempDir, "sec_orphaned_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\nOutput: %s", err, out)
	}
	defer os.Remove(binPath)

	cmd := exec.Command(binPath, "status", "--quick", "--profile", profile)
	cmd.Env = append(os.Environ(), "SEC_TEST_MODE=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected status --quick on orphaned socket to exit with error, output:\n%s", out)
	}

	outStr := string(out)
	if !strings.Contains(outStr, "Stale socket file detected") && !strings.Contains(outStr, "is not running") {
		t.Errorf("expected output to mention stale socket or daemon not running, got:\n%s", outStr)
	}
}

func TestSkillStatusScopesAndWorkspaceDiscovery(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}
	defer func() { _ = os.Chdir(origWd) }()

	// Create a mock .github/copilot-instructions.md in tmpDir
	copilotDir := filepath.Join(tmpDir, ".github")
	_ = os.MkdirAll(copilotDir, 0700)
	copilotFile := filepath.Join(copilotDir, "copilot-instructions.md")
	_ = os.WriteFile(copilotFile, []byte(copilotInstructionsTemplate), 0600)

	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	handleSkill("default", []string{"status"})

	w.Close()
	outBytes, _ := io.ReadAll(r)
	os.Stdout = rescueStdout
	out := string(outBytes)

	if !strings.Contains(out, "Scope Definitions:") {
		t.Errorf("expected Scope Definitions header in status output, got:\n%s", out)
	}
	if !strings.Contains(out, "global") || !strings.Contains(out, "workspace") {
		t.Errorf("expected global and workspace explanations in status output, got:\n%s", out)
	}
	if !strings.Contains(out, "copilot") || !strings.Contains(out, "[✓] Up to date") {
		t.Errorf("expected discovered copilot skill to be reported as Up to date, got:\n%s", out)
	}
}
