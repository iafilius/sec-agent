package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"secure_secrets/internal/store"
)

func TestVerifyLocalBackupMount(t *testing.T) {
	// Non-/Volumes local path is allowed
	if err := verifyLocalBackupMount(t.TempDir()); err != nil {
		t.Fatalf("expected non-/Volumes path to pass mount check, got: %v", err)
	}

	// Non-existent /Volumes mount must fail closed
	if err := verifyLocalBackupMount("/Volumes/SecAgentNonExistentVolume99999/Backups"); err == nil {
		t.Fatalf("expected unmounted /Volumes path to fail closed, got nil")
	}
}

func TestExclusionCandidateMonitor(t *testing.T) {
	var redactedBuf bytes.Buffer
	w := newRsyncStderrFilterWriter(&redactedBuf, false)

	_, _ = w.Write([]byte("rsync: opendir \"secret-sub/tcc-locked\" failed: Operation not permitted (1)\n"))
	_, _ = w.Write([]byte("rsync: opendir \"secret-sub/tcc-locked\" failed: Operation not permitted (1)\n"))
	_, _ = w.Write([]byte("rsync: send_files failed to open \"private/root-owned.db\": Permission denied (13)\n"))
	_, _ = w.Write([]byte("skipping non-regular file \"sockets/agent.sock\"\n"))

	skipped := w.Flush()
	report := w.FlushExclusionReport()

	if skipped != 1 {
		t.Errorf("expected skippedNonRegular=1, got %d", skipped)
	}
	if report.PermissionTCCCount != 3 {
		t.Errorf("expected PermissionTCCCount=3, got %d", report.PermissionTCCCount)
	}
	if len(report.Candidates) != 2 {
		t.Fatalf("expected 2 deduplicated candidates, got %v", report.Candidates)
	}
	if report.Candidates[0] != "secret-sub/tcc-locked" || report.Candidates[1] != "private/root-owned.db" {
		t.Errorf("unexpected candidates: %v", report.Candidates)
	}
	// Default privacy mode stderr must NOT leak raw paths
	if strings.Contains(redactedBuf.String(), "secret-sub/tcc-locked") || strings.Contains(redactedBuf.String(), "root-owned.db") {
		t.Errorf("LEAK: default redacted stderr exposed raw paths:\n%s", redactedBuf.String())
	}
}

func TestLocalRsyncBackupE2E(t *testing.T) {
	if _, err := exec.LookPath("rsync"); err != nil {
		t.Skip("rsync binary not available in PATH")
	}

	// Short /tmp config dir for macOS Unix socket path length
	tmpCfgDir, err := os.MkdirTemp("/tmp", "sec-locbck-")
	if err != nil {
		t.Fatalf("failed creating temp config dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpCfgDir) })

	localBase := t.TempDir()
	destBase := t.TempDir()

	// Create two source folders: personal/ and work/ (with excluded subdir archived-client/ + .DS_Store)
	if err := os.MkdirAll(filepath.Join(localBase, "personal"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(localBase, "work", "active-proj"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(localBase, "work", "archived-client"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localBase, "personal", "notes.txt"), []byte("v1-personal\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localBase, "work", "active-proj", "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localBase, "work", "archived-client", "skip.txt"), []byte("must-be-excluded\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localBase, "work", ".DS_Store"), []byte("mac-junk"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Build CLI binary and run full local backup flow via vault daemon
	binPath := filepath.Join(t.TempDir(), "sec-agent-local-bck")
	if out, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput(); err != nil {
		t.Fatalf("failed building binary: %v\n%s", err, string(out))
	}

	profile := "local-bck-test"
	baseEnv := func() []string {
		var env []string
		for _, kv := range os.Environ() {
			if strings.HasPrefix(kv, "SEC_PROFILE=") || strings.HasPrefix(kv, "SEC_SESSION_TOKEN=") {
				continue
			}
			env = append(env, kv)
		}
		return append(env, "SEC_CONFIG_DIR="+tmpCfgDir, "SEC_TEST_MODE=1", "SEC_NO_SOUND=1")
	}

	runCLI := func(token string, args ...string) string {
		t.Helper()
		cmd := exec.Command(binPath, args...)
		env := baseEnv()
		if token != "" {
			env = append(env, "SEC_SESSION_TOKEN="+token)
		}
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("sec %v failed: %v\nOutput:\n%s", args, err, string(out))
		}
		return string(out)
	}

	openOut := runCLI("", "--profile", profile, "open")
	var token string
	for _, line := range strings.Split(openOut, "\n") {
		if strings.HasPrefix(line, "export SEC_SESSION_TOKEN=") {
			token = strings.Trim(strings.TrimPrefix(line, "export SEC_SESSION_TOKEN="), `"' `)
		}
	}
	t.Cleanup(func() {
		cmd := exec.Command(binPath, "--profile", profile, "lock")
		cmd.Env = append(baseEnv(), "SEC_SESSION_TOKEN="+token)
		_ = cmd.Run()
	})

	// 1. Initialize local backup job with 2 folders
	runCLI(token, "--profile", profile, "backup", "init", "dev-disk",
		"--local",
		"--local-base", localBase,
		"--dest-base", destBase,
		"--folder", "personal",
		"--folder", "work",
	)

	// 2. Add folder-specific exclude to work (must merge with job-level defaults!)
	runCLI(token, "--profile", profile, "backup", "add-folder", "dev-disk", "work", "--exclude", "archived-client/")

	// Verify `backup show --json` reports transport=local and additive excludes
	showJSON := runCLI(token, "--profile", profile, "backup", "show", "dev-disk", "--json")
	var m store.BackupManifest
	if err := json.Unmarshal([]byte(showJSON), &m); err != nil {
		t.Fatalf("failed unmarshaling show JSON: %v\n%s", err, showJSON)
	}
	if m.EffectiveTransport() != store.BackupTransportLocal {
		t.Fatalf("expected transport=local, got %q", m.EffectiveTransport())
	}

	// 3. Run local backup #1
	runCLI(token, "--profile", profile, "backup", "run", "dev-disk")

	// Verify personal/notes.txt and work/active-proj/main.go were copied
	gotPersonal, err := os.ReadFile(filepath.Join(destBase, "personal", "notes.txt"))
	if err != nil || string(gotPersonal) != "v1-personal\n" {
		t.Fatalf("expected synced personal/notes.txt, got %q err=%v", string(gotPersonal), err)
	}
	if _, err := os.Stat(filepath.Join(destBase, "work", "active-proj", "main.go")); err != nil {
		t.Fatalf("expected synced work/active-proj/main.go, got err=%v", err)
	}
	// Verify excluded subdir AND job-level default .DS_Store were both excluded!
	if _, err := os.Stat(filepath.Join(destBase, "work", "archived-client", "skip.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected archived-client/skip.txt to be excluded, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(destBase, "work", ".DS_Store")); !os.IsNotExist(err) {
		t.Fatalf("expected job-level default .DS_Store to remain excluded, stat err=%v", err)
	}

	// 4. Modify personal/notes.txt (different byte length so rsync transfers even within --modify-window=2)
	// and run backup #2 -> verify dated -History preserves v1!
	if err := os.WriteFile(filepath.Join(localBase, "personal", "notes.txt"), []byte("v2-personal-updated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runCLI(token, "--profile", profile, "backup", "run", "dev-disk", "personal")

	gotV2, err := os.ReadFile(filepath.Join(destBase, "personal", "notes.txt"))
	if err != nil || string(gotV2) != "v2-personal-updated\n" {
		t.Fatalf("expected updated v2-personal-updated, got %q err=%v", string(gotV2), err)
	}
	histMatches, _ := filepath.Glob(filepath.Join(destBase, "personal-History", "*", "notes.txt"))
	if len(histMatches) == 0 {
		t.Fatalf("expected dated personal-History/<YYYY-MM-DD>/notes.txt preserving v1")
	}
	histData, err := os.ReadFile(histMatches[0])
	if err != nil || string(histData) != "v1-personal\n" {
		t.Fatalf("expected history file to preserve v1-personal, got %q err=%v", string(histData), err)
	}

	// Verify destination rsync_*.log was created
	logMatches, _ := filepath.Glob(filepath.Join(destBase, "rsync_personal_*.log"))
	if len(logMatches) == 0 {
		t.Fatalf("expected destination rsync_personal_*.log in %s", destBase)
	}
}

func TestBuildDirectLocalRsyncArgsZeroPathLeakage(t *testing.T) {
	m := store.BackupManifest{
		Name:       store.BackupJobName("dev-disk"),
		Transport:  store.BackupTransportLocal,
		LocalBase:  "/Users/exampleuser",
		RemoteBase: "/Volumes/SensitiveDiskName/PrivateDevBackups",
		Folders: []store.BackupFolderSpec{
			{Source: "SensitiveFolder"},
		},
	}
	m.ApplyDefaults()
	args := buildDirectLocalRsyncArgs(m, m.Folders[0], "/tmp/s123456", true, true, false, false)
	joined := strings.Join(args, " ")

	for _, forbidden := range []string{"SensitiveDiskName", "PrivateDevBackups", "SensitiveFolder", "History", "rsync_sensitive", "exampleuser"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("LEAK: direct local rsync argv exposed %q: %s", forbidden, joined)
		}
	}
	for _, required := range []string{"--backup-dir=/tmp/s123456/h", "--log-file=l", "--exclude-from=/dev/fd/3", "s/", "d/"} {
		if !strings.Contains(joined, required) {
			t.Errorf("expected direct local rsync argv to contain %q, got: %s", required, joined)
		}
	}
}

func TestNormalizeExclusionCandidatePath(t *testing.T) {
	if got := normalizeExclusionCandidatePath("/home/user/work/sub/locked.db", "", "work"); got != "sub/locked.db" {
		t.Errorf("expected remote relative path 'sub/locked.db', got %q", got)
	}
	if got := normalizeExclusionCandidatePath("/Users/example/personal/a/b.txt", "/Users/example/personal", "personal"); got != "a/b.txt" {
		t.Errorf("expected local relative path 'a/b.txt', got %q", got)
	}
	if got := normalizeExclusionCandidatePath("already/relative/file", "", "work"); got != "already/relative/file" {
		t.Errorf("expected unchanged relative path, got %q", got)
	}
}
