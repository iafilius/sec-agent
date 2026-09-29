package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"secure_secrets/internal/config"
	"secure_secrets/internal/crypto"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"
)

func TestProfileNewNonInteractiveBlocked(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_profile_test_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v, output: %s", err, string(out))
	}

	// In non-interactive mode without --seed, profile new should exit 78 with ASCII blocker
	cmd := exec.Command(binPath, "profile", "new", "testblocked")
	cmd.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir, "NONINTERACTIVE=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected profile new to fail in non-interactive mode without seed, but succeeded")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 78 {
		t.Errorf("expected exit code 78, got: %v (exit code: %d)", err, exitErr.ExitCode())
	}

	outStr := string(out)
	if !strings.Contains(outStr, "+------------------------------------------+") {
		t.Errorf("expected output to contain ASCII box border '+------------------------------------------+', got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "INTERACTIVE TERMINAL REQUIRED") {
		t.Errorf("expected output to contain 'INTERACTIVE TERMINAL REQUIRED', got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "sec-agent profile new testblocked") {
		t.Errorf("expected output to recommend running 'sec-agent profile new testblocked', got:\n%s", outStr)
	}
}

func TestProfileNewWithSeedAndSecrc(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %v", err)
	}

	binPath := filepath.Join(tmpDir, "sec_profile_test_bin2")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v, output: %s", err, string(out))
	}

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir to tmpDir: %v", err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	mnemonic, err := crypto.GenerateMnemonic()
	if err != nil {
		t.Fatalf("failed to generate mnemonic: %v", err)
	}

	// Run profile new testnode --seed "<mnemonic>" --secrc in SEC_TEST_MODE=1
	cmd := exec.Command(binPath, "profile", "new", "testnode", "--seed", mnemonic, "--secrc")
	cmd.Env = append(os.Environ(),
		"SEC_CONFIG_DIR="+tmpDir,
		"SEC_TEST_MODE=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("profile new failed: %v, output:\n%s", err, string(out))
	}

	outStr := string(out)
	if !strings.Contains(outStr, "Dual-Slot Touch ID + BIP39 recovery key") {
		t.Errorf("expected success message with Dual-Slot Touch ID + BIP39 recovery key, got:\n%s", outStr)
	}
	expectedSecrc := filepath.Join(tmpDir, ".secrc")
	if !strings.Contains(outStr, expectedSecrc) {
		t.Errorf("expected success message to contain absolute path %s, got:\n%s", expectedSecrc, outStr)
	}
	if !strings.Contains(outStr, "does not appear to be a Git repository") {
		t.Errorf("expected warning about missing Git repository marker, got:\n%s", outStr)
	}

	// 1. Verify vault file was created with complete v2.0 envelope
	vaultPath := filepath.Join(tmpDir, "secrets_testnode.enc")
	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatalf("vault file %s was not created: %v", vaultPath, err)
	}
	env, err := store.ReadVaultEnvelope(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault envelope: %v", err)
	}
	if !env.HasSlot1() || env.Slot1 == nil {
		t.Errorf("expected created vault to have Slot1 enrolled, got: %+v", env)
	}

	// 2. Verify .secrc file was written
	secrcPath := filepath.Join(tmpDir, ".secrc")
	secrcData, err := os.ReadFile(secrcPath)
	if err != nil {
		t.Fatalf("failed to read .secrc: %v", err)
	}
	if !strings.Contains(string(secrcData), `"profile": "testnode"`) {
		t.Errorf("expected .secrc to contain profile testnode, got:\n%s", string(secrcData))
	}

	// 3. Test sec profile ls
	lsCmd := exec.Command(binPath, "profile", "ls")
	lsCmd.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir)
	lsOut, err := lsCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("profile ls failed: %v, output: %s", err, string(lsOut))
	}
	if !strings.Contains(string(lsOut), "testnode") {
		t.Errorf("expected profile ls to show 'testnode', got:\n%s", string(lsOut))
	}

	// 4. Test duplicate creation fails
	dupCmd := exec.Command(binPath, "profile", "new", "testnode", "--seed", mnemonic)
	dupCmd.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir, "SEC_TEST_MODE=1")
	dupOut, dupErr := dupCmd.CombinedOutput()
	if dupErr == nil {
		t.Errorf("expected duplicate profile new to fail, but succeeded with output: %s", string(dupOut))
	}
	if !strings.Contains(string(dupOut), "already exists") {
		t.Errorf("expected duplicate profile error message to mention 'already exists', got:\n%s", string(dupOut))
	}
}

func TestProfileNewDefaultProfileRejection(t *testing.T) {
	binPath := "./sec_profile_def_test"
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v, output: %s", err, string(out))
	}
	defer os.Remove(binPath)

	cmd := exec.Command(binPath, "profile", "new", "default")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected profile new default to fail, but succeeded")
	}
	if !strings.Contains(string(out), "cannot create profile named 'default'") {
		t.Errorf("expected error message rejecting 'default', got:\n%s", string(out))
	}
}

func TestDoctorSkipKeychainAndHeadless(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SEC_CONFIG_DIR", tmpDir)

	binPath := "./sec_doctor_test_bin"
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v, output: %s", err, string(out))
	}
	defer os.Remove(binPath)

	// Test with --skip-keychain flag
	cmd := exec.Command(binPath, "doctor", "--skip-keychain")
	cmd.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("doctor --skip-keychain failed: %v, output:\n%s", err, string(out))
	}

	outStr := string(out)
	if !strings.Contains(outStr, "Skipped live Touch ID Keychain probe") {
		t.Errorf("expected skipped Touch ID Keychain probe message, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "--skip-keychain flag supplied") {
		t.Errorf("expected mention of --skip-keychain flag, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "All system diagnostic checks complete!") {
		t.Errorf("expected completion message, got:\n%s", outStr)
	}
}

func TestDoctorNestedEnvelopeDetectionAndRepair(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SEC_CONFIG_DIR", tmpDir)

	binPath := filepath.Join(tmpDir, "sec_doctor_repair_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v, output: %s", err, string(out))
	}

	// 1. Create a 4-level nested vault file in tmpDir
	vaultPath := filepath.Join(tmpDir, "secrets_test-nested.enc")
	currPayload := []byte("dummy-ciphertext-bytes")
	for level := 1; level <= 4; level++ {
		env := &store.VaultEnvelope{
			SchemaVersion: store.SchemaV2,
			Payload:       currPayload,
		}
		currPayload, _ = json.Marshal(env)
	}
	if err := os.WriteFile(vaultPath, currPayload, 0600); err != nil {
		t.Fatalf("failed to write nested vault file: %v", err)
	}

	if d := store.InspectVaultNesting(vaultPath); d != 4 {
		t.Fatalf("expected initial depth 4, got %d", d)
	}

	// 2. Execute `sec doctor --skip-keychain` and verify detection
	docCmd := exec.Command(binPath, "doctor", "--skip-keychain")
	docCmd.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir)
	docOut, err := docCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("doctor --skip-keychain failed: %v, output:\n%s", err, string(docOut))
	}
	docStr := string(docOut)
	if !strings.Contains(docStr, "Nested Envelope Detected (Depth: 4)") {
		t.Errorf("expected doctor output to detect depth 4 nesting, got:\n%s", docStr)
	}
	if !strings.Contains(docStr, "Run 'sec doctor --repair' to auto-heal") {
		t.Errorf("expected doctor output to suggest --repair, got:\n%s", docStr)
	}

	// 3. Execute `sec doctor --repair` and verify flattening
	repairCmd := exec.Command(binPath, "doctor", "--repair")
	repairCmd.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir)
	repairOut, err := repairCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("doctor --repair failed: %v, output:\n%s", err, string(repairOut))
	}
	repStr := string(repairOut)
	if !strings.Contains(repStr, "Flattened from depth 4 to 1") {
		t.Errorf("expected repair output to mention flattening from depth 4 to 1, got:\n%s", repStr)
	}
	if !strings.Contains(repStr, "Successfully repaired 1 nested vault envelope(s)") {
		t.Errorf("expected 1 repaired vault message, got:\n%s", repStr)
	}

	// Check backup file exists
	bakPath := vaultPath + ".bak_nested"
	if _, statErr := os.Stat(bakPath); statErr != nil {
		t.Errorf("expected backup file %s to exist: %v", bakPath, statErr)
	}

	// Check new depth is 1
	if d := store.InspectVaultNesting(vaultPath); d != 1 {
		t.Errorf("expected depth 1 after repair, got %d", d)
	}

	// 4. Re-running `doctor --repair` on clean vaults reports all clean
	rerunCmd := exec.Command(binPath, "doctor", "--repair")
	rerunCmd.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir)
	rerunOut, err := rerunCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("second doctor --repair failed: %v, output:\n%s", err, string(rerunOut))
	}
	if !strings.Contains(string(rerunOut), "All vault envelopes are already clean") {
		t.Errorf("expected clean message on rerun, got:\n%s", string(rerunOut))
	}
}

func TestCheckProductionGuard(t *testing.T) {
	// 1. Non-production profile executes without error or prompt
	checkProductionGuard("test-dev", nil)

	// 2. Production profile with --dry-run bypasses prompt
	checkProductionGuard("test-prod", []string{"--dry-run"})

	// 3. Production profile with --confirm-prod bypasses prompt
	checkProductionGuard("test-prod", []string{"--confirm-prod"})
}

func TestEvictStaleDaemonAndDeduplication(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "sec-dedup")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	t.Setenv("SEC_CONFIG_DIR", tmpDir)
	t.Setenv("SEC_TEST_ALLOW_KILL", "1")

	profile := "t-dedup"

	// 1. Spawn a dummy sleeper process to simulate an orphaned stale daemon
	dummyCmd := exec.Command("sleep", "60")
	if err := dummyCmd.Start(); err != nil {
		t.Fatalf("failed to spawn dummy process: %v", err)
	}
	defer func() {
		if dummyCmd.Process != nil {
			_ = dummyCmd.Process.Kill()
		}
	}()

	// 2. Write a simulated stale PID lockfile
	pidPath, err := config.GetPIDFilePath(profile)
	if err != nil {
		t.Fatalf("failed to get pid file path: %v", err)
	}
	info := daemon.PIDLockInfo{
		PID:        dummyCmd.Process.Pid,
		Profile:    profile,
		Executable: "/usr/local/bin/sec",
		Version:    "v2.10.0",
	}
	data, _ := json.Marshal(info)
	_ = os.WriteFile(pidPath, data, 0600)

	// Write dummy socket and lock file
	sockPath, _ := config.GetSocketPath(profile)
	lockPath, _ := config.GetLockFilePath(profile)
	_ = os.WriteFile(sockPath, []byte("stale-sock"), 0600)
	_ = os.WriteFile(lockPath, []byte("stale-lock"), 0600)

	// Verify findDaemonPIDs finds the dummy process
	pids := findDaemonPIDs(profile)
	found := false
	for _, p := range pids {
		if p == dummyCmd.Process.Pid {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected findDaemonPIDs to find dummy PID %d, got %v", dummyCmd.Process.Pid, pids)
	}

	// 3. Call evictStaleDaemon
	evictStaleDaemon(profile)

	// 4. Verify dummy process was terminated
	time.Sleep(150 * time.Millisecond)
	waitErr := dummyCmd.Wait()
	if waitErr == nil {
		t.Errorf("expected dummy process %d to be killed by evictStaleDaemon, but it exited cleanly", dummyCmd.Process.Pid)
	}

	// 5. Verify PID file, socket, and lock file were cleaned up
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Errorf("expected PID file %s to be removed", pidPath)
	}
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Errorf("expected socket %s to be removed", sockPath)
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Errorf("expected lock file %s to be removed", lockPath)
	}
}

func TestDaemonListCommand(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "sec-list")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	t.Setenv("SEC_CONFIG_DIR", tmpDir)

	// Verify handleDaemonList runs cleanly when no daemons are running
	handleDaemonList(nil)
	handleDaemonList([]string{"--json"})

	// Spawn a dummy process and write PID lockfile
	dummyCmd := exec.Command("sleep", "30")
	if err := dummyCmd.Start(); err != nil {
		t.Fatalf("failed to start dummy process: %v", err)
	}
	defer func() {
		if dummyCmd.Process != nil {
			_ = dummyCmd.Process.Kill()
			_ = dummyCmd.Wait()
		}
	}()

	pidPath, _ := config.GetPIDFilePath("testlist")
	info := daemon.PIDLockInfo{
		PID:        dummyCmd.Process.Pid,
		Profile:    "testlist",
		Executable: "/usr/local/bin/sec",
		Version:    "v2.13.0",
	}
	data, _ := json.Marshal(info)
	_ = os.WriteFile(pidPath, data, 0600)

	// Verify listing with active daemon entry
	handleDaemonList(nil)
	handleDaemonList([]string{"--json"})

	_ = dummyCmd.Process.Kill()
	_ = dummyCmd.Wait()
}

func TestDoctorDuplicateDaemonAnomaly(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "sec-anomaly")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	t.Setenv("SEC_CONFIG_DIR", tmpDir)

	// In-process doctor test with single or no daemon -> no duplicate anomaly
	handleDoctor("default", []string{"--skip-keychain"})
}

func TestRunProcessGroupIsolation(t *testing.T) {
	// Verify that a command spawned with Setpgid: true creates a distinct process group
	cmd := exec.Command("sleep", "10")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start process with Setpgid: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("failed to get pgid: %v", err)
	}
	if pgid != cmd.Process.Pid {
		t.Errorf("expected pgid to equal child pid %d, got %d", cmd.Process.Pid, pgid)
	}

	// Signal the process group via -pgid
	if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil {
		t.Fatalf("failed to signal process group: %v", err)
	}

	waitErr := cmd.Wait()
	if waitErr == nil {
		t.Errorf("expected command to terminate via signal, but exited cleanly")
	}
}

func TestCheckProductionGuardLiveSessionLifecycle(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "sec-guard-live")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	t.Setenv("SEC_CONFIG_DIR", tmpDir)

	profile := "prod"
	d, err := daemon.NewDaemon(profile, time.Hour, "v2.13.0")
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}
	d.IsTestInstance = true

	dErrChan := make(chan error, 1)
	go func() {
		dErrChan <- d.Start()
	}()
	defer d.Stop()

	sockPath, err := config.GetSocketPath(profile)
	if err != nil {
		t.Fatalf("failed to get socket path: %v", err)
	}

	for i := 0; i < 40; i++ {
		select {
		case err := <-dErrChan:
			t.Fatalf("d.Start failed: %v", err)
		default:
		}
		if _, statErr := os.Stat(sockPath); statErr == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	testToken := "live-session-test-token"
	d.SetMasterKeyForTest([]byte("mock-32-byte-master-key-01234567"))
	d.SetSessionTokenForTest(testToken)
	t.Setenv("SEC_SESSION_TOKEN", testToken)

	// 1. Initial state: ProductionConfirmed must be false
	resp, err := queryDaemonRaw(profile, daemon.IPCRequest{Action: daemon.IPCActionPing})
	if err != nil || resp == nil {
		t.Fatalf("ping failed: %v", err)
	}
	if resp.ProductionConfirmed {
		t.Fatalf("expected initial ProductionConfirmed to be false")
	}

	// 2. Calling with --confirm-prod propagates confirmation to daemon memory
	checkProductionGuard(store.ProfileName(profile), []string{"--confirm-prod"})

	resp, err = queryDaemonRaw(profile, daemon.IPCRequest{Action: daemon.IPCActionPing})
	if err != nil || resp == nil || !resp.ProductionConfirmed {
		t.Fatalf("expected ProductionConfirmed to be true after --confirm-prod, got: %v", resp)
	}

	// 3. Subsequent call without --confirm-prod succeeds because session is already confirmed
	checkProductionGuard(store.ProfileName(profile), nil)

	// 4. Dry-run always bypasses guard without affecting confirmation
	checkProductionGuard(store.ProfileName(profile), []string{"--dry-run"})

	// 5. Locking/wiping session resets confirmation
	_, _ = queryDaemonRaw(profile, daemon.IPCRequest{Action: daemon.IPCActionClear})
	resp, err = queryDaemonRaw(profile, daemon.IPCRequest{Action: daemon.IPCActionPing})
	if err != nil || resp == nil || resp.ProductionConfirmed {
		t.Fatalf("expected ProductionConfirmed to reset to false after clear, got: %v", resp)
	}
}

func TestRunProcessGroupGrandchildTermination(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "grandchild.pid")

	// Parent script creates a distinct process group and launches a grandchild background process
	cmd := exec.Command("sh", "-c", "sleep 60 & echo $! > "+pidFile+" && wait")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start parent script: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("failed to get pgid: %v", err)
	}

	var grandchildPid int
	for i := 0; i < 40; i++ {
		if data, err := os.ReadFile(pidFile); err == nil && len(strings.TrimSpace(string(data))) > 0 {
			grandchildPid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if grandchildPid <= 0 {
		t.Fatalf("failed to read grandchild PID from %s", pidFile)
	}

	// Verify grandchild is running
	if err := syscall.Kill(grandchildPid, 0); err != nil {
		t.Fatalf("grandchild process %d is not alive: %v", grandchildPid, err)
	}

	// Forward SIGTERM to the process group (-pgid), exactly as sec run does
	if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil {
		t.Fatalf("failed to signal process group -%d: %v", pgid, err)
	}

	_ = cmd.Wait()

	// Verify grandchild was cleanly reaped and did not linger as an orphan
	time.Sleep(100 * time.Millisecond)
	if err := syscall.Kill(grandchildPid, 0); err == nil {
		_ = syscall.Kill(grandchildPid, syscall.SIGKILL)
		t.Fatalf("grandchild process %d lingered as an orphan after parent process group termination!", grandchildPid)
	}
}

func TestDoctorDuplicateDaemonAnomalyReporting(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "sec-anomaly-rep")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	t.Setenv("SEC_CONFIG_DIR", tmpDir)

	profile := "dup-rep"

	// Spawn dummy process
	dummyCmd := exec.Command("sleep", "30")
	if err := dummyCmd.Start(); err != nil {
		t.Fatalf("failed to start dummy: %v", err)
	}
	defer func() {
		if dummyCmd.Process != nil {
			_ = dummyCmd.Process.Kill()
			_ = dummyCmd.Wait()
		}
	}()

	pidPath, _ := config.GetPIDFilePath(profile)
	info := daemon.PIDLockInfo{
		PID:        dummyCmd.Process.Pid,
		Profile:    profile,
		Executable: "/usr/local/bin/sec",
		Version:    "v2.13.0",
	}
	data, _ := json.Marshal(info)
	_ = os.WriteFile(pidPath, data, 0600)

	// Verify doctor runs cleanly with single instance detected
	handleDoctor(profile, []string{"--skip-keychain"})
}

func TestDetectDaemonAnomaly(t *testing.T) {
	// 1. Zero PIDs -> no anomaly
	hasAnomaly, msg, rem := detectDaemonAnomaly("test", []int{})
	if hasAnomaly || msg != "" || rem != "" {
		t.Errorf("expected no anomaly for 0 PIDs, got hasAnomaly=%v, msg=%q", hasAnomaly, msg)
	}

	// 2. Single PID -> healthy, single instance active
	hasAnomaly, msg, rem = detectDaemonAnomaly("test", []int{1234})
	if hasAnomaly || !strings.Contains(msg, "Single instance active (PID: 1234)") || rem != "" {
		t.Errorf("expected single instance message, got hasAnomaly=%v, msg=%q", hasAnomaly, msg)
	}

	// 3. Multiple PIDs -> anomaly detected with remediation
	hasAnomaly, msg, rem = detectDaemonAnomaly("prod", []int{101, 202, 303})
	if !hasAnomaly {
		t.Fatalf("expected anomaly to be true for multiple PIDs")
	}
	if !strings.Contains(msg, "Multiple daemon processes (3) detected for profile \"prod\"") {
		t.Errorf("expected count 3 in message, got: %q", msg)
	}
	if !strings.Contains(rem, "sec restart --profile prod") {
		t.Errorf("expected restart remediation, got: %q", rem)
	}
}

func TestRestartHotReloadSafeNonInteractive(t *testing.T) {
	tmpDir := t.TempDir()
	emptyConfigDir := filepath.Join(tmpDir, "nonexistent-config-dir")

	binPath := filepath.Join(tmpDir, "sec_restart_test_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v, output: %s", err, string(out))
	}

	// 1. Test when config dir is uninitialized: must exit 0 and not fail with VAULT_UNINITIALIZED
	cmdUninit := exec.Command(binPath, "restart", "--hot-reload")
	cmdUninit.Env = append(os.Environ(), "SEC_CONFIG_DIR="+emptyConfigDir)
	outUninit, err := cmdUninit.CombinedOutput()
	if err != nil {
		t.Fatalf("expected sec restart --hot-reload to exit 0 on uninitialized config, got error: %v, output: %s", err, string(outUninit))
	}
	if !strings.Contains(string(outUninit), "nothing to hot-reload") {
		t.Errorf("expected notice that nothing to hot-reload, got: %s", string(outUninit))
	}

	// 2. Test when config dir exists but daemon is not running: must exit 0 and not prompt for Touch ID
	initializedDir := filepath.Join(tmpDir, "init-dir")
	_ = os.MkdirAll(initializedDir, 0700)
	cmdNoDaemon := exec.Command(binPath, "restart", "--hot-reload", "--profile", "test-inactive")
	cmdNoDaemon.Env = append(os.Environ(), "SEC_CONFIG_DIR="+initializedDir)
	outNoDaemon, err := cmdNoDaemon.CombinedOutput()
	if err != nil {
		t.Fatalf("expected sec restart --hot-reload to exit 0 when daemon inactive, got error: %v, output: %s", err, string(outNoDaemon))
	}
	if !strings.Contains(string(outNoDaemon), "is not currently running; nothing to hot-reload") {
		t.Errorf("expected inactive daemon notice, got: %s", string(outNoDaemon))
	}
}

func TestProfileNewSensitiveDirectoryWarning(t *testing.T) {
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current wd: %v", err)
	}

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_test_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v\nOutput: %s", err, string(out))
	}

	// Create fake bin dir inside a mock HOME
	fakeHome := filepath.Join(tmpDir, "fakehome")
	fakeBin := filepath.Join(fakeHome, "bin")
	if err := os.MkdirAll(fakeBin, 0700); err != nil {
		t.Fatalf("failed to create fake bin dir: %v", err)
	}
	_ = os.MkdirAll(filepath.Join(fakeHome, ".config", "sec-agent"), 0700)

	if err := os.Chdir(fakeBin); err != nil {
		t.Fatalf("failed to chdir to fakeBin: %v", err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	mnemonic, err := crypto.GenerateMnemonic()
	if err != nil {
		t.Fatalf("failed to generate mnemonic: %v", err)
	}

	configDir := filepath.Join(tmpDir, "config")
	_ = os.MkdirAll(configDir, 0700)

	cmd := exec.Command(binPath, "profile", "new", "sensitivenode", "--seed", mnemonic, "--secrc")
	cmd.Env = append(os.Environ(),
		"HOME="+fakeHome,
		"SEC_CONFIG_DIR="+configDir,
		"SEC_TEST_MODE=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("profile new failed: %v, output:\n%s", err, string(out))
	}

	outStr := string(out)
	if !strings.Contains(outStr, "Notice: Creating .secrc in a home/system directory") {
		t.Errorf("expected warning about home/system directory, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "Bound workspace config:") || !strings.Contains(outStr, filepath.Join("fakehome", "bin", ".secrc")) {
		t.Errorf("expected bound workspace config with absolute path, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "Scope: Active for this directory and all subdirectories.") {
		t.Errorf("expected scope description in output, got:\n%s", outStr)
	}
}

func TestProfileNewProjectRootMarkers(t *testing.T) {
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current wd: %v", err)
	}

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_markers_test_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v\nOutput: %s", err, string(out))
	}

	mnemonic, err := crypto.GenerateMnemonic()
	if err != nil {
		t.Fatalf("failed to generate mnemonic: %v", err)
	}

	configDir := filepath.Join(tmpDir, "config")
	_ = os.MkdirAll(configDir, 0700)

	// 1. Directory WITHOUT markers: should emit warning with "All child subdirectories will inherit"
	noMarkerDir := filepath.Join(tmpDir, "nomarkers")
	_ = os.MkdirAll(noMarkerDir, 0700)
	if err := os.Chdir(noMarkerDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	cmd := exec.Command(binPath, "profile", "new", "testnomarkers", "--seed", mnemonic, "--secrc")
	cmd.Env = append(os.Environ(),
		"SEC_CONFIG_DIR="+configDir,
		"SEC_TEST_MODE=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("profile new failed: %v\nOutput: %s", err, string(out))
	}
	outStr := string(out)
	if !strings.Contains(outStr, "All child subdirectories will inherit profile \"testnomarkers\" via upward traversal!") {
		t.Errorf("expected warning copy to mention 'All child subdirectories will inherit', got:\n%s", outStr)
	}

	// 2. Directory WITH pyproject.toml: should NOT emit missing project root warning
	pythonDir := filepath.Join(tmpDir, "pythondir")
	_ = os.MkdirAll(pythonDir, 0700)
	_ = os.WriteFile(filepath.Join(pythonDir, "pyproject.toml"), []byte("[project]\nname=\"sample\"\n"), 0644)
	if err := os.Chdir(pythonDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}

	cmd2 := exec.Command(binPath, "profile", "new", "testpython", "--seed", mnemonic, "--secrc")
	cmd2.Env = append(os.Environ(),
		"SEC_CONFIG_DIR="+configDir,
		"SEC_TEST_MODE=1",
	)
	out2, err2 := cmd2.CombinedOutput()
	if err2 != nil {
		t.Fatalf("profile new failed: %v\nOutput: %s", err2, string(out2))
	}
	if strings.Contains(string(out2), "does not appear to be a Git repository") {
		t.Errorf("expected pyproject.toml to suppress missing project root warning, but got:\n%s", string(out2))
	}

	// 3. Umbrella directory with child .git: should NOT emit missing project root warning
	umbrellaDir := filepath.Join(tmpDir, "umbrelladir")
	childGit := filepath.Join(umbrellaDir, "childrepo", ".git")
	_ = os.MkdirAll(childGit, 0700)
	if err := os.Chdir(umbrellaDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}

	cmd3 := exec.Command(binPath, "profile", "new", "testumbrella", "--seed", mnemonic, "--secrc")
	cmd3.Env = append(os.Environ(),
		"SEC_CONFIG_DIR="+configDir,
		"SEC_TEST_MODE=1",
	)
	out3, err3 := cmd3.CombinedOutput()
	if err3 != nil {
		t.Fatalf("profile new failed: %v\nOutput: %s", err3, string(out3))
	}
	if strings.Contains(string(out3), "does not appear to be a Git repository") {
		t.Errorf("expected child .git to suppress missing project root warning, but got:\n%s", string(out3))
	}
}

func TestProfileNewUpfrontChoiceLinkExisting(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_profile_choice_test")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v, output: %s", err, string(out))
	}

	mnemonic, err := crypto.GenerateMnemonic()
	if err != nil {
		t.Fatalf("failed to generate mnemonic: %v", err)
	}

	// Stdin: choose "2", then provide mnemonic
	cmd := exec.Command(binPath, "profile", "new", "reusedprof", "--no-secrc")
	cmd.Env = append(os.Environ(),
		"SEC_CONFIG_DIR="+tmpDir,
		"SEC_TEST_MODE=1",
	)
	cmd.Stdin = strings.NewReader("2\n" + mnemonic + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("profile new with choice 2 failed: %v, output:\n%s", err, string(out))
	}

	outStr := string(out)
	if !strings.Contains(outStr, `Profile "reusedprof" recovery seed setup:`) {
		t.Errorf("expected output to contain upfront menu prompt, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "[1] Generate a new 24-word recovery seed (Default)") {
		t.Errorf("expected option [1] in output, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "[2] Link an existing 24-word master recovery seed phrase") {
		t.Errorf("expected option [2] in output, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "Existing recovery seed phrase verified and linked.") {
		t.Errorf("expected seed phrase verified and linked notice, got:\n%s", outStr)
	}
	if strings.Contains(outStr, "WRITE THIS DOWN NOW") {
		t.Errorf("expected throwaway mnemonic generation banner NOT to be printed, got:\n%s", outStr)
	}

	// Verify vault envelope and Slot 1 decryptability
	vaultPath := filepath.Join(tmpDir, "secrets_reusedprof.enc")
	env, err := store.ReadVaultEnvelope(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault envelope: %v", err)
	}
	if !env.HasSlot1() || env.Slot1 == nil {
		t.Fatalf("expected vault to have Slot 1 enrolled")
	}
	recoveredKey, err := store.UnwrapMasterKey(mnemonic, env.Slot1)
	if err != nil {
		t.Fatalf("failed to unwrap master key using linked seed: %v", err)
	}
	if len(recoveredKey) != 32 {
		t.Fatalf("expected 32-byte master key, got %d bytes", len(recoveredKey))
	}
}

func TestProfileNewReuseSeedFlag(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_profile_reuse_flag_test")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v, output: %s", err, string(out))
	}

	mnemonic, err := crypto.GenerateMnemonic()
	if err != nil {
		t.Fatalf("failed to generate mnemonic: %v", err)
	}

	// Test --reuse-seed
	cmd := exec.Command(binPath, "profile", "new", "flagprof", "--reuse-seed", "--no-secrc")
	cmd.Env = append(os.Environ(),
		"SEC_CONFIG_DIR="+tmpDir,
		"SEC_TEST_MODE=1",
	)
	cmd.Stdin = strings.NewReader(mnemonic + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("profile new with --reuse-seed failed: %v, output:\n%s", err, string(out))
	}

	outStr := string(out)
	// Upfront menu prompt should be skipped
	if strings.Contains(outStr, "Enter choice [1/2]") {
		t.Errorf("expected upfront menu to be skipped with --reuse-seed flag, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "Enter your existing 24-word recovery seed phrase:") {
		t.Errorf("expected direct seed prompt, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "Existing recovery seed phrase verified and linked.") {
		t.Errorf("expected seed phrase verified and linked notice, got:\n%s", outStr)
	}

	// Test --existing-seed alias
	cmd2 := exec.Command(binPath, "profile", "new", "aliasprof", "--existing-seed", "--no-secrc")
	cmd2.Env = append(os.Environ(),
		"SEC_CONFIG_DIR="+tmpDir,
		"SEC_TEST_MODE=1",
	)
	cmd2.Stdin = strings.NewReader(mnemonic + "\n")
	out2, err2 := cmd2.CombinedOutput()
	if err2 != nil {
		t.Fatalf("profile new with --existing-seed failed: %v, output:\n%s", err2, string(out2))
	}
	if !strings.Contains(string(out2), "Existing recovery seed phrase verified and linked.") {
		t.Errorf("expected --existing-seed to link seed, got:\n%s", string(out2))
	}
}

func TestProfileNewFallbackDuringVerification(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_profile_fallback_test")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v, output: %s", err, string(out))
	}

	mnemonic, err := crypto.GenerateMnemonic()
	if err != nil {
		t.Fatalf("failed to generate mnemonic: %v", err)
	}

	// Select option 1 (generate new), then at Word #4 prompt enter 'r' to fallback to existing seed
	cmd := exec.Command(binPath, "profile", "new", "fallbackprof", "--no-secrc")
	cmd.Env = append(os.Environ(),
		"SEC_CONFIG_DIR="+tmpDir,
		"SEC_TEST_MODE=1",
	)
	cmd.Stdin = strings.NewReader("1\nr\n" + mnemonic + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("profile new with fallback failed: %v, output:\n%s", err, string(out))
	}

	outStr := string(out)
	if !strings.Contains(outStr, "WRITE THIS DOWN NOW") {
		t.Errorf("expected generated word grid for choice 1, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "Word #4:") {
		t.Errorf("expected Word #4 verification prompt, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "Existing recovery seed phrase verified and linked.") {
		t.Errorf("expected fallback seed phrase verified and linked notice, got:\n%s", outStr)
	}
}

func TestProfileNewInvalidChoiceAndInvalidSeed(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_profile_invalid_test")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build test binary: %v, output: %s", err, string(out))
	}

	// 1. Invalid choice '3'
	cmd := exec.Command(binPath, "profile", "new", "badchoiceprof", "--no-secrc")
	cmd.Env = append(os.Environ(),
		"SEC_CONFIG_DIR="+tmpDir,
		"SEC_TEST_MODE=1",
	)
	cmd.Stdin = strings.NewReader("3\n")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected profile new with choice 3 to fail, but succeeded with output:\n%s", string(out))
	}
	if !strings.Contains(string(out), "invalid choice") {
		t.Errorf("expected error about invalid choice, got:\n%s", string(out))
	}

	// 2. Choice 2 with invalid mnemonic (word count error)
	cmd2 := exec.Command(binPath, "profile", "new", "badseedprof", "--no-secrc")
	cmd2.Env = append(os.Environ(),
		"SEC_CONFIG_DIR="+tmpDir,
		"SEC_TEST_MODE=1",
	)
	cmd2.Stdin = strings.NewReader("2\nnot a valid twenty four word recovery phrase\n")
	out2, err2 := cmd2.CombinedOutput()
	if err2 == nil {
		t.Fatalf("expected profile new with bad seed to fail, but succeeded with output:\n%s", string(out2))
	}
	if !strings.Contains(string(out2), "not a valid 24-word BIP39 mnemonic") {
		t.Errorf("expected error about invalid BIP39 mnemonic, got:\n%s", string(out2))
	}
	if !strings.Contains(string(out2), "mnemonic must have 24 words, got 8") {
		t.Errorf("expected detailed word count diagnostic, got:\n%s", string(out2))
	}

	// 2b. Choice 2 with unknown dictionary word in 24-word phrase
	unknownWordPhrase := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon aple"
	cmd2b := exec.Command(binPath, "profile", "new", "badwordprof", "--no-secrc")
	cmd2b.Env = append(os.Environ(),
		"SEC_CONFIG_DIR="+tmpDir,
		"SEC_TEST_MODE=1",
	)
	cmd2b.Stdin = strings.NewReader("2\n" + unknownWordPhrase + "\n")
	out2b, err2b := cmd2b.CombinedOutput()
	if err2b == nil {
		t.Fatalf("expected profile new with unknown word to fail, but succeeded with output:\n%s", string(out2b))
	}
	if !strings.Contains(string(out2b), `mnemonic word "aple" is not in BIP39 wordlist`) {
		t.Errorf("expected detailed unknown word diagnostic for 'aple', got:\n%s", string(out2b))
	}

	// 3. Non-interactive with --reuse-seed should exit 78
	cmd3 := exec.Command(binPath, "profile", "new", "blockedprof", "--reuse-seed")
	cmd3.Env = append(os.Environ(),
		"SEC_CONFIG_DIR="+tmpDir,
		"NONINTERACTIVE=1",
	)
	out3, err3 := cmd3.CombinedOutput()
	if err3 == nil {
		t.Fatalf("expected non-interactive profile new --reuse-seed to fail, but succeeded")
	}
	exitErr, ok := err3.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 78 {
		t.Errorf("expected exit code 78, got: %v (exit code: %d)", err3, exitErr.ExitCode())
	}
	if !strings.Contains(string(out3), "sec-agent profile new blockedprof --reuse-seed") {
		t.Errorf("expected blocker box to recommend command with --reuse-seed, got:\n%s", string(out3))
	}
}

func TestProfileDescribeAndSummaryIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sec_profile_summary_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v, output: %s", err, string(out))
	}

	mnemonic, err := crypto.GenerateMnemonic()
	if err != nil {
		t.Fatalf("failed to generate mnemonic: %v", err)
	}

	// 1. Create a new profile with --summary
	cmdNew := exec.Command(binPath, "profile", "new", "k8s-infra", "--seed", mnemonic, "--summary", "Kubernetes cluster production keys", "--no-secrc")
	cmdNew.Env = append(os.Environ(),
		"SEC_CONFIG_DIR="+tmpDir,
		"SEC_TEST_MODE=1",
	)
	outNew, errNew := cmdNew.CombinedOutput()
	if errNew != nil {
		t.Fatalf("profile new with summary failed: %v, output:\n%s", errNew, string(outNew))
	}

	// 2. Describe profile (text output)
	cmdDesc := exec.Command(binPath, "profile", "describe", "k8s-infra")
	cmdDesc.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir)
	outDesc, errDesc := cmdDesc.CombinedOutput()
	if errDesc != nil {
		t.Fatalf("profile describe failed: %v, output:\n%s", errDesc, string(outDesc))
	}
	descStr := string(outDesc)
	if !strings.Contains(descStr, "Profile:    k8s-infra") {
		t.Errorf("expected profile describe output to contain profile name, got:\n%s", descStr)
	}
	if !strings.Contains(descStr, "Summary:    Kubernetes cluster production keys") {
		t.Errorf("expected profile describe output to contain summary, got:\n%s", descStr)
	}
	if !strings.Contains(descStr, "Format:     v2.0 Dual-Slot") {
		t.Errorf("expected format v2.0 Dual-Slot, got:\n%s", descStr)
	}

	// 3. Describe profile (--json)
	cmdDescJSON := exec.Command(binPath, "profile", "describe", "k8s-infra", "--json")
	cmdDescJSON.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir)
	outJSON, errJSON := cmdDescJSON.CombinedOutput()
	if errJSON != nil {
		t.Fatalf("profile describe --json failed: %v, output:\n%s", errJSON, string(outJSON))
	}
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(outJSON, &jsonMap); err != nil {
		t.Fatalf("failed to parse JSON from profile describe --json: %v, output: %s", err, string(outJSON))
	}
	if jsonMap["profile"] != "k8s-infra" {
		t.Errorf("expected json profile 'k8s-infra', got: %v", jsonMap["profile"])
	}
	if jsonMap["summary"] != "Kubernetes cluster production keys" {
		t.Errorf("expected json summary 'Kubernetes cluster production keys', got: %v", jsonMap["summary"])
	}
	if jsonMap["is_v2"] != true || jsonMap["has_slot1"] != true {
		t.Errorf("expected is_v2 and has_slot1 true, got: %v, %v", jsonMap["is_v2"], jsonMap["has_slot1"])
	}

	// 4. List profiles and verify columnar formatting
	cmdLs := exec.Command(binPath, "profile", "ls")
	cmdLs.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir)
	outLs, errLs := cmdLs.CombinedOutput()
	if errLs != nil {
		t.Fatalf("profile ls failed: %v, output:\n%s", errLs, string(outLs))
	}
	lsStr := string(outLs)
	if !strings.Contains(lsStr, "k8s-infra") || !strings.Contains(lsStr, "[v2.0 Dual-Slot]") || !strings.Contains(lsStr, "Kubernetes cluster production keys") {
		t.Errorf("expected profile ls to show profile, status, and summary, got:\n%s", lsStr)
	}

	// 5. Update summary via describe
	cmdUpdate := exec.Command(binPath, "profile", "describe", "k8s-infra", "--summary", "Updated cluster secrets")
	cmdUpdate.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir)
	outUpdate, errUpdate := cmdUpdate.CombinedOutput()
	if errUpdate != nil {
		t.Fatalf("profile describe update summary failed: %v, output:\n%s", errUpdate, string(outUpdate))
	}
	if !strings.Contains(string(outUpdate), "Summary updated for profile \"k8s-infra\": Updated cluster secrets") {
		t.Errorf("expected update confirmation message, got:\n%s", string(outUpdate))
	}

	// Verify update took effect
	cmdCheckUpdate := exec.Command(binPath, "profile", "describe", "k8s-infra")
	cmdCheckUpdate.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir)
	outCheck, errCheck := cmdCheckUpdate.CombinedOutput()
	if errCheck != nil {
		t.Fatalf("profile describe check failed: %v, output:\n%s", errCheck, string(outCheck))
	}
	if !strings.Contains(string(outCheck), "Summary:    Updated cluster secrets") {
		t.Errorf("expected updated summary in describe output, got:\n%s", string(outCheck))
	}

	// 6. Clear summary via describe
	cmdClear := exec.Command(binPath, "profile", "describe", "k8s-infra", "--clear-summary")
	cmdClear.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir)
	outClear, errClear := cmdClear.CombinedOutput()
	if errClear != nil {
		t.Fatalf("profile describe --clear-summary failed: %v, output:\n%s", errClear, string(outClear))
	}
	if !strings.Contains(string(outClear), "Summary cleared for profile \"k8s-infra\"") {
		t.Errorf("expected clear confirmation message, got:\n%s", string(outClear))
	}

	// Verify cleared summary
	cmdCheckClear := exec.Command(binPath, "profile", "describe", "k8s-infra")
	cmdCheckClear.Env = append(os.Environ(), "SEC_CONFIG_DIR="+tmpDir)
	outCheckClear, _ := cmdCheckClear.CombinedOutput()
	if !strings.Contains(string(outCheckClear), "Summary:    (none)") {
		t.Errorf("expected (none) for cleared summary, got:\n%s", string(outCheckClear))
	}
}

func TestHasProjectRootMarkersExtended(t *testing.T) {
	markers := []string{".arjan", ".agent", "config.yaml", "config.yml"}
	for _, m := range markers {
		tmpDir := t.TempDir()
		if hasProjectRootMarkers(tmpDir) {
			t.Errorf("expected empty dir to not have root markers")
		}
		markerPath := filepath.Join(tmpDir, m)
		if strings.HasPrefix(m, ".") {
			if err := os.Mkdir(markerPath, 0755); err != nil {
				t.Fatalf("failed to create dir marker %s: %v", m, err)
			}
		} else {
			if err := os.WriteFile(markerPath, []byte("key: val\n"), 0644); err != nil {
				t.Fatalf("failed to create file marker %s: %v", m, err)
			}
		}
		if !hasProjectRootMarkers(tmpDir) {
			t.Errorf("expected dir with %s to be recognized as project root", m)
		}
	}
}









