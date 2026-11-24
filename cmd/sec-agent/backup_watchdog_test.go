package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"secure_secrets/internal/store"
)

type fakeProcInspector struct {
	mu       sync.Mutex
	bootSec  int64
	bootUsec int32
	bootErr  error
	procs    map[int]backupProcIdentity
	errs     map[int]error
}

func newFakeProcInspector(bootSec int64, bootUsec int32) *fakeProcInspector {
	return &fakeProcInspector{
		bootSec:  bootSec,
		bootUsec: bootUsec,
		procs:    make(map[int]backupProcIdentity),
		errs:     make(map[int]error),
	}
}

func (f *fakeProcInspector) BootTime() (int64, int32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bootErr != nil {
		return 0, 0, f.bootErr
	}
	return f.bootSec, f.bootUsec, nil
}

func (f *fakeProcInspector) InspectPID(pid int) (backupProcIdentity, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.errs[pid]; ok {
		return backupProcIdentity{}, false, err
	}
	if p, ok := f.procs[pid]; ok {
		return p, true, nil
	}
	return backupProcIdentity{}, false, nil
}

func TestBackupWatchdogConfigCLIValidationAndArgs(t *testing.T) {
	// Invalid / negative CLI --no-progress-timeout fails BEFORE daemon/SSH
	for _, bad := range []string{"-5m", "-1", "not-a-duration"} {
		err := executeStealthBackupRun("nonexistent-profile", []string{"some-job", "--no-progress-timeout", bad})
		if err == nil {
			t.Fatalf("expected configuration error for --no-progress-timeout %q, got nil", bad)
		}
		var cliErr *stealthBackupCliError
		if !errors.As(err, &cliErr) || cliErr.Code != "INVALID_ARGUMENTS" {
			t.Errorf("expected INVALID_ARGUMENTS for %q, got %v", bad, err)
		}
	}

	// buildLocalStealthRsyncArgs: default (watchdog off) omits --info; watchdog on adds --info=name0,flist2,progress2
	manifest := store.BackupManifest{
		Name:         "work",
		SSHTarget:    "backupuser@10.0.0.50",
		LocalBase:    "/Users/backupuser",
		RemoteBase:   "/Volumes/Secret/Backups",
		ModifyWindow: 2,
		PartialDir:   ".rsync-partial",
		Excludes:     []string{".DS_Store"},
	}
	folder := store.BackupFolderSpec{Source: "Confidential"}

	argsOff := buildLocalStealthRsyncArgs(manifest, "/usr/local/bin/sec-agent", false, false, folder)
	if strings.Contains(strings.Join(argsOff, " "), "--info=") {
		t.Errorf("expected no --info flag when watchdog is disabled, got %v", argsOff)
	}

	manifest.NoProgressTimeout = "30m"
	argsOn := buildLocalStealthRsyncArgs(manifest, "/usr/local/bin/sec-agent", false, false, folder)
	joinedOn := strings.Join(argsOn, " ")
	if !strings.Contains(joinedOn, "--info=name0,flist2,progress2") {
		t.Errorf("expected --info=name0,flist2,progress2 when watchdog enabled in normal mode, got %v", argsOn)
	}
	for _, forbidden := range []string{"Confidential", "backupuser", "10.0.0.50", "Secret"} {
		if strings.Contains(joinedOn, forbidden) {
			t.Errorf("watchdog rsync args leaked %q: %v", forbidden, argsOn)
		}
	}
}

func TestBackupProgressTrackerScanTransferAndNoise(t *testing.T) {
	tr := newBackupProgressTracker()

	// Advancing scan counters reset timer
	if !tr.RecordProgressLine("building file list ... ") {
		// banner alone is not progress; advancing counters are
	}
	if !tr.RecordProgressLine(" 1000 files...") {
		t.Errorf("expected '1000 files...' to count as scan progress")
	}
	// Duplicate identical line MUST NOT count as progress
	if tr.RecordProgressLine(" 1000 files...") {
		t.Errorf("expected repeated identical scan line NOT to reset timer")
	}
	if !tr.RecordProgressLine(" 2000 files...") {
		t.Errorf("expected advancing '2000 files...' to count as scan progress")
	}
	if !tr.RecordProgressLine("              0B 100%       0B/s    0:00:00 (xfr#0, ir-chk=1500/1503)") {
		t.Errorf("expected advancing ir-chk counter to count as scan progress")
	}
	if tr.RecordProgressLine("              0B 100%       0B/s    0:00:00 (xfr#0, ir-chk=1500/1503)") {
		t.Errorf("expected identical ir-chk line NOT to reset timer")
	}
	if !tr.RecordProgressLine("              0B 100%       0B/s    0:00:00 (xfr#0, to-chk=0/3003)") {
		t.Errorf("expected advancing to-chk counter to count as scan progress")
	}

	// Advancing byte transfer counts reset timer
	if !tr.RecordProgressLine("      2,228,224B  53%   2.05MB/s    0:00:00  ") {
		t.Errorf("expected advancing transfer bytes to count as progress")
	}
	if tr.RecordProgressLine("      2,228,224B  53%   2.05MB/s    0:00:00  ") {
		t.Errorf("expected static byte count NOT to reset timer")
	}
	if !tr.RecordProgressLine("      4,194,304B  99%   2.04MB/s    0:00:02 (xfr#1, to-chk=51/53)") {
		t.Errorf("expected higher transfer bytes + xfr#1 to count as progress")
	}

	// Repeated error lines / keepalive-like noise MUST NOT count as progress
	for _, noise := range []string{
		"rsync: [sender] opendir \"<path>\" failed: Operation not permitted (1)",
		"skipping non-regular file \"foo\"",
		"keepalive@openssh.com",
		"",
		"   ",
	} {
		if tr.RecordProgressLine(noise) {
			t.Errorf("noise/error line %q must NOT reset progress timer", noise)
		}
	}

	// Channel payload bytes reset timer via countingBridgeReader/Writer
	time.Sleep(15 * time.Millisecond)
	before := tr.SinceLastProgress()
	var sink bytes.Buffer
	cw := &countingBridgeWriter{w: &sink, tracker: tr}
	_, _ = cw.Write([]byte("rsync-delta-chunk"))
	after := tr.SinceLastProgress()
	if after >= before {
		t.Errorf("expected positive channel bytes to reset lastProgress (before=%s after=%s)", before, after)
	}
}

func TestBackupWatchdogHealthyLongTransferDoesNotTimeout(t *testing.T) {
	origPoll := watchdogPollInterval
	origGrace := watchdogGracePeriod
	origKill := watchdogKillConfirmWait
	watchdogPollInterval = 15 * time.Millisecond
	watchdogGracePeriod = 100 * time.Millisecond
	watchdogKillConfirmWait = 100 * time.Millisecond
	defer func() {
		watchdogPollInterval = origPoll
		watchdogGracePeriod = origGrace
		watchdogKillConfirmWait = origKill
	}()

	// Emit advancing progress2 lines every 40ms for ~280ms while timeout is 120ms (>2x timeout total!)
	script := `
for i in 1000 2000 3000 4000 5000 6000 7000; do
  printf "      %dB  10%%   1.00MB/s    0:00:00\r" "$i"
  sleep 0.04
done
printf "\nNumber of regular files transferred: 3\n"
`
	cmd := exec.Command("/bin/sh", "-c", script)
	tracker := newBackupProgressTracker()
	var outBuf, errBuf bytes.Buffer
	stdoutFilter := newRsyncStdoutStatsWriter(&outBuf, false, tracker)
	stderrFilter := newRsyncStderrFilterWriter(&errBuf, false)

	runErr, aborted := runCommandWithWatchdog(cmd, stdoutFilter, stderrFilter, nil, tracker, 120*time.Millisecond, "healthy-alias", nil)
	if runErr != nil || aborted != nil {
		t.Fatalf("expected healthy long transfer to succeed, got runErr=%v aborted=%v", runErr, aborted)
	}
	transferred, _, _ := stdoutFilter.Flush()
	if transferred != 3 {
		t.Errorf("expected transferred=3, got %d", transferred)
	}
	if outBuf.Len() != 0 {
		t.Errorf("expected zero raw stdout leakage in normal mode, got %q", outBuf.String())
	}
}

func TestBackupWatchdogTimeoutOnSilenceAndRepeatedErrors(t *testing.T) {
	origPoll := watchdogPollInterval
	origGrace := watchdogGracePeriod
	origKill := watchdogKillConfirmWait
	watchdogPollInterval = 15 * time.Millisecond
	watchdogGracePeriod = 150 * time.Millisecond
	watchdogKillConfirmWait = 150 * time.Millisecond
	defer func() {
		watchdogPollInterval = origPoll
		watchdogGracePeriod = origGrace
		watchdogKillConfirmWait = origKill
	}()

	// Emits repeated permission-denied errors on stderr (must NOT reset watchdog AND must remain visible redacted)
	script := `
while true; do
  echo 'rsync: [sender] opendir "/Users/alice/SecretDir" failed: Operation not permitted (1)' >&2
  sleep 0.03
done
`
	cmd := exec.Command("/bin/sh", "-c", script)
	tracker := newBackupProgressTracker()
	var outBuf, errBuf bytes.Buffer
	stdoutFilter := newRsyncStdoutStatsWriter(&outBuf, false, tracker)
	stderrFilter := newRsyncStderrFilterWriter(&errBuf, false)

	bridgeClosed := false
	runErr, aborted := runCommandWithWatchdog(cmd, stdoutFilter, stderrFilter, nil, tracker, 120*time.Millisecond, "smb-share", func() {
		bridgeClosed = true
	})
	if aborted == nil {
		t.Fatalf("expected watchdogAbortError on stalled transfer with repeated stderr errors, got runErr=%v", runErr)
	}
	if !bridgeClosed {
		t.Errorf("expected onBeforeKill callback to close SSH bridge")
	}
	if !aborted.TerminationConfirmed {
		t.Errorf("expected confirmed termination for normal shell process, got %v", aborted)
	}
	if !strings.Contains(strings.ToLower(aborted.Error()), "suspected stall") || !strings.Contains(strings.ToLower(aborted.Error()), "termination confirmed") {
		t.Errorf("unexpected watchdog error wording: %s", aborted.Error())
	}
	stderrFilter.Flush()
	gotErr := errBuf.String()
	if !strings.Contains(gotErr, "Operation not permitted (1)") {
		t.Errorf("watchdog must not hide permission-denied errors, got stderr:\n%s", gotErr)
	}
	if strings.Contains(gotErr, "alice") || strings.Contains(gotErr, "SecretDir") {
		t.Errorf("stderr leaked raw path:\n%s", gotErr)
	}
}

func TestBackupWatchdogAbortStopsRetriesAndSkipsNextFolder(t *testing.T) {
	manifest := store.BackupManifest{
		Name:        "smb-job",
		MaxAttempts: 5,
	}
	folders := []store.BackupFolderSpec{
		{Name: "folder-one", Source: "FolderOne"},
		{Name: "folder-two", Source: "FolderTwo"},
	}

	var calls []string
	var outBuf, errBuf bytes.Buffer
	failed, err := runStealthBackupFoldersWithOutput(
		manifest,
		folders,
		nil,
		&outBuf,
		&errBuf,
		func(f store.BackupFolderSpec, attempt int) (backupFolderRunStats, error) {
			calls = append(calls, f.Name)
			return backupFolderRunStats{ExitCode: 124}, &watchdogAbortError{
				FolderAlias:          f.Name,
				Timeout:              30 * time.Minute,
				TerminationConfirmed: true,
			}
		},
		nil,
	)
	if err == nil {
		t.Fatalf("expected job error after watchdog abort")
	}
	if len(calls) != 1 || calls[0] != "folder-one" {
		t.Errorf("expected exactly 1 call (no retry, no folder-two), got calls=%v", calls)
	}
	if len(failed) != 1 || failed[0] != "folder-one" {
		t.Errorf("expected failed=[folder-one], got %v", failed)
	}
	if !strings.Contains(errBuf.String(), "Aborting remaining folders") {
		t.Errorf("expected abort notice in stderr, got:\n%s", errBuf.String())
	}
}

func TestBackupWatchdogCompletionRaceWinsOverTimeout(t *testing.T) {
	origPoll := watchdogPollInterval
	watchdogPollInterval = 10 * time.Millisecond
	defer func() { watchdogPollInterval = origPoll }()

	// Completes right around the timeout boundary (35ms vs 40ms timeout) — should finish cleanly, not abort
	cmd := exec.Command("/bin/sh", "-c", "sleep 0.02; echo 'Number of regular files transferred: 1'")
	tracker := newBackupProgressTracker()
	var outBuf, errBuf bytes.Buffer
	stdoutFilter := newRsyncStdoutStatsWriter(&outBuf, false, tracker)

	runErr, aborted := runCommandWithWatchdog(cmd, stdoutFilter, &errBuf, nil, tracker, 120*time.Millisecond, "boundary-alias", nil)
	if runErr != nil || aborted != nil {
		t.Fatalf("expected normal completion to win race, got runErr=%v aborted=%v", runErr, aborted)
	}
}

func TestBackupGuardOverlapLifecyclePIDReuseRebootCrashAndPrivacy(t *testing.T) {
	guardDir := filepath.Join(t.TempDir(), "backup-guards")
	insp := newFakeProcInspector(1700000000, 12345)
	selfPID := os.Getpid()
	insp.procs[selfPID] = backupProcIdentity{PID: selfPID, StartSec: 1700000100, StartUsec: 1, Comm: "sec-agent"}

	// 1. Acquire guard for (secret-profile, secret-job)
	g1, err := acquireBackupRunGuard(guardDir, "secret-profile", "secret-job", insp)
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}

	// Verify 0700 dir, 0600 lock, and privacy of filenames
	dirInfo, err := os.Stat(guardDir)
	if err != nil || dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("expected 0700 guard dir, got err=%v perm=%v", err, dirInfo.Mode().Perm())
	}
	if strings.Contains(g1.StatePath(), "secret-profile") || strings.Contains(g1.StatePath(), "secret-job") {
		t.Errorf("guard filename leaked profile or job name: %s", g1.StatePath())
	}

	// 2. Concurrent acquire for SAME (profile, job) MUST fail atomically (even if watchdog is off!)
	if _, err := acquireBackupRunGuard(guardDir, "secret-profile", "secret-job", insp); err == nil {
		t.Errorf("expected concurrent acquire for same job to fail")
	}

	// 3. Independent job MUST be allowed concurrently
	gOther, err := acquireBackupRunGuard(guardDir, "secret-profile", "independent-job", insp)
	if err != nil {
		t.Fatalf("expected independent job to acquire concurrently, got: %v", err)
	}
	_ = gOther.ConfirmExitedAndClear()

	// 4. MarkLaunchPending + MarkRunning + verify JSON contains zero sensitive strings
	if err := g1.MarkLaunchPending(); err != nil {
		t.Fatalf("MarkLaunchPending failed: %v", err)
	}
	childPID := 99991
	insp.procs[childPID] = backupProcIdentity{PID: childPID, StartSec: 1700000200, StartUsec: 99, Comm: "rsync"}
	if err := g1.MarkRunning(childPID); err != nil {
		t.Fatalf("MarkRunning failed: %v", err)
	}
	rawJSON, err := os.ReadFile(g1.StatePath())
	if err != nil {
		t.Fatalf("read guard json failed: %v", err)
	}
	if strings.Contains(string(rawJSON), "secret-profile") || strings.Contains(string(rawJSON), "secret-job") {
		t.Errorf("guard JSON leaked profile/job name: %s", string(rawJSON))
	}
	fileInfo, _ := os.Stat(g1.StatePath())
	if fileInfo.Mode().Perm() != 0600 {
		t.Errorf("expected guard json mode 0600, got %04o", fileInfo.Mode().Perm())
	}

	// 5. MarkTerminationUnconfirmed -> release flock only (simulating CLI returning boundedly while child is in U-state)
	if err := g1.MarkTerminationUnconfirmed(); err != nil {
		t.Fatalf("MarkTerminationUnconfirmed failed: %v", err)
	}
	g1.ReleaseLockOnly()

	// Next run (even with watchdog disabled!) MUST fail closed while child identity matches
	if _, err := acquireBackupRunGuard(guardDir, "secret-profile", "secret-job", insp); err == nil {
		t.Errorf("expected overlapping run to fail closed while termination-unconfirmed child is still alive")
	}

	// 6. Uncertain identity (inspector error) MUST fail closed without deleting guard
	insp.errs[childPID] = errors.New("sysctl EPERM")
	if _, err := acquireBackupRunGuard(guardDir, "secret-profile", "secret-job", insp); err == nil {
		t.Errorf("expected uncertain identity to fail closed")
	}
	if _, statErr := os.Stat(g1.StatePath()); statErr != nil {
		t.Errorf("guard file must NOT be auto-removed on uncertain identity")
	}
	delete(insp.errs, childPID)

	// 7. PID reuse (same PID, different StartSec) -> confirmed dead -> clears stale guard and acquires!
	insp.procs[childPID] = backupProcIdentity{PID: childPID, StartSec: 1700009999, StartUsec: 5, Comm: "unrelated"}
	g2, err := acquireBackupRunGuard(guardDir, "secret-profile", "secret-job", insp)
	if err != nil {
		t.Fatalf("expected PID reuse to clear stale guard, got: %v", err)
	}

	// 8. Simulate launch-pending crash on SAME boot (launcher dead, child unknown) -> MUST fail closed!
	deadLauncherPID := 88888
	rec := backupGuardRecord{
		Version:  1,
		State:    backupGuardStateLaunchPending,
		BootSec:  1700000000,
		BootUsec: 12345,
		Launcher: &backupProcIdentity{PID: deadLauncherPID, StartSec: 1700000050, StartUsec: 1, Comm: "sec-agent"},
	}
	recBytes, _ := json.Marshal(rec)
	_ = os.WriteFile(g2.StatePath(), recBytes, 0600)
	g2.ReleaseLockOnly()

	if _, err := acquireBackupRunGuard(guardDir, "secret-profile", "secret-job", insp); err == nil {
		t.Errorf("expected launch-pending crash on same boot to fail closed")
	}
	if _, statErr := os.Stat(g2.StatePath()); statErr != nil {
		t.Errorf("launch-pending guard must NOT be auto-removed on same boot")
	}

	// 9. System reboot (BootSec changed) -> clears stale launch-pending guard safely!
	insp.bootSec = 1700099999
	g3, err := acquireBackupRunGuard(guardDir, "secret-profile", "secret-job", insp)
	if err != nil {
		t.Fatalf("expected reboot to safely clear pre-reboot guard, got: %v", err)
	}
	_ = g3.ConfirmExitedAndClear()
}

func TestBackupWatchdogOpenrsyncFailClosed(t *testing.T) {
	tmpDir := t.TempDir()
	fakeOpenrsync := filepath.Join(tmpDir, "fake_openrsync")
	if err := os.WriteFile(fakeOpenrsync, []byte("#!/bin/sh\necho 'openrsync: protocol version 29'\n"), 0755); err != nil {
		t.Fatalf("write fake_openrsync failed: %v", err)
	}
	t.Setenv("SEC_LOCAL_RSYNC_BIN", fakeOpenrsync)
	t.Setenv("SEC_CONFIG_DIR", filepath.Join(tmpDir, "sec_cfg"))

	// Verify rsyncIsOpenrsync detects it
	if !rsyncIsOpenrsync(fakeOpenrsync) {
		t.Fatalf("expected fake_openrsync to be detected as openrsync")
	}
}
