package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	backupGuardStateLaunchPending          = "launch-pending"
	backupGuardStateRunning                = "running"
	backupGuardStateTerminationUnconfirmed = "termination-unconfirmed"
)

// backupProcIdentity captures kernel-verified process start time and command name
// so PID reuse across exits or reboots is never mistaken for the original process.
type backupProcIdentity struct {
	PID       int    `json:"pid"`
	StartSec  int64  `json:"start_sec"`
	StartUsec int32  `json:"start_usec"`
	Comm      string `json:"comm,omitempty"`
}

// backupGuardRecord is the opaque, privacy-safe JSON state persisted in <sha256>.json.
// It intentionally contains zero profile names, job names, folder paths, hosts, or users.
type backupGuardRecord struct {
	Version  int                 `json:"version"`
	State    string              `json:"state"`
	BootSec  int64               `json:"boot_sec"`
	BootUsec int32               `json:"boot_usec"`
	Launcher *backupProcIdentity `json:"launcher,omitempty"`
	Child    *backupProcIdentity `json:"child,omitempty"`
}

// backupProcInspector abstracts kernel boot-time and PID inspection for deterministic testing.
type backupProcInspector interface {
	BootTime() (int64, int32, error)
	InspectPID(pid int) (backupProcIdentity, bool, error)
}

// backupGuardKey computes the privacy-safe opaque hex identifier for a (profile, job) pair.
func backupGuardKey(profile, jobName string) string {
	sum := sha256.Sum256([]byte(profile + "\x00" + jobName))
	return hex.EncodeToString(sum[:])
}

var (
	// watchdogGracePeriod is how long to wait after SIGTERM before escalating to SIGKILL.
	// Exported as a package var so unit tests can override to milliseconds.
	watchdogGracePeriod = 15 * time.Second

	// watchdogKillConfirmWait is how long to wait after SIGKILL to confirm process exit
	// before declaring termination unconfirmed (e.g. macOS uninterruptible U-state).
	watchdogKillConfirmWait = 10 * time.Second

	// watchdogPollInterval is how often the watchdog checks monotonic progress age.
	watchdogPollInterval = 250 * time.Millisecond

	// watchdogPipeDrainWait bounds pipe draining after confirmed child exit on timeout.
	watchdogPipeDrainWait = 200 * time.Millisecond
)

// watchdogAbortError signals that the no-progress watchdog aborted a backup run
// due to a suspected stall. Callers treat this as job-fatal (no retry, no next folder).
type watchdogAbortError struct {
	FolderAlias          string
	Timeout              time.Duration
	TerminationConfirmed bool
	ChildPID             int
	GuardFile            string
}

func (e *watchdogAbortError) Error() string {
	alias := e.FolderAlias
	if alias == "" {
		alias = "backup"
	}
	if e.TerminationConfirmed {
		return fmt.Sprintf(
			"no-progress watchdog aborted %s after %s without forward progress (suspected stall; termination confirmed)",
			alias, e.Timeout,
		)
	}
	extra := ""
	if e.ChildPID > 0 {
		extra += fmt.Sprintf(" [pid=%d]", e.ChildPID)
	}
	if e.GuardFile != "" {
		extra += fmt.Sprintf(" [guard=%s]", e.GuardFile)
	}
	return fmt.Sprintf(
		"no-progress watchdog aborted %s after %s without forward progress (suspected stall; "+
			"termination requested, NOT confirmed stopped (process may be stuck in uninterruptible kernel I/O); "+
			"guard kept active to prevent overlapping runs)%s",
		alias, e.Timeout, extra,
	)
}

func isWatchdogAbortError(err error) bool {
	var target *watchdogAbortError
	return errors.As(err, &target)
}

var (
	reRsyncFilesProgress = regexp.MustCompile(`^([\d,]+)\s+files(?:\.\.\.|\s+to\s+consider)(?:\s|$)`)
	reRsyncBytesProgress = regexp.MustCompile(`^([\d,]+)B?\s+\d+%\s+`)
	reRsyncXfrProgress   = regexp.MustCompile(`\bxfr#(\d+)\b`)
	reRsyncChkProgress   = regexp.MustCompile(`\b((?:ir-chk|to-chk)=\d+/\d+)\b`)
)

// backupProgressTracker tracks real forward backup progress using a monotonic clock.
// Only advancing rsync scan/transfer counters and non-zero SSH channel payload bytes
// reset the no-progress timer; static/repeated lines, stderr errors, and SSH keepalives do not.
type backupProgressTracker struct {
	mu                sync.Mutex
	lastProgress      time.Time
	lastBytes         int64
	lastTransferBytes int64
	lastXfrCount      int64
	lastFileCount     int64
	lastScanSignature string
}

func newBackupProgressTracker() *backupProgressTracker {
	return &backupProgressTracker{
		lastProgress: time.Now(),
	}
}

// RecordChannelBytes records raw payload bytes forwarded across the ssh-stdio channel.
// SSH keepalives never pass through this bridge; only n > 0 advances lastProgress.
func (t *backupProgressTracker) RecordChannelBytes(n int64) {
	if t == nil || n <= 0 {
		return
	}
	t.mu.Lock()
	t.lastBytes += n
	t.lastProgress = time.Now()
	t.mu.Unlock()
}

// RecordProgressLine parses a single GNU rsync `--info=name0,flist2,progress2` line
// and resets lastProgress ONLY when meaningful progress counters actually advance or change.
// Returns true if the line represented forward progress.
func (t *backupProgressTracker) RecordProgressLine(line string) bool {
	if t == nil {
		return false
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}

	advanced := false
	t.mu.Lock()
	defer t.mu.Unlock()

	if m := reRsyncFilesProgress.FindStringSubmatch(trimmed); len(m) == 2 {
		if count, err := parseCommaInt64(m[1]); err == nil && count > t.lastFileCount {
			t.lastFileCount = count
			advanced = true
		}
	}

	if m := reRsyncBytesProgress.FindStringSubmatch(trimmed); len(m) == 2 {
		if b, err := parseCommaInt64(m[1]); err == nil && b > t.lastTransferBytes {
			t.lastTransferBytes = b
			advanced = true
		}
	}

	if m := reRsyncXfrProgress.FindStringSubmatch(trimmed); len(m) == 2 {
		if xfr, err := strconv.ParseInt(m[1], 10, 64); err == nil && xfr > t.lastXfrCount {
			t.lastXfrCount = xfr
			advanced = true
		}
	}

	if m := reRsyncChkProgress.FindStringSubmatch(trimmed); len(m) == 2 {
		sig := m[1]
		if sig != "" && sig != t.lastScanSignature {
			t.lastScanSignature = sig
			advanced = true
		}
	}

	if advanced {
		t.lastProgress = time.Now()
	}
	return advanced
}

// SinceLastProgress returns the monotonic duration elapsed since the last recorded progress.
func (t *backupProgressTracker) SinceLastProgress() time.Duration {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	lp := t.lastProgress
	t.mu.Unlock()
	return time.Since(lp)
}

func parseCommaInt64(raw string) (int64, error) {
	clean := strings.ReplaceAll(raw, ",", "")
	return strconv.ParseInt(clean, 10, 64)
}

// countingBridgeReader wraps an io.Reader on the ssh-stdio bridge and reports
// positive byte reads to the backupProgressTracker.
type countingBridgeReader struct {
	r       io.Reader
	tracker *backupProgressTracker
}

func (c *countingBridgeReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 && c.tracker != nil {
		c.tracker.RecordChannelBytes(int64(n))
	}
	return n, err
}

// countingBridgeWriter wraps an io.Writer on the ssh-stdio bridge and reports
// positive byte writes to the backupProgressTracker.
type countingBridgeWriter struct {
	w       io.Writer
	tracker *backupProgressTracker
}

func (c *countingBridgeWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 && c.tracker != nil {
		c.tracker.RecordChannelBytes(int64(n))
	}
	return n, err
}

// runCommandWithWatchdog executes cmd in its own process group with explicit stdout/stderr pipes,
// persisted overlap-guard transitions, and an optional monotonic no-progress watchdog.
// When timeout <= 0, the watchdog is disabled and cmd runs to normal completion.
// When timeout > 0 and no forward progress is observed for timeout, onBeforeKill is invoked,
// SIGTERM -> watchdogGracePeriod -> SIGKILL -> watchdogKillConfirmWait is executed, and
// a bounded *watchdogAbortError is returned even if the child is stuck in uninterruptible I/O.
func runCommandWithWatchdog(
	cmd *exec.Cmd,
	stdoutDst, stderrDst io.Writer,
	guard *backupRunGuard,
	tracker *backupProgressTracker,
	timeout time.Duration,
	folderAlias string,
	onBeforeKill func(),
) (runErr error, aborted *watchdogAbortError) {
	if stdoutDst == nil {
		stdoutDst = io.Discard
	}
	if stderrDst == nil {
		stderrDst = io.Discard
	}
	if tracker == nil {
		tracker = newBackupProgressTracker()
	}

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	} else {
		attrCopy := *cmd.SysProcAttr
		attrCopy.Setpgid = true
		cmd.SysProcAttr = &attrCopy
	}

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("backup watchdog: failed to create stdout pipe: %w", err), nil
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		return fmt.Errorf("backup watchdog: failed to create stderr pipe: %w", err), nil
	}

	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW

	if guard != nil {
		if err := guard.MarkLaunchPending(); err != nil {
			_ = stdoutR.Close()
			_ = stdoutW.Close()
			_ = stderrR.Close()
			_ = stderrW.Close()
			return err, nil
		}
	}

	if err := cmd.Start(); err != nil {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		_ = stderrR.Close()
		_ = stderrW.Close()
		if guard != nil {
			_ = guard.ConfirmExitedAndClear()
		}
		return err, nil
	}

	// Close parent write ends immediately so reader goroutines observe EOF on child exit.
	_ = stdoutW.Close()
	_ = stderrW.Close()

	childPID := cmd.Process.Pid
	if guard != nil {
		// Best-effort transition to running; if it fails, child is already started so
		// we still supervise it and clean up or persist state on exit.
		_ = guard.MarkRunning(childPID)
	}

	pipeDone := make(chan struct{})
	var pipeWG sync.WaitGroup
	pipeWG.Add(2)
	go func() {
		defer pipeWG.Done()
		_, _ = io.Copy(stdoutDst, stdoutR)
	}()
	go func() {
		defer pipeWG.Done()
		_, _ = io.Copy(stderrDst, stderrR)
	}()
	go func() {
		pipeWG.Wait()
		close(pipeDone)
	}()

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	finishNormal := func(waitErr error) (error, *watchdogAbortError) {
		<-pipeDone
		_ = stdoutR.Close()
		_ = stderrR.Close()
		if guard != nil {
			_ = guard.ConfirmExitedAndClear()
			_ = guard.ClearChildStateKeepLock()
		}
		return waitErr, nil
	}

	if timeout <= 0 {
		return finishNormal(<-waitCh)
	}

	pollInterval := watchdogPollInterval
	if pollInterval <= 0 {
		pollInterval = 250 * time.Millisecond
	}
	if timeout < pollInterval {
		pollInterval = timeout / 4
		if pollInterval < 5*time.Millisecond {
			pollInterval = 5 * time.Millisecond
		}
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case waitErr := <-waitCh:
			return finishNormal(waitErr)
		case <-ticker.C:
			if tracker.SinceLastProgress() < timeout {
				continue
			}
			// Completion-vs-timeout race check: if cmd.Wait() already completed right
			// before we commit to a timeout, prefer normal completion.
			select {
			case waitErr := <-waitCh:
				return finishNormal(waitErr)
			default:
			}

			// Commit to watchdog abort.
			if onBeforeKill != nil {
				onBeforeKill()
			}

			// Step 1: Graceful SIGTERM to process group and child PID.
			_ = syscall.Kill(-childPID, syscall.SIGTERM)
			_ = syscall.Kill(childPID, syscall.SIGTERM)

			exited := false
			graceTimer := time.NewTimer(watchdogGracePeriod)
			select {
			case <-waitCh:
				exited = true
			case <-graceTimer.C:
			}
			graceTimer.Stop()

			// Step 2: Escalate to SIGKILL if still running.
			if !exited {
				_ = syscall.Kill(-childPID, syscall.SIGKILL)
				_ = syscall.Kill(childPID, syscall.SIGKILL)

				killTimer := time.NewTimer(watchdogKillConfirmWait)
				select {
				case <-waitCh:
					exited = true
				case <-killTimer.C:
				}
				killTimer.Stop()
			}

			// Final confirmation check via waitCh + kernel process identity inspector.
			if !exited {
				select {
				case <-waitCh:
					exited = true
				default:
				}
			}
			if !exited && guard != nil {
				if dead, verifyErr := guard.VerifyChildExited(); verifyErr == nil && dead {
					exited = true
				}
			}

			guardFile := ""
			if guard != nil {
				guardFile = guard.StatePath()
			}

			if exited {
				drainTimer := time.NewTimer(watchdogPipeDrainWait)
				select {
				case <-pipeDone:
				case <-drainTimer.C:
				}
				drainTimer.Stop()
				_ = stdoutR.Close()
				_ = stderrR.Close()
				if guard != nil {
					_ = guard.ConfirmExitedAndClear()
				}
				abortErr := &watchdogAbortError{
					FolderAlias:          folderAlias,
					Timeout:              timeout,
					TerminationConfirmed: true,
					ChildPID:             childPID,
					GuardFile:            guardFile,
				}
				return abortErr, abortErr
			}

			// Unconfirmed termination (e.g. stuck in macOS uninterruptible U-state):
			// persist termination-unconfirmed guard, close pipe read ends so reader
			// goroutines exit immediately, and return within bounded time.
			if guard != nil {
				_ = guard.MarkTerminationUnconfirmed()
			}
			_ = stdoutR.Close()
			_ = stderrR.Close()

			abortErr := &watchdogAbortError{
				FolderAlias:          folderAlias,
				Timeout:              timeout,
				TerminationConfirmed: false,
				ChildPID:             childPID,
				GuardFile:            guardFile,
			}
			return abortErr, abortErr
		}
	}
}
