//go:build darwin

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"secure_secrets/internal/config"

	"golang.org/x/sys/unix"
)

// isBackupGuardPlatformSupported reports whether native atomic overlap guard
// and kernel process-identity verification are supported on this platform.
func isBackupGuardPlatformSupported() bool {
	return true
}

// darwinProcInspector implements backupProcInspector using native macOS sysctls
// (`kern.boottime` and `kern.proc.pid`) via golang.org/x/sys/unix.
type darwinProcInspector struct{}

func (darwinProcInspector) BootTime() (int64, int32, error) {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return 0, 0, fmt.Errorf("sysctl kern.boottime: %w", err)
	}
	return tv.Sec, tv.Usec, nil
}

func (darwinProcInspector) InspectPID(pid int) (backupProcIdentity, bool, error) {
	if pid <= 0 {
		return backupProcIdentity{}, false, nil
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			return backupProcIdentity{}, false, nil
		}
		// On macOS, sysctl(KERN_PROC_PID) returns 0 bytes for a non-existent PID,
		// which golang.org/x/sys/unix surfaces as unix.EIO (n != SizeofKinfoProc).
		// Cross-check with kill(pid, 0): ESRCH confirms the PID does not exist;
		// any other result (nil or EPERM) means the identity is uncertain and must fail closed.
		if errors.Is(err, unix.EIO) {
			if killErr := unix.Kill(pid, 0); errors.Is(killErr, unix.ESRCH) {
				return backupProcIdentity{}, false, nil
			}
		}
		return backupProcIdentity{}, false, fmt.Errorf("sysctl kern.proc.pid(%d): %w", pid, err)
	}
	comm := unix.ByteSliceToString(kp.Proc.P_comm[:])
	return backupProcIdentity{
		PID:       pid,
		StartSec:  kp.Proc.P_starttime.Sec,
		StartUsec: kp.Proc.P_starttime.Usec,
		Comm:      comm,
	}, true, nil
}

// backupRunGuard enforces an atomic, reboot-safe, PID-reuse-safe per-(profile, job)
// overlap guard backed by unix.Flock and an opaque hashed JSON state file.
type backupRunGuard struct {
	mu        sync.Mutex
	guardDir  string
	lockPath  string
	statePath string
	lockFile  *os.File
	inspector backupProcInspector
	bootSec   int64
	bootUsec  int32
	record    backupGuardRecord
}

// acquireBackupRunGuard acquires the per-(profile, job) exclusive non-blocking flock
// and validates any persisted guard state before allowing a backup run to proceed.
// If guardDir is empty, it defaults to <configDir>/backup-guards.
// If inspector is nil, it defaults to darwinProcInspector{}.
func acquireBackupRunGuard(guardDir, profile, jobName string, inspector backupProcInspector) (*backupRunGuard, error) {
	if inspector == nil {
		inspector = darwinProcInspector{}
	}
	if guardDir == "" {
		cfgDir, err := config.GetConfigDir()
		if err != nil {
			return nil, fmt.Errorf("backup overlap guard: cannot resolve config directory: %w", err)
		}
		guardDir = filepath.Join(cfgDir, "backup-guards")
	}
	if err := os.MkdirAll(guardDir, 0o700); err != nil {
		return nil, fmt.Errorf("backup overlap guard: cannot create guard directory: %w", err)
	}
	if err := os.Chmod(guardDir, 0o700); err != nil { // #nosec G302 -- enforce owner-only permissions on guard directory
		return nil, fmt.Errorf("backup overlap guard: cannot secure guard directory permissions: %w", err)
	}

	key := backupGuardKey(profile, jobName)
	lockPath := filepath.Join(guardDir, key+".lock")
	statePath := filepath.Join(guardDir, key+".json")

	// #nosec G304 -- lockPath is derived from config/test guardDir and hex sha256 digest
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("backup overlap guard: cannot open lock file: %w", err)
	}
	if err := lockFile.Chmod(0o600); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("backup overlap guard: cannot secure lock file permissions: %w", err)
	}

	// #nosec G115 -- file descriptor fits in int on Darwin
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lockFile.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("backup overlap guard: another backup run for this job is already active (lock held); wait for it to finish before starting a new run")
		}
		return nil, fmt.Errorf("backup overlap guard: cannot acquire exclusive lock: %w", err)
	}

	curBootSec, curBootUsec, err := inspector.BootTime()
	if err != nil {
		releaseFlockFile(lockFile)
		return nil, fmt.Errorf("backup overlap guard: cannot verify system boot time (fail-closed): %w", err)
	}

	// Inspect any existing guard state file while holding the exclusive flock.
	if err := checkExistingBackupGuardState(statePath, curBootSec, curBootUsec, inspector); err != nil {
		releaseFlockFile(lockFile)
		return nil, err
	}

	return &backupRunGuard{
		guardDir:  guardDir,
		lockPath:  lockPath,
		statePath: statePath,
		lockFile:  lockFile,
		inspector: inspector,
		bootSec:   curBootSec,
		bootUsec:  curBootUsec,
	}, nil
}

func checkExistingBackupGuardState(statePath string, curBootSec int64, curBootUsec int32, inspector backupProcInspector) error {
	// #nosec G304 -- statePath is derived from guardDir and hex sha256 digest
	raw, err := os.ReadFile(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("backup overlap guard: cannot read existing guard state %s (fail-closed): %w", statePath, err)
	}

	var rec backupGuardRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return fmt.Errorf("backup overlap guard: existing guard state %s is unreadable (fail-closed); verify no backup process is running before removing %s: %w", statePath, statePath, err)
	}

	// Different boot time means any recorded PIDs from the prior boot are guaranteed dead.
	if rec.BootSec != curBootSec || rec.BootUsec != curBootUsec {
		if rmErr := os.Remove(statePath); rmErr != nil && !os.IsNotExist(rmErr) {
			return fmt.Errorf("backup overlap guard: cannot clear stale guard from previous boot %s: %w", statePath, rmErr)
		}
		return nil
	}

	switch rec.State {
	case backupGuardStateLaunchPending:
		if rec.Launcher == nil || rec.Launcher.PID <= 0 {
			return fmt.Errorf("backup overlap guard: prior run left an incomplete launch-pending guard (%s); verify no rsync process is running before removing %s", statePath, statePath)
		}
		actual, exists, err := inspector.InspectPID(rec.Launcher.PID)
		if err != nil {
			return fmt.Errorf("backup overlap guard: cannot verify prior launcher PID %d (fail-closed): %w", rec.Launcher.PID, err)
		}
		if exists && matchesProcIdentity(actual, *rec.Launcher) {
			return fmt.Errorf("backup overlap guard: another backup launch for this job is currently in progress (launcher PID %d)", rec.Launcher.PID)
		}
		// Launcher died on the same boot before MarkRunning completed: uncertain whether
		// the child process was spawned. Fail closed and never auto-delete or blindly kill.
		return fmt.Errorf(
			"backup overlap guard: previous launcher (PID %d) terminated during launch-pending on this boot; "+
				"cannot confirm whether a child rsync process was started (fail-closed). "+
				"Inspect running rsync processes (e.g., `ps -ax -o pid,stat,comm | grep rsync`), confirm none belong to this job, "+
				"and then remove %s to resume",
			rec.Launcher.PID, statePath,
		)

	case backupGuardStateRunning, backupGuardStateTerminationUnconfirmed:
		if rec.Child == nil || rec.Child.PID <= 0 {
			return fmt.Errorf("backup overlap guard: existing guard %s (state=%s) has no child identity (fail-closed); verify no rsync process is running before removing %s", statePath, rec.State, statePath)
		}
		actual, exists, err := inspector.InspectPID(rec.Child.PID)
		if err != nil {
			return fmt.Errorf("backup overlap guard: cannot verify prior child PID %d identity (fail-closed): %w", rec.Child.PID, err)
		}
		if !exists || !matchesProcIdentity(actual, *rec.Child) {
			// Child is confirmed dead or PID was reused by a different process.
			if rmErr := os.Remove(statePath); rmErr != nil && !os.IsNotExist(rmErr) {
				return fmt.Errorf("backup overlap guard: cannot clear stale guard %s: %w", statePath, rmErr)
			}
			return nil
		}
		return fmt.Errorf(
			"backup overlap guard: prior backup child process is still active (PID %d, state=%s). "+
				"Check its status with `ps -p %d -o pid,stat,comm`. If it is stuck in uninterruptible kernel I/O (`U` state), "+
				"wait for the underlying filesystem/mount to recover or reboot before retrying; "+
				"do not delete %s while the process is still alive",
			rec.Child.PID, rec.State, rec.Child.PID, statePath,
		)

	default:
		return fmt.Errorf("backup overlap guard: unrecognized guard state %q in %s (fail-closed); verify no backup process is running before removing %s", rec.State, statePath, statePath)
	}
}

func matchesProcIdentity(a, b backupProcIdentity) bool {
	return a.PID == b.PID && a.StartSec == b.StartSec && a.StartUsec == b.StartUsec
}

func releaseFlockFile(f *os.File) {
	if f == nil {
		return
	}
	// #nosec G115 -- file descriptor fits in int on Darwin
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	_ = f.Close()
}

// StatePath returns the absolute path to the opaque hashed guard JSON state file.
func (g *backupRunGuard) StatePath() string {
	if g == nil {
		return ""
	}
	return g.statePath
}

// MarkLaunchPending persists state="launch-pending" with the current launcher identity
// (fsynced atomically) BEFORE cmd.Start() is called.
func (g *backupRunGuard) MarkLaunchPending() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	launcherPID := os.Getpid()
	launcherID, exists, err := g.inspector.InspectPID(launcherPID)
	if err != nil {
		return fmt.Errorf("backup overlap guard: cannot inspect launcher PID %d: %w", launcherPID, err)
	}
	if !exists {
		return fmt.Errorf("backup overlap guard: launcher PID %d not found in process table", launcherPID)
	}

	rec := backupGuardRecord{
		Version:  1,
		State:    backupGuardStateLaunchPending,
		BootSec:  g.bootSec,
		BootUsec: g.bootUsec,
		Launcher: &launcherID,
	}
	if err := g.writeRecordAtomicLocked(rec); err != nil {
		return err
	}
	g.record = rec
	return nil
}

// MarkRunning inspects childPID and atomically persists state="running" with the child identity.
func (g *backupRunGuard) MarkRunning(childPID int) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	childID, exists, err := g.inspector.InspectPID(childPID)
	if err != nil {
		return fmt.Errorf("backup overlap guard: cannot inspect child PID %d: %w", childPID, err)
	}
	if !exists {
		// Child may have exited in the window between cmd.Start() and MarkRunning().
		// Record the PID with zero start time so ConfirmExitedAndClear() cleans up normally.
		childID = backupProcIdentity{PID: childPID}
	}

	rec := g.record
	rec.Version = 1
	rec.State = backupGuardStateRunning
	rec.BootSec = g.bootSec
	rec.BootUsec = g.bootUsec
	rec.Child = &childID
	if err := g.writeRecordAtomicLocked(rec); err != nil {
		return err
	}
	g.record = rec
	return nil
}

// MarkTerminationUnconfirmed atomically updates state="termination-unconfirmed",
// keeps the guard JSON file on disk, and releases only the flock so subsequent runs
// inspect the persisted guard and fail closed until the child exits or the host reboots.
func (g *backupRunGuard) MarkTerminationUnconfirmed() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	rec := g.record
	rec.Version = 1
	rec.State = backupGuardStateTerminationUnconfirmed
	rec.BootSec = g.bootSec
	rec.BootUsec = g.bootUsec
	err := g.writeRecordAtomicLocked(rec)
	if err == nil {
		g.record = rec
	}
	releaseFlockFile(g.lockFile)
	g.lockFile = nil
	return err
}

// VerifyChildExited checks via the kernel process inspector whether the recorded child
// process has exited (or its PID has been reused).
func (g *backupRunGuard) VerifyChildExited() (bool, error) {
	if g == nil {
		return true, nil
	}
	g.mu.Lock()
	child := g.record.Child
	inspector := g.inspector
	g.mu.Unlock()

	if child == nil || child.PID <= 0 {
		return false, fmt.Errorf("backup overlap guard: no child process identity recorded")
	}
	actual, exists, err := inspector.InspectPID(child.PID)
	if err != nil {
		return false, err
	}
	if !exists || !matchesProcIdentity(actual, *child) {
		return true, nil
	}
	return false, nil
}

// ClearChildStateKeepLock removes the persisted guard state file after confirmed
// child exit while keeping the exclusive per-job flock held for remaining folders.
func (g *backupRunGuard) ClearChildStateKeepLock() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.statePath != "" {
		if err := os.Remove(g.statePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("backup overlap guard: cannot remove guard state file: %w", err)
		}
	}
	g.record.Child = nil
	return nil
}

// ConfirmExitedAndClear removes the persisted guard state file and releases the flock.
func (g *backupRunGuard) ConfirmExitedAndClear() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	var rmErr error
	if g.statePath != "" {
		if err := os.Remove(g.statePath); err != nil && !os.IsNotExist(err) {
			rmErr = fmt.Errorf("backup overlap guard: cannot remove guard state file: %w", err)
		}
	}
	releaseFlockFile(g.lockFile)
	g.lockFile = nil
	return rmErr
}

// ReleaseLockOnly closes the flock without deleting the persisted guard state file.
func (g *backupRunGuard) ReleaseLockOnly() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	releaseFlockFile(g.lockFile)
	g.lockFile = nil
}

func (g *backupRunGuard) writeRecordAtomicLocked(rec backupGuardRecord) error {
	payload, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("backup overlap guard: cannot marshal guard state: %w", err)
	}
	payload = append(payload, '\n')

	tmpFile, err := os.CreateTemp(g.guardDir, ".guard-*.tmp")
	if err != nil {
		return fmt.Errorf("backup overlap guard: cannot create temporary guard file: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanupTmp := func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}

	if err := tmpFile.Chmod(0o600); err != nil {
		cleanupTmp()
		return fmt.Errorf("backup overlap guard: cannot secure temporary guard file: %w", err)
	}
	if _, err := tmpFile.Write(payload); err != nil {
		cleanupTmp()
		return fmt.Errorf("backup overlap guard: cannot write guard state: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		cleanupTmp()
		return fmt.Errorf("backup overlap guard: cannot fsync guard state: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("backup overlap guard: cannot close temporary guard file: %w", err)
	}
	if err := os.Rename(tmpPath, g.statePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("backup overlap guard: cannot atomically persist guard state: %w", err)
	}
	return nil
}
