//go:build !darwin

package main

import (
	"fmt"
	"runtime"
)

// isBackupGuardPlatformSupported reports whether native atomic overlap guard
// and kernel process-identity verification are supported on this platform.
func isBackupGuardPlatformSupported() bool {
	return false
}

// backupRunGuard is an unsupported-platform stub that fails closed rather than
// weakening process-identity or overlap-prevention guarantees.
type backupRunGuard struct{}

func acquireBackupRunGuard(_, _, _ string, _ backupProcInspector) (*backupRunGuard, error) {
	return nil, fmt.Errorf("backup overlap guard: native process-identity and boot-time verification is not supported on %s/%s (fail-closed)", runtime.GOOS, runtime.GOARCH)
}

func (g *backupRunGuard) StatePath() string { return "" }

func (g *backupRunGuard) MarkLaunchPending() error {
	return fmt.Errorf("backup overlap guard: unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)
}

func (g *backupRunGuard) MarkRunning(_ int) error {
	return fmt.Errorf("backup overlap guard: unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)
}

func (g *backupRunGuard) MarkTerminationUnconfirmed() error {
	return fmt.Errorf("backup overlap guard: unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)
}

func (g *backupRunGuard) VerifyChildExited() (bool, error) {
	return false, fmt.Errorf("backup overlap guard: unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)
}

func (g *backupRunGuard) ClearChildStateKeepLock() error { return nil }

func (g *backupRunGuard) ConfirmExitedAndClear() error { return nil }

func (g *backupRunGuard) ReleaseLockOnly() {}
