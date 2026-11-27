package main

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	backupRetryBaseDelay    = 5 * time.Second
	backupRetryMaxDelay     = 30 * time.Minute
	backupKeepaliveInterval = 10 * time.Minute
	backupExtendBelow       = 30 * time.Minute
	backupSessionTTL        = "8h"
)

// backupBackoff returns the exponential retry delay after failed attempt (1-based),
// doubling from backupRetryBaseDelay and capped at backupRetryMaxDelay.
func backupBackoff(attempt int) time.Duration {
	if attempt <= 1 {
		if backupRetryBaseDelay > backupRetryMaxDelay {
			return backupRetryMaxDelay
		}
		return backupRetryBaseDelay
	}
	d := backupRetryBaseDelay
	for i := 1; i < attempt; i++ {
		if d >= backupRetryMaxDelay/2 {
			return backupRetryMaxDelay
		}
		d *= 2
	}
	if d > backupRetryMaxDelay {
		return backupRetryMaxDelay
	}
	return d
}

// requireUnlockedForStealthBackup verifies that the target daemon profile is running and unlocked
// before starting any backup transfer.
func requireUnlockedForStealthBackup(profile string, noTrace bool) error {
	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:  daemon.IPCActionStatus,
		NoTrace: noTrace,
	})
	if err != nil {
		return fmt.Errorf("daemon not running for profile %q: %w", profile, err)
	}
	if resp == nil || !resp.Success || resp.StatusInfo == nil || !resp.StatusInfo.IsUnlocked {
		return fmt.Errorf("vault profile %q is locked; run 'sec open --profile %s' before starting backup", profile, profile)
	}
	return nil
}

// checkAndExtendStealthBackupSession checks the active daemon session status with NoTrace
// and extends the session TTL when remaining time drops below backupExtendBelow.
func checkAndExtendStealthBackupSession(profile string, noTrace bool) (unlocked bool, extended bool, err error) {
	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:  daemon.IPCActionStatus,
		NoTrace: noTrace,
	})
	if err != nil || resp == nil || !resp.Success || resp.StatusInfo == nil || !resp.StatusInfo.IsUnlocked {
		return false, false, fmt.Errorf("vault session locked or unavailable")
	}
	remDur := time.Duration(resp.StatusInfo.RemainingSeconds) * time.Second
	if remDur < backupExtendBelow {
		extResp, extErr := queryDaemon(profile, daemon.IPCRequest{
			Action:  daemon.IPCActionExtend,
			TTL:     backupSessionTTL,
			NoTrace: noTrace,
		})
		if extErr != nil || extResp == nil || !extResp.Success {
			return true, false, fmt.Errorf("failed to extend session")
		}
		return true, true, nil
	}
	return true, false, nil
}

// keepStealthBackupSessionAlive runs a background goroutine that periodically checks
// session status every backupKeepaliveInterval and extends the session when remaining TTL
// falls below backupExtendBelow. If the session is lost/locked, the returned `lost` channel is closed.
func keepStealthBackupSessionAlive(profile string, noTrace bool) (stop func(), lost <-chan struct{}) {
	stopCh := make(chan struct{})
	lostCh := make(chan struct{})
	var stopOnce sync.Once
	var lostOnce sync.Once

	go func() {
		ticker := time.NewTicker(backupKeepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				unlocked, _, _ := checkAndExtendStealthBackupSession(profile, noTrace)
				if !unlocked {
					lostOnce.Do(func() { close(lostCh) })
					return
				}
			}
		}
	}()

	stop = func() {
		stopOnce.Do(func() { close(stopCh) })
	}
	return stop, lostCh
}

func startStealthBackupKeepalive(profile string, noTrace bool) (stop func(), lost <-chan struct{}) {
	return keepStealthBackupSessionAlive(profile, noTrace)
}

// sshKeepaliveSender abstracts an in-memory Go SSH client for sending encrypted
// OpenSSH keepalive@openssh.com requests and closing dead connections.
type sshKeepaliveSender interface {
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)
	Close() error
}

// startSSHServerAliveMonitor sends OpenSSH `keepalive@openssh.com` requests over the in-memory
// Go SSH connection every `interval`. If `countMax` consecutive probes fail or time out without a
// reply, it closes `client` so a stalled transfer aborts immediately and triggers the retry loop.
// When `interval <= 0`, no background goroutine is started (zero hardcoded defaults).
func startSSHServerAliveMonitor(client sshKeepaliveSender, interval time.Duration, countMax int) (stop func()) {
	if client == nil || interval <= 0 {
		return func() {}
	}
	effectiveMax := countMax
	if effectiveMax <= 0 {
		effectiveMax = 3
	}

	stopCh := make(chan struct{})
	var stopOnce sync.Once

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		missed := 0
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				reqDone := make(chan error, 1)
				go func() {
					_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
					reqDone <- err
				}()

				var probeErr error
				select {
				case probeErr = <-reqDone:
				case <-time.After(interval):
					probeErr = fmt.Errorf("ssh keepalive probe timed out after %s", interval)
				case <-stopCh:
					return
				}

				if probeErr == nil {
					missed = 0
					continue
				}
				missed++
				if missed >= effectiveMax {
					_ = client.Close()
					return
				}
			}
		}
	}()

	return func() {
		stopOnce.Do(func() { close(stopCh) })
	}
}

// backupFolderRunStats captures privacy-safe per-folder counters returned by a single backup attempt.
type backupFolderRunStats struct {
	Transferred       int
	SkippedNonRegular int
	ExitCode          int
	Vanished          bool
}

// nonRetryableBackupError wraps a folder backup error that should fail immediately
// without re-walking the directory tree for additional retry attempts (e.g., rsync exit code 23 permission/TCC errors).
type nonRetryableBackupError struct {
	Err error
}

func (e *nonRetryableBackupError) Error() string {
	return e.Err.Error()
}

func (e *nonRetryableBackupError) Unwrap() error {
	return e.Err
}

func isNonRetryableBackupError(err error) bool {
	var nr *nonRetryableBackupError
	return errors.As(err, &nr)
}

func extractRsyncExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}

// classifyRsyncRunError inspects the exit status of local rsync:
//   - Exit code 24 (partial transfer due to vanished source files): logs a non-fatal warning and returns nil.
//   - Exit code 23 (partial transfer due to permission/TCC errors) or syntax/config exit codes (1..6, 11, 13, 14):
//     returns a *nonRetryableBackupError so the runner does not waste 4 retries re-walking a TCC-blocked directory tree.
//   - Transient network, socket, SSH, or timeout exit codes (10, 12, 30, 35, 255, etc.): returns a retryable error.
func classifyRsyncRunError(runErr, bridgeErr error, folderAlias string) error {
	if runErr == nil {
		return nil
	}
	safeBridge := ""
	if bridgeErr != nil {
		if Verbose {
			safeBridge = bridgeErr.Error()
		} else {
			safeBridge = redactBackupOutputLine(bridgeErr.Error())
		}
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		code := exitErr.ExitCode()
		if code == 24 {
			fmt.Fprintf(os.Stderr, "[!] Note: rsync exit 24 for folder %q (some source files vanished during transfer); treating as non-fatal.\n", folderAlias)
			return nil
		}
		switch code {
		case 1, 2, 3, 4, 5, 6, 11, 13, 14, 23:
			var baseErr error
			tccHint := ""
			if code == 23 {
				tccHint = " — hint: on macOS, exit 23 ('Operation not permitted') usually indicates a TCC-protected subpath; exclude the blocked subpath via --exclude or grant Full Disk Access to your terminal"
			}
			if safeBridge != "" {
				baseErr = fmt.Errorf("rsync failed for folder %q (exit %d, non-retryable%s): %v (remote: %s)", folderAlias, code, tccHint, runErr, safeBridge)
			} else {
				baseErr = fmt.Errorf("rsync failed for folder %q (exit %d, non-retryable%s): %w", folderAlias, code, tccHint, runErr)
			}
			return &nonRetryableBackupError{Err: baseErr}
		}
	}
	if safeBridge != "" {
		return fmt.Errorf("rsync failed for folder %q: %v (remote: %s)", folderAlias, runErr, safeBridge)
	}
	return fmt.Errorf("rsync failed for folder %q: %w", folderAlias, runErr)
}

// runStealthBackupFolders executes each folder in selectedFolders with up to manifest.MaxAttempts
// attempts, exponential backoff (backupBackoff), optional SSH reconnect between attempts, and
// continue-on-failure semantics so an exhausted folder does not block subsequent folders.
func runStealthBackupFolders(
	manifest store.BackupManifest,
	selectedFolders []store.BackupFolderSpec,
	lost <-chan struct{},
	attemptFn func(folder store.BackupFolderSpec, attempt int) error,
	reconnectFn func() error,
) ([]string, error) {
	return runStealthBackupFoldersWithOutput(
		manifest,
		selectedFolders,
		lost,
		os.Stdout,
		os.Stderr,
		func(folder store.BackupFolderSpec, attempt int) (backupFolderRunStats, error) {
			err := attemptFn(folder, attempt)
			return backupFolderRunStats{ExitCode: extractRsyncExitCode(err)}, err
		},
		reconnectFn,
	)
}

func runStealthBackupFoldersWithOutput(
	manifest store.BackupManifest,
	selectedFolders []store.BackupFolderSpec,
	lost <-chan struct{},
	out io.Writer,
	errOut io.Writer,
	attemptFn func(folder store.BackupFolderSpec, attempt int) (backupFolderRunStats, error),
	reconnectFn func() error,
) ([]string, error) {
	if out == nil {
		out = os.Stdout
	}
	if errOut == nil {
		errOut = os.Stderr
	}
	maxAttempts := manifest.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = store.DefaultBackupMaxAttempts
	}

	var failedFolders []string
	for idx, folder := range selectedFolders {
		folderAlias := safeFolderAlias(folder)
		fmt.Fprintf(out, "[%d/%d] alias=%s starting (stealth transport)...\n", idx+1, len(selectedFolders), folderAlias)

		var lastErr error
		var lastStats backupFolderRunStats
		succeeded := false
		attemptsRun := 0
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			if lost != nil {
				select {
				case <-lost:
					return failedFolders, fmt.Errorf("vault session was locked or lost during backup")
				default:
				}
			}

			attemptsRun = attempt
			lastStats, lastErr = attemptFn(folder, attempt)
			if lastErr == nil {
				succeeded = true
				break
			}
			if isWatchdogAbortError(lastErr) || isNonRetryableBackupError(lastErr) {
				break
			}

			if attempt < maxAttempts {
				delay := backupBackoff(attempt)
				fmt.Fprintf(errOut, "[!] Attempt %d/%d for alias=%s failed (%v); retrying in %s...\n", attempt, maxAttempts, folderAlias, lastErr, delay)
				if lost != nil {
					select {
					case <-lost:
						return failedFolders, fmt.Errorf("vault session was locked or lost during backup")
					case <-time.After(delay):
					}
				} else {
					time.Sleep(delay)
				}
				if reconnectFn != nil {
					_ = reconnectFn()
				}
			}
		}

		if succeeded {
			statusLabel := "ok"
			if lastStats.Vanished {
				statusLabel = "ok(vanished)"
			}
			fmt.Fprintf(out, "[%d/%d] alias=%s status=%s transferred=%d skipped_non_regular=%d exit=%d\n",
				idx+1, len(selectedFolders), folderAlias, statusLabel, lastStats.Transferred, lastStats.SkippedNonRegular, lastStats.ExitCode)
		} else {
			statusLabel := "failed"
			if isWatchdogAbortError(lastErr) {
				statusLabel = "failed(suspected-stall)"
			}
			fmt.Fprintf(errOut, "[%d/%d] alias=%s status=%s attempts=%d transferred=%d skipped_non_regular=%d exit=%d error=%v\n",
				idx+1, len(selectedFolders), folderAlias, statusLabel, attemptsRun, lastStats.Transferred, lastStats.SkippedNonRegular, lastStats.ExitCode, lastErr)
			failedFolders = append(failedFolders, folderAlias)
			if isWatchdogAbortError(lastErr) {
				fmt.Fprintf(errOut, "[✗] Aborting remaining folders in job %q after suspected stall on alias=%s.\n", manifest.Name, folderAlias)
				break
			}
		}
	}

	if len(failedFolders) > 0 {
		fmt.Fprintf(errOut, "[✗] Stealth backup job %q completed with %d failed folder(s): %s\n", manifest.Name, len(failedFolders), strings.Join(failedFolders, ", "))
		return failedFolders, fmt.Errorf("%d folder(s) failed backup synchronization: %s", len(failedFolders), strings.Join(failedFolders, ", "))
	}

	fmt.Fprintf(out, "[✓] Completed stealth backup job %q (%d folder(s) synchronized)\n", manifest.Name, len(selectedFolders))
	return nil, nil
}

type stealthBackupCliError struct {
	Code        string
	Err         error
	Remediation string
}

func (e *stealthBackupCliError) Error() string {
	return e.Err.Error()
}

func handleStealthBackupRun(profile string, args []string) {
	if err := executeStealthBackupRun(profile, args); err != nil {
		var cliErr *stealthBackupCliError
		if errors.As(err, &cliErr) {
			fail(cliErr.Code, cliErr.Err, cliErr.Remediation)
		}
		fail("BACKUP_SYNC_FAILED", err, "")
	}
}

func executeStealthBackupRun(profile string, args []string) error {
	var rawName, folderFilter, logFilePath string
	var noProgressOverride time.Duration
	noProgressOverrideSet := false
	dryRun := false
	localVerbose := false
	suggestExcludes := false
	noTrace := true
	trustOnFirstUse := false
	insecureHostKey := false
	updateHostKey := false
	maxAttemptsOverride := 0
	timeoutOverride := 0
	serverAliveIntervalOverride := 0
	serverAliveCountMaxOverride := 0

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--help" || a == "-h" {
			fmt.Println("Usage: sec backup run <name> [<folder-filter>] [--max-attempts <n>] [--timeout <sec>] [--no-progress-timeout <dur>] [--server-alive-interval <sec>] [--server-alive-count-max <count>] [--dry-run] [--verbose] [--suggest-excludes] [--log-file <path>] [--no-trace] [--trace] [--tofu] [--insecure]")
			return nil
		}
		switch {
		case a == "--dry-run" || a == "-n":
			dryRun = true
		case a == "--verbose" || a == "-v":
			localVerbose = true
		case a == "--suggest-excludes":
			suggestExcludes = true
		case a == "--log-file" && i+1 < len(args):
			logFilePath = args[i+1]
			i++
		case strings.HasPrefix(a, "--log-file="):
			logFilePath = strings.TrimPrefix(a, "--log-file=")
		case a == "--no-progress-timeout" && i+1 < len(args):
			d, err := store.ParseNoProgressTimeout(args[i+1])
			if err != nil {
				return &stealthBackupCliError{
					Code: "INVALID_ARGUMENTS",
					Err:  err,
				}
			}
			noProgressOverride = d
			noProgressOverrideSet = true
			i++
		case strings.HasPrefix(a, "--no-progress-timeout="):
			npStr := strings.TrimPrefix(a, "--no-progress-timeout=")
			d, err := store.ParseNoProgressTimeout(npStr)
			if err != nil {
				return &stealthBackupCliError{
					Code: "INVALID_ARGUMENTS",
					Err:  err,
				}
			}
			noProgressOverride = d
			noProgressOverrideSet = true
		case a == "--no-trace":
			noTrace = true
		case a == "--trace":
			noTrace = false
		case a == "--tofu" || a == "--trust-first-use":
			trustOnFirstUse = true
		case a == "--insecure" || a == "--no-verify":
			insecureHostKey = true
		case a == "--update-host-key":
			updateHostKey = true
		case a == "--max-attempts" && i+1 < len(args):
			ma, err := strconv.Atoi(args[i+1])
			if err != nil || ma <= 0 {
				return &stealthBackupCliError{
					Code: "INVALID_ARGUMENTS",
					Err:  fmt.Errorf("invalid --max-attempts %q", args[i+1]),
				}
			}
			maxAttemptsOverride = ma
			i++
		case strings.HasPrefix(a, "--max-attempts="):
			maStr := strings.TrimPrefix(a, "--max-attempts=")
			ma, err := strconv.Atoi(maStr)
			if err != nil || ma <= 0 {
				return &stealthBackupCliError{
					Code: "INVALID_ARGUMENTS",
					Err:  fmt.Errorf("invalid --max-attempts %q", maStr),
				}
			}
			maxAttemptsOverride = ma
		case a == "--timeout" && i+1 < len(args):
			to, err := strconv.Atoi(args[i+1])
			if err != nil || to < 0 {
				return &stealthBackupCliError{
					Code: "INVALID_ARGUMENTS",
					Err:  fmt.Errorf("invalid --timeout %q", args[i+1]),
				}
			}
			timeoutOverride = to
			i++
		case strings.HasPrefix(a, "--timeout="):
			toStr := strings.TrimPrefix(a, "--timeout=")
			to, err := strconv.Atoi(toStr)
			if err != nil || to < 0 {
				return &stealthBackupCliError{
					Code: "INVALID_ARGUMENTS",
					Err:  fmt.Errorf("invalid --timeout %q", toStr),
				}
			}
			timeoutOverride = to
		case a == "--server-alive-interval" && i+1 < len(args):
			sai, err := strconv.Atoi(args[i+1])
			if err != nil || sai < 0 {
				return &stealthBackupCliError{
					Code: "INVALID_ARGUMENTS",
					Err:  fmt.Errorf("invalid --server-alive-interval %q", args[i+1]),
				}
			}
			serverAliveIntervalOverride = sai
			i++
		case strings.HasPrefix(a, "--server-alive-interval="):
			saiStr := strings.TrimPrefix(a, "--server-alive-interval=")
			sai, err := strconv.Atoi(saiStr)
			if err != nil || sai < 0 {
				return &stealthBackupCliError{
					Code: "INVALID_ARGUMENTS",
					Err:  fmt.Errorf("invalid --server-alive-interval %q", saiStr),
				}
			}
			serverAliveIntervalOverride = sai
		case a == "--server-alive-count-max" && i+1 < len(args):
			sac, err := strconv.Atoi(args[i+1])
			if err != nil || sac < 0 {
				return &stealthBackupCliError{
					Code: "INVALID_ARGUMENTS",
					Err:  fmt.Errorf("invalid --server-alive-count-max %q", args[i+1]),
				}
			}
			serverAliveCountMaxOverride = sac
			i++
		case strings.HasPrefix(a, "--server-alive-count-max="):
			sacStr := strings.TrimPrefix(a, "--server-alive-count-max=")
			sac, err := strconv.Atoi(sacStr)
			if err != nil || sac < 0 {
				return &stealthBackupCliError{
					Code: "INVALID_ARGUMENTS",
					Err:  fmt.Errorf("invalid --server-alive-count-max %q", sacStr),
				}
			}
			serverAliveCountMaxOverride = sac
		default:
			if !strings.HasPrefix(a, "-") {
				if rawName == "" {
					rawName = a
				} else if folderFilter == "" {
					folderFilter = a
				}
			}
		}
	}

	if rawName == "" {
		return &stealthBackupCliError{
			Code:        "MISSING_ARGUMENT",
			Err:         fmt.Errorf("backup job <name> is required"),
			Remediation: "Usage: sec backup run <name> [<folder-filter>] [--max-attempts <n>] [--dry-run] [--verbose] [--log-file <path>] [--no-trace] [--trace] [--tofu] [--insecure]",
		}
	}

	prevVerbose := Verbose
	if localVerbose {
		Verbose = true
	}
	defer func() { Verbose = prevVerbose }()

	if err := requireUnlockedForStealthBackup(profile, noTrace); err != nil {
		return &stealthBackupCliError{
			Code:        "VAULT_LOCKED",
			Err:         err,
			Remediation: fmt.Sprintf("Run 'sec open --profile %s' first.", profile),
		}
	}

	manifest, err := loadStealthBackupManifest(profile, rawName, noTrace)
	if err != nil {
		code := "BACKUP_MANIFEST_ERROR"
		if errors.Is(err, store.ErrSecretNotFound) {
			code = "SECRET_NOT_FOUND"
		}
		return &stealthBackupCliError{Code: code, Err: err}
	}
	if maxAttemptsOverride > 0 {
		manifest.MaxAttempts = maxAttemptsOverride
	}
	if timeoutOverride > 0 {
		manifest.Timeout = timeoutOverride
	}
	if serverAliveIntervalOverride > 0 {
		manifest.ServerAliveInterval = serverAliveIntervalOverride
	}
	if serverAliveCountMaxOverride > 0 {
		manifest.ServerAliveCountMax = serverAliveCountMaxOverride
	}

	effectiveNoProgressTimeout, npErr := manifest.EffectiveNoProgressTimeout()
	if npErr != nil {
		return &stealthBackupCliError{
			Code: "INVALID_BACKUP_MANIFEST",
			Err:  npErr,
		}
	}
	if noProgressOverrideSet {
		effectiveNoProgressTimeout = noProgressOverride
		if noProgressOverride > 0 {
			manifest.NoProgressTimeout = noProgressOverride.String()
		} else {
			manifest.NoProgressTimeout = ""
		}
	}

	if len(manifest.Folders) == 0 {
		return &stealthBackupCliError{
			Code:        "EMPTY_BACKUP_FOLDERS",
			Err:         fmt.Errorf("backup job %q has no folders configured", manifest.Name),
			Remediation: fmt.Sprintf("Run 'sec backup add-folder %s \"<folder>\"' first.", manifest.Name),
		}
	}

	var selectedFolders []store.BackupFolderSpec
	for _, f := range manifest.Folders {
		if folderFilter == "" ||
			f.Name == folderFilter ||
			f.Source == folderFilter ||
			f.Dest == folderFilter ||
			f.EffectiveDestName() == folderFilter ||
			f.DeriveSlug() == folderFilter ||
			strings.EqualFold(f.DeriveHistoryPrefix(), folderFilter) {
			selectedFolders = append(selectedFolders, f)
		}
	}
	if len(selectedFolders) == 0 {
		return &stealthBackupCliError{
			Code: "FOLDER_NOT_FOUND",
			Err:  fmt.Errorf("no folder matching %q found in backup job %q", folderFilter, manifest.Name),
		}
	}

	localRsyncBin, err := findLocalRsyncBinary()
	if err != nil {
		return &stealthBackupCliError{
			Code:        "RSYNC_NOT_FOUND",
			Err:         fmt.Errorf("local 'rsync' binary not found on PATH: %w", err),
			Remediation: "Install rsync (e.g., 'brew install rsync')",
		}
	}
	if rsyncIsOpenrsync(localRsyncBin) {
		if effectiveNoProgressTimeout > 0 {
			return &stealthBackupCliError{
				Code:        "WATCHDOG_UNSUPPORTED_RSYNC",
				Err:         fmt.Errorf("no-progress watchdog (%s) cannot run with macOS openrsync (%s): openrsync (protocol 29) provides no reliable scan-phase progress signal", effectiveNoProgressTimeout, localRsyncBin),
				Remediation: "Install GNU rsync ('brew install rsync') or disable the watchdog with --no-progress-timeout 0",
			}
		}
		fmt.Fprintf(os.Stderr, "[!] Note: using macOS openrsync (%s); install GNU rsync ('brew install rsync') for full remote --log-file support.\n", localRsyncBin)
	}

	// Acquire atomic per-(profile, job) overlap guard for EVERY backup run (watchdog on or off).
	if !isBackupGuardPlatformSupported() {
		return &stealthBackupCliError{
			Code: "BACKUP_GUARD_UNSUPPORTED_PLATFORM",
			Err:  fmt.Errorf("atomic backup overlap guard and kernel process-identity verification are not supported on this platform"),
		}
	}
	cfgDir, cfgErr := config.GetConfigDir()
	if cfgErr != nil {
		return &stealthBackupCliError{
			Code: "CONFIG_DIR_ERROR",
			Err:  fmt.Errorf("failed to resolve config directory for backup overlap guard: %w", cfgErr),
		}
	}
	guardDir := filepath.Join(cfgDir, "backup-guards")
	runGuard, guardErr := acquireBackupRunGuard(guardDir, profile, manifest.Name.String(), nil)
	if guardErr != nil {
		return &stealthBackupCliError{
			Code: "BACKUP_OVERLAP_BLOCKED",
			Err:  guardErr,
		}
	}
	guardTerminationUnconfirmed := false
	defer func() {
		if guardTerminationUnconfirmed {
			runGuard.ReleaseLockOnly()
		} else {
			_ = runGuard.ConfirmExitedAndClear()
		}
	}()

	isLocal := manifest.EffectiveTransport() == store.BackupTransportLocal
	isPull := manifest.EffectiveTransport() == store.BackupTransportSSHPull
	if isLocal || isPull {
		if mountErr := verifyLocalBackupMount(manifest.RemoteBase); mountErr != nil {
			return &stealthBackupCliError{
				Code: "LOCAL_MOUNT_UNAVAILABLE",
				Err:  mountErr,
			}
		}
	}

	var selfExe string
	var sshCfg *resolvedStealthSSHConfig
	var hkOpts hostKeyOptions
	var sshClient *ssh.Client
	var reconnectFn func() error

	if !isLocal {
		var exeErr error
		selfExe, exeErr = os.Executable()
		if exeErr != nil {
			return &stealthBackupCliError{
				Code: "EXECUTABLE_NOT_FOUND",
				Err:  fmt.Errorf("failed to determine current executable path: %w", exeErr),
			}
		}

		var tgtErr error
		sshCfg, tgtErr = resolveStealthSSHTarget(profile, manifest, noTrace)
		if tgtErr != nil {
			return &stealthBackupCliError{
				Code:        "SSH_TARGET_ERROR",
				Err:         tgtErr,
				Remediation: "Configure target credentials in vault via 'sec ssh init <target>'",
			}
		}

		hkOpts = hostKeyOptions{
			insecure:        insecureHostKey,
			trustOnFirstUse: trustOnFirstUse,
			updateHostKey:   updateHostKey,
			noTrace:         noTrace,
		}

		var dialErr error
		sshClient, dialErr = dialStealthSSHClient(profile, sshCfg, hkOpts)
		if dialErr != nil {
			return &stealthBackupCliError{Code: "SSH_CONNECT_FAILED", Err: dialErr}
		}
		defer func() {
			if sshClient != nil {
				_ = sshClient.Close()
			}
		}()

		reconnectFn = func() error {
			if sshClient != nil {
				_ = sshClient.Close()
				sshClient = nil
			}
			var dErr error
			sshClient, dErr = dialStealthSSHClient(profile, sshCfg, hkOpts)
			return dErr
		}
	}

	stopKeepalive, lostCh := keepStealthBackupSessionAlive(profile, noTrace)
	defer stopKeepalive()

	expandedLocalBase := expandLocalBasePath(manifest.LocalBase)
	effectiveVerbose := Verbose || localVerbose

	outWriter := io.Writer(os.Stdout)
	errWriter := io.Writer(os.Stderr)
	if strings.TrimSpace(logFilePath) != "" {
		logFile, _, logErr := openHardenedBackupLogFile(logFilePath)
		if logErr != nil {
			return &stealthBackupCliError{
				Code: "LOG_FILE_ERROR",
				Err:  logErr,
			}
		}
		defer logFile.Close()
		outWriter = io.MultiWriter(os.Stdout, logFile)
		errWriter = io.MultiWriter(os.Stderr, logFile)
		fmt.Fprintln(errWriter, "[!] WARNING: --log-file enabled (mode 0600 in 0700 dir) — prefer a tmpfs/RAM-backed path and delete the log file immediately after inspection to minimize metadata exposure.")
	}
	if effectiveVerbose {
		fmt.Fprintln(errWriter, "[!] WARNING: --verbose enabled — per-file names, paths, and progress will be written to stdout/stderr; avoid piping to world-readable log files.")
	}

	emitExclusionSummary := func(folder store.BackupFolderSpec, folderAlias, localDir string, report backupExclusionReport) {
		if report.TotalErrors() == 0 {
			return
		}
		fmt.Fprintf(errWriter, "[!] Exclusion monitor for alias=%s: detected %d permission/TCC error(s) and %d I/O access error(s) (candidates for --exclude).\n",
			folderAlias, report.PermissionTCCCount, report.IOAccessCount)
		if effectiveVerbose || suggestExcludes {
			if len(report.Candidates) > 0 {
				fmt.Fprintf(errWriter, "    Suggested exclusion command(s) for job %q folder %q:\n", manifest.Name, folder.Source)
				seenRel := make(map[string]bool, len(report.Candidates))
				for _, cand := range report.Candidates {
					relCand := normalizeExclusionCandidatePath(cand, localDir, folder.Source)
					if relCand == "" || seenRel[relCand] {
						continue
					}
					seenRel[relCand] = true
					fmt.Fprintf(errWriter, "      sec backup add-folder %s %s --exclude %s\n",
						shellQuoteIfNeeded(manifest.Name.String()),
						shellQuoteIfNeeded(folder.Source),
						shellQuotePOSIX(relCand))
				}
			}
		} else {
			fmt.Fprintf(errWriter, "    Re-run with --suggest-excludes (or --verbose) to print deduplicated relative paths and ready-to-run 'sec backup add-folder ... --exclude' commands.\n")
		}
	}

	attemptFn := func(folder store.BackupFolderSpec, _ int) (backupFolderRunStats, error) {
		now := time.Now()
		dateStr := now.Format("2006-01-02")
		datetimeStr := now.Format("2006-01-02_1504")

		folderAlias := safeFolderAlias(folder)
		localDir := ""
		if !isPull {
			localDir = folder.ResolveLocalDir(expandedLocalBase)
		}
		destDir := folder.DeriveRemoteDest(manifest.RemoteBase)
		historyDir := folder.DeriveHistoryDir(manifest.RemoteBase, dateStr)
		destLogPath := folder.DeriveRemoteLogPath(manifest.RemoteBase, datetimeStr)

		if !isPull {
			// #nosec G703
			if fi, statErr := os.Stat(localDir); statErr != nil || !fi.IsDir() {
				if effectiveVerbose {
					return backupFolderRunStats{ExitCode: 1}, &nonRetryableBackupError{
						Err: fmt.Errorf("local source directory does not exist for folder %q: %s", folder.Source, localDir),
					}
				}
				return backupFolderRunStats{ExitCode: 1}, &nonRetryableBackupError{
					Err: fmt.Errorf("local source directory does not exist for alias %q (<path>)", folderAlias),
				}
			}
		}

		if effectiveVerbose {
			fmt.Fprintf(errWriter, "[VERBOSE] Dest: %s | History: %s | Log: %s\n", destDir, historyDir, destLogPath)
		}

		progressTracker := newBackupProgressTracker()
		stdoutFilter := newRsyncStdoutStatsWriter(outWriter, effectiveVerbose, progressTracker)
		stderrFilter := newRsyncStderrFilterWriter(errWriter, effectiveVerbose)

		excludePipeRead, excludePipeWrite, pErr := os.Pipe()
		if pErr != nil {
			return backupFolderRunStats{ExitCode: 1}, fmt.Errorf("failed to create anonymous exclude pipe: %w", pErr)
		}
		excludeContent := strings.Join(folder.EffectiveExcludes(manifest.Excludes), "\n") + "\n"
		go func(w *os.File, payload string) {
			_, _ = w.WriteString(payload)
			_ = w.Close()
		}(excludePipeWrite, excludeContent)

		if isLocal {
			if !dryRun {
				// #nosec G301 G703
				if mkErr := os.MkdirAll(destDir, 0750); mkErr != nil {
					_ = excludePipeRead.Close()
					return backupFolderRunStats{ExitCode: 1}, &nonRetryableBackupError{
						Err: fmt.Errorf("failed to create local destination directory for alias %q: %w", folderAlias, mkErr),
					}
				}
				// #nosec G301 G703
				if mkErr := os.MkdirAll(historyDir, 0750); mkErr != nil {
					_ = excludePipeRead.Close()
					return backupFolderRunStats{ExitCode: 1}, &nonRetryableBackupError{
						Err: fmt.Errorf("failed to create local history directory for alias %q: %w", folderAlias, mkErr),
					}
				}
				// #nosec G301 G703
				if mkErr := os.MkdirAll(filepath.Dir(destLogPath), 0750); mkErr != nil {
					_ = excludePipeRead.Close()
					return backupFolderRunStats{ExitCode: 1}, &nonRetryableBackupError{
						Err: fmt.Errorf("failed to create local log directory for alias %q: %w", folderAlias, mkErr),
					}
				}
			}

			stageDir, cleanupStage, stageErr := prepareLocalRsyncStageDir(localDir, destDir, historyDir, destLogPath, dryRun)
			if stageErr != nil {
				_ = excludePipeRead.Close()
				return backupFolderRunStats{ExitCode: 1}, &nonRetryableBackupError{Err: stageErr}
			}
			defer cleanupStage()

			rsyncArgs := buildDirectLocalRsyncArgs(manifest, folder, stageDir, strings.TrimSpace(historyDir) != "", strings.TrimSpace(destLogPath) != "", dryRun, effectiveVerbose)
			// #nosec G204 G702
			cmd := exec.Command(localRsyncBin, rsyncArgs...)
			cmd.Dir = stageDir
			cmd.ExtraFiles = []*os.File{excludePipeRead}
			cmd.Env = buildDirectLocalRsyncEnv(manifest)

			runErr, abortedErr := runCommandWithWatchdog(
				cmd,
				stdoutFilter,
				stderrFilter,
				runGuard,
				progressTracker,
				effectiveNoProgressTimeout,
				folderAlias,
				nil,
			)
			_ = excludePipeRead.Close()

			if abortedErr != nil {
				if !abortedErr.TerminationConfirmed {
					guardTerminationUnconfirmed = true
				}
				transferred, _, stdoutSkipped := stdoutFilter.Flush()
				stderrSkipped := stderrFilter.Flush()
				emitExclusionSummary(folder, folderAlias, localDir, stderrFilter.FlushExclusionReport())
				return backupFolderRunStats{
					Transferred:       transferred,
					SkippedNonRegular: stdoutSkipped + stderrSkipped,
					ExitCode:          124,
				}, abortedErr
			}

			transferred, _, stdoutSkipped := stdoutFilter.Flush()
			stderrSkipped := stderrFilter.Flush()
			emitExclusionSummary(folder, folderAlias, localDir, stderrFilter.FlushExclusionReport())
			rawExit := extractRsyncExitCode(runErr)
			stats := backupFolderRunStats{
				Transferred:       transferred,
				SkippedNonRegular: stdoutSkipped + stderrSkipped,
				ExitCode:          rawExit,
				Vanished:          rawExit == 24,
			}
			return stats, classifyRsyncRunError(runErr, nil, folderAlias)
		}

		// SSH transport path (both ssh push and ssh-pull)
		if sshClient == nil {
			if dErr := reconnectFn(); dErr != nil {
				_ = excludePipeRead.Close()
				return backupFolderRunStats{ExitCode: 1}, dErr
			}
		}

		var stageDir string
		if isPull {
			if !dryRun {
				// #nosec G301 G703
				if mkErr := os.MkdirAll(destDir, 0750); mkErr != nil {
					_ = excludePipeRead.Close()
					return backupFolderRunStats{ExitCode: 1}, &nonRetryableBackupError{
						Err: fmt.Errorf("failed to create local destination directory for alias %q: %w", folderAlias, mkErr),
					}
				}
				// #nosec G301 G703
				if mkErr := os.MkdirAll(historyDir, 0750); mkErr != nil {
					_ = excludePipeRead.Close()
					return backupFolderRunStats{ExitCode: 1}, &nonRetryableBackupError{
						Err: fmt.Errorf("failed to create local history directory for alias %q: %w", folderAlias, mkErr),
					}
				}
				// #nosec G301 G703
				if mkErr := os.MkdirAll(filepath.Dir(destLogPath), 0750); mkErr != nil {
					_ = excludePipeRead.Close()
					return backupFolderRunStats{ExitCode: 1}, &nonRetryableBackupError{
						Err: fmt.Errorf("failed to create local log directory for alias %q: %w", folderAlias, mkErr),
					}
				}
			}
			var cleanupStage func()
			var stageErr error
			stageDir, cleanupStage, stageErr = prepareLocalRsyncStageDir("", destDir, historyDir, destLogPath, dryRun)
			if stageErr != nil {
				_ = excludePipeRead.Close()
				return backupFolderRunStats{ExitCode: 1}, &nonRetryableBackupError{Err: stageErr}
			}
			defer cleanupStage()
		}

		aliveInterval := folder.EffectiveServerAliveInterval(manifest.ServerAliveInterval, sshCfg.ServerAliveInterval)
		aliveCountMax := folder.EffectiveServerAliveCountMax(manifest.ServerAliveCountMax, sshCfg.ServerAliveCountMax)
		stopServerAlive := startSSHServerAliveMonitor(sshClient, time.Duration(aliveInterval)*time.Second, aliveCountMax)
		defer stopServerAlive()

		sshRunner := func(remoteCmd string, stdin io.Reader, stdout, stderr io.Writer) error {
			session, sErr := sshClient.NewSession()
			if sErr != nil {
				return fmt.Errorf("failed to create SSH session: %w", sErr)
			}
			defer session.Close()

			sessStdin, pErr := session.StdinPipe()
			if pErr != nil {
				return fmt.Errorf("failed to create SSH session stdin pipe: %w", pErr)
			}
			session.Stdout = &countingBridgeWriter{w: stdout, tracker: progressTracker}
			session.Stderr = stderr

			if startErr := session.Start(remoteCmd); startErr != nil {
				return fmt.Errorf("failed to start remote rsync server: %w", startErr)
			}

			countingIn := &countingBridgeReader{r: stdin, tracker: progressTracker}
			go func() {
				_, _ = io.Copy(sessStdin, countingIn)
				_ = sessStdin.Close()
			}()

			return session.Wait()
		}

		sockPath, waitBridgeErr, cleanupBridge, bErr := startStealthStdioBridge(manifest, folder, now, sshRunner, stderrFilter)
		if bErr != nil {
			_ = excludePipeRead.Close()
			return backupFolderRunStats{ExitCode: 1}, bErr
		}

		var rsyncArgs []string
		var cmdDir string
		if isPull {
			rsyncArgs = buildStealthSSHPullRsyncArgs(manifest, folder, stageDir, strings.TrimSpace(historyDir) != "", strings.TrimSpace(destLogPath) != "", dryRun, effectiveVerbose)
			cmdDir = stageDir
		} else {
			rsyncArgs = buildLocalStealthRsyncArgs(manifest, selfExe, dryRun, effectiveVerbose, folder)
			cmdDir = localDir
		}
		// #nosec G204 G702
		cmd := exec.Command(localRsyncBin, rsyncArgs...)
		cmd.Dir = cmdDir
		cmd.ExtraFiles = []*os.File{excludePipeRead}
		cmd.Env = buildLocalStealthRsyncEnv(manifest, selfExe, sockPath)

		runErr, abortedErr := runCommandWithWatchdog(
			cmd,
			stdoutFilter,
			stderrFilter,
			runGuard,
			progressTracker,
			effectiveNoProgressTimeout,
			folderAlias,
			func() {
				cleanupBridge()
				if sshClient != nil {
					_ = sshClient.Close()
					sshClient = nil
				}
			},
		)
		_ = excludePipeRead.Close()

		if abortedErr != nil {
			cleanupBridge()
			if !abortedErr.TerminationConfirmed {
				guardTerminationUnconfirmed = true
			}
			transferred, _, stdoutSkipped := stdoutFilter.Flush()
			stderrSkipped := stderrFilter.Flush()
			emitExclusionSummary(folder, folderAlias, localDir, stderrFilter.FlushExclusionReport())
			return backupFolderRunStats{
				Transferred:       transferred,
				SkippedNonRegular: stdoutSkipped + stderrSkipped,
				ExitCode:          124,
			}, abortedErr
		}

		bridgeErr := waitBridgeErr()
		cleanupBridge()

		transferred, _, stdoutSkipped := stdoutFilter.Flush()
		stderrSkipped := stderrFilter.Flush()
		emitExclusionSummary(folder, folderAlias, localDir, stderrFilter.FlushExclusionReport())
		rawExit := extractRsyncExitCode(runErr)
		stats := backupFolderRunStats{
			Transferred:       transferred,
			SkippedNonRegular: stdoutSkipped + stderrSkipped,
			ExitCode:          rawExit,
			Vanished:          rawExit == 24,
		}

		return stats, classifyRsyncRunError(runErr, bridgeErr, folderAlias)
	}

	if _, err := runStealthBackupFoldersWithOutput(manifest, selectedFolders, lostCh, outWriter, errWriter, attemptFn, reconnectFn); err != nil {
		return &stealthBackupCliError{
			Code: "BACKUP_SYNC_FAILED",
			Err:  err,
		}
	}
	return nil
}
