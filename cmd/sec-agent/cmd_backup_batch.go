package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"
)

// Timing knobs. Variables so tests can shorten them.
var (
	batchRetryBaseDelay    = 5 * time.Second
	batchRetryMaxDelay     = 30 * time.Minute
	batchKeepaliveInterval = 10 * time.Minute
	batchExtendBelow       = 30 * time.Minute
	batchSessionTTL        = "8h"
	// batchRsyncRunner executes one rsync invocation. Replaced in tests.
	batchRsyncRunner = runBatchRsync
)

// batchPasswordEnv carries the SSH password to the askpass helper. It is set only in the rsync
// child environment, never on the command line or in a file.
const batchPasswordEnv = "SEC_BATCH_SSH_PASSWORD"

// batchAppleDoubleExclude keeps macOS AppleDouble "._*" metadata files off the backup target.
const batchAppleDoubleExclude = "._*"

// batchSSHAuth describes how rsync's ssh child authenticates. The zero value uses the system
// ssh configuration (keys, agent) unchanged.
type batchSSHAuth struct {
	AskPassPath string
	Password    string
}

func handleBackupBatch(profile string, args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printBackupBatchUsage()
		return
	}
	switch args[0] {
	case "define":
		handleBackupBatchDefine(profile, args[1:])
	case "list":
		handleBackupBatchList(profile)
	case "run":
		handleBackupBatchRun(profile, args[1:])
	default:
		printBackupBatchUsage()
		os.Exit(2)
	}
}

func printBackupBatchUsage() {
	fmt.Println("Usage:")
	fmt.Println("  sec backup batch define <name> --file <batch.json>")
	fmt.Println("  sec backup batch list")
	fmt.Println("  sec backup batch run <name> [--dry-run]")
}

// handleBackupBatchDefine stores a batch read from a local JSON file. Batch values are read from
// the file so personal paths never need to appear on the command line.
func handleBackupBatchDefine(profile string, args []string) {
	name, filePath := "", ""
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--file" && i+1 < len(args):
			filePath = args[i+1]
			i++
		case !strings.HasPrefix(args[i], "-") && name == "":
			name = args[i]
		default:
			fail("INVALID_ARGUMENT", fmt.Errorf("unexpected argument %q", args[i]), "usage: sec backup batch define <name> --file <batch.json>")
		}
	}
	if name == "" || filePath == "" {
		fail("INVALID_ARGUMENT", fmt.Errorf("batch name and --file are required"), "usage: sec backup batch define <name> --file <batch.json>")
	}
	jobName, err := store.NewBackupJobName(name)
	if err != nil {
		fail("INVALID_BACKUP_MANIFEST", err, "")
	}

	raw, err := os.ReadFile(filePath)
	if err != nil {
		fail("FILE_READ_FAILED", fmt.Errorf("failed to read batch file: %w", err), "")
	}
	var batch store.BackupBatch
	if err := json.Unmarshal(raw, &batch); err != nil {
		fail("INVALID_BACKUP_MANIFEST", fmt.Errorf("batch file is not valid JSON: %w", err), "")
	}
	batch.Name = jobName
	batch.ApplyDefaults()
	if err := batch.Validate(); err != nil {
		fail("INVALID_BACKUP_MANIFEST", err, "")
	}

	data, err := json.MarshalIndent(batch, "", "  ")
	if err != nil {
		fail("SERIALIZATION_FAILED", fmt.Errorf("failed to marshal backup batch: %w", err), "")
	}
	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:      daemon.IPCActionSet,
		Path:        string(batch.VaultKey()),
		Value:       string(data),
		Comment:     fmt.Sprintf("Backup batch (%s)", batch.Name),
		Description: fmt.Sprintf("Named backup batch %s", batch.Name),
		Metadata:    map[string]string{"secret_type": "backup_batch"},
	})
	if err != nil {
		failDaemonNotRunning(profile)
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("failed to save backup batch %q: %s", batch.Name, resp.Error), rem)
	}
	fmt.Printf("Stored backup batch %q with %d job(s) in profile %q\n", batch.Name, len(batch.Jobs), profile)
}

func handleBackupBatchList(profile string) {
	resp, err := queryDaemonRaw(profile, daemon.IPCRequest{
		Action:   daemon.IPCActionList,
		Path:     "backup-batch/",
		IsPrefix: true,
		NoTrace:  true,
	})
	if err != nil {
		failDaemonNotRunning(profile)
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("failed to list backup batches: %s", resp.Error), rem)
	}

	var names []string
	for _, line := range strings.Split(resp.Value, "\n") {
		key := strings.TrimSpace(line)
		if strings.HasPrefix(key, "backup-batch/") {
			names = append(names, strings.TrimPrefix(key, "backup-batch/"))
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		fmt.Println("No backup batches defined.")
		return
	}
	for _, n := range names {
		batch, err := loadBackupBatch(profile, n)
		if err != nil {
			fmt.Printf("%s\t(unreadable: %v)\n", n, err)
			continue
		}
		fmt.Printf("%s\t%d job(s)\n", batch.Name, len(batch.Jobs))
	}
}

func loadBackupBatch(profile, rawName string) (store.BackupBatch, error) {
	name, err := store.NewBackupJobName(rawName)
	if err != nil {
		return store.BackupBatch{}, err
	}
	key := store.BackupBatch{Name: name}.VaultKey()
	resp, err := queryDaemonRaw(profile, daemon.IPCRequest{Action: daemon.IPCActionGet, Path: string(key)})
	if err != nil {
		failDaemonNotRunning(profile)
	}
	if !resp.Success {
		if strings.Contains(strings.ToLower(resp.Error), "not found") {
			return store.BackupBatch{}, fmt.Errorf("%w: backup batch %q not found in profile %q", store.ErrSecretNotFound, name, profile)
		}
		return store.BackupBatch{}, fmt.Errorf("failed to load backup batch %q: %s", name, resp.Error)
	}
	var batch store.BackupBatch
	if err := json.Unmarshal([]byte(resp.Value), &batch); err != nil {
		return store.BackupBatch{}, fmt.Errorf("%w: failed to parse batch at %s: %v", store.ErrInvalidBackupManifest, key, err)
	}
	batch.Name = name
	batch.ApplyDefaults()
	if err := batch.Validate(); err != nil {
		return store.BackupBatch{}, err
	}
	return batch, nil
}

func handleBackupBatchRun(profile string, args []string) {
	name := ""
	dryRun := false
	for _, a := range args {
		switch {
		case a == "--dry-run" || a == "-n":
			dryRun = true
		case !strings.HasPrefix(a, "-") && name == "":
			name = a
		default:
			fail("INVALID_ARGUMENT", fmt.Errorf("unexpected argument %q", a), "usage: sec backup batch run <name> [--dry-run]")
		}
	}
	if name == "" {
		fail("INVALID_ARGUMENT", fmt.Errorf("batch name is required"), "usage: sec backup batch run <name> [--dry-run]")
	}

	// Refuse before any job starts. Batch runs never trigger a Touch ID prompt.
	requireUnlockedForBatch(profile)
	batch, err := loadBackupBatch(profile, name)
	if err != nil {
		fail("BACKUP_BATCH_LOAD_FAILED", err, "")
	}

	now := time.Now()
	if dryRun {
		for _, job := range batch.Jobs {
			fmt.Printf("# %s\nrsync %s\n", job.Name, strings.Join(buildBatchRsyncArgs(batch, job, now), " "))
		}
		return
	}

	auth, cleanupAuth := prepareBatchSSHAuth(profile, batch)
	failed := runBatchJobs(profile, batch, auth)
	cleanupAuth()
	printBatchSummary(batch, failed)
	if len(failed) > 0 {
		os.Exit(1)
	}
}

// runBatchJobs runs every job in order and returns the names of jobs that failed or were skipped.
func runBatchJobs(profile string, batch store.BackupBatch, auth batchSSHAuth) []string {
	lost, stopKeepalive := startBatchKeepalive(profile)
	defer stopKeepalive()

	var failed []string
	for i, job := range batch.Jobs {
		select {
		case <-lost:
			fmt.Fprintf(os.Stderr, "Session lost; stopping batch %q before job %q.\n", batch.Name, job.Name)
			failed = append(failed, job.Name+" (not run: session lost)")
			for _, rest := range batch.Jobs[i+1:] {
				failed = append(failed, rest.Name+" (not run: session lost)")
			}
			return failed
		default:
		}

		fmt.Printf("== [%d/%d] %s ==\n", i+1, len(batch.Jobs), job.Name)
		if err := runBatchJobWithRetry(batch, job, time.Now(), lost, auth); err != nil {
			fmt.Fprintf(os.Stderr, "Job %q failed: %v\n", job.Name, err)
			failed = append(failed, job.Name)
		}
	}
	return failed
}

// prepareBatchSSHAuth reads the batch's SSH password from the vault and writes an askpass helper
// that echoes it from the environment. The helper holds no secret. The returned cleanup removes
// the helper directory and must run before the process exits.
func prepareBatchSSHAuth(profile string, batch store.BackupBatch) (batchSSHAuth, func()) {
	noop := func() {}
	if batch.SSHPasswordKey == "" {
		return batchSSHAuth{}, noop
	}
	resp, err := queryDaemonRaw(profile, daemon.IPCRequest{
		Action:  daemon.IPCActionGet,
		Path:    batch.SSHPasswordKey,
		NoTrace: true,
	})
	if err != nil {
		failDaemonNotRunning(profile)
	}
	if !resp.Success || resp.Value == "" {
		fail("SSH_PASSWORD_NOT_FOUND", fmt.Errorf("ssh password %q not found or empty in profile %q", batch.SSHPasswordKey, profile), "store it with `sec set <path> --stdin` or fix ssh_password_key in the batch")
	}

	script, cleanup, err := writeBatchAskPass()
	if err != nil {
		fail("TEMP_FILE_FAILED", err, "")
	}
	return batchSSHAuth{AskPassPath: script, Password: resp.Value}, cleanup
}

// writeBatchAskPass writes the askpass helper into a new private directory and returns its path
// and a function that removes the directory.
func writeBatchAskPass() (string, func(), error) {
	dir, err := os.MkdirTemp("", "sec-batch-askpass-")
	if err != nil {
		return "", func() {}, fmt.Errorf("failed to create askpass directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	script := filepath.Join(dir, "askpass.sh")
	body := "#!/bin/sh\nprintf '%s\\n' \"$" + batchPasswordEnv + "\"\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("failed to write askpass helper: %w", err)
	}
	return script, cleanup, nil
}

func printBatchSummary(batch store.BackupBatch, failed []string) {
	if len(failed) == 0 {
		fmt.Printf("Batch %q completed: %d job(s) succeeded.\n", batch.Name, len(batch.Jobs))
		return
	}
	fmt.Fprintf(os.Stderr, "Batch %q finished with failures: %s\n", batch.Name, strings.Join(failed, ", "))
}

func requireUnlockedForBatch(profile string) {
	resp, err := queryDaemonRaw(profile, daemon.IPCRequest{Action: daemon.IPCActionStatus})
	if err != nil {
		failDaemonNotRunning(profile)
	}
	if !resp.Success || resp.StatusInfo == nil || !resp.StatusInfo.IsUnlocked {
		fail("VAULT_LOCKED", fmt.Errorf("profile %q is locked; the batch was not started", profile), "unlock the profile with `sec open` and run the batch again")
	}
}

// startBatchKeepalive sends a status request every batchKeepaliveInterval, extending the session
// when it is close to expiring. The returned channel closes if the session is lost.
func startBatchKeepalive(profile string) (<-chan struct{}, func()) {
	lost := make(chan struct{})
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(batchKeepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if err := keepBatchSessionAlive(profile); err != nil {
					fmt.Fprintf(os.Stderr, "Keepalive failed: %v\n", err)
					close(lost)
					return
				}
			}
		}
	}()
	return lost, func() { close(done) }
}

func keepBatchSessionAlive(profile string) error {
	resp, err := queryDaemonRaw(profile, daemon.IPCRequest{Action: daemon.IPCActionStatus})
	if err != nil {
		return err
	}
	if !resp.Success || resp.StatusInfo == nil || !resp.StatusInfo.IsUnlocked {
		return fmt.Errorf("session is no longer unlocked")
	}
	if time.Duration(resp.StatusInfo.RemainingSeconds)*time.Second >= batchExtendBelow {
		return nil
	}
	ext, err := queryDaemonRaw(profile, daemon.IPCRequest{Action: daemon.IPCActionExtend, TTL: batchSessionTTL})
	if err != nil {
		return err
	}
	if !ext.Success {
		return fmt.Errorf("could not extend session: %s", ext.Error)
	}
	return nil
}

// runBatchJobWithRetry runs a job up to the batch's max attempts. Waits double after each
// failure, starting at batchRetryBaseDelay and capped at batchRetryMaxDelay.
func runBatchJobWithRetry(batch store.BackupBatch, job store.BackupBatchJob, when time.Time, lost <-chan struct{}, auth batchSSHAuth) error {
	args := buildBatchRsyncArgs(batch, job, when)
	var lastErr error
	for attempt := 1; attempt <= batch.MaxAttempts; attempt++ {
		select {
		case <-lost:
			return fmt.Errorf("session lost before attempt %d", attempt)
		default:
		}
		lastErr = batchRsyncRunner(args, auth)
		if lastErr == nil {
			return nil
		}
		if attempt == batch.MaxAttempts {
			break
		}
		wait := batchBackoff(attempt)
		fmt.Fprintf(os.Stderr, "Attempt %d/%d failed; retrying in %s\n", attempt, batch.MaxAttempts, wait)
		time.Sleep(wait)
	}
	return fmt.Errorf("gave up after %d attempt(s): %w", batch.MaxAttempts, lastErr)
}

// batchBackoff returns the wait after the given failed attempt (1-based).
func batchBackoff(attempt int) time.Duration {
	wait := batchRetryBaseDelay
	for i := 1; i < attempt; i++ {
		wait *= 2
		if wait >= batchRetryMaxDelay {
			return batchRetryMaxDelay
		}
	}
	return wait
}

// buildBatchRsyncArgs returns the rsync argv for one job. The remote command is parsed by the
// remote shell, so the rsync-path log file and the remote destination are shell-quoted.
func buildBatchRsyncArgs(batch store.BackupBatch, job store.BackupBatchJob, when time.Time) []string {
	date := when.Format("2006-01-02")
	datetime := when.Format("2006-01-02_1504")
	expand := func(s string) string {
		return strings.NewReplacer("{date}", date, "{datetime}", datetime).Replace(s)
	}

	source := expandLocalBasePath(job.Source)
	if !strings.HasSuffix(source, "/") {
		source += "/"
	}
	excludes := job.Excludes
	if len(excludes) == 0 {
		excludes = store.DefaultBackupExcludes()
	}
	// AppleDouble metadata files are never copied to the backup target, whatever the job lists.
	if !slices.Contains(excludes, batchAppleDoubleExclude) {
		excludes = append(slices.Clone(excludes), batchAppleDoubleExclude)
	}

	args := []string{
		"-rtv", "--progress",
		"--partial-dir=" + store.DefaultPartialDir,
		"-b", "--backup-dir=" + expand(job.BackupDir),
		"--modify-window=" + fmt.Sprint(store.DefaultModifyWindow),
		"--rsync-path=" + store.DefaultRemoteRsyncBin + " --log-file=" + shellQuotePOSIX(expand(job.LogFile)),
	}
	if job.Sparse {
		args = append(args, "--sparse")
	}
	for _, ex := range excludes {
		args = append(args, "--exclude="+ex)
	}
	args = append(args, "-e", "ssh", source, batch.SSHTarget+":"+shellQuotePOSIX(job.Dest))
	return args
}

func runBatchRsync(args []string, auth batchSSHAuth) error {
	cmd := exec.Command("rsync", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if auth.Password != "" {
		cmd.Env = append(os.Environ(),
			"SSH_ASKPASS="+auth.AskPassPath,
			"SSH_ASKPASS_REQUIRE=force",
			batchPasswordEnv+"="+auth.Password,
		)
	}
	return cmd.Run()
}
