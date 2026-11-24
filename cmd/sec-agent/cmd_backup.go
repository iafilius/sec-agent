package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"secure_secrets/internal/config"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"

	"golang.org/x/crypto/ssh"
)

// sshStdioHandshake is the 1-line JSON control header sent by `sec ssh-stdio`
// over the ephemeral local Unix domain socket before raw rsync protocol streaming begins.
type sshStdioHandshake struct {
	Args []string `json:"args"`
}

// remoteCommandRunner abstracts executing the rewritten remote `rsync --server` command
// over an in-memory Go `ssh.Session` (or an in-process mock during unit tests).
type remoteCommandRunner func(remoteCmd string, stdin io.Reader, stdout, stderr io.Writer) error

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

// isStealthBackupSubcommand returns true when sub is a subcommand of the stealth
// multi-folder rsync backup subsystem (`sec backup <subcommand>`).
func isStealthBackupSubcommand(sub string) bool {
	switch sub {
	case "init", "add-folder", "remove-folder", "show", "jobs", "run", "batch", "ssh-stdio":
		return true
	default:
		return false
	}
}

// shellQuotePOSIX wraps a string in POSIX single quotes, escaping any internal single quotes.
func shellQuotePOSIX(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func printStealthBackupUsage() {
	fmt.Println("Usage:")
	fmt.Println("  sec backup init <name> [--file <manifest.json> | --stdin] --target <ssh-target-or-user@host> --remote-base <path> [--local-base <path>] [--max-attempts <n>] [--sparse] [--ssh-key-secret <vault-key>] [--ssh-password-key <vault-key>] [--port <port>] [--remote-rsync <path>] [--modify-window <sec>] [--partial-dir <dir>] [--exclude <pattern>...] [--folder <folder>...]")
	fmt.Println("  sec backup init <name> [--file <manifest.json> | --stdin] --target <ssh-target-or-user@host> --remote-base <path> [--local-base <path>] [--max-attempts <n>] [--timeout <sec>] [--no-progress-timeout <dur>] [--sparse] [--ssh-key-secret <vault-key>] [--ssh-password-key <vault-key>] [--port <port>] [--remote-rsync <path>] [--modify-window <sec>] [--partial-dir <dir>] [--exclude <pattern>...] [--folder <folder>...]")
	fmt.Println("  sec backup add-folder <name> <folder> [--dest <remote-folder-name>] [--history-prefix <prefix>] [--slug <slug>] [--sparse] [--backup-dir <path>] [--log-file <path>] [--exclude <pattern>...]")
	fmt.Println("  sec backup remove-folder <name> <folder>")
	fmt.Println("  sec backup show <name>")
	fmt.Println("  sec backup jobs")
	fmt.Println("  sec backup run <name> [<folder-filter>] [--max-attempts <n>] [--dry-run] [--verbose] [--log-file <path>] [--no-trace] [--trace] [--tofu] [--insecure]")
	fmt.Println("  sec backup run <name> [<folder-filter>] [--max-attempts <n>] [--timeout <sec>] [--no-progress-timeout <dur>] [--dry-run] [--verbose] [--log-file <path>] [--no-trace] [--trace] [--tofu] [--insecure]")
	fmt.Println("  sec backup batch <define|list|show|run> [<name>] [--file <manifest.json>]")
	fmt.Println("  sec backup <export|import|list> [<file.kdbx>]")
}

func handleStealthBackup(profile string, args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printStealthBackupUsage()
		return
	}

	// If leading flags precede the subcommand (e.g. "sec backup --dry-run run home-nas"),
	// move the subcommand token to position 0 while preserving all flags for the subcommand parser.
	if !isStealthBackupSubcommand(args[0]) && args[0] != "list" {
		for i, tok := range args {
			if isStealthBackupSubcommand(tok) {
				reordered := make([]string, 0, len(args))
				reordered = append(reordered, tok)
				reordered = append(reordered, args[:i]...)
				reordered = append(reordered, args[i+1:]...)
				args = reordered
				break
			}
		}
	}

	switch args[0] {
	case "init":
		handleStealthBackupInit(profile, args[1:])
	case "add-folder":
		handleStealthBackupAddFolder(profile, args[1:])
	case "remove-folder":
		handleStealthBackupRemoveFolder(profile, args[1:])
	case "show":
		handleStealthBackupShow(profile, args[1:])
	case "jobs", "list":
		handleStealthBackupJobs(profile, args[1:])
	case "run":
		handleStealthBackupRun(profile, args[1:])
	case "batch":
		handleStealthBackupBatch(profile, args[1:])
	case "ssh-stdio":
		os.Exit(runInternalSSHStdio(args[1:]))
	default:
		printStealthBackupUsage()
		os.Exit(2)
	}
}

func expandLocalBasePath(p string) string {
	trimmed := strings.TrimSpace(p)
	if trimmed == "" {
		trimmed = "~"
	}
	if trimmed == "~" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return home
		}
		return trimmed
	}
	if strings.HasPrefix(trimmed, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, strings.TrimPrefix(trimmed, "~/"))
		}
	}
	return filepath.Clean(trimmed)
}

func saveStealthBackupManifest(profile string, manifest store.BackupManifest, noTrace bool) {
	manifest.ApplyDefaults()
	if err := manifest.Validate(); err != nil {
		fail("INVALID_BACKUP_MANIFEST", err, "")
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fail("SERIALIZATION_FAILED", fmt.Errorf("failed to marshal backup manifest: %w", err), "")
	}

	req := daemon.IPCRequest{
		Action:      daemon.IPCActionSet,
		Path:        string(manifest.Name.VaultKey()),
		Value:       string(data),
		Comment:     fmt.Sprintf("Stealth Backup Manifest (%s)", manifest.Name),
		Description: fmt.Sprintf("Multi-folder stealth rsync backup manifest for %s", manifest.Name),
		Metadata: map[string]string{
			"secret_type": "backup_manifest",
		},
		NoTrace: noTrace,
	}

	resp, err := queryDaemon(profile, req)
	if err != nil {
		failDaemonNotRunning(profile)
	}
	if !resp.Success {
		code, rem := mapDaemonError(resp.Error)
		fail(code, fmt.Errorf("failed to save backup manifest %q: %s", manifest.Name, resp.Error), rem)
	}
}

func loadStealthBackupManifest(profile string, rawName string, noTrace bool) (store.BackupManifest, error) {
	jobName, err := store.NewBackupJobName(rawName)
	if err != nil {
		return store.BackupManifest{}, err
	}

	vaultPath := string(jobName.VaultKey())
	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action:  daemon.IPCActionGet,
		Path:    vaultPath,
		NoTrace: noTrace,
	})
	if err != nil {
		failDaemonNotRunning(profile)
	}
	if !resp.Success && strings.Contains(strings.ToLower(resp.Error), "not found") {
		legacyBatchPath := "backup-batch/" + jobName.String()
		if altResp, altErr := queryDaemon(profile, daemon.IPCRequest{
			Action:  daemon.IPCActionGet,
			Path:    legacyBatchPath,
			NoTrace: noTrace,
		}); altErr == nil && altResp != nil && altResp.Success {
			resp = altResp
			vaultPath = legacyBatchPath
		}
	}
	if !resp.Success {
		if strings.Contains(strings.ToLower(resp.Error), "not found") {
			return store.BackupManifest{}, fmt.Errorf("%w: backup job %q (%s) not found in profile %q", store.ErrSecretNotFound, jobName, jobName.VaultKey(), profile)
		}
		return store.BackupManifest{}, fmt.Errorf("failed to load backup job %q: %s", jobName, resp.Error)
	}

	var manifest store.BackupManifest
	if err := json.Unmarshal([]byte(resp.Value), &manifest); err != nil {
		return store.BackupManifest{}, fmt.Errorf("%w: failed to parse manifest JSON at %s: %v", store.ErrInvalidBackupManifest, vaultPath, err)
	}
	if manifest.Name == "" {
		manifest.Name = jobName
	}
	manifest.ApplyDefaults()

	// If this manifest was loaded from backup/<name> (e.g. imported prior to v2.19.3 before
	// rsync_timeout / ssh_options normalization existed), backfill any zero timeout or
	// server_alive_* values from a companion backup-batch/<name> entry if present.
	if vaultPath == string(jobName.VaultKey()) {
		legacyBatchPath := "backup-batch/" + jobName.String()
		if altResp, altErr := queryDaemon(profile, daemon.IPCRequest{
			Action:  daemon.IPCActionGet,
			Path:    legacyBatchPath,
			NoTrace: noTrace,
		}); altErr == nil && altResp != nil && altResp.Success && altResp.Value != "" {
			var legacyManifest store.BackupManifest
			if json.Unmarshal([]byte(altResp.Value), &legacyManifest) == nil {
				legacyManifest.ApplyDefaults()
				if manifest.Timeout == 0 && legacyManifest.Timeout > 0 {
					manifest.Timeout = legacyManifest.Timeout
				}
				if manifest.ServerAliveInterval == 0 && legacyManifest.ServerAliveInterval > 0 {
					manifest.ServerAliveInterval = legacyManifest.ServerAliveInterval
				}
				if manifest.ServerAliveCountMax == 0 && legacyManifest.ServerAliveCountMax > 0 {
					manifest.ServerAliveCountMax = legacyManifest.ServerAliveCountMax
				}
				for i := range manifest.Folders {
					mf := &manifest.Folders[i]
					for _, lf := range legacyManifest.Folders {
						if (mf.Name != "" && mf.Name == lf.Name) ||
							mf.Source == lf.Source ||
							mf.EffectiveDestName() == lf.EffectiveDestName() {
							if mf.Timeout == 0 && lf.Timeout > 0 {
								mf.Timeout = lf.Timeout
							}
							if mf.ServerAliveInterval == 0 && lf.ServerAliveInterval > 0 {
								mf.ServerAliveInterval = lf.ServerAliveInterval
							}
							if mf.ServerAliveCountMax == 0 && lf.ServerAliveCountMax > 0 {
								mf.ServerAliveCountMax = lf.ServerAliveCountMax
							}
							break
						}
					}
				}
			}
		}
	}

	if err := manifest.Validate(); err != nil {
		return store.BackupManifest{}, err
	}
	return manifest, nil
}

func handleStealthBackupInit(profile string, args []string) {
	var rawName, target, localBase, remoteBase, sshKeySecret, sshPasswordKey, remoteRsync, partialDir, filePath, noProgressTimeout string
	var port, modifyWindow, maxAttempts, timeoutSec, serverAliveInterval, serverAliveCountMax int
	var fromStdin, sparse, noProgressTimeoutSet bool
	var excludes []string
	var folders []store.BackupFolderSpec

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--help" || a == "-h" {
			printStealthBackupUsage()
			return
		}
		switch {
		case (a == "--file" || a == "-f") && i+1 < len(args):
			filePath = args[i+1]
			i++
		case strings.HasPrefix(a, "--file="):
			filePath = strings.TrimPrefix(a, "--file=")
		case a == "--stdin":
			fromStdin = true
		case a == "--sparse":
			sparse = true
		case a == "--max-attempts" && i+1 < len(args):
			ma, err := strconv.Atoi(args[i+1])
			if err != nil || ma <= 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid max-attempts %q", args[i+1]), "")
			}
			maxAttempts = ma
			i++
		case strings.HasPrefix(a, "--max-attempts="):
			maStr := strings.TrimPrefix(a, "--max-attempts=")
			ma, err := strconv.Atoi(maStr)
			if err != nil || ma <= 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid max-attempts %q", maStr), "")
			}
			maxAttempts = ma
		case a == "--timeout" && i+1 < len(args):
			to, err := strconv.Atoi(args[i+1])
			if err != nil || to < 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid timeout %q", args[i+1]), "")
			}
			timeoutSec = to
			i++
		case strings.HasPrefix(a, "--timeout="):
			toStr := strings.TrimPrefix(a, "--timeout=")
			to, err := strconv.Atoi(toStr)
			if err != nil || to < 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid timeout %q", toStr), "")
			}
			timeoutSec = to
		case a == "--no-progress-timeout" && i+1 < len(args):
			if _, err := store.ParseNoProgressTimeout(args[i+1]); err != nil {
				fail("INVALID_ARGUMENTS", err, "")
			}
			noProgressTimeout = strings.TrimSpace(args[i+1])
			noProgressTimeoutSet = true
			i++
		case strings.HasPrefix(a, "--no-progress-timeout="):
			npStr := strings.TrimPrefix(a, "--no-progress-timeout=")
			if _, err := store.ParseNoProgressTimeout(npStr); err != nil {
				fail("INVALID_ARGUMENTS", err, "")
			}
			noProgressTimeout = strings.TrimSpace(npStr)
			noProgressTimeoutSet = true
		case a == "--server-alive-interval" && i+1 < len(args):
			sai, err := strconv.Atoi(args[i+1])
			if err != nil || sai < 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid server-alive-interval %q", args[i+1]), "")
			}
			serverAliveInterval = sai
			i++
		case strings.HasPrefix(a, "--server-alive-interval="):
			saiStr := strings.TrimPrefix(a, "--server-alive-interval=")
			sai, err := strconv.Atoi(saiStr)
			if err != nil || sai < 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid server-alive-interval %q", saiStr), "")
			}
			serverAliveInterval = sai
		case a == "--server-alive-count-max" && i+1 < len(args):
			sac, err := strconv.Atoi(args[i+1])
			if err != nil || sac < 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid server-alive-count-max %q", args[i+1]), "")
			}
			serverAliveCountMax = sac
			i++
		case strings.HasPrefix(a, "--server-alive-count-max="):
			sacStr := strings.TrimPrefix(a, "--server-alive-count-max=")
			sac, err := strconv.Atoi(sacStr)
			if err != nil || sac < 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid server-alive-count-max %q", sacStr), "")
			}
			serverAliveCountMax = sac
		case a == "--target" && i+1 < len(args):
			target = args[i+1]
			i++
		case strings.HasPrefix(a, "--target="):
			target = strings.TrimPrefix(a, "--target=")
		case a == "--local-base" && i+1 < len(args):
			localBase = args[i+1]
			i++
		case strings.HasPrefix(a, "--local-base="):
			localBase = strings.TrimPrefix(a, "--local-base=")
		case a == "--remote-base" && i+1 < len(args):
			remoteBase = args[i+1]
			i++
		case strings.HasPrefix(a, "--remote-base="):
			remoteBase = strings.TrimPrefix(a, "--remote-base=")
		case (a == "--ssh-key-secret" || a == "--key-secret") && i+1 < len(args):
			sshKeySecret = args[i+1]
			i++
		case strings.HasPrefix(a, "--ssh-key-secret="):
			sshKeySecret = strings.TrimPrefix(a, "--ssh-key-secret=")
		case strings.HasPrefix(a, "--key-secret="):
			sshKeySecret = strings.TrimPrefix(a, "--key-secret=")
		case a == "--ssh-password-key" && i+1 < len(args):
			sshPasswordKey = args[i+1]
			i++
		case strings.HasPrefix(a, "--ssh-password-key="):
			sshPasswordKey = strings.TrimPrefix(a, "--ssh-password-key=")
		case (a == "--port" || a == "-p") && i+1 < len(args):
			p, err := strconv.Atoi(args[i+1])
			if err != nil || p <= 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid SSH port %q", args[i+1]), "")
			}
			port = p
			i++
		case strings.HasPrefix(a, "--port="):
			pStr := strings.TrimPrefix(a, "--port=")
			p, err := strconv.Atoi(pStr)
			if err != nil || p <= 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid SSH port %q", pStr), "")
			}
			port = p
		case a == "--remote-rsync" && i+1 < len(args):
			remoteRsync = args[i+1]
			i++
		case strings.HasPrefix(a, "--remote-rsync="):
			remoteRsync = strings.TrimPrefix(a, "--remote-rsync=")
		case a == "--modify-window" && i+1 < len(args):
			mw, err := strconv.Atoi(args[i+1])
			if err != nil || mw < 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid modify-window %q", args[i+1]), "")
			}
			modifyWindow = mw
			i++
		case strings.HasPrefix(a, "--modify-window="):
			mwStr := strings.TrimPrefix(a, "--modify-window=")
			mw, err := strconv.Atoi(mwStr)
			if err != nil || mw < 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid modify-window %q", mwStr), "")
			}
			modifyWindow = mw
		case a == "--partial-dir" && i+1 < len(args):
			partialDir = args[i+1]
			i++
		case strings.HasPrefix(a, "--partial-dir="):
			partialDir = strings.TrimPrefix(a, "--partial-dir=")
		case a == "--exclude" && i+1 < len(args):
			excludes = append(excludes, args[i+1])
			i++
		case strings.HasPrefix(a, "--exclude="):
			excludes = append(excludes, strings.TrimPrefix(a, "--exclude="))
		case a == "--folder" && i+1 < len(args):
			folders = append(folders, store.BackupFolderSpec{Source: args[i+1], Sparse: sparse})
			i++
		case strings.HasPrefix(a, "--folder="):
			folders = append(folders, store.BackupFolderSpec{Source: strings.TrimPrefix(a, "--folder="), Sparse: sparse})
		case !strings.HasPrefix(a, "-") && rawName == "":
			rawName = a
		}
	}

	var manifest store.BackupManifest
	if filePath != "" || fromStdin {
		var rawBytes []byte
		var rErr error
		if fromStdin || filePath == "-" {
			rawBytes, rErr = io.ReadAll(os.Stdin)
		} else {
			// #nosec G304 G703
			rawBytes, rErr = os.ReadFile(expandLocalBasePath(filePath))
		}
		if rErr != nil {
			fail("FILE_READ_FAILED", fmt.Errorf("failed to read backup manifest input: %w", rErr), "")
		}
		if err := json.Unmarshal(rawBytes, &manifest); err != nil {
			fail("INVALID_BACKUP_MANIFEST", fmt.Errorf("failed to parse backup manifest JSON: %w", err), "")
		}
		if rawName != "" {
			jobName, err := store.NewBackupJobName(rawName)
			if err != nil {
				fail("INVALID_ARGUMENTS", err, "")
			}
			manifest.Name = jobName
		}
		if target != "" {
			manifest.SSHTarget = strings.TrimSpace(target)
		}
		if localBase != "" {
			manifest.LocalBase = expandLocalBasePath(localBase)
		}
		if remoteBase != "" {
			manifest.RemoteBase = strings.TrimSpace(remoteBase)
		}
		if sshKeySecret != "" {
			manifest.SSHKeySecret = strings.TrimSpace(sshKeySecret)
		}
		if sshPasswordKey != "" {
			manifest.SSHPasswordKey = strings.TrimSpace(sshPasswordKey)
		}
		if port > 0 {
			manifest.SSHPort = port
		}
		if remoteRsync != "" {
			manifest.RemoteRsyncBin = strings.TrimSpace(remoteRsync)
		}
		if modifyWindow > 0 {
			manifest.ModifyWindow = modifyWindow
		}
		if partialDir != "" {
			manifest.PartialDir = strings.TrimSpace(partialDir)
		}
		if maxAttempts > 0 {
			manifest.MaxAttempts = maxAttempts
		}
		if timeoutSec > 0 {
			manifest.Timeout = timeoutSec
		}
		if noProgressTimeoutSet {
			manifest.NoProgressTimeout = noProgressTimeout
		}
		if serverAliveInterval > 0 {
			manifest.ServerAliveInterval = serverAliveInterval
		}
		if serverAliveCountMax > 0 {
			manifest.ServerAliveCountMax = serverAliveCountMax
		}
		if len(excludes) > 0 {
			manifest.Excludes = append(manifest.Excludes, excludes...)
		}
		if len(folders) > 0 {
			manifest.Folders = append(manifest.Folders, folders...)
		}
		manifest.ApplyDefaults()
		if sparse {
			for idx := range manifest.Folders {
				manifest.Folders[idx].Sparse = true
			}
		}
		if manifest.LocalBase != "" {
			manifest.LocalBase = expandLocalBasePath(manifest.LocalBase)
		}
	} else {
		jobName, err := store.NewBackupJobName(rawName)
		if err != nil {
			fail("INVALID_ARGUMENTS", err, "Usage: sec backup init <name> --target <ssh-target-or-user@host> --remote-base <path> [--local-base <path>]")
		}
		if strings.TrimSpace(target) == "" {
			fail("MISSING_ARGUMENT", fmt.Errorf("--target is required for 'sec backup init'"), "Pass --target <ssh-target-or-user@host>")
		}
		if strings.TrimSpace(remoteBase) == "" {
			fail("MISSING_ARGUMENT", fmt.Errorf("--remote-base is required for 'sec backup init'"), "Pass --remote-base <remote-path>")
		}

		expandedLocalBase := expandLocalBasePath(localBase)
		if sparse {
			for idx := range folders {
				folders[idx].Sparse = true
			}
		}

		manifest = store.BackupManifest{
			Name:                jobName,
			SSHTarget:           strings.TrimSpace(target),
			SSHKeySecret:        strings.TrimSpace(sshKeySecret),
			SSHPasswordKey:      strings.TrimSpace(sshPasswordKey),
			SSHPort:             port,
			LocalBase:           expandedLocalBase,
			RemoteBase:          strings.TrimSpace(remoteBase),
			RemoteRsyncBin:      strings.TrimSpace(remoteRsync),
			ModifyWindow:        modifyWindow,
			PartialDir:          strings.TrimSpace(partialDir),
			MaxAttempts:         maxAttempts,
			Timeout:             timeoutSec,
			NoProgressTimeout:   noProgressTimeout,
			ServerAliveInterval: serverAliveInterval,
			ServerAliveCountMax: serverAliveCountMax,
			Excludes:            excludes,
			Folders:             folders,
		}
		manifest.ApplyDefaults()
	}

	if err := manifest.Validate(); err != nil {
		fail("INVALID_BACKUP_MANIFEST", err, "")
	}

	saveStealthBackupManifest(profile, manifest, true)
	fmt.Printf("[✓] Initialized stealth backup manifest %q at vault path %s (profile %q)\n", manifest.Name, manifest.Name.VaultKey(), profile)
	fmt.Printf("    SSH Target:  %s\n", manifest.SSHTarget)
	fmt.Printf("    Local Base:  %s\n", manifest.LocalBase)
	fmt.Printf("    Remote Base: %s\n", manifest.RemoteBase)
	if len(manifest.Folders) > 0 {
		fmt.Printf("    Folders:     %d configured\n", len(manifest.Folders))
	} else {
		fmt.Printf("    Next step:   sec backup add-folder %s \"<Folder Name>\"\n", manifest.Name)
	}
}

func handleStealthBackupBatch(profile string, args []string) {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		fmt.Println("Usage:")
		fmt.Println("  sec backup batch define <name> --file <manifest.json> [--stdin]")
		fmt.Println("  sec backup batch list")
		fmt.Println("  sec backup batch show <name>")
		fmt.Println("  sec backup batch run <name> [<folder-filter>] [--max-attempts <n>] [--dry-run] [--verbose] [--log-file <path>] [--tofu]")
		fmt.Println("  sec backup batch run <name> [<folder-filter>] [--max-attempts <n>] [--timeout <sec>] [--no-progress-timeout <dur>] [--dry-run] [--verbose] [--log-file <path>] [--tofu]")
		return
	}
	switch args[0] {
	case "define", "init":
		handleStealthBackupInit(profile, args[1:])
	case "list", "jobs":
		handleStealthBackupJobs(profile, args[1:])
	case "show":
		handleStealthBackupShow(profile, args[1:])
	case "run":
		handleStealthBackupRun(profile, args[1:])
	default:
		printStealthBackupUsage()
		os.Exit(2)
	}
}

func handleStealthBackupAddFolder(profile string, args []string) {
	var rawName, folderSrc, dest, historyPrefix, slug, backupDir, logFile string
	var timeoutSec, serverAliveInterval, serverAliveCountMax int
	var sparse bool
	var excludes []string

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--help" || a == "-h" {
			fmt.Println("Usage: sec backup add-folder <name> <folder> [--dest <remote-folder-name>] [--history-prefix <prefix>] [--slug <slug>] [--sparse] [--timeout <sec>] [--server-alive-interval <sec>] [--server-alive-count-max <count>] [--backup-dir <path>] [--log-file <path>] [--exclude <pattern>...]")
			return
		}
		switch {
		case a == "--dest" && i+1 < len(args):
			dest = args[i+1]
			i++
		case strings.HasPrefix(a, "--dest="):
			dest = strings.TrimPrefix(a, "--dest=")
		case a == "--history-prefix" && i+1 < len(args):
			historyPrefix = args[i+1]
			i++
		case strings.HasPrefix(a, "--history-prefix="):
			historyPrefix = strings.TrimPrefix(a, "--history-prefix=")
		case a == "--slug" && i+1 < len(args):
			slug = args[i+1]
			i++
		case strings.HasPrefix(a, "--slug="):
			slug = strings.TrimPrefix(a, "--slug=")
		case a == "--sparse":
			sparse = true
		case a == "--timeout" && i+1 < len(args):
			to, err := strconv.Atoi(args[i+1])
			if err != nil || to < 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid timeout %q", args[i+1]), "")
			}
			timeoutSec = to
			i++
		case strings.HasPrefix(a, "--timeout="):
			toStr := strings.TrimPrefix(a, "--timeout=")
			to, err := strconv.Atoi(toStr)
			if err != nil || to < 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid timeout %q", toStr), "")
			}
			timeoutSec = to
		case a == "--server-alive-interval" && i+1 < len(args):
			sai, err := strconv.Atoi(args[i+1])
			if err != nil || sai < 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid server-alive-interval %q", args[i+1]), "")
			}
			serverAliveInterval = sai
			i++
		case strings.HasPrefix(a, "--server-alive-interval="):
			saiStr := strings.TrimPrefix(a, "--server-alive-interval=")
			sai, err := strconv.Atoi(saiStr)
			if err != nil || sai < 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid server-alive-interval %q", saiStr), "")
			}
			serverAliveInterval = sai
		case a == "--server-alive-count-max" && i+1 < len(args):
			sac, err := strconv.Atoi(args[i+1])
			if err != nil || sac < 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid server-alive-count-max %q", args[i+1]), "")
			}
			serverAliveCountMax = sac
			i++
		case strings.HasPrefix(a, "--server-alive-count-max="):
			sacStr := strings.TrimPrefix(a, "--server-alive-count-max=")
			sac, err := strconv.Atoi(sacStr)
			if err != nil || sac < 0 {
				fail("INVALID_ARGUMENTS", fmt.Errorf("invalid server-alive-count-max %q", sacStr), "")
			}
			serverAliveCountMax = sac
		case a == "--backup-dir" && i+1 < len(args):
			backupDir = args[i+1]
			i++
		case strings.HasPrefix(a, "--backup-dir="):
			backupDir = strings.TrimPrefix(a, "--backup-dir=")
		case a == "--log-file" && i+1 < len(args):
			logFile = args[i+1]
			i++
		case strings.HasPrefix(a, "--log-file="):
			logFile = strings.TrimPrefix(a, "--log-file=")
		case a == "--exclude" && i+1 < len(args):
			excludes = append(excludes, args[i+1])
			i++
		case strings.HasPrefix(a, "--exclude="):
			excludes = append(excludes, strings.TrimPrefix(a, "--exclude="))
		case !strings.HasPrefix(a, "-"):
			if rawName == "" {
				rawName = a
			} else if folderSrc == "" {
				folderSrc = a
			}
		}
	}

	if rawName == "" || folderSrc == "" {
		fail("MISSING_ARGUMENT", fmt.Errorf("both <name> and <folder> are required"), "Usage: sec backup add-folder <name> <folder> [--dest <remote-folder-name>] [--history-prefix <prefix>] [--slug <slug>]")
	}

	manifest, err := loadStealthBackupManifest(profile, rawName, true)
	if err != nil {
		code := "BACKUP_MANIFEST_ERROR"
		if errors.Is(err, store.ErrSecretNotFound) {
			code = "SECRET_NOT_FOUND"
		}
		fail(code, err, fmt.Sprintf("Run 'sec backup init %s --target <target> --remote-base <path>' first.", rawName))
	}

	spec := store.BackupFolderSpec{
		Source:              folderSrc,
		Dest:                strings.TrimSpace(dest),
		HistoryPrefix:       strings.TrimSpace(historyPrefix),
		Slug:                strings.TrimSpace(slug),
		Sparse:              sparse,
		BackupDir:           strings.TrimSpace(backupDir),
		LogFile:             strings.TrimSpace(logFile),
		Timeout:             timeoutSec,
		ServerAliveInterval: serverAliveInterval,
		ServerAliveCountMax: serverAliveCountMax,
		Excludes:            excludes,
	}
	if err := spec.Validate(); err != nil {
		fail("INVALID_ARGUMENTS", err, "")
	}

	updated := false
	for i, existing := range manifest.Folders {
		if existing.Source == spec.Source || existing.EffectiveDestName() == spec.EffectiveDestName() {
			manifest.Folders[i] = spec
			updated = true
			break
		}
	}
	if !updated {
		manifest.Folders = append(manifest.Folders, spec)
	}

	saveStealthBackupManifest(profile, manifest, true)

	now := time.Now()
	dateStr := now.Format("2006-01-02")
	datetimeStr := now.Format("2006-01-02_1504")

	actionVerb := "Added"
	if updated {
		actionVerb = "Updated"
	}
	fmt.Printf("[✓] %s folder %q in backup job %q (%s)\n", actionVerb, spec.Source, manifest.Name, manifest.Name.VaultKey())
	fmt.Printf("    Local Source: %s\n", spec.ResolveLocalDir(manifest.LocalBase))
	fmt.Printf("    Destination:  %s\n", spec.DeriveRemoteDest(manifest.RemoteBase))
	fmt.Printf("    History Dir:  %s\n", spec.DeriveHistoryDir(manifest.RemoteBase, dateStr))
	fmt.Printf("    Remote Log:   %s\n", spec.DeriveRemoteLogPath(manifest.RemoteBase, datetimeStr))
}

func handleStealthBackupRemoveFolder(profile string, args []string) {
	var rawName, folderTarget string
	for _, a := range args {
		if a == "--help" || a == "-h" {
			fmt.Println("Usage: sec backup remove-folder <name> <folder>")
			return
		}
		if !strings.HasPrefix(a, "-") {
			if rawName == "" {
				rawName = a
			} else if folderTarget == "" {
				folderTarget = a
			}
		}
	}

	if rawName == "" || folderTarget == "" {
		fail("MISSING_ARGUMENT", fmt.Errorf("both <name> and <folder> are required"), "Usage: sec backup remove-folder <name> <folder>")
	}

	manifest, err := loadStealthBackupManifest(profile, rawName, true)
	if err != nil {
		code := "BACKUP_MANIFEST_ERROR"
		if errors.Is(err, store.ErrSecretNotFound) {
			code = "SECRET_NOT_FOUND"
		}
		fail(code, err, "")
	}

	var kept []store.BackupFolderSpec
	removed := false
	for _, f := range manifest.Folders {
		if f.Source == folderTarget || f.Dest == folderTarget || f.EffectiveDestName() == folderTarget || f.DeriveSlug() == folderTarget {
			removed = true
			continue
		}
		kept = append(kept, f)
	}

	if !removed {
		fail("FOLDER_NOT_FOUND", fmt.Errorf("folder %q not found in backup job %q", folderTarget, manifest.Name), "")
	}

	manifest.Folders = kept
	saveStealthBackupManifest(profile, manifest, true)
	fmt.Printf("[✓] Removed folder %q from backup job %q (%d folders remaining)\n", folderTarget, manifest.Name, len(manifest.Folders))
}

func handleStealthBackupShow(profile string, args []string) {
	var rawName string
	jsonOutput := jsonErrors
	for _, a := range args {
		if a == "--help" || a == "-h" {
			fmt.Println("Usage: sec backup show <name> [--json]")
			return
		}
		if a == "--json" {
			jsonOutput = true
			continue
		}
		if !strings.HasPrefix(a, "-") && rawName == "" {
			rawName = a
		}
	}
	if rawName == "" {
		fail("MISSING_ARGUMENT", fmt.Errorf("backup job <name> is required"), "Usage: sec backup show <name> [--json]")
	}

	manifest, err := loadStealthBackupManifest(profile, rawName, true)
	if err != nil {
		code := "BACKUP_MANIFEST_ERROR"
		if errors.Is(err, store.ErrSecretNotFound) {
			code = "SECRET_NOT_FOUND"
		}
		fail(code, err, "")
	}

	var targetInterval, targetCountMax int
	if sshCfg, sErr := resolveStealthSSHTarget(profile, manifest, true); sErr == nil && sshCfg != nil {
		targetInterval = sshCfg.ServerAliveInterval
		targetCountMax = sshCfg.ServerAliveCountMax
	}

	if jsonOutput {
		outManifest := manifest
		if outManifest.ServerAliveInterval == 0 && targetInterval > 0 {
			outManifest.ServerAliveInterval = targetInterval
		}
		if outManifest.ServerAliveCountMax == 0 && targetCountMax > 0 {
			outManifest.ServerAliveCountMax = targetCountMax
		}
		data, jErr := json.MarshalIndent(outManifest, "", "  ")
		if jErr != nil {
			fail("SERIALIZATION_FAILED", jErr, "")
		}
		fmt.Println(string(data))
		return
	}

	now := time.Now()
	dateStr := now.Format("2006-01-02")
	datetimeStr := now.Format("2006-01-02_1504")

	fmt.Printf("Stealth Backup Job: %s (%s)\n", manifest.Name, manifest.Name.VaultKey())
	fmt.Printf("  SSH Target:     %s\n", manifest.SSHTarget)
	if manifest.SSHPort > 0 {
		fmt.Printf("  SSH Port:       %d\n", manifest.SSHPort)
	}
	if manifest.SSHKeySecret != "" {
		fmt.Printf("  SSH Key Secret: %s\n", manifest.SSHKeySecret)
	}
	if manifest.SSHPasswordKey != "" {
		fmt.Printf("  Password Key:   %s\n", manifest.SSHPasswordKey)
	}
	fmt.Printf("  Local Base:     %s\n", manifest.LocalBase)
	fmt.Printf("  Remote Base:    %s\n", manifest.RemoteBase)
	fmt.Printf("  Remote Rsync:   %s\n", manifest.RemoteRsyncBin)
	fmt.Printf("  Modify Window:  %ds\n", manifest.ModifyWindow)
	fmt.Printf("  Partial Dir:    %s\n", manifest.PartialDir)
	if manifest.Timeout > 0 {
		fmt.Printf("  Rsync Timeout:  %ds\n", manifest.Timeout)
	}
	if npDur, npErr := manifest.EffectiveNoProgressTimeout(); npErr == nil && npDur > 0 {
		fmt.Printf("  No-Progress:    %s\n", npDur)
	} else {
		fmt.Printf("  No-Progress:    (disabled)\n")
	}
	jobSAI := manifest.ServerAliveInterval
	if jobSAI == 0 {
		jobSAI = targetInterval
	}
	jobSAC := manifest.ServerAliveCountMax
	if jobSAC == 0 {
		jobSAC = targetCountMax
	}
	if jobSAI > 0 {
		fmt.Printf("  SSH Keepalive:  interval=%ds count_max=%d\n", jobSAI, jobSAC)
	}
	fmt.Printf("  Excludes:       %s\n", strings.Join(manifest.Excludes, ", "))
	fmt.Printf("  Folders (%d):\n", len(manifest.Folders))
	if len(manifest.Folders) == 0 {
		fmt.Println("    (none configured — add with 'sec backup add-folder <name> <folder>')")
		return
	}
	expandedLocalBase := expandLocalBasePath(manifest.LocalBase)
	for i, f := range manifest.Folders {
		fmt.Printf("    [%d] %s (slug: %s, prefix: %s)\n", i+1, f.Source, f.DeriveSlug(), f.DeriveHistoryPrefix())
		fmt.Printf("        Local Path:  %s\n", f.ResolveLocalDir(expandedLocalBase))
		fmt.Printf("        Destination: %s\n", f.DeriveRemoteDest(manifest.RemoteBase))
		fmt.Printf("        History Dir: %s\n", f.DeriveHistoryDir(manifest.RemoteBase, dateStr))
		fmt.Printf("        Remote Log:  %s\n", f.DeriveRemoteLogPath(manifest.RemoteBase, datetimeStr))
		if f.Sparse {
			fmt.Printf("        Sparse:      true\n")
		}
		if effTo := f.EffectiveTimeout(manifest.Timeout); effTo > 0 {
			fmt.Printf("        Timeout:     %ds\n", effTo)
		} else {
			fmt.Printf("        Timeout:     (not set, rsync default)\n")
		}
		if effSAI := f.EffectiveServerAliveInterval(manifest.ServerAliveInterval, targetInterval); effSAI > 0 {
			fmt.Printf("        SSH Alive:   interval=%ds count_max=%d\n", effSAI, f.EffectiveServerAliveCountMax(manifest.ServerAliveCountMax, targetCountMax))
		} else {
			fmt.Printf("        SSH Alive:   (not set)\n")
		}
		fmt.Printf("        Excludes:    %s\n", strings.Join(f.EffectiveExcludes(manifest.Excludes), ", "))
	}
}

func collectStealthBackupManifests(profile string) ([]store.BackupManifest, error) {
	resp, err := queryDaemon(profile, daemon.IPCRequest{
		Action: daemon.IPCActionBackup,
	})
	if err == nil && resp != nil && resp.Success && len(resp.Secrets) > 0 {
		var keys []string
		for k := range resp.Secrets {
			if strings.HasPrefix(k, "backup/") || strings.HasPrefix(k, "backup-batch/") {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		var manifests []store.BackupManifest
		seenNames := make(map[store.BackupJobName]bool)
		for _, k := range keys {
			entry := resp.Secrets[k]
			var m store.BackupManifest
			if json.Unmarshal([]byte(entry.Value), &m) == nil {
				if m.Name == "" {
					raw := strings.TrimPrefix(strings.TrimPrefix(k, "backup-batch/"), "backup/")
					m.Name = store.BackupJobName(raw)
				}
				if seenNames[m.Name] {
					continue
				}
				seenNames[m.Name] = true
				m.ApplyDefaults()
				manifests = append(manifests, m)
			}
		}
		return manifests, nil
	}

	// Fallback to IPCActionList with Path: "backup/" and "backup-batch/"
	listResp, listErr := queryDaemon(profile, daemon.IPCRequest{
		Action:   daemon.IPCActionList,
		Path:     "backup/",
		IsPrefix: true,
		NoTrace:  true,
	})
	if listErr != nil {
		return nil, listErr
	}
	if !listResp.Success {
		return nil, fmt.Errorf("%s", listResp.Error)
	}

	var keys []string
	for _, line := range strings.Split(listResp.Value, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "backup/") {
			keys = append(keys, trimmed)
		}
	}
	if batchResp, batchErr := queryDaemon(profile, daemon.IPCRequest{
		Action:   daemon.IPCActionList,
		Path:     "backup-batch/",
		IsPrefix: true,
		NoTrace:  true,
	}); batchErr == nil && batchResp != nil && batchResp.Success {
		for _, line := range strings.Split(batchResp.Value, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "backup-batch/") {
				keys = append(keys, trimmed)
			}
		}
	}
	sort.Strings(keys)

	var manifests []store.BackupManifest
	seenNames := make(map[store.BackupJobName]bool)
	for _, k := range keys {
		rawName := strings.TrimPrefix(strings.TrimPrefix(k, "backup-batch/"), "backup/")
		if m, mErr := loadStealthBackupManifest(profile, rawName, true); mErr == nil {
			if !seenNames[m.Name] {
				seenNames[m.Name] = true
				manifests = append(manifests, m)
			}
		}
	}
	return manifests, nil
}

func printStealthBackupJobsSection(profile string) {
	manifests, err := collectStealthBackupManifests(profile)
	if err != nil {
		return
	}
	fmt.Printf("\nStealth Rsync Backup Jobs (profile %q):\n", profile)
	if len(manifests) == 0 {
		fmt.Println("  (no stealth backup jobs configured under backup/*)")
		return
	}
	for _, m := range manifests {
		var folderNames []string
		for _, f := range m.Folders {
			folderNames = append(folderNames, f.Source)
		}
		folderSummary := "(no folders)"
		if len(folderNames) > 0 {
			folderSummary = strings.Join(folderNames, ", ")
		}
		fmt.Printf("  • %-16s target=%s  remote=%s  folders=[%s]\n", m.Name, m.SSHTarget, m.RemoteBase, folderSummary)
	}
}

func handleStealthBackupJobs(profile string, args []string) {
	for _, a := range args {
		if a == "--help" || a == "-h" {
			fmt.Println("Usage: sec backup jobs")
			return
		}
	}
	manifests, err := collectStealthBackupManifests(profile)
	if err != nil {
		failDaemonNotRunning(profile)
	}
	fmt.Printf("Stealth Rsync Backup Jobs in profile %q:\n", profile)
	if len(manifests) == 0 {
		fmt.Println("  (none configured — run 'sec backup init <name> --target <target> --remote-base <path>')")
		return
	}
	for _, m := range manifests {
		var folderNames []string
		for _, f := range m.Folders {
			folderNames = append(folderNames, f.Source)
		}
		folderSummary := "(no folders)"
		if len(folderNames) > 0 {
			folderSummary = strings.Join(folderNames, ", ")
		}
		fmt.Printf("  • %-16s target=%s  remote=%s  folders=[%s]\n", m.Name, m.SSHTarget, m.RemoteBase, folderSummary)
	}
}

type resolvedStealthSSHConfig struct {
	TargetName          string
	Host                string
	User                string
	Port                int
	Password            string
	KeyBytes            []byte
	Passphrase          string
	ServerAliveInterval int
	ServerAliveCountMax int
}

func resolveStealthSSHTarget(profile string, manifest store.BackupManifest, noTrace bool) (*resolvedStealthSSHConfig, error) {
	targetName := strings.TrimSpace(manifest.SSHTarget)
	var resolvedHost, resolvedUser, resolvedPassword string
	resolvedPort := 22
	var resolvedServerAliveInterval, resolvedServerAliveCountMax int
	sshKeySecret := strings.TrimSpace(manifest.SSHKeySecret)
	sshPasswordKey := strings.TrimSpace(manifest.SSHPasswordKey)
	sshKeyPath := ""
	sshPassphraseKey := ""

	getSecretNoTrace := func(vaultPath string) (string, bool) {
		if strings.TrimSpace(vaultPath) == "" {
			return "", false
		}
		resp, err := queryDaemon(profile, daemon.IPCRequest{
			Action:  daemon.IPCActionGet,
			Path:    vaultPath,
			NoTrace: noTrace,
		})
		if err != nil || resp == nil || !resp.Success || resp.Value == "" {
			return "", false
		}
		return resp.Value, true
	}

	// 1. Check .secrc for target configuration
	wsCfg := loadWorkspaceConfig()
	if wsCfg != nil && wsCfg.SSHTargets != nil && targetName != "" {
		if tgt, ok := wsCfg.SSHTargets[targetName]; ok {
			resolvedHost = tgt.Host
			resolvedUser = tgt.User
			if tgt.Port > 0 {
				resolvedPort = tgt.Port
			}
			if tgt.IdentityFile != "" && sshKeyPath == "" {
				sshKeyPath = tgt.IdentityFile
			}
			if tgt.KeySecret != "" && sshKeySecret == "" {
				ks := strings.TrimSpace(tgt.KeySecret)
				if !strings.Contains(ks, "/") {
					ks = "ssh/shared/" + ks + "/private_key"
				}
				sshKeySecret = ks
			}
			if tgt.PassphraseKey != "" && sshPassphraseKey == "" {
				sshPassphraseKey = tgt.PassphraseKey
			}
			if tgt.PasswordKey != "" && sshPasswordKey == "" {
				sshPasswordKey = tgt.PasswordKey
			}
		}
	}

	if sshPasswordKey != "" {
		if val, ok := getSecretNoTrace(sshPasswordKey); ok {
			resolvedPassword = val
		}
	}

	// 2. Check active profile vault for ssh/<targetName>/..., ssh/<host>/... (for user@host targets), or ssh/...
	var prefixes []string
	if targetName != "" {
		prefixes = append(prefixes, "ssh/"+targetName+"/")
		if strings.Contains(targetName, "@") {
			if hostPart := strings.TrimSpace(strings.SplitN(targetName, "@", 2)[1]); hostPart != "" {
				prefixes = append(prefixes, "ssh/"+hostPart+"/")
			}
		}
	}
	prefixes = append(prefixes, "ssh/")

	for _, pfx := range prefixes {
		if resolvedHost == "" {
			if val, ok := getSecretNoTrace(pfx + "host"); ok {
				resolvedHost = strings.TrimSpace(val)
			}
		}
		if resolvedUser == "" {
			if val, ok := getSecretNoTrace(pfx + "user"); ok {
				resolvedUser = strings.TrimSpace(val)
			}
		}
		if resolvedPort == 22 {
			if val, ok := getSecretNoTrace(pfx + "port"); ok {
				if p, err := strconv.Atoi(strings.TrimSpace(val)); err == nil && p > 0 {
					resolvedPort = p
				}
			}
		}
		if resolvedPassword == "" {
			if val, ok := getSecretNoTrace(pfx + "password"); ok {
				resolvedPassword = val
			}
		}
		if sshKeySecret == "" && sshKeyPath == "" {
			if val, ok := getSecretNoTrace(pfx + "private_key"); ok && val != "" {
				sshKeySecret = pfx + "private_key"
			} else if val, ok := getSecretNoTrace(pfx + "key_secret"); ok && val != "" {
				resolvedPtr := strings.TrimSpace(val)
				if !strings.Contains(resolvedPtr, "/") {
					resolvedPtr = "ssh/shared/" + resolvedPtr + "/private_key"
				}
				sshKeySecret = resolvedPtr
			} else if val, ok := getSecretNoTrace(pfx + "key"); ok && val != "" {
				if strings.HasPrefix(strings.TrimSpace(val), "-----BEGIN") {
					sshKeySecret = pfx + "key"
				} else {
					sshKeyPath = strings.TrimSpace(val)
				}
			}
		}
		if sshPassphraseKey == "" {
			if _, ok := getSecretNoTrace(pfx + "passphrase"); ok {
				sshPassphraseKey = pfx + "passphrase"
			}
		}
		if resolvedServerAliveInterval == 0 {
			if val, ok := getSecretNoTrace(pfx + "server_alive_interval"); ok {
				if sai, err := strconv.Atoi(strings.TrimSpace(val)); err == nil && sai > 0 {
					resolvedServerAliveInterval = sai
				}
			}
		}
		if resolvedServerAliveCountMax == 0 {
			if val, ok := getSecretNoTrace(pfx + "server_alive_count_max"); ok {
				if sac, err := strconv.Atoi(strings.TrimSpace(val)); err == nil && sac > 0 {
					resolvedServerAliveCountMax = sac
				}
			}
		}
	}

	// 3. Parse user@host or direct host if resolvedHost is still empty
	if resolvedHost == "" {
		if strings.Contains(targetName, "@") {
			parts := strings.SplitN(targetName, "@", 2)
			if resolvedUser == "" {
				resolvedUser = parts[0]
			}
			resolvedHost = parts[1]
		} else if targetName != "" {
			resolvedHost = targetName
		}
	}

	if resolvedHost == "" {
		if Verbose {
			return nil, fmt.Errorf("unknown SSH target %q and not a valid user@host destination", targetName)
		}
		return nil, fmt.Errorf("unknown SSH target and not a valid destination")
	}

	if manifest.SSHPort > 0 {
		resolvedPort = manifest.SSHPort
	}
	if resolvedUser == "" {
		if curUser, err := user.Current(); err == nil && curUser.Username != "" {
			resolvedUser = curUser.Username
		} else {
			resolvedUser = "root"
		}
	}

	var keyBytes []byte
	if sshKeySecret != "" {
		if val, ok := getSecretNoTrace(sshKeySecret); ok {
			keyBytes = []byte(val)
		} else {
			return nil, fmt.Errorf("failed to retrieve SSH private key secret %q from vault", sshKeySecret)
		}
	} else if sshKeyPath != "" {
		expandedKeyPath := expandLocalBasePath(sshKeyPath)
		// #nosec G304 G703
		if b, err := os.ReadFile(expandedKeyPath); err == nil {
			keyBytes = b
		} else if val, ok := getSecretNoTrace(sshKeyPath); ok {
			keyBytes = []byte(val)
		} else {
			return nil, fmt.Errorf("failed to read SSH private key %q: %w", sshKeyPath, err)
		}
	}

	passphrase := ""
	if sshPassphraseKey != "" {
		if val, ok := getSecretNoTrace(sshPassphraseKey); ok {
			passphrase = val
		}
	}

	return &resolvedStealthSSHConfig{
		TargetName:          targetName,
		Host:                resolvedHost,
		User:                resolvedUser,
		Port:                resolvedPort,
		Password:            resolvedPassword,
		KeyBytes:            keyBytes,
		Passphrase:          passphrase,
		ServerAliveInterval: resolvedServerAliveInterval,
		ServerAliveCountMax: resolvedServerAliveCountMax,
	}, nil
}

func dialStealthSSHClient(profile string, cfg *resolvedStealthSSHConfig, opts hostKeyOptions) (*ssh.Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil SSH configuration")
	}

	var authMethods []ssh.AuthMethod
	if len(cfg.KeyBytes) > 0 {
		var signer ssh.Signer
		var err error
		if cfg.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(cfg.KeyBytes, []byte(cfg.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(cfg.KeyBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse vault SSH private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if cfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(cfg.Password))
	}
	if len(authMethods) == 0 {
		if Verbose {
			return nil, fmt.Errorf("no vault SSH credentials (private_key or password) found for target %q", cfg.TargetName)
		}
		return nil, fmt.Errorf("no vault SSH credentials (private_key or password) found for configured target")
	}

	pinTarget := cfg.TargetName
	if strings.Contains(pinTarget, "@") {
		pinTarget = ""
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: vaultHostKeyCallback(profile, pinTarget, cfg.Host, cfg.Port, opts),
		Timeout:         15 * time.Second,
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		if Verbose {
			return nil, fmt.Errorf("failed to dial SSH server at %s: %w", addr, err)
		}
		return nil, fmt.Errorf("failed to dial SSH server: %s", redactBackupOutputLine(err.Error()))
	}
	return client, nil
}

// rewriteRemoteRsyncServerCommand intercepts the remote `rsync --server` argument vector
// passed by local `rsync` to `-e`, replaces the remote `rsync` binary with `manifest.RemoteRsyncBin`,
// injects `--log-file=<remoteLogPath>` and `-b --backup-dir=<remoteHistoryDir>` right after `--server`,
// replaces the opaque `"target"` destination with the real remote folder path, and prepends
// `mkdir -p <remoteHistoryDir> <remoteDest> && ` so parent/history directories always exist.
func rewriteRemoteRsyncServerCommand(clientArgs []string, manifest store.BackupManifest, folder store.BackupFolderSpec, now time.Time) string {
	manifest.ApplyDefaults()
	dateStr := now.Format("2006-01-02")
	datetimeStr := now.Format("2006-01-02_1504")

	remoteDest := folder.DeriveRemoteDest(manifest.RemoteBase)
	remoteHistoryDir := folder.DeriveHistoryDir(manifest.RemoteBase, dateStr)
	remoteLogPath := folder.DeriveRemoteLogPath(manifest.RemoteBase, datetimeStr)

	normalized := make([]string, 0, len(clientArgs))
	for _, a := range clientArgs {
		if strings.Contains(a, "--server") && strings.Contains(a, " ") {
			normalized = append(normalized, strings.Fields(a)...)
		} else {
			normalized = append(normalized, a)
		}
	}

	serverIdx := -1
	for i, a := range normalized {
		if a == "--server" {
			serverIdx = i
			break
		}
	}

	var tailArgs []string
	if serverIdx != -1 && serverIdx+1 < len(normalized) {
		tailArgs = append(tailArgs, normalized[serverIdx+1:]...)
	} else {
		tailArgs = []string{"-vlogDtprze.iLsfxCIvu", fmt.Sprintf("--modify-window=%d", manifest.ModifyWindow), fmt.Sprintf("--partial-dir=%s", manifest.PartialDir), ".", "target"}
	}

	if len(tailArgs) == 0 {
		tailArgs = []string{".", shellQuotePOSIX(remoteDest)}
	} else {
		tailArgs[len(tailArgs)-1] = shellQuotePOSIX(remoteDest)
	}

	var cmdParts []string
	cmdParts = append(cmdParts,
		shellQuotePOSIX(manifest.RemoteRsyncBin),
		"--server",
		"--log-file="+shellQuotePOSIX(remoteLogPath),
		"-b",
		"--backup-dir="+shellQuotePOSIX(remoteHistoryDir),
	)
	if folder.Sparse {
		hasSparse := false
		for _, ta := range tailArgs {
			if ta == "--sparse" || ta == "-S" {
				hasSparse = true
				break
			}
		}
		if !hasSparse {
			cmdParts = append(cmdParts, "--sparse")
		}
	}
	if effTimeout := folder.EffectiveTimeout(manifest.Timeout); effTimeout > 0 {
		hasTimeout := false
		for _, ta := range tailArgs {
			if strings.HasPrefix(ta, "--timeout=") {
				hasTimeout = true
				break
			}
		}
		if !hasTimeout {
			cmdParts = append(cmdParts, fmt.Sprintf("--timeout=%d", effTimeout))
		}
	}
	cmdParts = append(cmdParts, tailArgs...)

	remoteRsyncCmd := strings.Join(cmdParts, " ")
	return fmt.Sprintf("mkdir -p %s %s && %s",
		shellQuotePOSIX(remoteHistoryDir),
		shellQuotePOSIX(remoteDest),
		remoteRsyncCmd,
	)
}

func shellQuoteIfNeeded(s string) string {
	if strings.ContainsAny(s, " \t\"'\\") {
		return shellQuotePOSIX(s)
	}
	return s
}

// buildLocalStealthRsyncArgs constructs a minimal local `rsync` command-line argument slice.
// By setting `cmd.Dir = localDir`, moving transport (`RSYNC_RSH`) and partial-dir (`RSYNC_PARTIAL_DIR`)
// into `cmd.Env`, passing excludes via `/dev/fd/3`, and using compact flags + opaque `. s:t`,
// zero folder names, volume paths, usernames, IP addresses, or verbose transport options
// appear in the local host's `ps aux` process table.
// In normal mode (`!verbose`), `-v` and `--progress` are omitted and `--stats` is used so
// filenames are never emitted over stdout; per-file output (`-rtvP`) is gated behind `--verbose`.
func buildLocalStealthRsyncArgs(manifest store.BackupManifest, selfExe string, dryRun bool, verbose bool, folders ...store.BackupFolderSpec) []string {
	_ = selfExe
	manifest.ApplyDefaults()
	var activeFolder store.BackupFolderSpec
	if len(folders) > 0 {
		activeFolder = folders[0]
	} else if len(manifest.Folders) == 1 {
		activeFolder = manifest.Folders[0]
	}

	shortFlags := "-rt"
	if verbose {
		shortFlags = "-rtvP"
	}
	if activeFolder.Sparse {
		shortFlags += "S"
	}
	if dryRun {
		shortFlags += "n"
	}
	args := []string{shortFlags}
	if !verbose {
		args = append(args, "--partial", "--stats")
		if npDur, npErr := manifest.EffectiveNoProgressTimeout(); npErr == nil && npDur > 0 {
			args = append(args, "--info=name0,flist2,progress2")
		}
	}
	if effTimeout := activeFolder.EffectiveTimeout(manifest.Timeout); effTimeout > 0 {
		args = append(args, fmt.Sprintf("--timeout=%d", effTimeout))
	}
	args = append(args, fmt.Sprintf("--modify-window=%d", manifest.ModifyWindow))
	if len(activeFolder.EffectiveExcludes(manifest.Excludes)) > 0 {
		args = append(args, "--exclude-from=/dev/fd/3")
	}
	args = append(args, ".", "s:t")
	return args
}

// buildLocalStealthRsyncEnv builds the subprocess environment for local `rsync`,
// passing the stealth transport (`RSYNC_RSH`), partial-dir (`RSYNC_PARTIAL_DIR`),
// and ephemeral stdio socket (`SEC_STDIO_SOCK`) privately via environment variables
// rather than process argv.
func buildLocalStealthRsyncEnv(manifest store.BackupManifest, selfExe string, sockPath string) []string {
	manifest.ApplyDefaults()
	rshCmd := fmt.Sprintf("%s ssh-stdio", shellQuoteIfNeeded(selfExe))
	env := make([]string, 0, len(os.Environ())+3)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "RSYNC_RSH=") ||
			strings.HasPrefix(kv, "RSYNC_PARTIAL_DIR=") ||
			strings.HasPrefix(kv, "SEC_STDIO_SOCK=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env,
		fmt.Sprintf("SEC_STDIO_SOCK=%s", sockPath),
		fmt.Sprintf("RSYNC_RSH=%s", rshCmd),
	)
	if strings.TrimSpace(manifest.PartialDir) != "" {
		env = append(env, fmt.Sprintf("RSYNC_PARTIAL_DIR=%s", manifest.PartialDir))
	}
	return env
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

var (
	reQuotedSegment = regexp.MustCompile(`"[^"\r\n]+"`)
	reUserAtHost    = regexp.MustCompile(`\b[A-Za-z0-9._-]+@[A-Za-z0-9.-]+(?::\d+)?\b`)
	reIPv4Addr      = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b`)
	reAbsOrHomePath = regexp.MustCompile(`(^|[\s(\['=])(?:~/|/)[^\s:,"')\]]+`)
	reStatsNumber   = regexp.MustCompile(`:\s*([0-9,]+)`)
)

// safeFolderAlias returns a privacy-preserving display label for a backup folder:
// its explicit alias Name if configured, otherwise its derived slug (never raw Source or localDir).
func safeFolderAlias(folder store.BackupFolderSpec) string {
	if n := strings.TrimSpace(folder.Name); n != "" {
		return n
	}
	return folder.DeriveSlug()
}

// redactBackupOutputLine scrubs filesystem paths, quoted filenames, user@host tokens, and
// IPv4 addresses from rsync/SSH error lines while preserving error classes and exit codes.
func redactBackupOutputLine(line string) string {
	suffix := ""
	body := line
	if strings.HasSuffix(body, "\n") {
		suffix = "\n"
		body = strings.TrimSuffix(body, "\n")
	}
	if strings.TrimSpace(body) == "" {
		return line
	}
	body = reQuotedSegment.ReplaceAllString(body, `"<path>"`)
	body = reUserAtHost.ReplaceAllString(body, "<host>")
	body = reIPv4Addr.ReplaceAllString(body, "<host>")
	body = reAbsOrHomePath.ReplaceAllString(body, "${1}<path>")
	return body + suffix
}

// openHardenedBackupLogFile creates parent directories with 0700 permissions and opens/creates
// the local backup log file with strict 0600 permissions.
func openHardenedBackupLogFile(rawPath string) (*os.File, string, error) {
	expanded := expandLocalBasePath(rawPath)
	if strings.TrimSpace(expanded) == "" {
		return nil, "", fmt.Errorf("log file path cannot be empty")
	}
	dir := filepath.Dir(expanded)
	// #nosec G301 G703
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, "", fmt.Errorf("failed to create log directory: %w", err)
	}
	// #nosec G302 G703
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, "", fmt.Errorf("failed to harden log directory permissions to 0700: %w", err)
	}
	// #nosec G304 G703
	f, err := os.OpenFile(expanded, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open log file: %w", err)
	}
	// #nosec G302 G703
	if err := os.Chmod(expanded, 0600); err != nil {
		_ = f.Close()
		return nil, "", fmt.Errorf("failed to harden log file permissions to 0600: %w", err)
	}
	return f, expanded, nil
}

// rsyncStdoutStatsWriter consumes local rsync stdout.
// In normal mode (!verbose), zero raw lines are forwarded; instead, `--stats` transfer counters
// (compatible with both GNU rsync and macOS openrsync) are parsed in memory.
// In verbose mode, raw stdout is forwarded to dst.
type rsyncStdoutStatsWriter struct {
	mu                sync.Mutex
	dst               io.Writer
	verbose           bool
	buf               []byte
	transferredFiles  int
	totalFiles        int
	skippedNonRegular int
	tracker           *backupProgressTracker
}

func newRsyncStdoutStatsWriter(dst io.Writer, verbose bool, trackers ...*backupProgressTracker) *rsyncStdoutStatsWriter {
	var tr *backupProgressTracker
	if len(trackers) > 0 {
		tr = trackers[0]
	}
	return &rsyncStdoutStatsWriter{dst: dst, verbose: verbose, tracker: tr}
}

func (w *rsyncStdoutStatsWriter) parseStatsLine(line string) {
	if w.tracker != nil {
		w.tracker.RecordProgressLine(line)
	}
	trimmed := strings.TrimSpace(line)
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "skipping non-regular file") {
		w.skippedNonRegular++
		return
	}
	if strings.HasPrefix(lower, "number of regular files transferred:") ||
		strings.HasPrefix(lower, "number of files transferred:") {
		if m := reStatsNumber.FindStringSubmatch(trimmed); len(m) == 2 {
			if n, err := strconv.Atoi(strings.ReplaceAll(m[1], ",", "")); err == nil {
				w.transferredFiles = n
			}
		}
	} else if strings.HasPrefix(lower, "number of files:") {
		if m := reStatsNumber.FindStringSubmatch(trimmed); len(m) == 2 {
			if n, err := strconv.Atoi(strings.ReplaceAll(m[1], ",", "")); err == nil {
				w.totalFiles = n
			}
		}
	}
}

func (w *rsyncStdoutStatsWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.verbose && w.dst != nil {
		if _, err := w.dst.Write(p); err != nil {
			return 0, err
		}
	}
	w.buf = append(w.buf, p...)
	for {
		idx := strings.IndexAny(string(w.buf), "\r\n")
		if idx == -1 {
			break
		}
		line := string(w.buf[:idx+1])
		w.buf = w.buf[idx+1:]
		w.parseStatsLine(line)
	}
	return len(p), nil
}

func (w *rsyncStdoutStatsWriter) Flush() (transferred int, total int, skippedNonRegular int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) > 0 {
		w.parseStatsLine(string(w.buf))
		w.buf = nil
	}
	return w.transferredFiles, w.totalFiles, w.skippedNonRegular
}

// rsyncRedactingStderrWriter filters noisy informational "skipping non-regular file" lines
// emitted by rsync for symlinks/sockets and redacts paths/hosts on remaining error lines when
// not in Verbose mode, counting skipped items so a single concise summary can be printed.
type rsyncRedactingStderrWriter struct {
	mu                sync.Mutex
	dst               io.Writer
	verbose           bool
	buf               []byte
	skippedNonRegular int
}

// rsyncStderrFilterWriter is kept as a type alias for backward compatibility with internal callers/tests.
type rsyncStderrFilterWriter = rsyncRedactingStderrWriter

func newRsyncStderrFilterWriter(dst io.Writer, verbose bool) *rsyncRedactingStderrWriter {
	return &rsyncRedactingStderrWriter{dst: dst, verbose: verbose}
}

func (w *rsyncRedactingStderrWriter) processLineLocked(line string) {
	if strings.HasPrefix(strings.TrimSpace(line), "skipping non-regular file") {
		w.skippedNonRegular++
		return
	}
	if w.dst != nil {
		_, _ = io.WriteString(w.dst, redactBackupOutputLine(line))
	}
}

func (w *rsyncRedactingStderrWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.verbose {
		if w.dst == nil {
			return len(p), nil
		}
		return w.dst.Write(p)
	}
	w.buf = append(w.buf, p...)
	for {
		idx := strings.IndexByte(string(w.buf), '\n')
		if idx == -1 {
			break
		}
		line := string(w.buf[:idx+1])
		w.buf = w.buf[idx+1:]
		w.processLineLocked(line)
	}
	return len(p), nil
}

func (w *rsyncRedactingStderrWriter) Flush() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) > 0 {
		line := string(w.buf)
		w.buf = nil
		if w.verbose {
			if w.dst != nil {
				_, _ = io.WriteString(w.dst, line)
			}
		} else {
			w.processLineLocked(line)
		}
	}
	return w.skippedNonRegular
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

// startStealthStdioBridge starts an ephemeral Unix domain socket listener (0600 in a private temp dir)
// for a single folder synchronization session. When the local `ssh-stdio` helper connects and sends
// its 1-line JSON argument header, the bridge rewrites the remote `rsync --server` command and streams
// stdin/stdout bi-directionally through `runner`. Optional `stderrWriters` lets callers route remote
// SSH stderr through a privacy-preserving redacting filter instead of raw os.Stderr.
func startStealthStdioBridge(manifest store.BackupManifest, folder store.BackupFolderSpec, now time.Time, runner remoteCommandRunner, stderrWriters ...io.Writer) (sockPath string, waitErr func() error, cleanup func(), err error) {
	remoteStderr := io.Writer(os.Stderr)
	if len(stderrWriters) > 0 && stderrWriters[0] != nil {
		remoteStderr = stderrWriters[0]
	}

	tmpDir, err := os.MkdirTemp("", "sec_stdio_*")
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to create ephemeral stdio socket dir: %w", err)
	}

	sockPath = filepath.Join(tmpDir, "s.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, nil, fmt.Errorf("failed to listen on ephemeral unix socket %s: %w", sockPath, err)
	}
	// #nosec G302
	if err := os.Chmod(sockPath, 0600); err != nil {
		_ = listener.Close()
		_ = os.RemoveAll(tmpDir)
		return "", nil, nil, fmt.Errorf("failed to set 0600 permissions on %s: %w", sockPath, err)
	}

	errCh := make(chan error, 1)
	var once sync.Once

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		headerLine, readErr := br.ReadBytes('\n')
		if readErr != nil {
			errCh <- fmt.Errorf("failed reading ssh-stdio handshake header: %w", readErr)
			return
		}

		var hs sshStdioHandshake
		if unmarshalErr := json.Unmarshal(headerLine, &hs); unmarshalErr != nil {
			errCh <- fmt.Errorf("invalid ssh-stdio handshake JSON: %w", unmarshalErr)
			return
		}

		remoteCmd := rewriteRemoteRsyncServerCommand(hs.Args, manifest, folder, now)
		runErr := runner(remoteCmd, br, conn, remoteStderr)
		if uc, ok := conn.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
		errCh <- runErr
	}()

	waitErr = func() error {
		select {
		case e := <-errCh:
			return e
		case <-time.After(2 * time.Second):
			return nil
		}
	}

	cleanup = func() {
		once.Do(func() {
			_ = listener.Close()
			_ = os.RemoveAll(tmpDir)
		})
	}

	return sockPath, waitErr, cleanup, nil
}

// runSSHStdioClient connects to `sockPath`, sends the 1-line JSON argument handshake,
// and bi-directionally copies stdin -> conn (half-closing write on EOF) and conn -> stdout.
func runSSHStdioClient(sockPath string, args []string, stdin io.Reader, stdout io.Writer) error {
	if strings.TrimSpace(sockPath) == "" {
		return fmt.Errorf("SEC_STDIO_SOCK is not set")
	}
	// #nosec G704
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return fmt.Errorf("failed to connect to SEC_STDIO_SOCK (%s): %w", sockPath, err)
	}
	defer conn.Close()

	headerBytes, err := json.Marshal(sshStdioHandshake{Args: args})
	if err != nil {
		return fmt.Errorf("failed to marshal ssh-stdio handshake: %w", err)
	}
	headerBytes = append(headerBytes, '\n')
	if _, err := conn.Write(headerBytes); err != nil {
		return fmt.Errorf("failed to send ssh-stdio handshake: %w", err)
	}

	go func() {
		if stdin != nil {
			_, _ = io.Copy(conn, stdin)
		}
		if uc, ok := conn.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
	}()

	if stdout != nil {
		if _, err := io.Copy(stdout, conn); err != nil {
			return fmt.Errorf("error streaming from ssh-stdio socket: %w", err)
		}
	}
	return nil
}

// runInternalSSHStdio is the entrypoint for `sec ssh-stdio` (and `sec backup ssh-stdio`)
// invoked by local `rsync -e "<selfExe> ssh-stdio"`.
func runInternalSSHStdio(args []string) int {
	sockPath := os.Getenv("SEC_STDIO_SOCK")
	if err := runSSHStdioClient(sockPath, args, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "sec ssh-stdio error: %v\n", err)
		return 1
	}
	return 0
}

// rsyncIsOpenrsync reports whether bin is Apple's openrsync (protocol 29, shipped at /usr/bin/rsync).
// openrsync does not support server-side --log-file in the same way as GNU rsync (protocol 31+).
func rsyncIsOpenrsync(bin string) bool {
	if strings.TrimSpace(bin) == "" {
		return false
	}
	// #nosec G204 G702
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil && len(out) == 0 {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "openrsync")
}

func findLocalRsyncBinary() (string, error) {
	if custom := strings.TrimSpace(os.Getenv("SEC_LOCAL_RSYNC_BIN")); custom != "" {
		return custom, nil
	}
	for _, candidate := range []string{"/opt/homebrew/bin/rsync", "/usr/local/bin/rsync"} {
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate, nil
		}
	}
	return exec.LookPath("rsync")
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
			fmt.Println("Usage: sec backup run <name> [<folder-filter>] [--max-attempts <n>] [--timeout <sec>] [--server-alive-interval <sec>] [--server-alive-count-max <count>] [--dry-run] [--verbose] [--log-file <path>] [--no-trace] [--trace] [--tofu] [--insecure]")
			fmt.Println("Usage: sec backup run <name> [<folder-filter>] [--max-attempts <n>] [--timeout <sec>] [--no-progress-timeout <dur>] [--server-alive-interval <sec>] [--server-alive-count-max <count>] [--dry-run] [--verbose] [--log-file <path>] [--no-trace] [--trace] [--tofu] [--insecure]")
			return nil
		}
		switch {
		case a == "--dry-run" || a == "-n":
			dryRun = true
		case a == "--verbose" || a == "-v":
			localVerbose = true
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

	selfExe, err := os.Executable()
	if err != nil {
		return &stealthBackupCliError{
			Code: "EXECUTABLE_NOT_FOUND",
			Err:  fmt.Errorf("failed to determine current executable path: %w", err),
		}
	}

	sshCfg, err := resolveStealthSSHTarget(profile, manifest, noTrace)
	if err != nil {
		return &stealthBackupCliError{
			Code:        "SSH_TARGET_ERROR",
			Err:         err,
			Remediation: "Configure target credentials in vault via 'sec ssh init <target>'",
		}
	}

	hkOpts := hostKeyOptions{
		insecure:        insecureHostKey,
		trustOnFirstUse: trustOnFirstUse,
		updateHostKey:   updateHostKey,
		noTrace:         noTrace,
	}

	sshClient, err := dialStealthSSHClient(profile, sshCfg, hkOpts)
	if err != nil {
		return &stealthBackupCliError{Code: "SSH_CONNECT_FAILED", Err: err}
	}
	defer func() {
		if sshClient != nil {
			_ = sshClient.Close()
		}
	}()

	stopKeepalive, lostCh := keepStealthBackupSessionAlive(profile, noTrace)
	defer stopKeepalive()

	reconnectFn := func() error {
		if sshClient != nil {
			_ = sshClient.Close()
			sshClient = nil
		}
		var dErr error
		sshClient, dErr = dialStealthSSHClient(profile, sshCfg, hkOpts)
		return dErr
	}

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

	attemptFn := func(folder store.BackupFolderSpec, _ int) (backupFolderRunStats, error) {
		if sshClient == nil {
			if dErr := reconnectFn(); dErr != nil {
				return backupFolderRunStats{ExitCode: 1}, dErr
			}
		}

		aliveInterval := folder.EffectiveServerAliveInterval(manifest.ServerAliveInterval, sshCfg.ServerAliveInterval)
		aliveCountMax := folder.EffectiveServerAliveCountMax(manifest.ServerAliveCountMax, sshCfg.ServerAliveCountMax)
		stopServerAlive := startSSHServerAliveMonitor(sshClient, time.Duration(aliveInterval)*time.Second, aliveCountMax)
		defer stopServerAlive()

		now := time.Now()
		dateStr := now.Format("2006-01-02")
		datetimeStr := now.Format("2006-01-02_1504")

		folderAlias := safeFolderAlias(folder)
		localDir := folder.ResolveLocalDir(expandedLocalBase)
		remoteDest := folder.DeriveRemoteDest(manifest.RemoteBase)
		remoteHistoryDir := folder.DeriveHistoryDir(manifest.RemoteBase, dateStr)
		remoteLogPath := folder.DeriveRemoteLogPath(manifest.RemoteBase, datetimeStr)

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

		if effectiveVerbose {
			fmt.Fprintf(errWriter, "[VERBOSE] Remote Dest: %s | History: %s | Log: %s\n", remoteDest, remoteHistoryDir, remoteLogPath)
		}

		progressTracker := newBackupProgressTracker()

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
			session.Stdout = stdout
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

		stdoutFilter := newRsyncStdoutStatsWriter(outWriter, effectiveVerbose, progressTracker)
		stderrFilter := newRsyncStderrFilterWriter(errWriter, effectiveVerbose)

		sockPath, waitBridgeErr, cleanupBridge, bErr := startStealthStdioBridge(manifest, folder, now, sshRunner, stderrFilter)
		if bErr != nil {
			return backupFolderRunStats{ExitCode: 1}, bErr
		}

		excludePipeRead, excludePipeWrite, pErr := os.Pipe()
		if pErr != nil {
			cleanupBridge()
			return backupFolderRunStats{ExitCode: 1}, fmt.Errorf("failed to create anonymous exclude pipe: %w", pErr)
		}
		excludeContent := strings.Join(folder.EffectiveExcludes(manifest.Excludes), "\n") + "\n"
		go func(w *os.File, payload string) {
			_, _ = w.WriteString(payload)
			_ = w.Close()
		}(excludePipeWrite, excludeContent)

		rsyncArgs := buildLocalStealthRsyncArgs(manifest, selfExe, dryRun, effectiveVerbose, folder)
		// #nosec G204 G702
		cmd := exec.Command(localRsyncBin, rsyncArgs...)
		cmd.Dir = localDir
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
