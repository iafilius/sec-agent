package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"secure_secrets/internal/daemon"
	"secure_secrets/internal/store"
	"sort"
	"strconv"
	"strings"
	"time"
)

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
	var fromStdin, sparse, noProgressTimeoutSet, isLocal, isPull bool
	var excludes []string
	var folders []store.BackupFolderSpec

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--help" || a == "-h" {
			printStealthBackupUsage()
			return
		}
		switch {
		case a == "--local":
			isLocal = true
		case a == "--pull":
			isPull = true
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
		case (a == "--local-base" || a == "--source-base") && i+1 < len(args):
			localBase = args[i+1]
			i++
		case strings.HasPrefix(a, "--local-base="):
			localBase = strings.TrimPrefix(a, "--local-base=")
		case strings.HasPrefix(a, "--source-base="):
			localBase = strings.TrimPrefix(a, "--source-base=")
		case (a == "--remote-base" || a == "--dest-base") && i+1 < len(args):
			remoteBase = args[i+1]
			i++
		case strings.HasPrefix(a, "--remote-base="):
			remoteBase = strings.TrimPrefix(a, "--remote-base=")
		case strings.HasPrefix(a, "--dest-base="):
			remoteBase = strings.TrimPrefix(a, "--dest-base=")
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
		if isLocal {
			manifest.Transport = store.BackupTransportLocal
		} else if isPull {
			manifest.Transport = store.BackupTransportSSHPull
		}
		if target != "" {
			manifest.SSHTarget = strings.TrimSpace(target)
		}
		if localBase != "" {
			if manifest.EffectiveTransport() == store.BackupTransportSSHPull {
				manifest.LocalBase = strings.TrimSpace(localBase)
			} else {
				manifest.LocalBase = expandLocalBasePath(localBase)
			}
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
		if manifest.LocalBase != "" && manifest.EffectiveTransport() != store.BackupTransportSSHPull {
			manifest.LocalBase = expandLocalBasePath(manifest.LocalBase)
		}
	} else {
		jobName, err := store.NewBackupJobName(rawName)
		if err != nil {
			fail("INVALID_ARGUMENTS", err, "Usage: sec backup init <name> [--local | --pull] [--target <ssh-target-or-user@host>] (--remote-base <path> | --dest-base <path>) [--local-base <path> | --source-base <path>]")
		}
		if isLocal && isPull {
			fail("INVALID_ARGUMENTS", fmt.Errorf("--local and --pull cannot be combined"), "Use --local for local-to-local or --pull --target <ssh-target> for remote-to-local")
		}
		transport := store.BackupTransportSSH
		if isLocal {
			transport = store.BackupTransportLocal
		} else if isPull {
			transport = store.BackupTransportSSHPull
		}
		if (transport == store.BackupTransportSSH || transport == store.BackupTransportSSHPull) && strings.TrimSpace(target) == "" {
			fail("MISSING_ARGUMENT", fmt.Errorf("--target is required for 'sec backup init' (or pass --local for local rsync backup)"), "Pass --target <ssh-target-or-user@host> or --local")
		}
		if strings.TrimSpace(remoteBase) == "" {
			fail("MISSING_ARGUMENT", fmt.Errorf("--remote-base (or --dest-base) is required for 'sec backup init'"), "Pass --dest-base <path> or --remote-base <path>")
		}

		resolvedSourceBase := expandLocalBasePath(localBase)
		if transport == store.BackupTransportSSHPull {
			resolvedSourceBase = strings.TrimSpace(localBase)
			if resolvedSourceBase == "" {
				resolvedSourceBase = "~"
			}
		}
		if sparse {
			for idx := range folders {
				folders[idx].Sparse = true
			}
		}

		manifest = store.BackupManifest{
			Name:                jobName,
			Transport:           transport,
			SSHTarget:           strings.TrimSpace(target),
			SSHKeySecret:        strings.TrimSpace(sshKeySecret),
			SSHPasswordKey:      strings.TrimSpace(sshPasswordKey),
			SSHPort:             port,
			LocalBase:           resolvedSourceBase,
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
	switch manifest.EffectiveTransport() {
	case store.BackupTransportLocal:
		fmt.Printf("    Transport:   local (direct rsync)\n")
		fmt.Printf("    Local Base:  %s\n", manifest.LocalBase)
		fmt.Printf("    Dest Base:   %s\n", manifest.RemoteBase)
	case store.BackupTransportSSHPull:
		fmt.Printf("    Transport:   ssh-pull (remote -> local)\n")
		fmt.Printf("    SSH Target:  %s\n", manifest.SSHTarget)
		fmt.Printf("    Source Base: %s (remote)\n", manifest.LocalBase)
		fmt.Printf("    Dest Base:   %s (local)\n", manifest.RemoteBase)
	default:
		fmt.Printf("    Transport:   ssh\n")
		fmt.Printf("    SSH Target:  %s\n", manifest.SSHTarget)
		fmt.Printf("    Local Base:  %s\n", manifest.LocalBase)
		fmt.Printf("    Remote Base: %s\n", manifest.RemoteBase)
	}
	if len(manifest.Folders) > 0 {
		fmt.Printf("    Folders:     %d configured\n", len(manifest.Folders))
	} else {
		fmt.Printf("    Next step:   sec backup add-folder %s \"<Folder Name>\"\n", manifest.Name)
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
			// Merge newly supplied fields into the existing folder spec so adding
			// --exclude patterns to an existing folder preserves its other settings.
			merged := existing
			merged.Source = spec.Source
			if spec.Dest != "" {
				merged.Dest = spec.Dest
			}
			if spec.HistoryPrefix != "" {
				merged.HistoryPrefix = spec.HistoryPrefix
			}
			if spec.Slug != "" {
				merged.Slug = spec.Slug
			}
			if spec.Sparse {
				merged.Sparse = true
			}
			if spec.BackupDir != "" {
				merged.BackupDir = spec.BackupDir
			}
			if spec.LogFile != "" {
				merged.LogFile = spec.LogFile
			}
			if spec.Timeout > 0 {
				merged.Timeout = spec.Timeout
			}
			if spec.ServerAliveInterval > 0 {
				merged.ServerAliveInterval = spec.ServerAliveInterval
			}
			if spec.ServerAliveCountMax > 0 {
				merged.ServerAliveCountMax = spec.ServerAliveCountMax
			}
			if len(spec.Excludes) > 0 {
				seen := make(map[string]bool, len(merged.Excludes)+len(spec.Excludes))
				var combined []string
				for _, pat := range append(merged.Excludes, spec.Excludes...) {
					trimmed := strings.TrimSpace(pat)
					if trimmed == "" || seen[trimmed] {
						continue
					}
					seen[trimmed] = true
					combined = append(combined, trimmed)
				}
				merged.Excludes = combined
			}
			manifest.Folders[i] = merged
			spec = merged
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
	if manifest.EffectiveTransport() != store.BackupTransportLocal {
		if sshCfg, sErr := resolveStealthSSHTarget(profile, manifest, true); sErr == nil && sshCfg != nil {
			targetInterval = sshCfg.ServerAliveInterval
			targetCountMax = sshCfg.ServerAliveCountMax
		}
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
	fmt.Printf("  Transport:      %s\n", manifest.EffectiveTransport())
	if manifest.EffectiveTransport() != store.BackupTransportLocal {
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
	}
	switch manifest.EffectiveTransport() {
	case store.BackupTransportLocal:
		fmt.Printf("  Local Base:     %s\n", manifest.LocalBase)
		fmt.Printf("  Dest Base:      %s\n", manifest.RemoteBase)
	case store.BackupTransportSSHPull:
		fmt.Printf("  Source Base:    %s (remote)\n", manifest.LocalBase)
		fmt.Printf("  Dest Base:      %s (local)\n", manifest.RemoteBase)
		fmt.Printf("  Remote Rsync:   %s\n", manifest.RemoteRsyncBin)
	default:
		fmt.Printf("  Local Base:     %s\n", manifest.LocalBase)
		fmt.Printf("  Remote Base:    %s\n", manifest.RemoteBase)
		fmt.Printf("  Remote Rsync:   %s\n", manifest.RemoteRsyncBin)
	}
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
		if manifest.EffectiveTransport() == store.BackupTransportSSHPull {
			fmt.Printf("        Remote Src:  %s\n", f.ResolveRemoteSource(manifest.LocalBase))
		} else {
			fmt.Printf("        Local Path:  %s\n", f.ResolveLocalDir(expandedLocalBase))
		}
		fmt.Printf("        Destination: %s\n", f.DeriveRemoteDest(manifest.RemoteBase))
		fmt.Printf("        History Dir: %s\n", f.DeriveHistoryDir(manifest.RemoteBase, dateStr))
		if manifest.EffectiveTransport() == store.BackupTransportSSH {
			fmt.Printf("        Remote Log:  %s\n", f.DeriveRemoteLogPath(manifest.RemoteBase, datetimeStr))
		} else {
			fmt.Printf("        Local Log:   %s\n", f.DeriveRemoteLogPath(manifest.RemoteBase, datetimeStr))
		}
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
		if m.EffectiveTransport() == store.BackupTransportLocal {
			fmt.Printf("  • %-16s transport=local  dest=%s  folders=[%s]\n", m.Name, m.RemoteBase, folderSummary)
		} else {
			fmt.Printf("  • %-16s target=%s  remote=%s  folders=[%s]\n", m.Name, m.SSHTarget, m.RemoteBase, folderSummary)
		}
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
		if m.EffectiveTransport() == store.BackupTransportLocal {
			fmt.Printf("  • %-16s transport=local  dest=%s  folders=[%s]\n", m.Name, m.RemoteBase, folderSummary)
		} else {
			fmt.Printf("  • %-16s target=%s  remote=%s  folders=[%s]\n", m.Name, m.SSHTarget, m.RemoteBase, folderSummary)
		}
	}
}
